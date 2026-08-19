"""
Protocol-level tests for INS 0x27 — PLT (Protocol Level Token) signing.

The handler validates APDU framing and CIS-7 CBOR structure, then shows UI for
user approval.  Tests here exercise the protocol layer (framing, state machine,
buffer management, CIS-7 rejection) using synchronous backend.exchange() calls.
Tests that require user approval / signature output live in test_sign_plt_ui.py.

APDU wire format:
  INIT (P1=0x00): path + account_tx_header[60] + kind[1]=0x1B + token_id_length[1]
                  + token_id[1..128] + cbor_total_length[4 BE]
  CONT (P1=0x01): raw CBOR chunk[1..255]

Error status words (all in 0x6Bxx range):
  0x6B01  ERROR_INVALID_STATE       — CONT before INIT
  0x6B04  ERROR_INVALID_TRANSACTION — wrong transaction kind byte (must be 27/0x1B)
  0x6B0D  ERROR_PLT_CBOR_ERROR      — overflow, empty chunk, or invalid CIS-7 CBOR
  0x6B0E  ERROR_PLT_BUFFER_ERROR    — cbor_total_length is 0 or > APP_PLT_CBOR_MAX (512)
  0x6B0F  ERROR_PLT_DATA_ERROR      — token_id_length out of range [1..128]
  0x6B10  ERROR_PLT_MULTI_OP        — outer CBOR array has more than one operation
"""

import pytest

from ragger.error import StatusWords

from application_client.command_sender import CommandSender

# ------------------------------------------------------------------ #
# Minimal CBOR encoder (CIS-7 payloads)                              #
# ------------------------------------------------------------------ #


def _cbor_encode_len(major: int, n: int) -> bytes:
    major <<= 5
    if n <= 23:
        return bytes([major | n])
    elif n <= 0xFF:
        return bytes([major | 24, n])
    elif n <= 0xFFFF:
        return bytes([major | 25, n >> 8, n & 0xFF])
    else:
        return bytes([major | 26]) + n.to_bytes(4, "big")


def _tstr(s: str) -> bytes:
    b = s.encode("utf-8")
    return _cbor_encode_len(3, len(b)) + b


def _array(items) -> bytes:
    return _cbor_encode_len(4, len(items)) + b"".join(items)


def _map(pairs) -> bytes:
    return _cbor_encode_len(5, len(pairs)) + b"".join(k + v for k, v in pairs)


def _plt_pause() -> bytes:
    return _array([_map([(_tstr("pause"), _map([]))])])


# ------------------------------------------------------------------ #
# Shared test constants                                               #
# ------------------------------------------------------------------ #

# Standard test path used across the Concordium test suite.
_PATH = "m/1105/0/0/0/0/2/0/0"

# 60-byte account transaction header:
#   sender[32]   = well-known test account
#   seq_num[8]   = 10
#   energy[8]    = 100
#   payload_size[4] = 0 (placeholder — not validated by the app)
#   expiry[8]    = 0x63de5da7
_HEADER_60 = bytes.fromhex(
    "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    "000000000000000a"
    "0000000000000064"
    "00000000"
    "0000000063de5da7"
)
assert len(_HEADER_60) == 60

# Minimal valid token ID (1 byte, the minimum allowed length).
_TOKEN_ID_MIN = b"T"

# Valid CIS-7 CBOR payloads.
# Small: array(1) [ map(1) { "pause": map(0) } ] — 9 bytes, single CONT frame.
_CBOR_SMALL = _plt_pause()

# Large: 300 raw zero bytes (not valid CIS-7) — two CONT frames, used to test
# buffer accumulation logic before the CIS-7 parse step.
_CBOR_LARGE = bytes(300)

# APP_PLT_CBOR_MAX constant (must match src/helpers/app_sizes.h).
_APP_PLT_CBOR_MAX = 512


# ------------------------------------------------------------------ #
# Positive tests                                                      #
# ------------------------------------------------------------------ #


@pytest.mark.skip(reason="requires UI navigation — covered by test_sign_plt_ui.py")
@pytest.mark.active_test_scope
def test_sign_plt_single_cont_frame(backend):
    """INIT + one CONT frame: small CIS-7 CBOR that fits in a single chunk."""
    client = CommandSender(backend)
    resp = client.sign_plt(_PATH, _HEADER_60, _TOKEN_ID_MIN, _CBOR_SMALL)

    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_sign_plt_multi_cont_frame(backend):
    """INIT + two CONT frames: _CBOR_LARGE is a raw byte string, not CIS-7.
    The parser rejects it with ERROR_PLT_CBOR_ERROR on the final CONT frame."""
    from application_client.command_sender import CLA, InsType, pack_derivation_path

    init_data = pack_derivation_path(_PATH) + _HEADER_60 + bytes([0x1B, len(_TOKEN_ID_MIN)]) + _TOKEN_ID_MIN + len(_CBOR_LARGE).to_bytes(4, "big")
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x00, p2=0x00, data=init_data)
    assert resp.status == StatusWords.SWO_SUCCESS

    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=_CBOR_LARGE[:255])
    assert resp.status == StatusWords.SWO_SUCCESS

    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=_CBOR_LARGE[255:])
    assert resp.status == 0x6B0D  # ERROR_PLT_CBOR_ERROR


@pytest.mark.skip(reason="requires UI navigation — covered by test_sign_plt_ui.py")
@pytest.mark.active_test_scope
def test_sign_plt_max_token_id(backend):
    """INIT + one CONT with a 128-byte token ID (maximum allowed length)."""
    client = CommandSender(backend)
    token_id = bytes(range(128))  # 128 bytes of distinct values
    resp = client.sign_plt(_PATH, _HEADER_60, token_id, _CBOR_SMALL)

    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_sign_plt_exact_cbor_max(backend):
    """APP_PLT_CBOR_MAX bytes are buffered without overflow then rejected by CIS-7 parser."""
    from application_client.command_sender import CLA, InsType, pack_derivation_path

    # 512 raw zero bytes — not a CIS-7 outer array, so parser returns 0x6B0D.
    # The test verifies the buffer accepts exactly MAX bytes before the parse step.
    cbor = bytes(_APP_PLT_CBOR_MAX)
    assert len(cbor) == _APP_PLT_CBOR_MAX

    init_data = pack_derivation_path(_PATH) + _HEADER_60 + bytes([0x1B, len(_TOKEN_ID_MIN)]) + _TOKEN_ID_MIN + len(cbor).to_bytes(4, "big")
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x00, p2=0x00, data=init_data)
    assert resp.status == StatusWords.SWO_SUCCESS

    # Send in two chunks (255 + 257) to exercise multi-frame buffering.
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=cbor[:255])
    assert resp.status == StatusWords.SWO_SUCCESS

    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=cbor[255:])
    assert resp.status == 0x6B0D  # ERROR_PLT_CBOR_ERROR


@pytest.mark.active_test_scope
def test_sign_plt_intermediate_cont_returns_no_data(backend):
    """Intermediate CONT frames return 0x9000 with an empty data payload."""
    from application_client.command_sender import CLA, InsType, pack_derivation_path

    # _CBOR_LARGE is raw bytes (not CIS-7), so the final frame returns 0x6B0D.
    # The test focuses on verifying the intermediate frame returns empty data.
    init_data = pack_derivation_path(_PATH) + _HEADER_60 + bytes([0x1B, len(_TOKEN_ID_MIN)]) + _TOKEN_ID_MIN + len(_CBOR_LARGE).to_bytes(4, "big")
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x00, p2=0x00, data=init_data)
    assert resp.status == StatusWords.SWO_SUCCESS

    # First chunk (255 bytes) — intermediate: 0x9000 + no data.
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=_CBOR_LARGE[:255])
    assert resp.status == StatusWords.SWO_SUCCESS
    assert resp.data == b""

    # Final chunk — raw bytes fail CIS-7 parse.
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=_CBOR_LARGE[255:])
    assert resp.status == 0x6B0D  # ERROR_PLT_CBOR_ERROR


# ------------------------------------------------------------------ #
# Negative tests — INIT frame errors                                  #
# ------------------------------------------------------------------ #


@pytest.mark.active_test_scope
def test_sign_plt_wrong_transaction_kind(backend):
    """INIT with kind != 0x1B (27) must return ERROR_INVALID_TRANSACTION (0x6B04)."""
    client = CommandSender(backend)
    resp = client.sign_plt_init(
        _PATH, _HEADER_60, _TOKEN_ID_MIN, len(_CBOR_SMALL), kind=0x03
    )
    assert resp.status == 0x6B04  # ERROR_INVALID_TRANSACTION


@pytest.mark.active_test_scope
def test_sign_plt_cbor_total_zero(backend):
    """cbor_total_length == 0 must return ERROR_PLT_BUFFER_ERROR (0x6B0E)."""
    client = CommandSender(backend)
    resp = client.sign_plt_init(_PATH, _HEADER_60, _TOKEN_ID_MIN, 0)
    assert resp.status == 0x6B0E  # ERROR_PLT_BUFFER_ERROR


@pytest.mark.active_test_scope
def test_sign_plt_cbor_total_exceeds_max(backend):
    """cbor_total_length > APP_PLT_CBOR_MAX must return ERROR_PLT_BUFFER_ERROR (0x6B0E)."""
    client = CommandSender(backend)
    resp = client.sign_plt_init(_PATH, _HEADER_60, _TOKEN_ID_MIN, _APP_PLT_CBOR_MAX + 1)
    assert resp.status == 0x6B0E  # ERROR_PLT_BUFFER_ERROR


@pytest.mark.active_test_scope
def test_sign_plt_token_id_length_zero(backend):
    """token_id_length == 0 must return ERROR_PLT_DATA_ERROR (0x6B0F)."""
    client = CommandSender(backend)
    # Pass an empty bytes object — results in token_id_length byte = 0x00 in the APDU.
    resp = client.sign_plt_init(_PATH, _HEADER_60, b"", len(_CBOR_SMALL))
    assert resp.status == 0x6B0F  # ERROR_PLT_DATA_ERROR


@pytest.mark.active_test_scope
def test_sign_plt_token_id_length_too_long(backend):
    """token_id_length > 128 must return ERROR_PLT_DATA_ERROR (0x6B0F)."""
    client = CommandSender(backend)
    token_id = bytes(129)  # 129 bytes — one over the limit
    resp = client.sign_plt_init(_PATH, _HEADER_60, token_id, len(_CBOR_SMALL))
    assert resp.status == 0x6B0F  # ERROR_PLT_DATA_ERROR


# ------------------------------------------------------------------ #
# Negative tests — CONT frame errors                                  #
# ------------------------------------------------------------------ #


@pytest.mark.active_test_scope
def test_sign_plt_cont_before_init(backend):
    """CONT frame without a preceding INIT must return ERROR_INVALID_STATE (0x6B01)."""
    client = CommandSender(backend)
    # No INIT sent — state is TX_PLT_INITIAL, so CONT is rejected.
    resp = client.sign_plt_cont(_CBOR_SMALL)
    assert resp.status == 0x6B01  # ERROR_INVALID_STATE


@pytest.mark.active_test_scope
def test_sign_plt_cont_overflow(backend):
    """CONT frame carrying more bytes than the declared cbor_total_length must fail."""
    client = CommandSender(backend)

    resp = client.sign_plt_init(_PATH, _HEADER_60, _TOKEN_ID_MIN, len(_CBOR_SMALL))
    assert resp.status == StatusWords.SWO_SUCCESS

    resp = client.sign_plt_cont(_CBOR_SMALL + b"\x00")  # one byte over the declared total
    assert resp.status == 0x6B0D  # ERROR_PLT_CBOR_ERROR


@pytest.mark.active_test_scope
def test_sign_plt_empty_cont_chunk(backend):
    """CONT frame with zero-length data must return ERROR_PLT_CBOR_ERROR (0x6B0D)."""
    client = CommandSender(backend)

    resp = client.sign_plt_init(_PATH, _HEADER_60, _TOKEN_ID_MIN, len(_CBOR_SMALL))
    assert resp.status == StatusWords.SWO_SUCCESS

    resp = client.sign_plt_cont(b"")
    assert resp.status == 0x6B0D  # ERROR_PLT_CBOR_ERROR


@pytest.mark.active_test_scope
def test_sign_plt_p1_invalid(backend):
    """P1=0x02 on a fresh session must return ERROR_INVALID_PARAM (0x6B03)."""
    from application_client.command_sender import CLA, InsType

    resp = backend.exchange(
        cla=CLA, ins=InsType.SIGN_PLT, p1=0x02, p2=0x00,
        data=b"\x01\x00",  # minimal data so lc > 0
    )
    assert resp.status == 0x6B03  # ERROR_INVALID_PARAM


@pytest.mark.active_test_scope
def test_sign_plt_cont_split_three_ways(backend):
    """600 raw bytes split into three CONT frames (255+255+90) accumulate correctly."""
    from application_client.command_sender import CLA, InsType, pack_derivation_path

    # 600 zero bytes — not CIS-7, so the final frame returns 0x6B0D.
    # The test focuses on verifying the two intermediate frames return empty data.
    cbor_600 = bytes(600)

    init_data = pack_derivation_path(_PATH) + _HEADER_60 + bytes([0x1B, len(_TOKEN_ID_MIN)]) + _TOKEN_ID_MIN + len(cbor_600).to_bytes(4, "big")
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x00, p2=0x00, data=init_data)
    assert resp.status == StatusWords.SWO_SUCCESS

    # Chunk 1: 255 bytes — intermediate.
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=cbor_600[:255])
    assert resp.status == StatusWords.SWO_SUCCESS
    assert resp.data == b""

    # Chunk 2: 255 bytes — still intermediate.
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=cbor_600[255:510])
    assert resp.status == StatusWords.SWO_SUCCESS
    assert resp.data == b""

    # Chunk 3: final 90 bytes — raw bytes fail CIS-7 parse.
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=cbor_600[510:])
    assert resp.status == 0x6B0D  # ERROR_PLT_CBOR_ERROR


@pytest.mark.skip(reason="requires UI navigation for the first full sign — covered by test_sign_plt_ui.py")
@pytest.mark.active_test_scope
def test_sign_plt_double_init_resets(backend):
    """A fresh INIT after a completed sign is accepted (state machine resets)."""
    client = CommandSender(backend)

    # Complete a full sign.
    resp = client.sign_plt(_PATH, _HEADER_60, _TOKEN_ID_MIN, _CBOR_SMALL)
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64

    # A new INIT on the same session must be accepted.
    resp = client.sign_plt_init(_PATH, _HEADER_60, _TOKEN_ID_MIN, len(_CBOR_SMALL))
    assert resp.status == StatusWords.SWO_SUCCESS


@pytest.mark.active_test_scope
def test_sign_plt_trailing_byte_in_init(backend):
    """Extra byte after cbor_total_length in INIT must return SWO_INCORRECT_DATA (0x6A80)."""
    from application_client.command_sender import CLA, InsType, pack_derivation_path

    # Build a valid INIT payload and append one trailing zero byte.
    data = pack_derivation_path(_PATH)
    data += _HEADER_60
    data += bytes([0x1B])             # PLT kind
    data += bytes([len(_TOKEN_ID_MIN)])
    data += _TOKEN_ID_MIN
    data += len(_CBOR_SMALL).to_bytes(4, byteorder="big")
    data += b"\x00"                   # trailing byte — must be rejected

    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x00, p2=0x00, data=data)
    assert resp.status == 0x6A80  # SWO_INCORRECT_DATA


@pytest.mark.active_test_scope
def test_sign_plt_wrong_p2(backend):
    """Any P2 != 0x00 must return SWO_WRONG_P1_P2 (0x6B00)."""
    client = CommandSender(backend)
    from application_client.command_sender import CLA, InsType

    resp = backend.exchange(
        cla=CLA, ins=InsType.SIGN_PLT, p1=0x00, p2=0x01,
        data=(
            b"\x08"                     # path depth 8
            + b"\x00\x00\x04\x51"       # 1105
            + b"\x00\x00\x00\x00" * 6
            + b"\x00\x00\x00\x02"
            + b"\x00\x00\x00\x00"
            + _HEADER_60
            + b"\x1b"                   # kind PLT
            + b"\x01\x54"               # token_id_length=1, token_id=b"T"
            + b"\x00\x00\x00\x04"       # cbor_total=4
        ),
    )
    assert resp.status == 0x6B00  # SWO_WRONG_P1_P2
