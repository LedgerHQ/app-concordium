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


@pytest.mark.active_test_scope
def test_sign_plt_multi_cont_frame(backend):
    """INIT + two CONT frames: _CBOR_LARGE is raw bytes (not CIS-7).
    The parser rejects it with ERROR_PLT_CBOR_ERROR on the final CONT frame."""
    client = CommandSender(backend)

    resp = client.sign_plt_init(_PATH, _HEADER_60, _TOKEN_ID_MIN, len(_CBOR_LARGE))
    assert resp.status == StatusWords.SWO_SUCCESS

    resp = client.sign_plt_cont(_CBOR_LARGE[:255])
    assert resp.status == StatusWords.SWO_SUCCESS

    resp = client.sign_plt_cont(_CBOR_LARGE[255:])
    assert resp.status == 0x6B0D  # ERROR_PLT_CBOR_ERROR


@pytest.mark.active_test_scope
def test_sign_plt_exact_cbor_max(backend):
    """APP_PLT_CBOR_MAX bytes are buffered without overflow then rejected by CIS-7 parser."""
    client = CommandSender(backend)

    # 512 raw zero bytes — not a CIS-7 outer array, so parser returns 0x6B0D.
    # Split into 255+255+2 because each CONT frame is limited to 255 bytes.
    cbor = bytes(_APP_PLT_CBOR_MAX)
    assert len(cbor) == _APP_PLT_CBOR_MAX

    resp = client.sign_plt_init(_PATH, _HEADER_60, _TOKEN_ID_MIN, len(cbor))
    assert resp.status == StatusWords.SWO_SUCCESS

    resp = client.sign_plt_cont(cbor[:255])
    assert resp.status == StatusWords.SWO_SUCCESS

    resp = client.sign_plt_cont(cbor[255:510])
    assert resp.status == StatusWords.SWO_SUCCESS

    resp = client.sign_plt_cont(cbor[510:])
    assert resp.status == 0x6B0D  # ERROR_PLT_CBOR_ERROR


@pytest.mark.active_test_scope
def test_sign_plt_intermediate_cont_returns_no_data(backend):
    """Intermediate CONT frames return 0x9000 with an empty data payload."""
    client = CommandSender(backend)

    # _CBOR_LARGE is raw bytes (not CIS-7), so the final frame returns 0x6B0D.
    resp = client.sign_plt_init(_PATH, _HEADER_60, _TOKEN_ID_MIN, len(_CBOR_LARGE))
    assert resp.status == StatusWords.SWO_SUCCESS

    # First chunk (255 bytes) — intermediate: 0x9000 + no data.
    resp = client.sign_plt_cont(_CBOR_LARGE[:255])
    assert resp.status == StatusWords.SWO_SUCCESS
    assert resp.data == b""

    # Final chunk — raw bytes fail CIS-7 parse.
    resp = client.sign_plt_cont(_CBOR_LARGE[255:])
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
    from ragger.error import ExceptionRAPDU

    try:
        resp = backend.exchange(
            cla=CLA, ins=InsType.SIGN_PLT, p1=0x02, p2=0x00,
            data=b"\x01\x00",  # minimal data so lc > 0
        )
    except ExceptionRAPDU as e:
        assert e.status == 0x6B03  # ERROR_INVALID_PARAM
    else:
        assert resp.status == 0x6B03  # ERROR_INVALID_PARAM


@pytest.mark.active_test_scope
def test_sign_plt_cont_split_three_ways(backend):
    """512 raw bytes split into three CONT frames (255+255+2) accumulate correctly."""
    client = CommandSender(backend)

    # 512 zero bytes (= APP_PLT_CBOR_MAX) — not CIS-7, so the final frame returns 0x6B0D.
    cbor_512 = bytes(512)

    resp = client.sign_plt_init(_PATH, _HEADER_60, _TOKEN_ID_MIN, len(cbor_512))
    assert resp.status == StatusWords.SWO_SUCCESS

    # Chunk 1: 255 bytes — intermediate.
    resp = client.sign_plt_cont(cbor_512[:255])
    assert resp.status == StatusWords.SWO_SUCCESS
    assert resp.data == b""

    # Chunk 2: 255 bytes — still intermediate.
    resp = client.sign_plt_cont(cbor_512[255:510])
    assert resp.status == StatusWords.SWO_SUCCESS
    assert resp.data == b""

    # Chunk 3: final 2 bytes — raw bytes fail CIS-7 parse.
    resp = client.sign_plt_cont(cbor_512[510:])
    assert resp.status == 0x6B0D  # ERROR_PLT_CBOR_ERROR


@pytest.mark.active_test_scope
def test_sign_plt_trailing_byte_in_init(backend):
    """Extra byte after cbor_total_length in INIT must return SWO_INCORRECT_DATA (0x6A80)."""
    from application_client.command_sender import CLA, InsType, pack_derivation_path
    from ragger.error import ExceptionRAPDU

    # Build a valid INIT payload and append one trailing zero byte.
    data = pack_derivation_path(_PATH)
    data += _HEADER_60
    data += bytes([0x1B])             # PLT kind
    data += bytes([len(_TOKEN_ID_MIN)])
    data += _TOKEN_ID_MIN
    data += len(_CBOR_SMALL).to_bytes(4, byteorder="big")
    data += b"\x00"                   # trailing byte — must be rejected

    try:
        resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x00, p2=0x00, data=data)
    except ExceptionRAPDU as e:
        assert e.status == 0x6A80  # SWO_INCORRECT_DATA
    else:
        assert resp.status == 0x6A80  # SWO_INCORRECT_DATA


@pytest.mark.active_test_scope
def test_sign_plt_wrong_p2(backend):
    """Any P2 != 0x00 must return SWO_WRONG_P1_P2 (0x6B00)."""
    from application_client.command_sender import CLA, InsType
    from ragger.error import ExceptionRAPDU

    try:
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
    except ExceptionRAPDU as e:
        assert e.status == 0x6B00  # SWO_WRONG_P1_P2
    else:
        assert resp.status == 0x6B00  # SWO_WRONG_P1_P2
