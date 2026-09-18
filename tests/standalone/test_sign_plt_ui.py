"""
UI-flow tests for INS 0x27 — PLT (Protocol Level Token) signing.

Each test sends INIT + CONT frames and navigates the device UI to approve or
reject the transaction.  Screenshots are compared against golden images stored
alongside the test (first run generates them automatically).

Tests 17-18 (multi-op / malformed CBOR) are protocol-layer tests that never
reach the UI; they are placed here because they were deferred from the main
test_sign_plt.py file and belong logically with the CBOR parsing group.

CBOR wire format (CIS-7):
  Outer:  array(1) [ map(1) { "opName": map({fields}) } ]
  Amount: tag 4 ( array(2) [exponent, significand] )
  Addr:   tag 40307 ( { ?1: tag 40305({1: 919}), 3: bstr(32) } )
"""

import pytest

from ragger.error import ExceptionRAPDU, StatusWords
from ragger.navigator import NavInsID

from application_client.command_sender import CommandSender
from utils import navigate_until_text_and_compare

# ------------------------------------------------------------------ #
# Shared test constants (reuse the same values as test_sign_plt.py)   #
# ------------------------------------------------------------------ #

_PATH = "m/1105/0/0/0/0/2/0/0"

_HEADER_60 = bytes.fromhex(
    "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    "000000000000000a"
    "0000000000000064"
    "00000000"
    "0000000063de5da7"
)
assert len(_HEADER_60) == 60

_TOKEN_ID_MIN = b"T"

# 32-byte all-zero test account address (base58check encodes to a known string).
_ADDR_32 = bytes(32)

# ------------------------------------------------------------------ #
# Minimal CBOR encoder (enough for CIS-7 test payloads)               #
# ------------------------------------------------------------------ #


def _cbor_encode_len(major: int, n: int) -> bytes:
    major <<= 5
    if n <= 23:
        return bytes([major | n])
    elif n <= 0xFF:
        return bytes([major | 24, n])
    elif n <= 0xFFFF:
        return bytes([major | 25, n >> 8, n & 0xFF])
    elif n <= 0xFFFFFFFF:
        return bytes([major | 26]) + n.to_bytes(4, "big")
    else:
        return bytes([major | 27]) + n.to_bytes(8, "big")


def _uint(n: int) -> bytes:
    return _cbor_encode_len(0, n)


def _negint(n: int) -> bytes:
    """Encode a negative integer n (n must be < 0)."""
    return _cbor_encode_len(1, -n - 1)


def _bstr(b: bytes) -> bytes:
    return _cbor_encode_len(2, len(b)) + b


def _tstr(s: str) -> bytes:
    b = s.encode("utf-8")
    return _cbor_encode_len(3, len(b)) + b


def _array(items) -> bytes:
    return _cbor_encode_len(4, len(items)) + b"".join(items)


def _map(pairs) -> bytes:
    return _cbor_encode_len(5, len(pairs)) + b"".join(k + v for k, v in pairs)


def _tag(t: int, v: bytes) -> bytes:
    return _cbor_encode_len(6, t) + v


# ------------------------------------------------------------------ #
# CIS-7 field builders                                                #
# ------------------------------------------------------------------ #


def _cis7_amount(exponent: int, significand: int) -> bytes:
    """tag 4([exponent, significand])"""
    exp_enc = _negint(exponent) if exponent < 0 else _uint(exponent)
    return _tag(4, _array([exp_enc, _uint(significand)]))


def _cis7_coininfo(coin_type: int = 919) -> bytes:
    """tag 40305({1: coin_type}) — 919 is the SLIP-44 code for CCD."""
    return _tag(40305, _map([(_uint(1), _uint(coin_type))]))


def _cis7_addr(addr: bytes = _ADDR_32, coininfo: bytes = None) -> bytes:
    """tag 40307({?1: coininfo, 3: bstr[32]}).

    CIS-7 makes the info field (key 1) optional; by default this builds the
    shorter form, which decoders must treat as a Concordium address.  Pass
    coininfo=_cis7_coininfo() for the full form emitted by the JS SDK.
    """
    assert len(addr) == 32
    pairs = []
    if coininfo is not None:
        pairs.append((_uint(1), coininfo))
    pairs.append((_uint(3), _bstr(addr)))
    return _tag(40307, _map(pairs))


# ------------------------------------------------------------------ #
# CIS-7 operation payload builders                                    #
# ------------------------------------------------------------------ #


def _cis7_memo(text: str) -> bytes:
    """tag 24(bstr(<CBOR text string>)) — the CborMemo::Cbor variant.

    CborMemo is a discriminated union (concordium-base token_operations.rs): an untagged bstr is
    Raw(Memo) and a tag-24 bstr is Cbor(Memo), whose content is an encoded CBOR data item
    (RFC 8949 tag 24).  The device accepts only this form, and only when the encoded item is one
    definite-length text string filling the whole envelope.
    """
    return _tag(24, _bstr(_tstr(text)))


def _plt_transfer(exp: int, sig: int, recipient: bytes = _ADDR_32, memo: str = None,
                  coininfo: bytes = None, memo_value: bytes = None) -> bytes:
    """transfer payload.

    memo:       text carried in the accepted tag-24 CBOR-text-string form.
    memo_value: a CBOR value placed in the memo slot verbatim, for refusal cases.
    """
    fields = [
        (_tstr("amount"), _cis7_amount(exp, sig)),
        (_tstr("recipient"), _cis7_addr(recipient, coininfo)),
    ]
    if memo is not None:
        fields.append((_tstr("memo"), _cis7_memo(memo)))
    elif memo_value is not None:
        fields.append((_tstr("memo"), memo_value))
    return _array([_map([(_tstr("transfer"), _map(fields))])])


def _plt_mint(exp: int, sig: int) -> bytes:
    return _array([_map([(_tstr("mint"), _map([
        (_tstr("amount"), _cis7_amount(exp, sig)),
    ]))])])


def _plt_burn(exp: int, sig: int) -> bytes:
    return _array([_map([(_tstr("burn"), _map([
        (_tstr("amount"), _cis7_amount(exp, sig)),
    ]))])])


def _plt_list_op(op_name: str, target: bytes = _ADDR_32, coininfo: bytes = None) -> bytes:
    return _array([_map([(_tstr(op_name), _map([
        (_tstr("target"), _cis7_addr(target, coininfo)),
    ]))])])


def _plt_no_fields(op_name: str) -> bytes:
    return _array([_map([(_tstr(op_name), _map([]))])])


# ------------------------------------------------------------------ #
# Helper: reject navigation                                           #
# ------------------------------------------------------------------ #


def _navigate_reject(backend, navigator, default_screenshot_path, test_name):
    """Navigate to the device's rejection button (device-type-aware).

    Touch devices need two steps: USE_CASE_REVIEW_REJECT (opens the dialog)
    then USE_CASE_CHOICE_CONFIRM (confirms the rejection).
    """
    if backend.device.is_nano:
        navigate_until_text_and_compare(
            backend, navigator, "Reject", default_screenshot_path, test_name
        )
    else:
        # Spelled out per device rather than swiping until "Sign" is found: the page count is
        # part of what the review looks like, so a page appearing or disappearing should fail
        # here instead of being absorbed by a search loop. stax fits the transfer in one page
        # fewer than flex and apex_p. Keys are backend.device.name, which is also what the
        # snapshot directories are named after, so an unlisted device fails loudly.
        swipes_to_sign = {"stax": 3, "flex": 4, "apex_p": 4}[backend.device.name]
        navigator.navigate_and_compare(
            default_screenshot_path,
            test_name,
            [NavInsID.SWIPE_CENTER_TO_LEFT] * swipes_to_sign
            + [NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM],
            screen_change_before_first_instruction=True,
            # navigate_and_compare captures the first screen, then one per instruction except
            # the last when this is False - so swipes_to_sign + 2 snapshots, ending on the
            # "Reject transaction?" dialog. USE_CASE_CHOICE_CONFIRM then returns to the
            # dashboard, which no device has a golden for, so it must not be captured.
            screen_change_after_last_instruction=False,
        )


# ================================================================== #
# Tests 1–2: Transfer approve / reject                                #
# ================================================================== #


@pytest.mark.active_test_scope
def test_plt_transfer_approve(backend, navigator, default_screenshot_path, test_name):
    """Transfer + amount + recipient — user approves — 64-byte signature returned.

    Recipient carries the coininfo field, i.e. the exact form the JS SDK emits.
    """
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 1_000_000, coininfo=_cis7_coininfo())
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_transfer_reject(backend, navigator, default_screenshot_path, test_name):
    """Transfer — user rejects — device raises ExceptionRAPDU with status 0x6985 (DENY)."""
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 1_000_000)
    with pytest.raises(ExceptionRAPDU) as exc_info:
        with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
            _navigate_reject(backend, navigator, default_screenshot_path, test_name)
    assert exc_info.value.status == 0x6985  # DENY


# ================================================================== #
# Tests 3–6: Transfer with a tag-24 CBOR memo                         #
# ================================================================== #


@pytest.mark.active_test_scope
def test_plt_transfer_memo_cbor_text(backend, navigator, default_screenshot_path, test_name):
    """tag-24 memo holding the CBOR text string "send with memo" — text shown, header decoded.

    The envelope is 6e73656e64… : the device used to unwrap the tag and hand the bytes straight
    to the display, so the inner CBOR header 0x6E reviewed as a leading 'n' ("nsend with memo").
    The snapshot must show the text alone.
    """
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 500_000, memo="send with memo")
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_transfer_memo_empty_text(backend, navigator, default_screenshot_path, test_name):
    """tag-24 memo holding a zero-length CBOR text string — memo row present but empty."""
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 1_000_000, memo="")
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_transfer_memo_20_bytes(backend, navigator, default_screenshot_path, test_name):
    """A 20-character memo is shown in full — regression cover for the 15-29 byte window.

    The old format_memo_display sampled 14 bytes upstream but compared the memo's true length
    against displayMemo's 29-byte capacity, so 15-29 byte memos rendered as their first 14 bytes
    with no ellipsis and no flag while the full memo was hashed and signed. Both branches are
    gone, but nothing else in this file lands in that window: "send with memo" is exactly 14
    characters, so it sat on the old boundary and would not have caught it.
    """
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 250_000, memo="twenty-byte memo!!!!")
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_transfer_memo_long_text(backend, navigator, default_screenshot_path, test_name):
    """A 200-character memo is shown in full, not truncated.

    displayMemo holds the whole envelope (PLT_MEMO_DISPLAY_SIZE), because the memo is signed and
    permanent on chain: a trimmed review would have the user approve text never shown.
    """
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 1_000_000, memo="A" * 200)
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


# ------------------------------------------------------------------ #
# Memos the review cannot show faithfully — refused, never signed.    #
# ------------------------------------------------------------------ #

# An indefinite-length text string: 0x7F, one "ab" chunk, 0xFF break.
_INDEFINITE_TEXT = bytes([0x7F]) + _tstr("ab") + bytes([0xFF])

_BAD_MEMOS = {
    # CborMemo::Raw — the node's own vector for bytes 01020304 (4401020304). Opaque bytes have
    # no faithful rendering, so the raw variant is refused outright.
    "raw_variant_node_vector": _bstr(bytes([0x01, 0x02, 0x03, 0x04])),
    "raw_variant_text_bytes": _bstr(b"send with memo"),
    # CborMemo::Cbor — the node's vector d8184401020304. The envelope decodes as CBOR uint 1
    # followed by three bytes outside the item, which stay in the hash unseen.
    "cbor_variant_node_vector": _tag(24, _bstr(bytes([0x01, 0x02, 0x03, 0x04]))),
    # Encoded item is not a text string: nothing to put in the Memo row that is what was signed.
    "encoded_uint": _tag(24, _bstr(_uint(1))),
    "encoded_negint": _tag(24, _bstr(_negint(-1))),
    "encoded_bstr": _tag(24, _bstr(_bstr(b"ab"))),
    "encoded_array": _tag(24, _bstr(_array([_uint(1)]))),
    "encoded_map": _tag(24, _bstr(_map([(_uint(1), _uint(2))]))),
    # Text string plus trailing bytes inside the envelope.
    "trailing_bytes": _tag(24, _bstr(_tstr("ab") + bytes([0xFF]))),
    # Indefinite length: several chunks, no single canonical encoding.
    "indefinite_text": _tag(24, _bstr(_INDEFINITE_TEXT)),
    # Bytes no screen can render honestly; the NUL would end the string early while the
    # signature still covered what follows it.
    "embedded_nul": _tag(24, _bstr(_tstr("a\x00b"))),
    "control_byte": _tag(24, _bstr(_tstr("a\x1fb"))),
    "del_byte": _tag(24, _bstr(_tstr("a\x7fb"))),
    # Text longer than the review buffer: refused rather than trimmed.
    "text_past_display": _tag(24, _bstr(_tstr("A" * 300))),
    # Wrong discriminator tag entirely.
    "wrong_tag": _tag(23, _bstr(_tstr("ab"))),
    # Tagged value is not a byte string.
    "tag24_over_text": _tag(24, _tstr("ab")),
    # Memo slot holds a bare text string — neither union variant.
    "bare_text": _tstr("ab"),
    "bare_uint": _uint(1),
}


@pytest.mark.active_test_scope
@pytest.mark.parametrize("case", sorted(_BAD_MEMOS))
def test_plt_invalid_memo_encoding(backend, case):
    """A memo that cannot be parsed aborts signing with ERROR_PLT_UNSUPPORTED_MEMO (0x6B12).

    Signing used to continue with hasMemo = false, so the user approved a transaction carrying a
    memo that was never displayed — and the memo is part of the signed payload.
    """
    cbor = _plt_transfer(-6, 100, memo_value=_BAD_MEMOS[case])
    assert _exchange_plt_cbor(backend, cbor) == 0x6B12  # ERROR_PLT_UNSUPPORTED_MEMO


# ================================================================== #
# Tests 7–8: Mint / Burn                                              #
# ================================================================== #


@pytest.mark.active_test_scope
def test_plt_mint(backend, navigator, default_screenshot_path, test_name):
    """Mint operation — amount displayed, no recipient/target field."""
    client = CommandSender(backend)
    cbor = _plt_mint(-3, 5_000)
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_burn(backend, navigator, default_screenshot_path, test_name):
    """Burn operation — amount displayed, no recipient/target field."""
    client = CommandSender(backend)
    cbor = _plt_burn(-3, 2_500)
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


# ================================================================== #
# Tests 9–12: Allow-list / Deny-list operations                       #
# ================================================================== #


@pytest.mark.active_test_scope
def test_plt_add_allow_list(backend, navigator, default_screenshot_path, test_name):
    """addAllowList operation — target address displayed (coininfo form)."""
    client = CommandSender(backend)
    cbor = _plt_list_op("addAllowList", coininfo=_cis7_coininfo())
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_remove_allow_list(backend, navigator, default_screenshot_path, test_name):
    """removeAllowList operation — target address displayed."""
    client = CommandSender(backend)
    cbor = _plt_list_op("removeAllowList")
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_add_deny_list(backend, navigator, default_screenshot_path, test_name):
    """addDenyList operation — target address displayed."""
    client = CommandSender(backend)
    cbor = _plt_list_op("addDenyList")
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_remove_deny_list(backend, navigator, default_screenshot_path, test_name):
    """removeDenyList operation — target address displayed."""
    client = CommandSender(backend)
    cbor = _plt_list_op("removeDenyList")
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


# ================================================================== #
# Tests 13–14: Pause / Unpause (no fields)                            #
# ================================================================== #


@pytest.mark.active_test_scope
def test_plt_pause(backend, navigator, default_screenshot_path, test_name):
    """Pause operation — no amount or address fields."""
    client = CommandSender(backend)
    cbor = _plt_no_fields("pause")
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_unpause(backend, navigator, default_screenshot_path, test_name):
    """Unpause operation — no amount or address fields."""
    client = CommandSender(backend)
    cbor = _plt_no_fields("unpause")
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


# ================================================================== #
# Tests 15–16: Amount edge cases                                      #
# ================================================================== #


@pytest.mark.active_test_scope
def test_plt_amount_zero(backend, navigator, default_screenshot_path, test_name):
    """Transfer with tag4([0, 0]) — significand zero, exponent zero."""
    client = CommandSender(backend)
    cbor = _plt_transfer(0, 0)
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_amount_max_uint64(backend, navigator, default_screenshot_path, test_name):
    """Transfer with significand = 2^64-1 (max uint64) — no overflow in display."""
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 0xFFFF_FFFF_FFFF_FFFF)
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


# ================================================================== #
# Tests 17–18: Protocol-layer errors (no UI needed)                   #
# ================================================================== #


@pytest.mark.active_test_scope
def test_plt_multi_op_rejected(backend):
    """Two operations in the outer array — rejected with ERROR_PLT_MULTI_OP (0x6B10)."""
    from application_client.command_sender import CLA, InsType, pack_derivation_path

    cbor = _array([
        _map([(_tstr("transfer"), _map([
            (_tstr("amount"), _cis7_amount(-6, 100)),
            (_tstr("recipient"), _cis7_addr()),
        ]))]),
        _map([(_tstr("burn"), _map([
            (_tstr("amount"), _cis7_amount(0, 0)),
        ]))]),
    ])

    init_data = pack_derivation_path(_PATH) + _HEADER_60 + bytes([0x1B, len(_TOKEN_ID_MIN)]) + _TOKEN_ID_MIN + len(cbor).to_bytes(4, "big")
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x00, p2=0x00, data=init_data)
    assert resp.status == StatusWords.SWO_SUCCESS

    try:
        resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=cbor)
    except ExceptionRAPDU as e:
        assert e.status == 0x6B10  # ERROR_PLT_MULTI_OP
    else:
        assert resp.status == 0x6B10  # ERROR_PLT_MULTI_OP


# ================================================================== #
# Tests 19–20: Fee display (P2=0x01)                                  #
# ================================================================== #


@pytest.mark.active_test_scope
def test_plt_transfer_fee_display(backend, navigator, default_screenshot_path, test_name):
    """Transfer with P2=0x01 fee suffix — 'Max fees' screen appears before Sign."""
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 1_000_000)
    # 726_675 µCCD ≈ 0.000727 CCD (typical PLT transfer fee on testnet)
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor,
                                 display_fee_microccd=726_675):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_transfer_fee_omit(backend, navigator, default_screenshot_path, test_name):
    """Transfer with P2=0x01 and FEE_OMIT sentinel — fee line suppressed, flow identical to P2=0x00."""
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 1_000_000)
    # 0xFFFFFFFFFFFFFFFF is the FEE_DISPLAY_VALUE_OMIT sentinel — no fee line on screen.
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor,
                                 display_fee_microccd=0xFFFF_FFFF_FFFF_FFFF):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_malformed_cbor(backend):
    """Indefinite array without break byte — rejected with ERROR_PLT_CBOR_ERROR (0x6B0D)."""
    from application_client.command_sender import CLA, InsType, pack_derivation_path

    cbor = b"\x9f"  # start of indefinite-length array, no 0xFF break

    init_data = pack_derivation_path(_PATH) + _HEADER_60 + bytes([0x1B, len(_TOKEN_ID_MIN)]) + _TOKEN_ID_MIN + len(cbor).to_bytes(4, "big")
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x00, p2=0x00, data=init_data)
    assert resp.status == StatusWords.SWO_SUCCESS

    try:
        resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=cbor)
    except ExceptionRAPDU as e:
        assert e.status == 0x6B0D  # ERROR_PLT_CBOR_ERROR
    else:
        assert resp.status == 0x6B0D  # ERROR_PLT_CBOR_ERROR


# ================================================================== #
# Tests 21+: Address encoding rejections (no UI needed)                #
# ================================================================== #


def _exchange_plt_cbor(backend, cbor: bytes) -> int:
    """Send INIT + as many CONT frames as the payload needs, and return the last status word.

    The blob must be split at MAX_APDU_LEN: a single frame caps at 255 bytes, and a payload
    over that would fail in the transport instead of reaching the parser, so an over-length
    refusal case would pass for the wrong reason. The device accumulates up to
    APP_PLT_CBOR_MAX (512) across frames and parses only once the declared total has arrived,
    so the refusal always comes from the final frame.
    """
    from application_client.command_sender import (
        CLA, InsType, MAX_APDU_LEN, pack_derivation_path,
    )
    from utils import split_message

    init_data = (pack_derivation_path(_PATH) + _HEADER_60
                 + bytes([0x1B, len(_TOKEN_ID_MIN)]) + _TOKEN_ID_MIN
                 + len(cbor).to_bytes(4, "big"))
    resp = backend.exchange(cla=CLA, ins=InsType.SIGN_PLT, p1=0x00, p2=0x00, data=init_data)
    assert resp.status == StatusWords.SWO_SUCCESS

    chunks = split_message(cbor, MAX_APDU_LEN)
    try:
        for chunk in chunks[:-1]:
            resp = backend.exchange(
                cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=chunk
            )
            # An intermediate frame only accumulates; a refusal here is the answer.
            if resp.status != StatusWords.SWO_SUCCESS:
                return resp.status
        return backend.exchange(
            cla=CLA, ins=InsType.SIGN_PLT, p1=0x01, p2=0x00, data=chunks[-1]
        ).status
    except ExceptionRAPDU as e:
        return e.status


def _plt_transfer_raw_addr(addr_value: bytes) -> bytes:
    """transfer payload whose recipient is the given (possibly invalid) CBOR value."""
    return _array([_map([(_tstr("transfer"), _map([
        (_tstr("amount"), _cis7_amount(-6, 100)),
        (_tstr("recipient"), addr_value),
    ]))])])


# Each entry is a tag-40307 value that CIS-7 does not permit.
_BAD_ADDRESSES = {
    # Pre-CIS-7 shape this app used to accept: bare bstr instead of a map.
    "bare_bstr": _tag(40307, _bstr(_ADDR_32)),
    # Address bytes placed under key 1 (the info slot) with no key 3 at all.
    "addr_under_info_key": _tag(40307, _map([(_uint(1), _bstr(_ADDR_32))])),
    # coininfo present but the mandatory data field is missing.
    "no_data_key": _tag(40307, _map([(_uint(1), _cis7_coininfo())])),
    # data is not 32 bytes.
    "short_data": _tag(40307, _map([(_uint(3), _bstr(bytes(31)))])),
    "long_data": _tag(40307, _map([(_uint(3), _bstr(bytes(33)))])),
    # coin type is not CCD (0 = BTC) — an address for another chain.
    "foreign_coin_type": _tag(40307, _map([
        (_uint(1), _cis7_coininfo(0)),
        (_uint(3), _bstr(_ADDR_32)),
    ])),
    # coininfo map not wrapped in tag 40305.
    "untagged_coininfo": _tag(40307, _map([
        (_uint(1), _map([(_uint(1), _uint(919))])),
        (_uint(3), _bstr(_ADDR_32)),
    ])),
    # BCR key 2 (address type) is not part of CIS-7.
    "unknown_map_key": _tag(40307, _map([
        (_uint(2), _uint(0)),
        (_uint(3), _bstr(_ADDR_32)),
    ])),
    # Wrong tag number entirely (40305 instead of 40307).
    "wrong_tag": _tag(40305, _map([(_uint(3), _bstr(_ADDR_32))])),
}


@pytest.mark.active_test_scope
@pytest.mark.parametrize("case", sorted(_BAD_ADDRESSES))
def test_plt_invalid_address_encoding(backend, case):
    """Non-conformant tag-40307 values are rejected with ERROR_PLT_CBOR_ERROR (0x6B0D)."""
    cbor = _plt_transfer_raw_addr(_BAD_ADDRESSES[case])
    assert _exchange_plt_cbor(backend, cbor) == 0x6B0D  # ERROR_PLT_CBOR_ERROR


# ================================================================== #
# Test 21: 128-byte token ID (PLT_TOKEN_ID_MAX) display buffer fix   #
# ================================================================== #


@pytest.mark.active_test_scope
def test_plt_transfer_18_decimals(backend, navigator, default_screenshot_path, test_name):
    """Transfer with exponent -18 (app limit) must succeed and return a signature.

    Boundary test: -18 is the last accepted exponent; -19 returns ERROR_PLT_UNSUPPORTED_DECIMALS.
    """
    client = CommandSender(backend)
    # significand 1, exponent -18 → "0.000000000000000001 T"
    cbor = _plt_transfer(-18, 1)
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_transfer_max_token_id(backend, navigator, default_screenshot_path, test_name):
    """Transfer with a 128-byte token ID (PLT_TOKEN_ID_MAX) and UINT64_MAX significand.

    Regression test for the displayAmount buffer: before the fix, plt_amount_to_display
    threw ERROR_BUFFER_OVERFLOW (0x6B06) for token IDs ≥ 18 bytes on large amounts.
    With PLT_AMOUNT_DISPLAY_SIZE = 170 the buffer fits any valid token ID + any valid
    formatted number without overflow.
    """
    client = CommandSender(backend)
    token_id = b"A" * 128  # max allowed length per PLT_TOKEN_ID_MAX
    # UINT64_MAX with exponent 0 → "18446744073709551615" (20 chars): worst-case numLen.
    cbor = _plt_transfer(0, 0xFFFF_FFFF_FFFF_FFFF)
    with client.sign_plt_with_ui(_PATH, _HEADER_60, token_id, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64
