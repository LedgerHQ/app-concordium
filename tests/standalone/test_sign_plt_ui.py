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
  Addr:   tag 40307 ( bstr(32) )
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


def _cis7_addr(addr: bytes = _ADDR_32) -> bytes:
    """tag 40307(bstr[32])"""
    assert len(addr) == 32
    return _tag(40307, _bstr(addr))


# ------------------------------------------------------------------ #
# CIS-7 operation payload builders                                    #
# ------------------------------------------------------------------ #


def _plt_transfer(exp: int, sig: int, recipient: bytes = _ADDR_32, memo: bytes = None) -> bytes:
    fields = [
        (_tstr("amount"), _cis7_amount(exp, sig)),
        (_tstr("recipient"), _cis7_addr(recipient)),
    ]
    if memo is not None:
        fields.append((_tstr("memo"), _bstr(memo)))
    return _array([_map([(_tstr("transfer"), _map(fields))])])


def _plt_mint(exp: int, sig: int) -> bytes:
    return _array([_map([(_tstr("mint"), _map([
        (_tstr("amount"), _cis7_amount(exp, sig)),
    ]))])])


def _plt_burn(exp: int, sig: int) -> bytes:
    return _array([_map([(_tstr("burn"), _map([
        (_tstr("amount"), _cis7_amount(exp, sig)),
    ]))])])


def _plt_list_op(op_name: str, target: bytes = _ADDR_32) -> bytes:
    return _array([_map([(_tstr(op_name), _map([
        (_tstr("target"), _cis7_addr(target)),
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
            backend, navigator, "Decline", default_screenshot_path, test_name
        )
    else:
        # navigate_until_text_and_compare only supports one confirm instruction,
        # so use the ragger navigator directly with the two-step rejection list.
        navigator.navigate_until_text_and_compare(
            NavInsID.SWIPE_CENTER_TO_LEFT,
            [NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM],
            "Sign",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )


# ================================================================== #
# Tests 1–2: Transfer approve / reject                                #
# ================================================================== #


@pytest.mark.active_test_scope
def test_plt_transfer_approve(backend, navigator, default_screenshot_path, test_name):
    """Transfer + amount + recipient — user approves — 64-byte signature returned."""
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 1_000_000)
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
# Tests 3–6: Transfer with various memo payloads                      #
# ================================================================== #


@pytest.mark.active_test_scope
def test_plt_transfer_memo_ascii(backend, navigator, default_screenshot_path, test_name):
    """Transfer with short printable-ASCII memo — memo displayed as-is."""
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 500_000, memo=b"Hello")
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_transfer_memo_non_ascii(backend, navigator, default_screenshot_path, test_name):
    """Transfer with non-ASCII memo bytes — displayed as 0x<hex>."""
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 1, memo=b"\x80\x81")
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_transfer_memo_empty(backend, navigator, default_screenshot_path, test_name):
    """Transfer with zero-length memo bstr — memo field present but content empty."""
    client = CommandSender(backend)
    cbor = _plt_transfer(-6, 1_000_000, memo=b"")
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


@pytest.mark.active_test_scope
def test_plt_transfer_memo_256b(backend, navigator, default_screenshot_path, test_name):
    """Transfer with 256-byte ASCII memo — display truncated with '...'."""
    client = CommandSender(backend)
    # 256 'A' bytes: exceeds ctx->displayMemo capacity, truncated to fit with "..."
    cbor = _plt_transfer(-6, 1_000_000, memo=b"A" * 256)
    with client.sign_plt_with_ui(_PATH, _HEADER_60, _TOKEN_ID_MIN, cbor):
        navigate_until_text_and_compare(
            backend, navigator, "Sign", default_screenshot_path, test_name
        )
    resp = client.get_async_response()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 64


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
    """addAllowList operation — target address displayed."""
    client = CommandSender(backend)
    cbor = _plt_list_op("addAllowList")
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
