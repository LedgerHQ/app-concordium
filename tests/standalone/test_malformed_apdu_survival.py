"""
The app must answer a malformed APDU and stay alive (finding V-006).

Handlers report attacker-controlled input errors with THROW(...), which is os_longjmp. The only
handler above apdu_dispatcher() used to be the SDK's own, in standalone_app_main(), and that one
*exits the application*. So one malformed command dropped the user to the dashboard, and
repeating it kept the app unavailable and aborted any signing flow in progress.

Each test here sends something the app must refuse, and then sends a plain GET_APP_NAME. That
second command is the whole point: if the app had exited, it cannot answer. Asserting only the
error status word of the first command would pass even with the app dead, because the status
word is sent before the exception unwinds.
"""

import pytest

from application_client.command_sender import CLA, CommandSender, InsType
from application_client.response_unpacker import unpack_get_app_name_response
from ragger.error import ExceptionRAPDU

# P1/P2 are given as literals rather than through the P1/P2 enums: those carry per-instruction
# aliases (P1_NONE is also P1_VERIFY_ADDRESS_LEGACY_PATH), which reads as if it meant something
# here. These commands are meant to be malformed, so the values are deliberately arbitrary.
UNKNOWN_INS = 0xFE
SWO_INVALID_INS = 0x6D00
SWO_INVALID_CLA = 0x6E00
SWO_SUCCESS = 0x9000


def _assert_app_still_alive(backend) -> None:
    """A successful GET_APP_NAME proves the app is still running and dispatching."""
    response = CommandSender(backend).get_app_name()
    assert unpack_get_app_name_response(response.data) == "Concordium"


def _expect_error(backend, cla, ins, p1, p2, data) -> int:
    """Send a command that must be refused, and return the status word it was refused with."""
    try:
        rapdu = backend.exchange(cla=cla, ins=ins, p1=p1, p2=p2, data=data)
    except ExceptionRAPDU as e:
        return e.status
    # Depending on the raise policy the backend returns the RAPDU instead of raising.
    return rapdu.status


@pytest.mark.active_test_scope
def test_unknown_instruction_is_refused_and_app_survives(backend):
    """The dispatcher default branch: an unsupported INS must not end the session.

    This is the exact case the finding names. It also covers the instruction-switching guard:
    app_main() claims currentInstruction from cmd.ins before dispatching, so an unknown
    instruction opens a flow no handler will ever close. If that claim is not released, the
    GET_APP_NAME below is refused with ERROR_INVALID_STATE instead of succeeding.
    """
    sw = _expect_error(backend, CLA, UNKNOWN_INS, 0x00, 0x00, b"")
    assert sw == SWO_INVALID_INS, f"expected SWO_INVALID_INS, got {sw:#06x}"
    _assert_app_still_alive(backend)


@pytest.mark.active_test_scope
def test_repeated_unknown_instructions_keep_the_app_available(backend):
    """Denial of service was the impact: repeating the command must not wear the app down."""
    for _ in range(5):
        sw = _expect_error(backend, CLA, UNKNOWN_INS, 0x00, 0x00, b"")
        assert sw == SWO_INVALID_INS, f"expected SWO_INVALID_INS, got {sw:#06x}"
    _assert_app_still_alive(backend)


@pytest.mark.active_test_scope
def test_truncated_transfer_payload_is_refused_and_app_survives(backend):
    """A handler-level THROW, not a dispatcher one.

    A SIGN_TRANSFER whose command data stops inside the derivation path reaches a THROW deep in
    parsing (derivation_path.c / tx_hash.c), which is the class of site that makes per-THROW
    conversion impractical - 70 distinct ones were reachable in 90s of fuzzing.
    """
    sw = _expect_error(backend, CLA, InsType.SIGN_TRANSFER, 0x00, 0x00, b"\x05\x00\x00")
    assert sw != SWO_SUCCESS, "a truncated transfer must not be accepted"
    _assert_app_still_alive(backend)


@pytest.mark.active_test_scope
def test_bad_p1_is_refused_and_app_survives(backend):
    """P1/P2 validation throws SWO_WRONG_P1_P2 in several handlers."""
    sw = _expect_error(backend, CLA, InsType.SIGN_TRANSFER, 0xFF, 0xFF, b"\x00")
    assert sw != SWO_SUCCESS, "an out-of-range P1/P2 must not be accepted"
    _assert_app_still_alive(backend)


@pytest.mark.active_test_scope
def test_wrong_cla_is_refused_and_app_survives(backend):
    """Rejected in app_main() before dispatch, so this is the control for the tests above."""
    sw = _expect_error(backend, 0x00, InsType.GET_APP_NAME, 0x00, 0x00, b"")
    assert sw == SWO_INVALID_CLA, f"expected SWO_INVALID_CLA, got {sw:#06x}"
    _assert_app_still_alive(backend)
