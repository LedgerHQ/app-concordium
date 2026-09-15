"""
An APDU arriving while the export review is up must not change what gets exported.

INS 0x37 derives in its approval callback rather than in the handler, so that no exportable
secret exists in RAM while the review is on screen. The cost is that the callback reads its
parameters long after the handler stored them, and those parameters live in the `global`
instruction union -- which app_main() zeroes whenever it opens an instruction and
dispatch_guarded() zeroes when a handler throws. Zeroed parameters still derive a valid key set,
for IDP#0 ID#0, which is not what the review described.

The sequence that would reach that:

  1. INS 0x37 opens the review. The latch holds 0x37 and the host's reply is owed.
  2. A CLA 0xE0 APDU with a different INS is refused by the instruction-switching guard in
     apdu_dispatcher() -- which *releases* the latch. The review stays on screen.
  3. INS 0x37 with Lc = 0 then finds a free latch, so app_main() zeroes `global` before
     dispatch, and the dispatcher refuses it for the missing data without reaching a handler.
  4. The user approves, and the callback derives from the zeroed parameters.

Two things stop this, and the test asserts the outcome rather than either mechanism:

  * The SDK will not deliver an APDU while the UX holds a pending reply
    (os_io_handle_ux_event_reject_apdu, SWO_COMMAND_NOT_ACCEPTED 0x6901), and the transport
    that used to get around that is disabled (V-119). This is what answers on HID today, so
    step 2 never reaches app_main() at all.
  * sendPrivateKeysNewPath() refuses to derive unless ctx->isNewPath says the handler populated
    the context. That is the local check, which does not depend on the SDK.

So what is asserted is the property: the injected APDU does not succeed, and the keys that
leave the device after approval are the ones the review described. Pinning a status word would
tie the test to whichever layer happens to answer first.
"""

import pytest

from application_client.command_sender import CLA, CommandSender, InsType
from ragger.error import ExceptionRAPDU
from utils import navigate_until_text_and_compare

SWO_SUCCESS = 0x9000

# Same request as test_export_identity_credential_creation_private_key_new_path_mainnet, so the
# expected keys are that test's, unchanged: approving after the injected APDUs must export
# exactly what approving without them exports.
EXPECTED_KEYS = bytes.fromhex(
    "2020348347485688f67ce7256353549ae2bd986b8b9306f8ed78732fb5426c5e89"
    "200dd6831a46dd093b21fe43bdd01b7ede216d5689ff12143d7d4ceb77d16041bb"
    "202e4dc8653f7fc57bc51778c0d16537507a1f6388a439ea95c146cb2f15022f99"
)


def _inject(client: CommandSender, ins: int) -> int:
    """Send one APDU while the review is up and return the status word it came back with."""
    try:
        rapdu = client.backend.exchange(cla=CLA, ins=ins, p1=0x00, p2=0x00, data=b"")
    except ExceptionRAPDU as e:
        return e.status
    return rapdu.status


@pytest.mark.active_test_scope
def test_apdu_during_export_review_cannot_change_the_exported_keys(
    backend, navigator, test_name, default_screenshot_path
):
    """Replay steps 2 and 3, approve, and check the keys are still bound to the review."""
    client = CommandSender(backend)
    with client.export_private_key_new_path(
        "identity_credential_creation", "mainnet", idp_index=0, identity_index=1
    ):
        # Step 2. GET_APP_NAME is otherwise always answerable -- test_malformed_apdu_survival
        # uses it as its liveness probe -- so a refusal here is a guard, not a parse error.
        assert _inject(client, InsType.GET_APP_NAME) != SWO_SUCCESS

        # Step 3. The APDU that would zero the reviewed parameters.
        assert _inject(client, InsType.EXPORT_PRIVATE_KEY_NEW) != SWO_SUCCESS

        navigate_until_text_and_compare(
            backend,
            navigator,
            "Approve export",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )

    # Step 4. This is the assertion that matters: the callback derived from the reviewed
    # parameters, not from zeros.
    result = client.get_async_response()
    assert result.data == EXPECTED_KEYS


@pytest.mark.active_test_scope
def test_app_still_serves_commands_after_the_export_review(
    backend, navigator, test_name, default_screenshot_path
):
    """Refusing mid-review must not leave the app wedged once the review is answered."""
    client = CommandSender(backend)
    with client.export_private_key_new_path(
        "identity_credential_creation", "mainnet", idp_index=0, identity_index=1
    ):
        assert _inject(client, InsType.GET_APP_NAME) != SWO_SUCCESS
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Approve export",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    client.get_async_response()

    assert client.get_app_name().status == SWO_SUCCESS
