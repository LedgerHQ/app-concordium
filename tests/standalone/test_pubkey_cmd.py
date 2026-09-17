import pytest

from application_client.command_sender import CommandSender
from application_client.response_unpacker import (
    unpack_get_public_key_response,
)
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.error import ExceptionRAPDU, StatusWords
from ragger.navigator import NavInsID, NavIns

nano_accept_instructions = [
    NavInsID.RIGHT_CLICK,
    NavInsID.RIGHT_CLICK,
    NavInsID.RIGHT_CLICK,
    NavInsID.BOTH_CLICK,
]

nano_refuse_instructions = [
    NavInsID.RIGHT_CLICK,
    NavInsID.RIGHT_CLICK,
    NavInsID.RIGHT_CLICK,
    NavInsID.RIGHT_CLICK,
    NavInsID.BOTH_CLICK,
]

wallet_accept_instructions = [
    NavInsID.USE_CASE_REVIEW_NEXT,     # intro → content
    NavInsID.USE_CASE_REVIEW_NEXT,     # content → confirm
    NavInsID.USE_CASE_REVIEW_CONFIRM,
    NavInsID.USE_CASE_REVIEW_NEXT,     # content → confirm
    NavInsID.USE_CASE_REVIEW_NEXT,     # content → confirm
    NavInsID.USE_CASE_REVIEW_CONFIRM,
    NavInsID.WAIT_FOR_HOME_SCREEN,
]

wallet_refuse_instructions = [
    NavInsID.USE_CASE_REVIEW_NEXT,     # intro → content
    NavInsID.USE_CASE_REVIEW_NEXT,     # content → confirm
    NavInsID.USE_CASE_REVIEW_REJECT,   # opens rejection confirmation dialog
    NavInsID.USE_CASE_CHOICE_CONFIRM,  # confirm rejection
    NavInsID.WAIT_FOR_HOME_SCREEN,
]


# In this test we check that the GET_CHALLENGE returns an 8-byte random challenge
@pytest.mark.active_test_scope
def test_get_challenge(backend):
    client = CommandSender(backend)
    response = client.get_challenge()
    assert response.status == StatusWords.SWO_SUCCESS
    assert len(response.data) == 8


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode
@pytest.mark.active_test_scope
def test_get_legacy_public_key_confirm_accepted(
    backend, navigator, default_screenshot_path, test_name, scenario_navigator
):
    client = CommandSender(backend)
    path = "m/1105/0/0/0/0/2/0/0"
    if backend.device.is_nano:
        instructions = nano_accept_instructions
    else:
        instructions = wallet_accept_instructions

    with client.get_public_key_with_confirmation(path=path):
        navigator.navigate_and_compare(
            default_screenshot_path,
            test_name,
            instructions,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=False,
        )

    response = client.get_async_response().data
    assert (
        response.hex()
        == "87e16c8269270b1c75b930224df456d2927b80c760ffa77e57dbd738f6399492"
    )


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode with signing
@pytest.mark.active_test_scope
def test_get_signed_legacy_public_key_confirm_accepted(
    backend, navigator, default_screenshot_path, test_name
):
    client = CommandSender(backend)
    path = "m/1105/0/0/0/0/2/0/0"
    if backend.device.is_nano:
        instructions = nano_accept_instructions
    else:
        instructions = wallet_accept_instructions

    with client.get_public_key_with_confirmation(path=path, signPublicKey=True):
        navigator.navigate_and_compare(
            default_screenshot_path,
            test_name,
            instructions,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=False,
        )

    response = client.get_async_response().data
    assert (
        response.hex()
        == "87e16c8269270b1c75b930224df456d2927b80c760ffa77e57dbd738f63994923f499aa9fe41f0b911a3cccde3080143f10d108b2ba72343ad70fa03458333a328c542ce0685632b16636cc579fcfe715743c332eff416589631057eb0e08d04"
    )


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode with signing for governance key
@pytest.mark.active_test_scope
def test_get_signed_legacy_governance_public_key_confirm_accepted(
    backend, navigator, default_screenshot_path, test_name
):
    client = CommandSender(backend)
    path = "m/1105/0/1/0/0"
    if backend.device.is_nano:
        instructions = nano_accept_instructions
    else:
        instructions = wallet_accept_instructions

    with client.get_public_key_with_confirmation(path=path, signPublicKey=True):
        navigator.navigate_and_compare(
            default_screenshot_path,
            test_name,
            instructions,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=False,
        )

    response = client.get_async_response().data
    assert (
        response.hex()
        == "91fcf639f03a8e1c00ab0837383728c9a105df9d44c293b2436dddd7213bee1c62cf20d6c17d1971e66808d325ce1fed188b26b0d543de9f25e5a1c5e46d979cbd2ab98bc4213159883837b9fffa67d43dc5bcbc7b694d164feea777abc4a30d"
    )


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode with signing
@pytest.mark.active_test_scope
def test_get_signed_new_public_key_confirm_accepted(
    backend, navigator, default_screenshot_path, test_name
):
    client = CommandSender(backend)
    path = "m/44/919/0/0/0"
    if backend.device.is_nano:
        instructions = nano_accept_instructions
    else:
        instructions = wallet_accept_instructions

    with client.get_public_key_with_confirmation(path=path, signPublicKey=True):
        navigator.navigate_and_compare(
            default_screenshot_path,
            test_name,
            instructions,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=False,
        )

    response = client.get_async_response().data
    assert (
        response.hex()
        == "e31d69e500b0f83983fb6080aaa46129cf7c70e27d59b1aae9820b1d03f9840252c415c2552d81fde03a9aef6bba24325711a5924b417d79324f60ef67466a017542c6423387fd0d7679cab784d8178bf15e10eb4cb2eef944d47611682c930c"
    )


# In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
@pytest.mark.active_test_scope
def test_get_public_key_confirm_refused(
    backend, navigator, default_screenshot_path, test_name
):
    client = CommandSender(backend)
    path = "m/44'/919'/0'/0/0"
    if backend.device.is_nano:
        instructions = nano_refuse_instructions
    else:
        instructions = wallet_refuse_instructions

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_public_key_with_confirmation(path=path):
            navigator.navigate_and_compare(
                default_screenshot_path,
                test_name,
                instructions,
                screen_change_before_first_instruction=True,
                screen_change_after_last_instruction=False,
            )

    # Assert that we have received a refusal
    assert e.value.status == StatusWords.SWO_CONDITIONS_NOT_SATISFIED
    assert len(e.value.data) == 0


# handle_get_public_key() refuses a second request while a review of it is unanswered, so that a
# host cannot swap the path under the user's finger. The claim that makes it refuse is released
# on the way back to the idle screen (menu_bagl.c / menu_nbgl.c) for a rejection and in
# send_public_key() for an approval. If either release is missing, one refused review answers
# every later GET_PUBLIC_KEY with ERROR_INVALID_STATE and the app is wedged until it restarts.
#
# This is the half of that guard a device test can reach: the refusal itself is unreachable here,
# because the SDK does not deliver an APDU while a reply is pending. Asserting it through Ragger
# would be asserting os_io_handle_ux_event_reject_apdu, not this app - the app-level half is
# unit-tests/test_get_public_key.c. No snapshot comparison: the screens are already covered by
# the accept and refuse tests above, and what is under test is the status word afterwards.
@pytest.mark.active_test_scope
def test_public_key_review_claim_is_released_after_a_refusal(backend, navigator):
    client = CommandSender(backend)
    # The path test_get_signed_new_public_key_confirm_accepted uses, so the key asserted below
    # is that test's constant rather than a new one.
    path = "m/44/919/0/0/0"
    if backend.device.is_nano:
        refuse, accept = nano_refuse_instructions, nano_accept_instructions
    else:
        refuse, accept = wallet_refuse_instructions, wallet_accept_instructions

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_public_key_with_confirmation(path=path):
            navigator.navigate(
                refuse,
                screen_change_before_first_instruction=True,
                screen_change_after_last_instruction=False,
            )
    assert e.value.status == StatusWords.SWO_CONDITIONS_NOT_SATISFIED

    # The claim is gone: this request gets its own review rather than an immediate refusal.
    with client.get_public_key_with_confirmation(path=path):
        navigator.navigate(
            accept,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=False,
        )

    response = client.get_async_response()
    assert response.status == StatusWords.SWO_SUCCESS
    # And it exports the key for the path it just reviewed - the first 32 bytes of
    # test_get_signed_new_public_key_confirm_accepted's response, which is the same key without
    # the signature this request did not ask for.
    assert (
        response.data.hex()
        == "e31d69e500b0f83983fb6080aaa46129cf7c70e27d59b1aae9820b1d03f98402"
    )
