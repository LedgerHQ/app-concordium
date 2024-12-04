import pytest

from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
)
from application_client.boilerplate_response_unpacker import (
    unpack_get_public_key_response,
)
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID, NavIns
from utils import navigate_until_text_and_compare


# TODO: remove this test
# # In this test we check that the GET_PUBLIC_KEY works in non-confirmation mode
# def test_get_public_key_no_confirm(backend):
#     for path in ["m/44'/919'/0'/0/0", "m/44'/919'/0/0/0", "m/44'/919'/911'/0/0", "m/44'/919'/255/255/255", "m/44'/919'/2147483647/0/0/0/0/0/0/0",
#                  "m/1105'/0'/0'/0/0", "m/1105'/0'/0/0/0", "m/1105'/0'/911'/0/0", "m/1105'/0'/255/255/255", "m/1105'/0'/2147483647/0/0/0/0/0/0/0"]:
#         client = BoilerplateCommandSender(backend)
#         response = client.get_public_key(path=path).data
#         _, public_key, _, chain_code = unpack_get_public_key_response(response)

#         ref_public_key, ref_chain_code = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
#         assert public_key.hex() == ref_public_key
#         assert chain_code.hex() == ref_chain_code

nano_accept_instructions = [
    NavInsID.BOTH_CLICK,
    NavInsID.RIGHT_CLICK,
    NavInsID.RIGHT_CLICK,
    NavInsID.BOTH_CLICK,
]


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode
@pytest.mark.active_test_scope
def test_get_legacy_public_key_confirm_accepted(
    backend, navigator, firmware, default_screenshot_path, test_name
):
    client = BoilerplateCommandSender(backend)
    path = "m/1105/0/0/0/0/2/0/0"
    with client.get_public_key_with_confirmation(path=path):
        if firmware.is_nano:
            navigator.navigate_and_compare(
                default_screenshot_path,
                test_name,
                nano_accept_instructions,
                screen_change_before_first_instruction=False,
            )

    response = client.get_async_response().data
    print("km------------------|response:", response.hex())
    assert (
        response.hex()
        == "87e16c8269270b1c75b930224df456d2927b80c760ffa77e57dbd738f6399492"
    )


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode with signing
@pytest.mark.active_test_scope
def test_get_signed_legacy_public_key_confirm_accepted(
    backend, navigator, firmware, default_screenshot_path, test_name
):
    client = BoilerplateCommandSender(backend)
    path = "m/1105/0/0/0/0/2/0/0"
    with client.get_public_key_with_confirmation(path=path, signPublicKey=True):
        if firmware.is_nano:
            navigator.navigate_and_compare(
                default_screenshot_path,
                test_name,
                nano_accept_instructions,
                screen_change_before_first_instruction=False,
            )

    response = client.get_async_response().data
    print("km------------------|response:", response.hex())
    assert (
        response.hex()
        == "87e16c8269270b1c75b930224df456d2927b80c760ffa77e57dbd738f63994923f499aa9fe41f0b911a3cccde3080143f10d108b2ba72343ad70fa03458333a328c542ce0685632b16636cc579fcfe715743c332eff416589631057eb0e08d04"
    )


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode with signing for governance key
def test_get_signed_legacy_governance_public_key_confirm_accepted(
    backend, navigator, firmware, default_screenshot_path, test_name
):
    client = BoilerplateCommandSender(backend)
    path = "m/1105/0/1/0/0"
    with client.get_public_key_with_confirmation(path=path, signPublicKey=True):
        navigate_until_text_and_compare(
            firmware, navigator, "Approve", default_screenshot_path, test_name
        )

    response = client.get_async_response().data
    print("km------------------|response:", response.hex())
    assert (
        response.hex()
        == "2091fcf639f03a8e1c00ab0837383728c9a105df9d44c293b2436dddd7213bee1c4062cf20d6c17d1971e66808d325ce1fed188b26b0d543de9f25e5a1c5e46d979cbd2ab98bc4213159883837b9fffa67d43dc5bcbc7b694d164feea777abc4a30d"
    )


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode
def test_get_legacy_public_key_confirm_accepted_2(
    backend, navigator, firmware, default_screenshot_path, test_name
):
    client = BoilerplateCommandSender(backend)
    path = "m/1105/0/0/0/0/2/0/0"
    with client.get_public_key_with_confirmation(path=path):
        navigate_until_text_and_compare(
            firmware, navigator, "Approve", default_screenshot_path, test_name
        )

    response = client.get_async_response().data
    print("km------------------|response:", response.hex())
    assert (
        response.hex()
        == "2087e16c8269270b1c75b930224df456d2927b80c760ffa77e57dbd738f6399492"
    )


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode with signing
def test_get_signed_new_public_key_confirm_accepted(
    backend, navigator, firmware, default_screenshot_path, test_name
):
    client = BoilerplateCommandSender(backend)
    path = "m/44/919/0/0/0"
    with client.get_public_key_with_confirmation(path=path, signPublicKey=True):
        navigate_until_text_and_compare(
            firmware, navigator, "Approve", default_screenshot_path, test_name
        )

    response = client.get_async_response().data
    print("km------------------|response:", response.hex())
    assert (
        response.hex()
        == "20e31d69e500b0f83983fb6080aaa46129cf7c70e27d59b1aae9820b1d03f984024052c415c2552d81fde03a9aef6bba24325711a5924b417d79324f60ef67466a017542c6423387fd0d7679cab784d8178bf15e10eb4cb2eef944d47611682c930c"
    )


# # In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
# def test_get_public_key_confirm_refused(backend, scenario_navigator):
#     client = BoilerplateCommandSender(backend)
#     path = "m/44'/919'/0'/0/0"

#     with pytest.raises(ExceptionRAPDU) as e:
#         with client.get_public_key_with_confirmation(path=path):
#             scenario_navigator.address_review_reject()

#     # Assert that we have received a refusal
#     assert e.value.status == Errors.SW_DENY
#     assert len(e.value.data) == 0
