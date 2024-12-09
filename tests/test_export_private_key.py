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
from ragger.firmware import Firmware
from utils import navigate_until_text_and_compare


@pytest.mark.active_test_scope
def test_export_private_key_legacy_path(
    backend, firmware, navigator, test_name, default_screenshot_path
):
    client = BoilerplateCommandSender(backend)
    with client.export_private_key(export_type="standard", identity_index=0):
        navigate_until_text_and_compare(
            firmware,
            navigator,
            "Accept",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=False,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    print("km------------result", result)
    assert result.data == bytes.fromhex(
        "48235b90248b6e552d59bf8b533292d25c5afd1f8e1ad5d1e00478794642ba38"
    )


@pytest.mark.active_test_scope
def test_export_private_key_new_path(
    backend, firmware, navigator, test_name, default_screenshot_path
):
    client = BoilerplateCommandSender(backend)
    with client.export_private_key(
        export_type="standard", identity_index=0, idp_index=0
    ):
        navigate_until_text_and_compare(
            firmware,
            navigator,
            "Accept",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=False,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    print("km------------result", result)
    assert result.data == bytes.fromhex(
        "00beb8ab5d68b55f39dacc0d0847bb9cd62a327549d41a4dfe7c5845f70c5562"
    )


# TODO: Add test case for other export types
