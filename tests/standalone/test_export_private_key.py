import pytest

from application_client.command_sender import CommandSender
from application_client.response_unpacker import (
    unpack_get_public_key_response,
)
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID, NavIns
from utils import navigate_until_text_and_compare

# Legacy Path


@pytest.mark.active_test_scope
def test_export_standard_private_key_legacy_path(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_legacy(export_type="standard", identity_index=0):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert result.data == bytes.fromhex(
        "48235b90248b6e552d59bf8b533292d25c5afd1f8e1ad5d1e00478794642ba38"
    )


@pytest.mark.active_test_scope
def test_export_recovery_private_key_legacy_path(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_legacy(export_type="recovery", identity_index=0):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert result.data == bytes.fromhex(
        "48235b90248b6e552d59bf8b533292d25c5afd1f8e1ad5d1e00478794642ba38"
    )


@pytest.mark.active_test_scope
def test_export_prfkey_and_idcredsed_private_key_legacy_path(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_legacy(
        export_type="prfkey_and_idcredsec", identity_index=0
    ):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert result.data == bytes.fromhex(
        "48235b90248b6e552d59bf8b533292d25c5afd1f8e1ad5d1e00478794642ba3802a5a44c0b2e0abcaf313c77fa05f6449c092ad449a081098bd48515bf95e947"
    )


# New Path


@pytest.mark.active_test_scope
def test_export_identity_credential_creation_private_key_new_path_mainnet(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_new_path(
        "identity_credential_creation", "mainnet", idp_index=0, identity_index=1
    ):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert len(result.data) == 33 * 3
    assert result.data == bytes.fromhex(
        "2020348347485688f67ce7256353549ae2bd986b8b9306f8ed78732fb5426c5e89200dd6831a46dd093b21fe43bdd01b7ede216d5689ff12143d7d4ceb77d16041bb202e4dc8653f7fc57bc51778c0d16537507a1f6388a439ea95c146cb2f15022f99"
    )


@pytest.mark.active_test_scope
def test_export_identity_credential_creation_private_key_new_path_testnet(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_new_path(
        "identity_credential_creation", "testnet", idp_index=0, identity_index=1
    ):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert len(result.data) == 33 * 3
    assert result.data == bytes.fromhex(
        "2053db453318231b1a43497551677cf23652ff306fc1d2e1f1cb5cd42ff680b12620336bfcd76a6e0756ee5b0f4a6d3434092d68eb38921aac96c85e0a4d4b6d9b59206225bc94caf90bc2aff95144d21c5f445582f8214cd10d3488085a09d8731ca5"
    )


@pytest.mark.active_test_scope
def test_export_account_creation_private_key_new_path_mainnet(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_new_path(
        "account_creation", "mainnet", idp_index=0, identity_index=1, account_index=2
    ):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert len(result.data) == 33 * 2 + 65
    assert result.data == bytes.fromhex(
        "200dd6831a46dd093b21fe43bdd01b7ede216d5689ff12143d7d4ceb77d16041bb2020348347485688f67ce7256353549ae2bd986b8b9306f8ed78732fb5426c5e8940d9d1f46a11fe0ed8279e1406ab5b9f49584996c8112be5884ddd8adebe7b3e0061eeb73df1acfee68b10d26e655e1a563ea4919e4b69a6e2ec255483d1e9826e"
    )


@pytest.mark.active_test_scope
def test_export_account_creation_private_key_new_path_testnet(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_new_path(
        "account_creation", "testnet", idp_index=0, identity_index=1, account_index=2
    ):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert len(result.data) == 33 * 2 + 65
    assert result.data == bytes.fromhex(
        "20336bfcd76a6e0756ee5b0f4a6d3434092d68eb38921aac96c85e0a4d4b6d9b592053db453318231b1a43497551677cf23652ff306fc1d2e1f1cb5cd42ff680b126406b0e171c79a0572999170fbd8593723911005d06d2aaabb8ebc7ec130a4cd5ce6afaca787b11f89dee5958945450760d0753a7428ed5c656bed22e98d6b23610"
    )


@pytest.mark.active_test_scope
def test_export_id_recovery_private_key_new_path_mainnet(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_new_path(
        "id_recovery", "mainnet", idp_index=0, identity_index=1
    ):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert len(result.data) == 33 * 2
    assert result.data == bytes.fromhex(
        "2020348347485688f67ce7256353549ae2bd986b8b9306f8ed78732fb5426c5e89202e4dc8653f7fc57bc51778c0d16537507a1f6388a439ea95c146cb2f15022f99"
    )


@pytest.mark.active_test_scope
def test_export_id_recovery_private_key_new_path_testnet(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_new_path(
        "id_recovery", "testnet", idp_index=0, identity_index=1
    ):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert len(result.data) == 33 * 2
    assert result.data == bytes.fromhex(
        "2053db453318231b1a43497551677cf23652ff306fc1d2e1f1cb5cd42ff680b126206225bc94caf90bc2aff95144d21c5f445582f8214cd10d3488085a09d8731ca5"
    )


@pytest.mark.active_test_scope
def test_export_account_credential_discovery_private_key_new_path_mainnet(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_new_path(
        "account_credential_discovery", "mainnet", idp_index=0, identity_index=1
    ):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert len(result.data) == 33 * 1
    assert result.data == bytes.fromhex(
        "200dd6831a46dd093b21fe43bdd01b7ede216d5689ff12143d7d4ceb77d16041bb"
    )


@pytest.mark.active_test_scope
def test_export_account_credential_discovery_private_key_new_path_testnet(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_new_path(
        "account_credential_discovery", "testnet", idp_index=0, identity_index=1
    ):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert len(result.data) == 33 * 1
    assert result.data == bytes.fromhex(
        "20336bfcd76a6e0756ee5b0f4a6d3434092d68eb38921aac96c85e0a4d4b6d9b59"
    )


@pytest.mark.active_test_scope
def test_export_creation_of_zk_proof_private_key_new_path_mainnet(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_new_path(
        "creation_of_zk_proof",
        "mainnet",
        idp_index=0,
        identity_index=1,
        account_index=2,
    ):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert len(result.data) == 65 * 1
    assert result.data == bytes.fromhex(
        "40d9d1f46a11fe0ed8279e1406ab5b9f49584996c8112be5884ddd8adebe7b3e0061eeb73df1acfee68b10d26e655e1a563ea4919e4b69a6e2ec255483d1e9826e"
    )


@pytest.mark.active_test_scope
def test_export_creation_of_zk_proof_private_key_new_path_testnet(
    backend, navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.export_private_key_new_path(
        "creation_of_zk_proof",
        "testnet",
        idp_index=0,
        identity_index=1,
        account_index=2,
    ):
        navigate_until_text_and_compare(
            backend,
            navigator,
            "Sign operation",
            default_screenshot_path,
            test_name,
            screen_change_before_first_instruction=True,
            screen_change_after_last_instruction=True,
        )
    result = client.get_async_response()
    assert len(result.data) == 65 * 1
    assert result.data == bytes.fromhex(
        "406b0e171c79a0572999170fbd8593723911005d06d2aaabb8ebc7ec130a4cd5ce6afaca787b11f89dee5958945450760d0753a7428ed5c656bed22e98d6b23610"
    )
