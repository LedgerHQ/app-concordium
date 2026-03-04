import pytest
from bip32 import BIP32, HARDENED_INDEX
from bip_utils import Bip32Slip10Ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from application_client.command_sender import CommandSender
from application_client.response_unpacker import (
    unpack_get_public_key_response,
)
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.error import ExceptionRAPDU, StatusWords
from ragger.navigator import NavInsID, NavIns, NavigateWithScenario


# In this test we check that the VERIFY ADDRESS works in confirmation mode
@pytest.mark.active_test_scope
def test_verify_address_confirm_legacy_path_accepted(
    backend,
    scenario_navigator: NavigateWithScenario,
    test_name: str,
    default_screenshot_path: str,
):
    client = CommandSender(backend)
    with client.verify_address(identity_index=0, credential_counter=0):
        scenario_navigator.address_review_approve()

    response = client.get_async_response().status
    assert response == StatusWords.SWO_SUCCESS


# In this test we check that the VERIFY ADDRESS works in confirmation mode
@pytest.mark.active_test_scope
def test_verify_address_confirm_new_path_accepted(
    backend, scenario_navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.verify_address(identity_index=0, credential_counter=0, idp_index=0):
        scenario_navigator.address_review_approve()

    response = client.get_async_response().status
    assert response == StatusWords.SWO_SUCCESS


# In this test we check that the VERIFY ADDRESS in confirmation mode replies an error if the user refuses
@pytest.mark.active_test_scope
def test_verify_address_confirm_refused(
    backend, scenario_navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    try:
        with client.verify_address(identity_index=0, credential_counter=0, idp_index=0):
            scenario_navigator.address_review_reject()

    except ExceptionRAPDU as e:
        response = e.status

    assert response == StatusWords.SWO_CONDITIONS_NOT_SATISFIED


@pytest.mark.active_test_scope
def test_verify_address_confirm_full_path_accepted(
    backend, scenario_navigator, test_name, default_screenshot_path
):
    """Verify address with P1_FULL_PATH (derivation-path format) succeeds when user approves."""
    client = CommandSender(backend)
    path_nodes = [44, 919, 403, 404, 8]
    with client.verify_address_full_path(path_nodes):
        scenario_navigator.address_review_approve()

    response = client.get_async_response().status
    assert response == StatusWords.SWO_SUCCESS

