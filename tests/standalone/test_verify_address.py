import pytest
from bip32 import BIP32, HARDENED_INDEX
from bip_utils import Bip32Slip10Ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from application_client.command_sender import (
    CLA,
    CommandSender,
    InsType,
    P1,
    P2,
)
from application_client.response_unpacker import (
    unpack_get_public_key_response,
)
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.error import ExceptionRAPDU, StatusWords
from ragger.navigator import NavInsID, NavIns, NavigateWithScenario

from test_set_trusted_name import (
    _ensure_trusted_name_test_key,
    _get_device_name,
    _requires_speculos_pki,
)
from trusted_name_helper import (
    PKI_KEY_USAGE_TRUSTED_NAME,
    TrustedNameTlvBuilder,
    get_pki_certificate,
)

# ── Real Ledger API descriptor sample ─────────────────────────────────────────
# Source: https://nft.api.live.ledger-test.com/v2/concordium/owner/.../...?network=testnet
# The signedDescriptor from the API cannot be sent as-is in tests (production signature +
# fixed challenge). We reuse tag 0x20 display text and TLV metadata; tag 0x22 is the
# device-derived Ed25519 key for the chosen path, re-signed with the Speculos test PKI key.
#
# The flow uses mainnet derivation (44'/919'/…) and chain_id=0: Speculos GET_PUBLIC_KEY
# fails with 0x6B07 on testnet coin type 1' for this path (OS/crypto stack), while 919' works.
REAL_API_DESCRIPTOR_DISPLAY_ADDRESS = (
    "3g8qKNTvKE5m2Zt7jmS5Fi8ParWiaSzzn5xPhyT31TGTomQPuV"
)
REAL_DESCRIPTOR_TLV_VERSION = 0x03
REAL_DESCRIPTOR_NAME_TYPE = 0x07  # ccd_context_address
REAL_DESCRIPTOR_NAME_SOURCE = 0x06  # dynamic_resolver
REAL_DESCRIPTOR_CHAIN_ID_MAINNET = 0


def _concordium_new_account_path_cdata(
    idp: int, identity: int, *, mainnet: bool = True
) -> bytes:
    """Serialized path for GET_PUBLIC_KEY / VERIFY: m/44'/(919|1)'/idp'/identity'/3' (PRF key)."""
    hardened = 0x80000000
    new_prf_key = 3
    coin_type = 919 if mainnet else 1
    nodes = [
        hardened | 44,
        hardened | coin_type,
        hardened | idp,
        hardened | identity,
        hardened | new_prf_key,
    ]
    return bytes([len(nodes)]) + b"".join(n.to_bytes(4, "big") for n in nodes)


def _get_ed25519_pubkey_32(client: CommandSender, path_cdata: bytes) -> bytes:
    rapdu = client.backend.exchange(
        cla=CLA,
        ins=InsType.GET_PUBLIC_KEY,
        p1=P1.P1_NO_CONFIRM,
        p2=P2.P2_NO_SIGN,
        data=path_cdata,
    )
    assert rapdu.status == StatusWords.SWO_SUCCESS, (
        f"GET_PUBLIC_KEY SW=0x{rapdu.status:04X}"
    )
    assert len(rapdu.data) == 32, len(rapdu.data)
    return rapdu.data


def _load_pki_certificate_only(backend, client: CommandSender) -> None:
    """Load Nano PKI cert for trusted_name (does not call GET_CHALLENGE)."""
    _ensure_trusted_name_test_key(backend, client)
    cert = get_pki_certificate(_get_device_name(backend))
    if cert is None:
        pytest.skip(f"No PKI certificate for device {_get_device_name(backend)}")
    resp = client.load_pki_certificate(PKI_KEY_USAGE_TRUSTED_NAME, cert)
    assert resp.status == StatusWords.SWO_SUCCESS, (
        f"PKI cert load failed: 0x{resp.status:04X}"
    )


# In this test we check that the VERIFY ADDRESS works in confirmation mode
@pytest.mark.active_test_scope
def test_verify_address_confirm_legacy_path_accepted(
    backend,
    scenario_navigator: NavigateWithScenario,
    test_name: str,
    default_screenshot_path: str,
):
    client = CommandSender(backend)
    with client.verify_address(
        network_indicator="mainnet", identity_index=0, credential_counter=0
    ):
        scenario_navigator.address_review_approve()

    response = client.get_async_response().status
    assert response == StatusWords.SWO_SUCCESS


# In this test we check that the VERIFY ADDRESS works in confirmation mode
@pytest.mark.active_test_scope
def test_verify_address_confirm_new_path_accepted(
    backend, scenario_navigator, test_name, default_screenshot_path
):
    client = CommandSender(backend)
    with client.verify_address(
        network_indicator="mainnet", identity_index=0, credential_counter=0
    ):
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
        with client.verify_address(
            network_indicator="testnet", identity_index=0, credential_counter=0
        ):
            scenario_navigator.address_review_reject()

    except ExceptionRAPDU as e:
        response = e.status

    assert response == StatusWords.SWO_CONDITIONS_NOT_SATISFIED


@pytest.mark.active_test_scope
def test_verify_address_confirm_full_path_accepted(
    backend, scenario_navigator, test_name, default_screenshot_path
):
    """Verify address with P1_FULL_PATH (derivation-path format) succeeds when user approves.

    This flow does not load SET_TRUSTED_NAME, so the device still shows the path-derived base58
    address. Golden snapshots therefore typically stay unchanged when only PKI/cert display logic
    changes; add a separate test that calls SET_TRUSTED_NAME first if you need new goldens for
    cert-backed address text.
    """
    HARDENED = 0x80000000
    client = CommandSender(backend)
    # 44'/919'/404'/404'/8' (matches doc example)
    path_nodes = [
        HARDENED | 44,
        HARDENED | 919,
        HARDENED | 403,
        HARDENED | 404,
        HARDENED | 8,
    ]
    with client.verify_address_full_path(path_nodes):
        scenario_navigator.address_review_approve()

    response = client.get_async_response().status
    assert response == StatusWords.SWO_SUCCESS


@pytest.mark.active_test_scope
def test_verify_address_trusted_name_full_flow_accepted(
    backend,
    scenario_navigator: NavigateWithScenario,
    test_name: str,
    default_screenshot_path: str,
):
    """PKI → GET_PUBLIC_KEY → GET_CHALLENGE → SET_TRUSTED_NAME → VERIFY_ADDRESS (new path).

    Uses the UTF-8 display string from a real Ledger API ``TrustedName`` sample; TLV
    metadata matches that style but chain_id and BIP44 coin type are mainnet so GET_PUBLIC_KEY
    and VERIFY_ADDRESS agree with Speculos. See module constants and
    https://nft.api.live.ledger-test.com/v2/concordium/owner/…

    Requires Speculos, PKI test certificate, and app built with TRUSTED_NAME_TEST_KEY
    (see tests/standalone/README.md). Tag 0x20 is the certified UTF-8 address string; tag 0x22
    must match get_public_key() for the same path as VERIFY (re-signed with the test PKI key).

    GET_PUBLIC_KEY must run *before* GET_CHALLENGE: the challenge is stored in the same
    ``instructionContext`` union as the export-public-key state and would be overwritten
    otherwise (SET_TRUSTED_NAME would then fail with 0x6B03).
    """
    _requires_speculos_pki(backend)
    client = CommandSender(backend)

    _load_pki_certificate_only(backend, client)

    idp_index = 0
    identity_index = 0
    credential_counter = 0
    path_cdata = _concordium_new_account_path_cdata(
        idp_index, identity_index, mainnet=True
    )
    pubkey = _get_ed25519_pubkey_32(client, path_cdata)

    resp = client.get_challenge()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 8
    challenge = int.from_bytes(resp.data, "big")

    builder = TrustedNameTlvBuilder(
        name=REAL_API_DESCRIPTOR_DISPLAY_ADDRESS,
        address=pubkey,
        chain_id=REAL_DESCRIPTOR_CHAIN_ID_MAINNET,
        challenge=challenge,
        name_type=REAL_DESCRIPTOR_NAME_TYPE,
        name_source=REAL_DESCRIPTOR_NAME_SOURCE,
        version=REAL_DESCRIPTOR_TLV_VERSION,
    )
    rapdu = client.set_trusted_name(builder.build_signed())
    assert rapdu.status == StatusWords.SWO_SUCCESS

    with client.verify_address(
        network_indicator="mainnet",
        identity_index=identity_index,
        credential_counter=credential_counter,
        idp_index=idp_index,
    ):
        scenario_navigator.address_review_approve()

    assert client.get_async_response().status == StatusWords.SWO_SUCCESS
