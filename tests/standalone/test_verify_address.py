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
    _get_device_name,
    _requires_speculos_pki,
)
from trusted_name_helper import (
    PKI_KEY_USAGE_TRUSTED_NAME,
    TrustedNameTlvBuilder,
    get_pki_certificate,
    CCD_SPEC_VERSION,
    CCD_NAME_TYPE_CONTEXT_ADDRESS,
    CCD_NAME_SOURCE_DYNAMIC_RESOLVER,
    CCD_CHAIN_ID_MAINNET,
    CCD_CHAIN_ID_TESTNET,
)

SW_INVALID_PATH = 0x6B02
SW_TRUSTED_NAME_MISMATCH = 0x6B0C

# ── Real Ledger API descriptor sample ─────────────────────────────────────────
# Source: https://nft.api.live.ledger-test.com/v2/concordium/owner/.../...?network=testnet
# The signedDescriptor from the API cannot be sent as-is in tests (production signature +
# fixed challenge). We reuse its TLV metadata (version / name type / name source); tag 0x22 is the
# device-derived Ed25519 key for the chosen path and tag 0x20 the device-derived account address,
# re-signed with the Speculos test PKI key.
#
# The flow uses mainnet derivation (44'/919'/…) and chain_id=0: Speculos GET_PUBLIC_KEY
# fails with 0x6B07 on testnet coin type 1' for this path (OS/crypto stack), while 919' works.
REAL_DESCRIPTOR_TLV_VERSION = CCD_SPEC_VERSION
REAL_DESCRIPTOR_NAME_TYPE = CCD_NAME_TYPE_CONTEXT_ADDRESS  # ccd_context_address
REAL_DESCRIPTOR_NAME_SOURCE = CCD_NAME_SOURCE_DYNAMIC_RESOLVER  # dynamic_resolver
REAL_DESCRIPTOR_CHAIN_ID_MAINNET = CCD_CHAIN_ID_MAINNET

# Account address the device derives for m/44'/919'/0'/0'/3' with credential counter 0 on the
# Speculos default seed. VERIFY_ADDRESS now requires a trusted-name descriptor's tag 0x20 to be
# exactly this string, so a descriptor issued for another credential counter cannot be shown
# against this one. To refresh it, run a plain VERIFY_ADDRESS for the same path and read the
# "Address" row off the review.
DEVICE_ADDRESS_MAINNET_IDP0_ID0_COUNTER0 = (
    "3E7XtabVDd3XFxpsNh6AQkNao2oB18LyycJPfVZwdyCzDeeRTr"
)
# Any other syntactically valid Concordium account address; used to show that a descriptor for a
# different account is refused even though it is correctly signed.
OTHER_ACCOUNT_ADDRESS = "3g8qKNTvKE5m2Zt7jmS5Fi8ParWiaSzzn5xPhyT31TGTomQPuV"


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
    _requires_speculos_pki(backend)
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
    with client.verify_address(
        identity_index=0, credential_counter=0, idp_index=0, network_indicator="testnet"
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
        with client.verify_address(identity_index=0, credential_counter=0, idp_index=0):
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
        name=DEVICE_ADDRESS_MAINNET_IDP0_ID0_COUNTER0,
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
        identity_index=identity_index,
        credential_counter=credential_counter,
        idp_index=idp_index,
    ):
        scenario_navigator.address_review_approve()

    assert client.get_async_response().status == StatusWords.SWO_SUCCESS


# ── Binding the descriptor to the account under review ───────────────────────


def _verify_address_new_path_sw(
    client: CommandSender,
    *,
    idp_index: int,
    identity_index: int,
    credential_counter: int,
    mainnet: bool = True,
) -> int:
    """Synchronous VERIFY_ADDRESS (new path); returns the status word without any UI."""
    data = (
        idp_index.to_bytes(4, "big")
        + identity_index.to_bytes(4, "big")
        + credential_counter.to_bytes(4, "big")
    )
    try:
        rapdu = client.backend.exchange(
            cla=CLA,
            ins=InsType.VERIFY_ADDRESS,
            p1=P1.P1_VERIFY_ADDRESS_NEW_PATH,
            p2=P2.P2_MAINNET if mainnet else P2.P2_TESTNET,
            data=data,
        )
    except ExceptionRAPDU as e:
        return e.status
    return rapdu.status


def _set_trusted_name_for_mainnet_path(
    backend, client: CommandSender, *, name: str, chain_id: int = CCD_CHAIN_ID_MAINNET
) -> None:
    """PKI + GET_PUBLIC_KEY + GET_CHALLENGE + SET_TRUSTED_NAME for m/44'/919'/0'/0'/3'."""
    _load_pki_certificate_only(backend, client)
    pubkey = _get_ed25519_pubkey_32(
        client, _concordium_new_account_path_cdata(0, 0, mainnet=True)
    )
    resp = client.get_challenge()
    assert resp.status == StatusWords.SWO_SUCCESS
    builder = TrustedNameTlvBuilder(
        name=name,
        address=pubkey,
        chain_id=chain_id,
        challenge=int.from_bytes(resp.data, "big"),
        name_type=CCD_NAME_TYPE_CONTEXT_ADDRESS,
        name_source=CCD_NAME_SOURCE_DYNAMIC_RESOLVER,
        version=CCD_SPEC_VERSION,
    )
    rapdu = client.set_trusted_name(builder.build_signed())
    assert rapdu.status == StatusWords.SWO_SUCCESS


@pytest.mark.active_test_scope
def test_verify_address_rejects_descriptor_for_another_credential_counter(backend):
    """Tag 0x22 is identity-level, so it matches every counter under one identity.

    The descriptor is signed for account address A; VERIFY_ADDRESS is then asked to review
    credential counter 1, whose address is not A. Without the address binding the device would
    have paired counter 1's path label with counter 0's certified address.
    """
    client = CommandSender(backend)
    _set_trusted_name_for_mainnet_path(
        backend, client, name=DEVICE_ADDRESS_MAINNET_IDP0_ID0_COUNTER0
    )

    sw = _verify_address_new_path_sw(
        client, idp_index=0, identity_index=0, credential_counter=1
    )
    assert sw == SW_TRUSTED_NAME_MISMATCH, f"SW=0x{sw:04X}"


@pytest.mark.active_test_scope
def test_verify_address_rejects_descriptor_for_another_account(backend):
    """A correctly signed descriptor naming a different account address is refused."""
    client = CommandSender(backend)
    _set_trusted_name_for_mainnet_path(backend, client, name=OTHER_ACCOUNT_ADDRESS)

    sw = _verify_address_new_path_sw(
        client, idp_index=0, identity_index=0, credential_counter=0
    )
    assert sw == SW_TRUSTED_NAME_MISMATCH, f"SW=0x{sw:04X}"


@pytest.mark.active_test_scope
def test_verify_address_rejects_descriptor_signed_for_other_network(backend):
    """A descriptor signed for testnet must not be shown against a mainnet path."""
    client = CommandSender(backend)
    _set_trusted_name_for_mainnet_path(
        backend,
        client,
        name=DEVICE_ADDRESS_MAINNET_IDP0_ID0_COUNTER0,
        chain_id=CCD_CHAIN_ID_TESTNET,
    )

    sw = _verify_address_new_path_sw(
        client, idp_index=0, identity_index=0, credential_counter=0
    )
    assert sw == SW_TRUSTED_NAME_MISMATCH, f"SW=0x{sw:04X}"


@pytest.mark.active_test_scope
def test_verify_address_rejects_empty_full_path(backend):
    """A zero-node path would derive from the master key and review as an empty label."""
    client = CommandSender(backend)
    try:
        rapdu = client.backend.exchange(
            cla=CLA,
            ins=InsType.VERIFY_ADDRESS,
            p1=P1.P1_VERIFY_ADDRESS_FULL_PATH,
            p2=P2.P2_MAINNET,
            data=bytes([0]),
        )
        sw = rapdu.status
    except ExceptionRAPDU as e:
        sw = e.status
    assert sw == SW_INVALID_PATH, f"SW=0x{sw:04X}"
