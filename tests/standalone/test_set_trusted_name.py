"""
Set Trusted Name (INS 0x22) – TLV-based wire format.

The CDATA is a raw TLV payload (the ``signedDescriptor``).
Before calling SET_TRUSTED_NAME the host must:
  1. Load a Nano PKI certificate for KeyUsage trusted_name (``CLA=0xB0 INS=0x06``).
  2. Call GET_CHALLENGE (INS 0x23) to obtain a fresh challenge.

The TLV is built and signed in Python using ``trusted_name_helper.py`` with the
same test key/certificate pair that Speculos accepts.

Tests require a Speculos backend with a device that supports PKI (Nano S Plus or newer).

If you see ``ExceptionRAPDU: Error [0x6b03]`` on the PKI tests, the firmware was built
without ``ENABLE_TRUSTED_NAME_TEST_KEY=1``. These tests use signer_key_id=0x0000 (test key),
which is structurally rejected by production firmware before signature verification.
Rebuild with ``make DEBUG=1`` or ``make ENABLE_TRUSTED_NAME_TEST_KEY=1`` and re-run.
"""

import pytest

from application_client.command_sender import CommandSender
from ragger.backend import SpeculosBackend
from ragger.error import ExceptionRAPDU, StatusWords

from trusted_name_helper import (
    PKI_KEY_USAGE_TRUSTED_NAME,
    TrustedNameTlvBuilder,
    get_pki_certificate,
    sign_tlv,
    _tlv,
    TAG_STRUCTURE_TYPE,
    STRUCTURE_TYPE_TRUSTED_NAME,
    TAG_VERSION,
    TAG_TRUSTED_NAME_TYPE,
    TAG_TRUSTED_NAME_SOURCE,
    TAG_TRUSTED_NAME,
    TAG_CHAIN_ID,
    TAG_ADDRESS,
    TAG_CHALLENGE,
    TAG_SIGNER_KEY_ID,
    TAG_SIGNER_ALGORITHM,
    TAG_DER_SIGNATURE,
    SIGNER_KEY_ID_TEST,
    SIGNER_ALGO_ECDSA_SHA256,
    CCD_SPEC_VERSION,
    CCD_NAME_TYPE_CONTEXT_ADDRESS,
    CCD_NAME_SOURCE_DYNAMIC_RESOLVER,
    CCD_CHAIN_ID_MAINNET,
    CCD_CHAIN_ID_TESTNET,
    semver,
)

SW_INVALID_PARAM = 0x6B03


def _requires_speculos_pki(backend):
    if not isinstance(backend, SpeculosBackend):
        pytest.skip("PKI test certificates only work with Speculos backend")


def _get_device_name(backend) -> str:
    if hasattr(backend, "device") and hasattr(backend.device, "type"):
        return backend.device.type.name.lower()
    return "nanosp"


def _load_pki(backend, client: CommandSender) -> None:
    _requires_speculos_pki(backend)
    cert = get_pki_certificate(_get_device_name(backend))
    if cert is None:
        pytest.skip(f"No PKI certificate for device {_get_device_name(backend)}")
    resp = client.load_pki_certificate(PKI_KEY_USAGE_TRUSTED_NAME, cert)
    assert resp.status == StatusWords.SWO_SUCCESS, f"PKI cert load failed: 0x{resp.status:04X}"


def _load_pki_and_get_challenge(backend, client: CommandSender) -> int:
    _load_pki(backend, client)
    resp = client.get_challenge()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 8
    return int.from_bytes(resp.data, "big")


def _expect_set_trusted_name_sw(
    client: CommandSender, data: bytes, *, p1: int = 0, p2: int = 0, expected_sw: int = SW_INVALID_PARAM
) -> None:
    try:
        rapdu = client.set_trusted_name(data, p1=p1, p2=p2)
    except ExceptionRAPDU as e:
        assert e.status == expected_sw
    else:
        assert rapdu.status == expected_sw


def _assert_set_trusted_name_ok(client: CommandSender, payload: bytes) -> None:
    try:
        rapdu = client.set_trusted_name(payload)
    except ExceptionRAPDU as e:
        if e.status == SW_INVALID_PARAM:
            pytest.fail("0x6b03: test key (0x0000) rejected — missing ENABLE_TRUSTED_NAME_TEST_KEY=1?")
        raise
    assert rapdu.status == StatusWords.SWO_SUCCESS


# ── Positive tests ───────────────────────────────────────────────────────────


@pytest.mark.active_test_scope
def test_set_trusted_name_accepts_valid_pki_payload(backend):
    """Happy path: GET_CHALLENGE -> build TLV -> sign -> SET_TRUSTED_NAME -> success."""
    client = CommandSender(backend)
    challenge = _load_pki_and_get_challenge(backend, client)

    builder = TrustedNameTlvBuilder(
        name="TestAccount.ccd",
        address=bytes.fromhex("ab" * 32),
        chain_id=1,
        challenge=challenge,
    )
    _assert_set_trusted_name_ok(client, builder.build_signed())


@pytest.mark.active_test_scope
def test_set_trusted_name_long_name(backend):
    """Trusted name up to 64 chars should be accepted."""
    client = CommandSender(backend)
    challenge = _load_pki_and_get_challenge(backend, client)

    builder = TrustedNameTlvBuilder(
        name="A" * 64,
        address=bytes.fromhex("cd" * 32),
        chain_id=1,
        challenge=challenge,
    )
    _assert_set_trusted_name_ok(client, builder.build_signed())


# ── Negative tests ───────────────────────────────────────────────────────────


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_wrong_p1(backend):
    client = CommandSender(backend)
    _expect_set_trusted_name_sw(client, b"\x01\x01\x03", p1=0x01, p2=0x00)


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_wrong_p2(backend):
    client = CommandSender(backend)
    _expect_set_trusted_name_sw(client, b"\x01\x01\x03", p1=0x00, p2=0x01)


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_empty_cdata(backend):
    client = CommandSender(backend)
    _expect_set_trusted_name_sw(client, b"")


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_invalid_tlv(backend):
    client = CommandSender(backend)
    _expect_set_trusted_name_sw(client, b"\xff\xff\xff\xff\xff")


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_missing_challenge(backend):
    """TLV omitting the challenge tag -> reject (missing required field)."""
    client = CommandSender(backend)
    _load_pki(backend, client)
    client.get_challenge()

    # Every other field is valid, so the missing challenge is the only reason to reject.
    msg = b"".join([
        _tlv(TAG_STRUCTURE_TYPE, bytes([STRUCTURE_TYPE_TRUSTED_NAME])),
        _tlv(TAG_VERSION, bytes([CCD_SPEC_VERSION])),
        _tlv(TAG_TRUSTED_NAME_TYPE, bytes([CCD_NAME_TYPE_CONTEXT_ADDRESS])),
        _tlv(TAG_TRUSTED_NAME_SOURCE, bytes([CCD_NAME_SOURCE_DYNAMIC_RESOLVER])),
        _tlv(TAG_TRUSTED_NAME, b"test"),
        _tlv(TAG_CHAIN_ID, bytes([CCD_CHAIN_ID_TESTNET])),
        _tlv(TAG_ADDRESS, b"\x00" * 32),
        _tlv(TAG_SIGNER_KEY_ID, bytes([SIGNER_KEY_ID_TEST])),
        _tlv(TAG_SIGNER_ALGORITHM, bytes([SIGNER_ALGO_ECDSA_SHA256])),
    ])
    payload = msg + _tlv(TAG_DER_SIGNATURE, sign_tlv(msg))
    _expect_set_trusted_name_sw(client, payload)


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_wrong_challenge(backend):
    """TLV with incorrect challenge value -> reject."""
    client = CommandSender(backend)
    challenge = _load_pki_and_get_challenge(backend, client)

    builder = TrustedNameTlvBuilder(
        name="test",
        address=b"\x00" * 32,
        chain_id=1,
        challenge=challenge ^ 0xFFFFFFFFFFFFFFFF,
    )
    _expect_set_trusted_name_sw(client, builder.build_signed())


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_bad_signature(backend):
    """Valid TLV structure but corrupted signature -> reject."""
    client = CommandSender(backend)
    challenge = _load_pki_and_get_challenge(backend, client)

    builder = TrustedNameTlvBuilder(
        name="test",
        address=b"\x00" * 32,
        chain_id=1,
        challenge=challenge,
    )
    payload = builder.build_message() + _tlv(TAG_DER_SIGNATURE, bytes(64))
    _expect_set_trusted_name_sw(client, payload)


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_no_pki_cert_loaded(backend):
    """SET_TRUSTED_NAME without prior PKI certificate load -> reject."""
    _requires_speculos_pki(backend)
    client = CommandSender(backend)

    resp = client.get_challenge()
    challenge = int.from_bytes(resp.data, "big")

    builder = TrustedNameTlvBuilder(
        name="test",
        address=b"\x00" * 32,
        chain_id=1,
        challenge=challenge,
    )
    _expect_set_trusted_name_sw(client, builder.build_signed())


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_without_get_challenge(backend):
    """SET_TRUSTED_NAME without prior GET_CHALLENGE -> reject."""
    client = CommandSender(backend)
    _load_pki(backend, client)

    builder = TrustedNameTlvBuilder(
        name="test",
        address=b"\x00" * 32,
        chain_id=CCD_CHAIN_ID_TESTNET,
        challenge=0,
    )
    _expect_set_trusted_name_sw(client, builder.build_signed())


# ── Semantic authorization of the signed descriptor ──────────────────────────
#
# Each descriptor below is correctly signed with the test PKI key and carries the current
# challenge, so it passes signature and freshness verification. It must still be refused, because
# a valid Ledger signature does not say the descriptor was issued for *this* use case.


def _expect_rejected_descriptor(backend, client: CommandSender, **builder_kwargs) -> None:
    challenge = _load_pki_and_get_challenge(backend, client)
    builder = TrustedNameTlvBuilder(challenge=challenge, **builder_kwargs)
    _expect_set_trusted_name_sw(client, builder.build_signed())


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_unsupported_version(backend):
    """A future or superseded serialization version must not be parsed as the current one."""
    client = CommandSender(backend)
    _expect_rejected_descriptor(backend, client, version=CCD_SPEC_VERSION + 1)


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_non_context_address_type(backend):
    """A wallet-label descriptor (type 0x05) is not a Concordium account address."""
    client = CommandSender(backend)
    _expect_rejected_descriptor(backend, client, name_type=0x05)


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_foreign_name_source(backend):
    """Only the backend's dynamic resolver may name a Concordium account (0x02 is ENS)."""
    client = CommandSender(backend)
    _expect_rejected_descriptor(backend, client, name_source=0x02)


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_unknown_chain_id(backend):
    """Chain ids other than Concordium mainnet/testnet are not networks this app derives for."""
    client = CommandSender(backend)
    _expect_rejected_descriptor(backend, client, chain_id=137)


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_nft_id_tag(backend):
    """Tag 0x72 means the descriptor describes an NFT, not a plain account address."""
    client = CommandSender(backend)
    _expect_rejected_descriptor(backend, client, nft_id=bytes.fromhex("0102"))


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_source_contract_tag(backend):
    """Tag 0x73 likewise belongs to a contract-scoped descriptor."""
    client = CommandSender(backend)
    _expect_rejected_descriptor(backend, client, source_contract=bytes(20))


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_malformed_not_valid_after(backend):
    """Tag 0x10 must be exactly four bytes (major || minor || patch16)."""
    client = CommandSender(backend)
    _expect_rejected_descriptor(backend, client, not_valid_after=bytes([9, 9, 9]))


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_revoked_not_valid_after(backend):
    """A cutoff this app version is already past revokes the descriptor."""
    client = CommandSender(backend)
    _expect_rejected_descriptor(backend, client, not_valid_after=semver(0, 0, 1))


@pytest.mark.active_test_scope
def test_set_trusted_name_accepts_future_not_valid_after(backend):
    """A cutoff beyond this app version leaves the descriptor valid."""
    client = CommandSender(backend)
    challenge = _load_pki_and_get_challenge(backend, client)

    builder = TrustedNameTlvBuilder(
        name="TestAccount.ccd",
        address=bytes.fromhex("ab" * 32),
        chain_id=CCD_CHAIN_ID_MAINNET,
        challenge=challenge,
        not_valid_after=semver(255, 255, 0xFFFF),
    )
    _assert_set_trusted_name_ok(client, builder.build_signed())
