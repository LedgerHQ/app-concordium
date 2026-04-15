"""
Set Trusted Name (INS 0x22) – TLV-based wire format.

The CDATA is a raw TLV payload (the ``signedDescriptor``).
Before calling SET_TRUSTED_NAME the host must:
  1. Load a Nano PKI certificate for KeyUsage trusted_name (``CLA=0xB0 INS=0x06``).
  2. Call GET_CHALLENGE (INS 0x23) to obtain a fresh challenge.

The TLV is built and signed in Python using ``trusted_name_helper.py`` with the
same test key/certificate pair that Speculos accepts.

Tests require a Speculos backend with a device that supports PKI (Nano S Plus or newer).

PKI tests that need the **test** signer key (0x00) are skipped when the app was built
without ``TRUSTED_NAME_TEST_KEY`` (e.g. release). Build with ``make DEBUG=1`` or
``ENABLE_TRUSTED_NAME_TEST_KEY=1``.
"""

from typing import Optional

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
)

SW_INVALID_PARAM = 0x6B03

# None = not probed yet; True = app accepts test PKI; False = release build, skip PKI tests
_trusted_name_test_key_ok: Optional[bool] = None


def _ensure_trusted_name_test_key(backend, client: CommandSender) -> None:
    """Skip PKI tests if the app was built without TRUSTED_NAME_TEST_KEY (production signer only)."""
    global _trusted_name_test_key_ok
    _requires_speculos_pki(backend)
    if _trusted_name_test_key_ok is True:
        return
    if _trusted_name_test_key_ok is False:
        pytest.skip(
            "App built without TRUSTED_NAME_TEST_KEY (release). "
            "Rebuild with DEBUG=1 or ENABLE_TRUSTED_NAME_TEST_KEY=1 to run PKI tests."
        )

    cert = get_pki_certificate(_get_device_name(backend))
    if cert is None:
        pytest.skip(f"No PKI certificate for device {_get_device_name(backend)}")

    client.load_pki_certificate(PKI_KEY_USAGE_TRUSTED_NAME, cert)
    resp = client.get_challenge()
    assert resp.status == StatusWords.SWO_SUCCESS
    challenge = int.from_bytes(resp.data, "big")
    builder = TrustedNameTlvBuilder(
        name="probe",
        address=b"\x00" * 32,
        chain_id=1,
        challenge=challenge,
    )
    payload = builder.build_signed()
    try:
        rapdu = client.set_trusted_name(payload)
        status = rapdu.status
    except ExceptionRAPDU as e:
        status = e.status
    if status != StatusWords.SWO_SUCCESS:
        _trusted_name_test_key_ok = False
        pytest.skip(
            "App built without TRUSTED_NAME_TEST_KEY (release). "
            "Rebuild with DEBUG=1 or ENABLE_TRUSTED_NAME_TEST_KEY=1 to run PKI tests."
        )
    _trusted_name_test_key_ok = True


def _expect_set_trusted_name_sw(
    client: CommandSender, data: bytes, *, p1: int = 0, p2: int = 0, expected_sw: int = SW_INVALID_PARAM
) -> None:
    """Speculos raises ExceptionRAPDU on non-9000; other paths may return RAPDU — cover both."""
    try:
        rapdu = client.set_trusted_name(data, p1=p1, p2=p2)
    except ExceptionRAPDU as e:
        assert e.status == expected_sw
    else:
        assert rapdu.status == expected_sw


def _get_device_name(backend) -> str:
    """Extract the device name from the backend for PKI certificate selection."""
    if hasattr(backend, "device") and hasattr(backend.device, "type"):
        return backend.device.type.name.lower()
    return "nanosp"


def _load_pki_and_get_challenge(backend, client: CommandSender) -> int:
    """Load PKI certificate and get a fresh challenge. Returns challenge as int."""
    _ensure_trusted_name_test_key(backend, client)
    cert = get_pki_certificate(_get_device_name(backend))
    if cert is None:
        pytest.skip(f"No PKI certificate for device {_get_device_name(backend)}")

    resp = client.load_pki_certificate(PKI_KEY_USAGE_TRUSTED_NAME, cert)
    assert resp.status == StatusWords.SWO_SUCCESS, f"PKI cert load failed: 0x{resp.status:04X}"

    resp = client.get_challenge()
    assert resp.status == StatusWords.SWO_SUCCESS
    assert len(resp.data) == 8
    return int.from_bytes(resp.data, "big")


def _requires_speculos_pki(backend):
    """Skip test if not running on Speculos (PKI test certs only work there)."""
    if not isinstance(backend, SpeculosBackend):
        pytest.skip("PKI test certificates only work with Speculos backend")


# ── Positive tests ───────────────────────────────────────────────────────────


@pytest.mark.active_test_scope
def test_set_trusted_name_accepts_valid_pki_payload(backend):
    """Happy path: GET_CHALLENGE -> build TLV -> sign -> SET_TRUSTED_NAME -> success."""
    _requires_speculos_pki(backend)
    client = CommandSender(backend)

    challenge = _load_pki_and_get_challenge(backend, client)

    builder = TrustedNameTlvBuilder(
        name="TestAccount.ccd",
        address=bytes.fromhex("ab" * 32),
        chain_id=1,
        challenge=challenge,
    )
    payload = builder.build_signed()

    response = client.set_trusted_name(payload)
    assert response.status == StatusWords.SWO_SUCCESS


@pytest.mark.active_test_scope
def test_set_trusted_name_long_name(backend):
    """Trusted name up to 64 chars should be accepted."""
    _requires_speculos_pki(backend)
    client = CommandSender(backend)

    challenge = _load_pki_and_get_challenge(backend, client)

    builder = TrustedNameTlvBuilder(
        name="A" * 64,
        address=bytes.fromhex("cd" * 32),
        chain_id=1,
        challenge=challenge,
    )
    payload = builder.build_signed()

    response = client.set_trusted_name(payload)
    assert response.status == StatusWords.SWO_SUCCESS


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
    """Garbage bytes that don't form valid TLV should be rejected."""
    client = CommandSender(backend)
    _expect_set_trusted_name_sw(client, b"\xff\xff\xff\xff\xff")


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_missing_challenge(backend):
    """TLV with all required fields except challenge -> reject."""
    _requires_speculos_pki(backend)
    client = CommandSender(backend)
    _ensure_trusted_name_test_key(backend, client)

    cert = get_pki_certificate(_get_device_name(backend))
    if cert is None:
        pytest.skip("No PKI certificate")
    client.load_pki_certificate(PKI_KEY_USAGE_TRUSTED_NAME, cert)
    client.get_challenge()

    msg = b"".join([
        _tlv(TAG_STRUCTURE_TYPE, bytes([STRUCTURE_TYPE_TRUSTED_NAME])),
        _tlv(TAG_VERSION, bytes([0x01])),
        _tlv(TAG_TRUSTED_NAME_TYPE, bytes([0x05])),
        _tlv(TAG_TRUSTED_NAME_SOURCE, bytes([0x01])),
        _tlv(TAG_TRUSTED_NAME, b"test"),
        _tlv(TAG_CHAIN_ID, bytes([0x01])),
        _tlv(TAG_ADDRESS, b"\x00" * 32),
        _tlv(TAG_SIGNER_KEY_ID, bytes([0x00])),
        _tlv(TAG_SIGNER_ALGORITHM, bytes([SIGNER_ALGO_ECDSA_SHA256])),
    ])
    sig = sign_tlv(msg)
    payload = msg + _tlv(TAG_DER_SIGNATURE, sig)

    _expect_set_trusted_name_sw(client, payload)


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_wrong_challenge(backend):
    """TLV with incorrect challenge value -> reject."""
    _requires_speculos_pki(backend)
    client = CommandSender(backend)

    challenge = _load_pki_and_get_challenge(backend, client)

    builder = TrustedNameTlvBuilder(
        name="test",
        address=b"\x00" * 32,
        chain_id=1,
        challenge=challenge ^ 0xFFFFFFFFFFFFFFFF,
    )
    payload = builder.build_signed()

    _expect_set_trusted_name_sw(client, payload)


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_bad_signature(backend):
    """Valid TLV structure but corrupted signature -> reject."""
    _requires_speculos_pki(backend)
    client = CommandSender(backend)

    challenge = _load_pki_and_get_challenge(backend, client)

    builder = TrustedNameTlvBuilder(
        name="test",
        address=b"\x00" * 32,
        chain_id=1,
        challenge=challenge,
    )
    msg = builder.build_message()
    bad_sig = bytes(64)
    payload = msg + _tlv(TAG_DER_SIGNATURE, bad_sig)

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
    payload = builder.build_signed()

    _expect_set_trusted_name_sw(client, payload)


@pytest.mark.active_test_scope
def test_set_trusted_name_rejects_without_get_challenge(backend):
    """SET_TRUSTED_NAME without prior GET_CHALLENGE -> reject (challenge is 0)."""
    _requires_speculos_pki(backend)
    client = CommandSender(backend)
    _ensure_trusted_name_test_key(backend, client)

    cert = get_pki_certificate(_get_device_name(backend))
    if cert is None:
        pytest.skip("No PKI certificate")
    client.load_pki_certificate(PKI_KEY_USAGE_TRUSTED_NAME, cert)

    builder = TrustedNameTlvBuilder(
        name="test",
        address=b"\x00" * 32,
        chain_id=1,
        challenge=0,
    )
    payload = builder.build_signed()

    _expect_set_trusted_name_sw(client, payload)
