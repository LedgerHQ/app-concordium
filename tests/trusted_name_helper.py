"""
TLV builder and PKI signing helper for SET_TRUSTED_NAME (INS 0x22) tests.

Uses the same test PKI certificate and private key as app-ethereum so that
Speculos accepts the signature through ``check_signature_with_pki``.

Flow:
    1. Load PKI certificate for trusted_name key usage (``load_pki_certificate``)
    2. GET_CHALLENGE → 8-byte challenge
    3. Build TLV with ``TrustedNameTlvBuilder``
    4. Sign with ``sign_tlv``
    5. SET_TRUSTED_NAME with the full TLV (including signature tag)

The TLV ``signer_key_id`` is set to 0 (test) matching ``TRUSTED_NAME_TEST_KEY``.
"""

from __future__ import annotations

import hashlib
from typing import Optional

from ecdsa import SigningKey  # type: ignore[import-untyped]
from ecdsa.util import sigencode_der  # type: ignore[import-untyped]

# ── Tag constants (same values as SDK tlv_use_case_trusted_name) ────────────

TAG_STRUCTURE_TYPE      = 0x01
TAG_VERSION             = 0x02
TAG_NOT_VALID_AFTER     = 0x10
TAG_CHALLENGE           = 0x12
TAG_SIGNER_KEY_ID       = 0x13
TAG_SIGNER_ALGORITHM    = 0x14
TAG_DER_SIGNATURE       = 0x15
TAG_TRUSTED_NAME        = 0x20
TAG_ADDRESS             = 0x22
TAG_CHAIN_ID            = 0x23
TAG_TRUSTED_NAME_TYPE   = 0x70
TAG_TRUSTED_NAME_SOURCE = 0x71

STRUCTURE_TYPE_TRUSTED_NAME = 0x03
SIGNER_KEY_ID_TEST = 0x0000
SIGNER_ALGO_ECDSA_SHA256 = 0x01

PKI_KEY_USAGE_TRUSTED_NAME = 0x04


def _tlv(tag: int, value: bytes) -> bytes:
    """Encode a single TLV field (1-byte tag, DER-style length, value)."""
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    elif len(value) <= 0xFF:
        return bytes([tag, 0x81, len(value)]) + value
    else:
        return bytes([tag, 0x82]) + len(value).to_bytes(2, "big") + value


# ── Test PKI certificates (from app-ethereum, signed by Speculos test root) ─

# These certificates contain the public key matching TRUSTED_NAME_PRIVATE_KEY_PEM.
PKI_CERTIFICATES_TRUSTED_NAME = {
    "nanosp": "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020007310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F6534010135010315473045022100F394484C045418507E0F76A3231F233B920C733D3E5BB68AFBAA80A55195F70D022012BC1FD796CD2081D8355DEEFA051FBB9329E34826FF3125098F4C6A0C29992A",
    "nanox":  "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020007310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F65340101350102154730450221009D97646C49EE771BE56C321AB59C732E10D5D363EBB9944BF284A3A04EC5A14102200633518E851984A7EA00C5F81EDA9DAA58B4A6C98E57DA1FBB9074AEFF0FE49F",
    "stax":   "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020007310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F6534010135010415473045022100A57DC7AB3F0E38A8D10783C7449024D929C60843BB75E5FF7B8088CB71CB130C022045A03E6F501F3702871466473BA08CE1F111357ED9EF395959733477165924C4",
    "flex":   "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020007310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F6534010135010515473045022100D5BB77756C3D7C1B4254EA8D5351B94A89B13BA69C3631A523F293A10B7144B302201519B29A882BB22DCDDF6BE79A9CBA76566717FA877B7CA4B9CC40361A2D579E",
    "apex_p": "01010102010211040000000212010013020002140101160400000000200C547275737465645F4E616D6530020007310104320121332102B91FBEC173E3BA4A714E014EBC827B6F899A9FA7F4AC769CDE284317A00F4F65340101350106154630440220200261047BAF050570EA5105D1E05855131CB98A94C58B019732F849BD1CE5330220237D303A9606EA631DDD3E5E12D2A70878A0ED954D975BF55DD7A84BF08506AA",
}

# secp256k1 private key matching the public key in the certificates above.
TRUSTED_NAME_PRIVATE_KEY_PEM = """\
-----BEGIN EC PARAMETERS-----
BgUrgQQACg==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIHfwyko1dEHTTQ7es7EUy2ajZo1IRRcEC8/9b+MDOzUaoAcGBSuBBAAK
oUQDQgAEuR++wXPjukpxTgFOvIJ7b4man6f0rHac3ihDF6APT2UPCfCapP9aMXYC
Vf5d/IETKbO1C+mRlPyhFhnmXy7f6g==
-----END EC PRIVATE KEY-----
"""


def get_pki_certificate(device_name: str) -> Optional[bytes]:
    """Return the PKI certificate bytes for the given device, or None."""
    device_key = device_name.lower().replace(" ", "").replace("nano", "nano")
    # Aliases not matched by substring rules (e.g. SDK folder "nanos2" vs DeviceType.nanosp).
    aliases = {
        "nanos2": "nanosp",
        "nanosplus": "nanosp",
        "apex_m": "nanosp",  # no dedicated Speculos TrustedName cert yet; same test key as CI
    }
    if device_key in aliases:
        device_key = aliases[device_key]
    for key, val in PKI_CERTIFICATES_TRUSTED_NAME.items():
        if key in device_key or device_key in key:
            return bytes.fromhex(val)
    return None


def _get_signing_key() -> SigningKey:
    return SigningKey.from_pem(TRUSTED_NAME_PRIVATE_KEY_PEM, hashfunc=hashlib.sha256)


class TrustedNameTlvBuilder:
    """Build a trusted-name TLV descriptor payload."""

    def __init__(
        self,
        *,
        name: str = "test-name",
        address: bytes = b"\x00" * 32,
        chain_id: int = 1,
        challenge: int = 0,
        name_type: int = 0x05,
        name_source: int = 0x01,
        version: int = 0x01,
        signer_key_id: int = SIGNER_KEY_ID_TEST,
        signer_algo: int = SIGNER_ALGO_ECDSA_SHA256,
    ):
        self.name = name
        self.address = address
        self.chain_id = chain_id
        self.challenge = challenge
        self.name_type = name_type
        self.name_source = name_source
        self.version = version
        self.signer_key_id = signer_key_id
        self.signer_algo = signer_algo

    def _encode_uint(self, val: int, min_bytes: int = 1) -> bytes:
        """Encode an unsigned integer in big-endian with minimum byte width."""
        if val == 0:
            return b"\x00" * min_bytes
        length = max(min_bytes, (val.bit_length() + 7) // 8)
        return val.to_bytes(length, "big")

    def build_message(self) -> bytes:
        """Build the TLV payload up to (and including) signer_algo, excluding signature."""
        parts = [
            _tlv(TAG_STRUCTURE_TYPE, bytes([STRUCTURE_TYPE_TRUSTED_NAME])),
            _tlv(TAG_VERSION, bytes([self.version])),
            _tlv(TAG_TRUSTED_NAME_TYPE, bytes([self.name_type])),
            _tlv(TAG_TRUSTED_NAME_SOURCE, bytes([self.name_source])),
            _tlv(TAG_TRUSTED_NAME, self.name.encode("utf-8")),
            _tlv(TAG_CHAIN_ID, self._encode_uint(self.chain_id)),
            _tlv(TAG_ADDRESS, self.address),
            _tlv(TAG_CHALLENGE, self._encode_uint(self.challenge, min_bytes=8)),
            _tlv(TAG_SIGNER_KEY_ID, self._encode_uint(self.signer_key_id, min_bytes=1)),
            _tlv(TAG_SIGNER_ALGORITHM, bytes([self.signer_algo])),
        ]
        return b"".join(parts)

    def build_signed(self) -> bytes:
        """Build the full TLV payload including DER signature."""
        msg = self.build_message()
        sig = sign_tlv(msg)
        return msg + _tlv(TAG_DER_SIGNATURE, sig)


def sign_tlv(message: bytes) -> bytes:
    """Sign the TLV message (everything except signature tag) with the test key.
    Returns DER-encoded ECDSA signature."""
    sk = _get_signing_key()
    return sk.sign_deterministic(message, sigencode=sigencode_der, hashfunc=hashlib.sha256)
