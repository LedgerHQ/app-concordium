"""
Helpers and tests for Ledger test-API TrustedName JSON (e.g. getV2 Concordium owner/address).

Example:
https://nft.api.live.ledger-test.com/v2/concordium/owner/.../...?challenge=0x...&network=testnet

The API returns ``signedDescriptor`` (hex): full TLV payload including the DER ECDSA signature
as the last tag (``0x15``).  INS 0x22 now expects this TLV as raw CDATA.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

import pytest

_FIXTURE_JSON: Final = (
    Path(__file__).resolve().parent / "fixtures" / "trusted_name" / "ledger_api_descriptor.json"
)


def tlv_walk_trusted_name_fields(tlv: bytes) -> dict[int, bytes]:
    """Minimal TLV parser: tag (1 byte) + length (1 byte) + value."""
    out: dict[int, bytes] = {}
    i = 0
    while i < len(tlv):
        tag = tlv[i]
        i += 1
        if i >= len(tlv):
            break
        ln = tlv[i]
        i += 1
        out[tag] = tlv[i : i + ln]
        i += ln
    return out


def load_ledger_api_fixture() -> dict:
    with _FIXTURE_JSON.open(encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.active_test_scope
def test_ledger_api_fixture_signed_descriptor_is_valid_tlv() -> None:
    """The API signedDescriptor should parse as valid TLV with expected fields."""
    data = load_ledger_api_fixture()
    raw = bytes.fromhex(data["signedDescriptor"])
    fields = tlv_walk_trusted_name_fields(raw)

    assert 0x01 in fields, "missing structure type"
    assert 0x20 in fields, "missing trusted name"
    assert 0x22 in fields, "missing address"
    assert 0x15 in fields, "missing DER signature"

    assert fields[0x20].decode("utf-8") == data["address"]
    assert fields[0x22].hex() == data["owner"]


@pytest.mark.active_test_scope
def test_ledger_api_fixture_can_be_used_as_cdata() -> None:
    """The raw signedDescriptor hex should be directly usable as SET_TRUSTED_NAME CDATA."""
    data = load_ledger_api_fixture()
    raw = bytes.fromhex(data["signedDescriptor"])
    assert len(raw) < 256, "payload must fit in single APDU Lc byte"
    assert raw[0] == 0x01, "first byte should be structure type tag"
