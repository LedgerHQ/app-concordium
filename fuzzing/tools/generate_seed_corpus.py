#!/usr/bin/env python3
"""Regenerate the tracked fuzz seed corpus under ``fuzzing/seeds/<target>/``.

Why this exists
---------------
Every Concordium APDU parser demands a long, structured prefix before it reaches anything
interesting: a packed derivation path, a 60-byte account-transaction header, an exact
transaction-kind byte, then per-kind length fields.  A cold libFuzzer process mutating from
the empty input essentially never assembles that prefix, so a campaign spends its whole
budget failing the first few length checks (finding V-108).

The seeds below are therefore not invented bytes.  They are the same payloads the functional
Ragger tests in ``tests/standalone/`` send to a real device, re-framed into each harness's
input layout, plus deliberate boundary cases (empty ``lc``, one byte short of a fixed field,
the largest chunk an APDU can carry).

Harness input layouts (derived from the header comment of each ``fuzzing/src/*.c``)
----------------------------------------------------------------------------------
* ``[p1][p2][control][command data...]`` - the 13 handlers that take an ``isInitialCall``
  flag; bit 0 of ``control`` drives it.
* ``[p1][p2][command data...]`` - the 5 handlers with no ``isInitialCall`` parameter
  (export pk legacy/new, get public key, sign transfer, verify address).
* ``[control][declared_cbor_length][data...]`` - ``standalone_cbor_data_blob_fuzzer``;
  ``control`` bit 0 additionally calls ``readCborContent``, and ``declared_cbor_length``
  seeds ``cborContext.cborLength``.

If a harness's layout changes, update the corresponding ``PREFIX_*`` helper here and rerun.

Usage
-----
    python3 fuzzing/tools/generate_seed_corpus.py            # rewrite fuzzing/seeds/
    python3 fuzzing/tools/generate_seed_corpus.py --check    # fail if seeds are stale

``fuzz_make_command()`` clamps ``lc`` to 255, so no seed carries more than 255 bytes of
command data; anything past that would be invisible to the handler.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SEEDS_ROOT = REPO_ROOT / "fuzzing" / "seeds"
DICTS_ROOT = REPO_ROOT / "fuzzing" / "dictionaries"

MAX_CDATA_LENGTH = 255
HARDENED = 0x80000000


# --------------------------------------------------------------------------------------
# Building blocks
# --------------------------------------------------------------------------------------
def h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", "").replace("\n", ""))


def path(*nodes: int) -> bytes:
    """Pack a derivation path the way ragger's ``pack_derivation_path`` does."""
    out = len(nodes).to_bytes(1, "big")
    for node in nodes:
        out += node.to_bytes(4, "big")
    return out


# The two path shapes the app accepts, as used throughout tests/standalone/.
PATH_LEGACY = path(1105, 0, 0, 0, 0, 2, 0, 0)  # "m/1105/0/0/0/0/2/0/0"
PATH_NEW = path(44, 919, 0, 0, 0, 0)  # "m/44/919/0/0/0/0"   (mainnet coin type)
PATH_NEW_TESTNET = path(44, 1, 0, 0, 0, 0)  # "m/44/1/0/0/0/0"     (testnet coin type)
PATH_NEW_HARDENED = path(
    HARDENED | 44, HARDENED | 919, HARDENED | 403, HARDENED | 404, HARDENED | 8
)

# 60-byte account-transaction header: sender(32) nonce(8) energy(8) payloadSize(4) expiry(8).
ACCOUNT_HEADER = h(
    "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7"
    "000000000000000a"
    "0000000000000064"
    "00000029"
    "0000000063de5da7"
)
assert len(ACCOUNT_HEADER) == 60

# Transaction kinds, as serialised right after the header.
KIND_DEPLOY_MODULE = 0x00
KIND_INIT_CONTRACT = 0x01
KIND_UPDATE_CONTRACT = 0x02
KIND_TRANSFER = 0x03
KIND_TRANSFER_TO_PUBLIC = 0x12
KIND_TRANSFER_WITH_SCHEDULE = 0x13
KIND_UPDATE_CREDENTIALS = 0x14
KIND_REGISTER_DATA = 0x15
KIND_TRANSFER_WITH_MEMO = 0x16
KIND_TRANSFER_WITH_SCHEDULE_AND_MEMO = 0x18
KIND_CONFIGURE_BAKER = 0x19
KIND_CONFIGURE_DELEGATION = 0x1A


def header(kind: int) -> bytes:
    return ACCOUNT_HEADER + bytes([kind])


ADDRESS = h("20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7")
AMOUNT_MAX = h("ffffffffffffffff")
FEE_DISPLAY = (123_456_798).to_bytes(8, "big")  # TEST_DISPLAY_FEE_MICROCCD

# CBOR memo / register-data payloads (see src/helpers/cbor_data_blob.c).
CBOR_TEXT_TEST = h("6474657374")  # text(4) "test"
CBOR_TEXT_1BYTE_LEN = bytes([0x78, 0x20]) + b"A" * 0x20  # text, 1-byte length argument
CBOR_UINT_INLINE = h("01")  # unsigned(1), inline short count
CBOR_UINT_1BYTE = h("1864")  # unsigned(100), 1-byte argument
CBOR_NINT_INLINE = h("20")  # negative(-1)
CBOR_UINT_8BYTE = h("1bffffffffffffffff")  # unsigned, 8-byte argument
CBOR_NONCANONICAL = h("1804")  # unsigned(4) in a wider form than needed
CBOR_INDEFINITE = h("7f6474657374ff")  # indefinite-length text (refused)

SCHEDULE_PAIR = h("0000017a396883d90000000005f5e100")  # timestamp(8) + amount(8)
MAX_SCHEDULE_PAIRS_PER_APDU = (250 // 16) * 16  # 240 bytes = 15 pairs

MODULE_REF = h("a00000000000000000000000000000000000000000000000000000000000000a")
CONTRACT_NAME = h("696e69745f5465737420436f6e7472616374")  # "init_Test Contract"
CONTRACT_PARAMS = h("0102030405060708090a")
CONTRACT_INDEX = h("00000000000004d2")
CONTRACT_SUBINDEX = h("000000000000162e")

# Credential-deployment / update-credential field vectors (tests/standalone/
# test_credential_deployment.py).
CRED_KEY = h("00f78929ec8a9819f6ae2e10e79522b6b311949635fecc3d924d9d1e23f8e9e1c3")
CRED_KEY_UPDATE = h("0100f78929ec8a9819f6ae2e10e79522b6b311949635fecc3d924d9d1e23f8e9e1c3")
CRED_SIGNATURE_THRESHOLD = h(
    "ff85d8a7aa296c162e4e2f0d6bfbdc562db240e28942f7f3ddef6979a1133b5c"
    "719ec3581869aaf88388824b0f6755e63c0000f013010001"
)
CRED_AR_IDENTITY = h(
    "000f0301aca024ce6083d4956edad825c3721da9b61e5b3712606ba1465f7818"
    "a43849121bdb3e4d99624e9a74b9436cc8948d178b9b144122aa070372e3fade"
    "e4998e1cc21161186a3d19698ad245e10912810df1aaddda16a27f654716108e"
    "27758099"
)
CRED_DATES = h("07e40b07e10c0001")
CRED_ATTRIBUTE_TAG = h("0104")  # tag 1 ("Last name"), value length 4
CRED_ATTRIBUTE_VALUE = h("4a6f686e")  # "John"
CRED_PROOF_LENGTH = h("00000831")
CRED_PROOF_CHUNK = h(
    "b8dc01d4fdd0c1b455e9a48285eac39ffc0a433929bbd29344016a2fdbd3892f"
    "abed9a607da37140ea2046aa7c924022a130cc78688e8174c4c244ea97461007"
    "b167f4c941585ff9b945eddff0f87942bf91bedc8d33355e7f3e09e4168c6ec9"
    "8e3aa4b7b2e6a7807dd5cc6b057646115b82c65c97e3bc7a5898c61d99465ad6"
)
CRED_ID = h(
    "85d8a7aa296c162e4e2f0d6bfbdc562db240e28942f7f3ddef6979a1133b5c71"
    "9ec3581869aaf88388824b0f6755e63c"
)
CRED_NEW_OR_EXISTING = h("00000000006040f27e")

# Baker key vectors (tests/standalone/test_configure_baker.py).
BAKER_ELECTION_KEY = h("7873cd57848d7aea7be03fbb3f1e8b9e69987fc73f13e473356776a16f26c96b")
BAKER_ELECTION_PROOF = h(
    "a47cdf9133572e9ad5c02c3a7ffd1d05db7bb98860d918092454146153d62788"
    "f224c0157c65853ed4a0245ab3e0a593a3f85fa81cc4cb99eeaa643bfc793eab"
)
BAKER_SIGN_KEY = h("32f892fb3d0dc6138976b6848259cf730e37fa4a61a659c782ec6def978c0828")
BAKER_SIGN_PROOF = h(
    "01fc695a8c51d4599cbe032a39832ad49bab900d88105b01d025b760b0d0d555"
    "b8c828f2d8fe29cc78c6307d979e6358b8bba9cf4d8200f272cc85b2a3813eff"
)
BAKER_AGGREGATION_KEY = h(
    "7873cd57848d7aea7be03fbb3f1e8b9e69987fc73f13e473356776a16f26c96b"
    "32f892fb3d0dc6138976b6848259cf730e37fa4a61a659c782ec6def978c0828"
    "32f892fb3d0dc6138976b6848259cf730e37fa4a61a659c782ec6def978c0828"
)
BAKER_AGGREGATION_PROOF = h(
    "957aec4b2b7ed979ba2079d62246d135aefd61e7f46690c452fec8bcbb593481"
    "e229f6f1968194a09cf612490887e71d96730e2d852201e53fec9c89d36f8a90"
)

# Transfer-to-public: encrypted remaining amount (192) + amount (8) + index (1) + proof size (1).
TTP_REMAINING_AND_AMOUNT = h(
    "97a9558421515a34f7c27c3b55c8dc561ed8c45a983387edf4f95ef834c5fd12"
    "d4fc5bb772490cb5653d249926bd9fc9938768d3921a4aa2361ae620e294637b"
    "eb2d052cb0351745d81e2b34fee677c1e37cd8fedd1e4afbd66557d08f827db6"
    "803e57a7473ee78c7ba2db84c6910d355f497d257f89588a5e7176265b890841"
    "add54085462b35c3d0a01d562a29023db80fbac86061bf8970ceb5cf0889cc76"
    "2e0cc6720ffac0b932c6168038aaec96e824c68cdb95e8cea823fa32792f4360"
    "0000c0a0000f4240"
    "b9"
    "e2"
)
TTP_PROOF_CHUNK = h(
    "a47cdf9133572e9ad5c02c3a7ffd1d05db7bb98860d918092454146153d62788"
    "f224c0157c65853ed4a0245ab3e0a593a3f85fa81cc4cb99eeaa643bfc793eab"
    "01fc695a8c51d4599cbe032a39832ad49bab900d88105b01d025b760b0d0d555"
    "b8c828f2d8fe29cc78c6307d979e6358b8bba9cf4d8200f272cc85b2a3813eff"
)

# Public-information-for-IP chunks (tests/standalone/test_public_information_for_ip.py).
PIIP_CHUNK_1 = h(
    "0800000451000000000000000000000000000000000000000200000000000000"
    "008196e718f392ec8d07216b22b555cbb71bcee88037566d3f758b9786b945e3"
    "b614660f4bf954dbe57bc2304e5a863d2e89a1f69196a1d0423f4936aa664da9"
    "5de16f40a639dba085073c5a7c8e710c2a402136cc89a39c12ed044e1035649c"
    "0f03"
)
PIIP_CHUNK_2 = h("0000b6bc751f1abfb6440ff5cce27d7cdd1e7b0b8ec174f54de426890635b27e7daf")
PIIP_CHUNK_3 = h("000146a3e38ddf8b493be6e979034510b91db5448da9cba48c106139c288d658a004")
PIIP_CHUNK_4 = h("000271d5f16bc3be249043dc0f9e20b4872f5c3477bf2f285336609c5b0873ab3c9c")
PIIP_THRESHOLD = h("02")


# --------------------------------------------------------------------------------------
# Harness framing
# --------------------------------------------------------------------------------------
# Control-byte bits, shared by every handler harness (fuzzing/src/standalone_*_fuzzer.c).
CONTROL_INITIAL = 0x01  # bit 0: enter the handler as the first packet of its flow
CONTROL_APPROVE = 0x02  # bit 1: approve the review screen the handler parks


def apdu(p1: int, p2: int, data: bytes = b"", *, approve: bool = True) -> bytes:
    """``[p1][p2][control][command data...]`` - handlers with no isInitialCall parameter.

    These harnesses carried no control byte until the approval callbacks became reachable
    (finding V-102); p1 and p2 are strictly validated by every one of these handlers, so
    there was no spare bit to take from them.
    """
    assert len(data) <= MAX_CDATA_LENGTH, f"{len(data)} bytes of command data would be clamped"
    return bytes([p1, p2, CONTROL_APPROVE if approve else 0x00]) + data


def apdu_ic(p1: int, p2: int, initial: bool, data: bytes = b"", *, approve: bool = True) -> bytes:
    """``[p1][p2][control][command data...]`` - bit 0 isInitialCall, bit 1 approve."""
    assert len(data) <= MAX_CDATA_LENGTH, f"{len(data)} bytes of command data would be clamped"
    control = (CONTROL_INITIAL if initial else 0x00) | (CONTROL_APPROVE if approve else 0x00)
    return bytes([p1, p2, control]) + data


def raw_frame(ins: int, p1: int, p2: int, data: bytes = b"", *, cla: int = 0xE0) -> bytes:
    """One on-the-wire APDU: ``[cla][ins][p1][p2][lc][cdata]`` (Lc omitted when empty)."""
    assert len(data) <= MAX_CDATA_LENGTH, f"{len(data)} bytes of command data is not sendable"
    if not data:
        return bytes([cla, ins, p1, p2])
    return bytes([cla, ins, p1, p2, len(data)]) + data


def dispatch_input(frames: "list[bytes]", *, approve: bool = True) -> bytes:
    """``[control][len][frame]...`` - standalone_apdu_dispatch_fuzzer.

    Each frame is length-delimited so one input can replay a whole multi-packet flow through
    the real parser and dispatcher.
    """
    out = bytes([CONTROL_APPROVE if approve else 0x00])
    for frame in frames:
        assert len(frame) <= 0xFF, "a frame longer than 255 bytes cannot be length-delimited"
        out += bytes([len(frame)]) + frame
    return out


def trusted_name_input(
    descriptor: bytes,
    path: bytes,
    *,
    verify_p1: int = 0,
    pki_status: int = 0,
    approve: bool = True,
    skip_set: bool = False,
    seed_challenge: bool = True,
) -> bytes:
    """``[control][pki_status][set_len][descriptor][path]`` - set_trusted_name fuzzer.

    control bit 0 approve, bit 1 skip the SET step, bit 2 seed a stored challenge,
    bits 3..7 the P1 handed to VERIFY_ADDRESS.
    """
    assert len(descriptor) <= 0xFF, "descriptor length is carried in one byte"
    assert verify_p1 <= 0x1F, "verify P1 is carried in the top five control bits"
    control = (
        (0x01 if approve else 0x00)
        | (0x02 if skip_set else 0x00)
        | (0x04 if seed_challenge else 0x00)
        | (verify_p1 << 3)
    )
    return bytes([control, pki_status, len(descriptor)]) + descriptor + path


def cbor_input(data: bytes, *, read_content: bool, declared: int | None = None) -> bytes:
    """``[control][declared_cbor_length][data...]`` - standalone_cbor_data_blob_fuzzer."""
    if declared is None:
        declared = min(len(data), 0xFF)
    return bytes([0x01 if read_content else 0x00, declared]) + data


# --------------------------------------------------------------------------------------
# Per-target seeds
# --------------------------------------------------------------------------------------
def seeds_sign_transfer() -> dict[str, bytes]:
    body = header(KIND_TRANSFER) + ADDRESS + AMOUNT_MAX
    return {
        "legacy_path": apdu(0x00, 0x00, PATH_LEGACY + body),
        "legacy_path_fee_display": apdu(0x00, 0x01, PATH_LEGACY + body + FEE_DISPLAY),
        "new_path_mainnet": apdu(0x00, 0x00, PATH_NEW + body),
        "new_path_testnet": apdu(0x00, 0x00, PATH_NEW_TESTNET + body),
        # Boundaries: nothing at all, path only, and one byte short of the amount.
        "empty_lc": apdu(0x00, 0x00),
        "path_only": apdu(0x00, 0x00, PATH_LEGACY),
        "amount_one_byte_short": apdu(0x00, 0x00, PATH_LEGACY + body[:-1]),
        # Fee display declared by P2 but the trailing uint64 is absent.
        "fee_flag_without_fee": apdu(0x00, 0x01, PATH_LEGACY + body),
    }


def seeds_transfer_with_memo() -> dict[str, bytes]:
    initial = PATH_LEGACY + header(KIND_TRANSFER_WITH_MEMO) + ADDRESS
    return {
        "p1_initial": apdu_ic(0x01, 0x00, True, initial + len(CBOR_TEXT_TEST).to_bytes(2, "big")),
        "p1_initial_fee_display": apdu_ic(
            0x01, 0x01, True, initial + len(CBOR_TEXT_TEST).to_bytes(2, "big") + FEE_DISPLAY
        ),
        "p1_initial_new_path": apdu_ic(
            0x01,
            0x00,
            True,
            PATH_NEW
            + header(KIND_TRANSFER_WITH_MEMO)
            + ADDRESS
            + len(CBOR_TEXT_TEST).to_bytes(2, "big"),
        ),
        "p1_initial_memo_len_max": apdu_ic(
            0x01, 0x00, True, initial + (0xFFFF).to_bytes(2, "big")
        ),
        "p1_initial_memo_len_zero": apdu_ic(0x01, 0x00, True, initial + b"\x00\x00"),
        "p2_memo_text": apdu_ic(0x02, 0x00, False, CBOR_TEXT_TEST),
        "p2_memo_1byte_len": apdu_ic(0x02, 0x00, False, CBOR_TEXT_1BYTE_LEN),
        "p2_memo_uint": apdu_ic(0x02, 0x00, False, CBOR_UINT_INLINE),
        "p2_memo_empty": apdu_ic(0x02, 0x00, False),
        "p3_amount": apdu_ic(0x03, 0x00, False, AMOUNT_MAX),
        "p3_amount_one_byte_short": apdu_ic(0x03, 0x00, False, AMOUNT_MAX[:-1]),
    }


def seeds_transfer_with_schedule() -> dict[str, bytes]:
    initial = PATH_LEGACY + header(KIND_TRANSFER_WITH_SCHEDULE) + ADDRESS
    return {
        "p1_initial": apdu_ic(0x00, 0x00, True, initial + bytes([5])),
        "p1_initial_fee_display": apdu_ic(0x00, 0x01, True, initial + bytes([5]) + FEE_DISPLAY),
        "p1_initial_new_path": apdu_ic(
            0x00,
            0x00,
            True,
            PATH_NEW + header(KIND_TRANSFER_WITH_SCHEDULE) + ADDRESS + bytes([1]),
        ),
        "p1_initial_zero_pairs": apdu_ic(0x00, 0x00, True, initial + bytes([0])),
        "p1_initial_max_pairs": apdu_ic(0x00, 0x00, True, initial + bytes([0xFF])),
        "p2_one_pair": apdu_ic(0x01, 0x00, False, SCHEDULE_PAIR),
        "p2_five_pairs": apdu_ic(0x01, 0x00, False, SCHEDULE_PAIR * 5),
        "p2_full_apdu_pairs": apdu_ic(
            0x01, 0x00, False, (SCHEDULE_PAIR * 15)[:MAX_SCHEDULE_PAIRS_PER_APDU]
        ),
        # Not a whole number of 16-byte pairs.
        "p2_misaligned_pair": apdu_ic(0x01, 0x00, False, SCHEDULE_PAIR[:-1]),
        "p2_empty": apdu_ic(0x01, 0x00, False),
    }


def seeds_transfer_with_schedule_and_memo() -> dict[str, bytes]:
    initial = PATH_LEGACY + header(KIND_TRANSFER_WITH_SCHEDULE_AND_MEMO) + ADDRESS
    return {
        "p2_initial": apdu_ic(
            0x02, 0x00, True, initial + bytes([5]) + len(CBOR_TEXT_TEST).to_bytes(2, "big")
        ),
        "p2_initial_fee_display": apdu_ic(
            0x02,
            0x01,
            True,
            initial + bytes([5]) + len(CBOR_TEXT_TEST).to_bytes(2, "big") + FEE_DISPLAY,
        ),
        "p2_initial_new_path": apdu_ic(
            0x02,
            0x00,
            True,
            PATH_NEW
            + header(KIND_TRANSFER_WITH_SCHEDULE_AND_MEMO)
            + ADDRESS
            + bytes([1])
            + b"\x00\x05",
        ),
        "p2_initial_memo_len_max": apdu_ic(
            0x02, 0x00, True, initial + bytes([1]) + (0xFFFF).to_bytes(2, "big")
        ),
        "p3_memo_text": apdu_ic(0x03, 0x00, False, CBOR_TEXT_TEST),
        "p3_memo_1byte_len": apdu_ic(0x03, 0x00, False, CBOR_TEXT_1BYTE_LEN),
        "p3_memo_empty": apdu_ic(0x03, 0x00, False),
        "p1_one_pair": apdu_ic(0x01, 0x00, False, SCHEDULE_PAIR),
        "p1_five_pairs": apdu_ic(0x01, 0x00, False, SCHEDULE_PAIR * 5),
        "p1_full_apdu_pairs": apdu_ic(
            0x01, 0x00, False, (SCHEDULE_PAIR * 15)[:MAX_SCHEDULE_PAIRS_PER_APDU]
        ),
    }


def seeds_configure_delegation() -> dict[str, bytes]:
    prefix = header(KIND_CONFIGURE_DELEGATION)
    # bitmap(2) then, per set bit: capital(8), restake(1), delegation target(1[+8]).
    payloads = {
        "capital": h("00010000ffffffffffff"),
        "stop_delegation": h("00010000000000000000"),
        "restake": h("000201"),
        "target_baker": h("00040100000000abcdefff"),
        "capital_and_target": h("00050000ffffffffffff0100000000abcdefff"),
        "capital_restake_target": h("00070000ffffffffffff010100000000abcdefff"),
        "target_passive": h("000400"),
    }
    out = {
        f"legacy_path_{name}": apdu_ic(0x00, 0x00, True, PATH_LEGACY + prefix + body)
        for name, body in payloads.items()
    }
    out["new_path_capital"] = apdu_ic(
        0x00, 0x00, True, PATH_NEW + prefix + payloads["capital"]
    )
    out["new_path_testnet_capital"] = apdu_ic(
        0x00, 0x00, True, PATH_NEW_TESTNET + prefix + payloads["capital"]
    )
    # Boundaries: header without a bitmap, and a bitmap whose fields are missing.
    out["header_only"] = apdu_ic(0x00, 0x00, True, PATH_LEGACY + prefix)
    out["bitmap_without_fields"] = apdu_ic(0x00, 0x00, True, PATH_LEGACY + prefix + h("0007"))
    out["continuation_packet"] = apdu_ic(0x00, 0x00, False, PATH_LEGACY + prefix + payloads["capital"])
    return out


def seeds_configure_baker() -> dict[str, bytes]:
    # P1 0x00 carries the packed path, the header and the 2-byte field bitmap.
    p0 = PATH_LEGACY + header(KIND_CONFIGURE_BAKER)
    keys = (
        BAKER_ELECTION_KEY
        + BAKER_ELECTION_PROOF
        + BAKER_SIGN_KEY
        + BAKER_SIGN_PROOF
    )
    out = {}
    for name, bitmap in {
        "bitmap_capital": "0001",
        "bitmap_restake": "0002",
        "bitmap_open_status": "0004",
        "bitmap_keys": "0008",
        "bitmap_url": "0010",
        "bitmap_commissions": "00e0",
        "bitmap_suspended": "0100",
        "bitmap_capital_restake_open_keys": "000f",
        "bitmap_all": "01ff",
        "bitmap_none": "0000",
    }.items():
        out[f"p1_00_{name}"] = apdu_ic(0x00, 0x00, True, p0 + h(bitmap))
    out["p1_00_new_path"] = apdu_ic(0x00, 0x00, True, PATH_NEW + header(KIND_CONFIGURE_BAKER) + h("000f"))
    out["p1_00_header_without_bitmap"] = apdu_ic(0x00, 0x00, True, p0)
    # P1 0x01: capital(8) restake(1) openStatus(1) then the election/signature keys+proofs.
    out["p1_01_capital_restake_open_keys"] = apdu_ic(0x01, 0x00, False, h("0000ffffffffffff0102") + keys)
    out["p1_01_capital_only"] = apdu_ic(0x01, 0x00, False, h("0000000000000000"))
    out["p1_01_capital_restake_open"] = apdu_ic(0x01, 0x00, False, h("0000ffffffffffff0102"))
    out["p1_01_open_status_out_of_range"] = apdu_ic(0x01, 0x00, False, h("0000ffffffffffff01ff"))
    out["p1_01_empty"] = apdu_ic(0x01, 0x00, False)
    # P1 0x02: aggregation key (96) + its proof (64).
    out["p1_02_aggregation_key"] = apdu_ic(
        0x02, 0x00, False, BAKER_AGGREGATION_KEY + BAKER_AGGREGATION_PROOF
    )
    out["p1_02_aggregation_key_truncated"] = apdu_ic(0x02, 0x00, False, BAKER_AGGREGATION_KEY)
    # P1 0x03: URL length as a uint16.  P1 0x04: URL bytes.
    out["p1_03_url_length"] = apdu_ic(0x03, 0x00, False, (32).to_bytes(2, "big"))
    out["p1_03_url_length_zero"] = apdu_ic(0x03, 0x00, False, b"\x00\x00")
    out["p1_03_url_length_max"] = apdu_ic(0x03, 0x00, False, b"\xff\xff")
    out["p1_04_url_chunk"] = apdu_ic(0x04, 0x00, False, b"https://baker.example/metadata.json")
    out["p1_04_url_chunk_full"] = apdu_ic(0x04, 0x00, False, b"a" * MAX_CDATA_LENGTH)
    out["p1_04_url_chunk_empty"] = apdu_ic(0x04, 0x00, False)
    # P1 0x05: 4-byte commission rates, one per selected bit.  P1 0x06: suspended flag.
    out["p1_05_one_commission"] = apdu_ic(0x05, 0x00, False, h("0000b0c1"))
    out["p1_05_three_commissions"] = apdu_ic(0x05, 0x00, False, h("0000b0c10000c00100000b11"))
    out["p1_05_empty"] = apdu_ic(0x05, 0x00, False)
    out["p1_06_suspended"] = apdu_ic(0x06, 0x00, False, h("01"))
    out["p1_06_not_suspended"] = apdu_ic(0x06, 0x00, False, h("00"))
    return out


def seeds_credential_deployment() -> dict[str, bytes]:
    return {
        "p1_00_initial_path": apdu_ic(0x00, 0x00, True, PATH_LEGACY),
        "p1_00_initial_new_path": apdu_ic(0x00, 0x00, True, PATH_NEW),
        "p1_00_initial_empty": apdu_ic(0x00, 0x00, True),
        "p1_0a_key_count": apdu_ic(0x0A, 0x00, False, bytes([3])),
        "p1_0a_key_count_zero": apdu_ic(0x0A, 0x00, False, bytes([0])),
        "p1_0a_key_count_max": apdu_ic(0x0A, 0x00, False, bytes([0xFF])),
        "p1_01_key": apdu_ic(0x01, 0x00, False, bytes([1]) + CRED_KEY),
        "p1_01_last_key": apdu_ic(0x01, 0x00, False, bytes([0]) + CRED_KEY),
        "p1_01_key_truncated": apdu_ic(0x01, 0x00, False, bytes([1]) + CRED_KEY[:-1]),
        "p1_02_signature_threshold": apdu_ic(0x02, 0x00, False, CRED_SIGNATURE_THRESHOLD),
        "p1_03_ar_identity": apdu_ic(0x03, 0x00, False, CRED_AR_IDENTITY),
        "p1_04_credential_dates": apdu_ic(0x04, 0x00, False, CRED_DATES),
        "p1_05_attribute_tag": apdu_ic(0x05, 0x00, False, CRED_ATTRIBUTE_TAG),
        "p1_05_attribute_tag_unknown": apdu_ic(0x05, 0x00, False, h("ff04")),
        "p1_05_attribute_value_len_zero": apdu_ic(0x05, 0x00, False, h("0100")),
        "p1_05_attribute_value_len_max": apdu_ic(0x05, 0x00, False, h("01ff")),
        "p1_06_attribute_value": apdu_ic(0x06, 0x00, False, CRED_ATTRIBUTE_VALUE),
        "p1_06_attribute_value_full": apdu_ic(0x06, 0x00, False, b"X" * MAX_CDATA_LENGTH),
        "p1_07_proof_length": apdu_ic(0x07, 0x00, False, CRED_PROOF_LENGTH),
        "p1_07_proof_length_zero": apdu_ic(0x07, 0x00, False, h("00000000")),
        "p1_07_proof_length_max": apdu_ic(0x07, 0x00, False, h("ffffffff")),
        "p1_08_proof_chunk": apdu_ic(0x08, 0x00, False, CRED_PROOF_CHUNK),
        "p1_08_proof_chunk_full": apdu_ic(0x08, 0x00, False, (CRED_PROOF_CHUNK * 2)[:MAX_CDATA_LENGTH]),
        "p1_09_new_or_existing": apdu_ic(0x09, 0x00, False, CRED_NEW_OR_EXISTING),
        "p1_09_existing_credential_id": apdu_ic(0x09, 0x00, False, bytes([1]) + CRED_ID),
    }


def seeds_update_credential() -> dict[str, bytes]:
    initial = PATH_LEGACY + header(KIND_UPDATE_CREDENTIALS) + bytes([1])
    return {
        "p1_00_p2_00_initial": apdu_ic(0x00, 0x00, True, initial),
        "p1_00_p2_00_initial_new_path": apdu_ic(
            0x00, 0x00, True, PATH_NEW + header(KIND_UPDATE_CREDENTIALS) + bytes([1])
        ),
        "p1_00_p2_00_zero_credentials": apdu_ic(
            0x00, 0x00, True, PATH_LEGACY + header(KIND_UPDATE_CREDENTIALS) + bytes([0])
        ),
        "p1_00_p2_01_credential_index": apdu_ic(0x00, 0x01, False, bytes([0])),
        "p1_0a_p2_02_key_count": apdu_ic(0x0A, 0x02, False, bytes([1])),
        "p1_01_p2_02_key": apdu_ic(0x01, 0x02, False, CRED_KEY_UPDATE),
        "p1_02_p2_02_signature_threshold": apdu_ic(0x02, 0x02, False, CRED_SIGNATURE_THRESHOLD),
        "p1_03_p2_02_ar_identity": apdu_ic(0x03, 0x02, False, CRED_AR_IDENTITY),
        "p1_04_p2_02_credential_dates": apdu_ic(0x04, 0x02, False, CRED_DATES),
        "p1_05_p2_02_attribute_tag": apdu_ic(0x05, 0x02, False, CRED_ATTRIBUTE_TAG),
        "p1_06_p2_02_attribute_value": apdu_ic(0x06, 0x02, False, CRED_ATTRIBUTE_VALUE),
        "p1_07_p2_02_proof_length": apdu_ic(0x07, 0x02, False, CRED_PROOF_LENGTH),
        "p1_08_p2_02_proof_chunk": apdu_ic(0x08, 0x02, False, CRED_PROOF_CHUNK),
        "p1_00_p2_03_id_count": apdu_ic(0x00, 0x03, False, bytes([1])),
        "p1_00_p2_03_id_count_zero": apdu_ic(0x00, 0x03, False, bytes([0])),
        "p1_00_p2_03_id_count_max": apdu_ic(0x00, 0x03, False, bytes([0xFF])),
        "p1_00_p2_04_credential_id": apdu_ic(0x00, 0x04, False, CRED_ID),
        "p1_00_p2_04_credential_id_truncated": apdu_ic(0x00, 0x04, False, CRED_ID[:-1]),
        "p1_00_p2_05_threshold": apdu_ic(0x00, 0x05, False, bytes([1])),
        "p1_00_p2_05_threshold_empty": apdu_ic(0x00, 0x05, False),
    }


def seeds_public_information_for_ip() -> dict[str, bytes]:
    return {
        "p1_00_initial": apdu_ic(0x00, 0x00, True, PIIP_CHUNK_1),
        "p1_00_initial_truncated": apdu_ic(0x00, 0x00, True, PIIP_CHUNK_1[:33]),
        "p1_00_initial_empty": apdu_ic(0x00, 0x00, True),
        "p1_01_ar_chunk_1": apdu_ic(0x01, 0x00, False, PIIP_CHUNK_2),
        "p1_01_ar_chunk_2": apdu_ic(0x01, 0x00, False, PIIP_CHUNK_3),
        "p1_01_ar_chunk_3": apdu_ic(0x01, 0x00, False, PIIP_CHUNK_4),
        "p1_01_ar_chunks_concatenated": apdu_ic(
            0x01, 0x00, False, PIIP_CHUNK_2 + PIIP_CHUNK_3 + PIIP_CHUNK_4
        ),
        "p1_01_ar_chunk_truncated": apdu_ic(0x01, 0x00, False, PIIP_CHUNK_2[:-1]),
        "p1_02_threshold": apdu_ic(0x02, 0x00, False, PIIP_THRESHOLD),
        "p1_02_threshold_zero": apdu_ic(0x02, 0x00, False, h("00")),
        "p1_02_threshold_empty": apdu_ic(0x02, 0x00, False),
    }


def seeds_transfer_to_public() -> dict[str, bytes]:
    return {
        "p1_00_initial": apdu_ic(0x00, 0x00, True, PATH_LEGACY + header(KIND_TRANSFER_TO_PUBLIC)),
        "p1_00_initial_new_path": apdu_ic(
            0x00, 0x00, True, PATH_NEW + header(KIND_TRANSFER_TO_PUBLIC)
        ),
        "p1_00_initial_header_truncated": apdu_ic(
            0x00, 0x00, True, PATH_LEGACY + header(KIND_TRANSFER_TO_PUBLIC)[:-1]
        ),
        "p1_01_remaining_amount": apdu_ic(0x01, 0x00, False, TTP_REMAINING_AND_AMOUNT),
        "p1_01_remaining_amount_truncated": apdu_ic(
            0x01, 0x00, False, TTP_REMAINING_AND_AMOUNT[:-1]
        ),
        "p1_01_empty": apdu_ic(0x01, 0x00, False),
        "p1_02_proof_chunk": apdu_ic(0x02, 0x00, False, TTP_PROOF_CHUNK),
        "p1_02_proof_chunk_full": apdu_ic(
            0x02, 0x00, False, (TTP_PROOF_CHUNK * 2)[:MAX_CDATA_LENGTH]
        ),
        "p1_02_proof_chunk_empty": apdu_ic(0x02, 0x00, False),
    }


def seeds_register_data() -> dict[str, bytes]:
    initial = PATH_LEGACY + header(KIND_REGISTER_DATA)
    return {
        "p1_00_initial": apdu_ic(0x00, 0x00, True, initial + len(CBOR_TEXT_TEST).to_bytes(2, "big")),
        "p1_00_initial_new_path": apdu_ic(
            0x00,
            0x00,
            True,
            PATH_NEW + header(KIND_REGISTER_DATA) + len(CBOR_TEXT_TEST).to_bytes(2, "big"),
        ),
        "p1_00_initial_len_zero": apdu_ic(0x00, 0x00, True, initial + b"\x00\x00"),
        "p1_00_initial_len_max": apdu_ic(0x00, 0x00, True, initial + b"\xff\xff"),
        "p1_00_initial_without_len": apdu_ic(0x00, 0x00, True, initial),
        "p1_01_payload_text": apdu_ic(0x01, 0x00, False, CBOR_TEXT_TEST),
        "p1_01_payload_1byte_len": apdu_ic(0x01, 0x00, False, CBOR_TEXT_1BYTE_LEN),
        "p1_01_payload_uint": apdu_ic(0x01, 0x00, False, CBOR_UINT_1BYTE),
        "p1_01_payload_nint": apdu_ic(0x01, 0x00, False, CBOR_NINT_INLINE),
        "p1_01_payload_noncanonical": apdu_ic(0x01, 0x00, False, CBOR_NONCANONICAL),
        "p1_01_payload_indefinite": apdu_ic(0x01, 0x00, False, CBOR_INDEFINITE),
        "p1_01_payload_full": apdu_ic(0x01, 0x00, False, bytes([0x78, 0xFD]) + b"D" * 0xFD),
        "p1_01_payload_empty": apdu_ic(0x01, 0x00, False),
    }


def seeds_deploy_module() -> dict[str, bytes]:
    initial = PATH_LEGACY + header(KIND_DEPLOY_MODULE)
    return {
        "p1_00_initial": apdu_ic(
            0x00, 0x00, True, initial + (1).to_bytes(4, "big") + (6).to_bytes(4, "big")
        ),
        "p1_00_initial_new_path": apdu_ic(
            0x00,
            0x00,
            True,
            PATH_NEW + header(KIND_DEPLOY_MODULE) + (1).to_bytes(4, "big") + (6).to_bytes(4, "big"),
        ),
        "p1_00_initial_source_len_zero": apdu_ic(
            0x00, 0x00, True, initial + (0).to_bytes(4, "big") + (0).to_bytes(4, "big")
        ),
        "p1_00_initial_source_len_max": apdu_ic(
            0x00, 0x00, True, initial + (0xFFFFFFFF).to_bytes(4, "big") + b"\xff\xff\xff\xff"
        ),
        "p1_00_initial_without_lengths": apdu_ic(0x00, 0x00, True, initial),
        "p1_01_source": apdu_ic(0x01, 0x00, False, b"source"),
        "p1_01_source_full": apdu_ic(0x01, 0x00, False, b"S" * MAX_CDATA_LENGTH),
        "p1_01_source_empty": apdu_ic(0x01, 0x00, False),
    }


def seeds_init_contract() -> dict[str, bytes]:
    initial = PATH_LEGACY + header(KIND_INIT_CONTRACT) + AMOUNT_MAX + MODULE_REF
    return {
        "p1_00_initial": apdu_ic(0x00, 0x00, True, initial),
        "p1_00_initial_new_path": apdu_ic(
            0x00,
            0x00,
            True,
            PATH_NEW + header(KIND_INIT_CONTRACT) + AMOUNT_MAX + MODULE_REF,
        ),
        "p1_00_initial_zero_amount": apdu_ic(
            0x00, 0x00, True, PATH_LEGACY + header(KIND_INIT_CONTRACT) + bytes(8) + MODULE_REF
        ),
        "p1_00_initial_module_ref_truncated": apdu_ic(0x00, 0x00, True, initial[:-1]),
        "p1_01_name": apdu_ic(
            0x01, 0x00, False, len(CONTRACT_NAME).to_bytes(2, "big") + CONTRACT_NAME
        ),
        "p1_01_name_len_zero": apdu_ic(0x01, 0x00, False, b"\x00\x00"),
        "p1_01_name_len_exceeds_chunk": apdu_ic(0x01, 0x00, False, b"\xff\xff" + CONTRACT_NAME),
        "p1_01_name_full_chunk": apdu_ic(
            0x01, 0x00, False, (253).to_bytes(2, "big") + b"N" * 253
        ),
        "p1_01_name_continuation": apdu_ic(0x01, 0x00, False, b"N" * 32),
        "p1_02_params": apdu_ic(
            0x02, 0x00, False, len(CONTRACT_PARAMS).to_bytes(2, "big") + CONTRACT_PARAMS
        ),
        "p1_02_params_len_zero": apdu_ic(0x02, 0x00, False, b"\x00\x00"),
        "p1_02_params_full_chunk": apdu_ic(
            0x02, 0x00, False, (253).to_bytes(2, "big") + bytes(range(253))
        ),
        "p1_02_params_continuation": apdu_ic(0x02, 0x00, False, bytes(range(64))),
        "p1_02_params_empty": apdu_ic(0x02, 0x00, False),
    }


def seeds_update_contract() -> dict[str, bytes]:
    initial = (
        PATH_LEGACY
        + header(KIND_UPDATE_CONTRACT)
        + AMOUNT_MAX
        + CONTRACT_INDEX
        + CONTRACT_SUBINDEX
    )
    return {
        "p1_00_initial": apdu_ic(0x00, 0x00, True, initial),
        "p1_00_initial_new_path": apdu_ic(
            0x00,
            0x00,
            True,
            PATH_NEW
            + header(KIND_UPDATE_CONTRACT)
            + AMOUNT_MAX
            + CONTRACT_INDEX
            + CONTRACT_SUBINDEX,
        ),
        "p1_00_initial_zero_amount": apdu_ic(
            0x00,
            0x00,
            True,
            PATH_LEGACY
            + header(KIND_UPDATE_CONTRACT)
            + bytes(8)
            + CONTRACT_INDEX
            + CONTRACT_SUBINDEX,
        ),
        "p1_00_initial_subindex_truncated": apdu_ic(0x00, 0x00, True, initial[:-1]),
        "p1_01_name": apdu_ic(
            0x01, 0x00, False, len(CONTRACT_NAME).to_bytes(2, "big") + CONTRACT_NAME
        ),
        "p1_01_name_len_zero": apdu_ic(0x01, 0x00, False, b"\x00\x00"),
        "p1_01_name_len_exceeds_chunk": apdu_ic(0x01, 0x00, False, b"\xff\xff" + CONTRACT_NAME),
        "p1_01_name_full_chunk": apdu_ic(
            0x01, 0x00, False, (253).to_bytes(2, "big") + b"R" * 253
        ),
        "p1_01_name_continuation": apdu_ic(0x01, 0x00, False, b"R" * 32),
        "p1_02_params": apdu_ic(
            0x02, 0x00, False, len(CONTRACT_PARAMS).to_bytes(2, "big") + CONTRACT_PARAMS
        ),
        "p1_02_params_len_zero": apdu_ic(0x02, 0x00, False, b"\x00\x00"),
        "p1_02_params_full_chunk": apdu_ic(
            0x02, 0x00, False, (253).to_bytes(2, "big") + bytes(range(253))
        ),
        "p1_02_params_continuation": apdu_ic(0x02, 0x00, False, bytes(range(64))),
        "p1_02_params_empty": apdu_ic(0x02, 0x00, False),
    }


def seeds_get_public_key() -> dict[str, bytes]:
    return {
        "confirm_no_sign_legacy": apdu(0x00, 0x00, PATH_LEGACY),
        "confirm_sign_legacy": apdu(0x00, 0x01, PATH_LEGACY),
        "no_confirm_no_sign_legacy": apdu(0x01, 0x00, PATH_LEGACY),
        "no_confirm_sign_legacy": apdu(0x01, 0x01, PATH_LEGACY),
        "confirm_sign_new_path": apdu(0x00, 0x01, PATH_NEW),
        "confirm_sign_new_path_testnet": apdu(0x00, 0x01, PATH_NEW_TESTNET),
        "confirm_sign_hardened_path": apdu(0x00, 0x01, PATH_NEW_HARDENED),
        "legacy_governance_path": apdu(0x00, 0x01, path(1105, 0, 1, 0, 0)),
        # Boundaries: no path, a zero-node path, a node count larger than the bytes supplied,
        # and the largest node count that still fits one APDU.
        "empty_lc": apdu(0x00, 0x00),
        "zero_nodes": apdu(0x00, 0x00, b"\x00"),
        "node_count_exceeds_data": apdu(0x00, 0x00, b"\x08" + b"\x00" * 4),
        "node_count_max": apdu(0x00, 0x00, b"\xff" + b"\x00" * 4),
        "path_63_nodes": apdu(0x00, 0x00, bytes([63]) + bytes(63 * 4)),
    }


def seeds_verify_address() -> dict[str, bytes]:
    identity = (0).to_bytes(4, "big")
    counter = (0).to_bytes(4, "big")
    idp = (0).to_bytes(4, "big")
    return {
        "p1_00_legacy": apdu(0x00, 0x00, identity + counter),
        "p1_01_new_mainnet": apdu(0x01, 0x00, idp + identity + counter),
        "p1_01_new_testnet": apdu(0x01, 0x01, idp + identity + counter),
        "p1_01_new_max_indices": apdu(0x01, 0x00, b"\xff\xff\xff\xff" * 3),
        "p1_02_full_path": apdu(0x02, 0x00, PATH_NEW_HARDENED),
        "p1_02_full_path_testnet": apdu(0x02, 0x01, PATH_NEW_HARDENED),
        "p1_02_full_path_legacy_shape": apdu(0x02, 0x00, PATH_LEGACY),
        # Boundaries: the empty full path a functional test asserts on, a node count that
        # overruns the data, the largest node count, and a truncated compact payload.
        "p1_02_empty_full_path": apdu(0x02, 0x00, b"\x00"),
        "p1_02_node_count_exceeds_data": apdu(0x02, 0x00, b"\x05" + b"\x00" * 4),
        "p1_02_node_count_max": apdu(0x02, 0x00, b"\xff" + b"\x00" * 4),
        "p1_00_legacy_truncated": apdu(0x00, 0x00, identity + counter[:-1]),
        "p1_01_new_truncated": apdu(0x01, 0x00, idp + identity),
        "p1_00_empty_lc": apdu(0x00, 0x00),
        "p1_unknown": apdu(0x03, 0x00, identity + counter),
    }


def seeds_export_pk_legacy() -> dict[str, bytes]:
    identity = (0).to_bytes(4, "big")
    return {
        "p1_00_standard_bls": apdu(0x00, 0x02, identity),
        "p1_01_recovery_bls": apdu(0x01, 0x02, identity),
        "p1_02_prfkey_idcredsec_bls": apdu(0x02, 0x02, identity),
        "p1_00_standard_p2_none": apdu(0x00, 0x00, identity),
        "p1_01_recovery_p2_none": apdu(0x01, 0x00, identity),
        "p1_02_prfkey_idcredsec_p2_none": apdu(0x02, 0x00, identity),
        "identity_index_max": apdu(0x00, 0x02, b"\xff\xff\xff\xff"),
        "identity_index_truncated": apdu(0x00, 0x02, identity[:-1]),
        "empty_lc": apdu(0x00, 0x02),
        "p1_unknown": apdu(0x05, 0x02, identity),
    }


def seeds_export_pk_new() -> dict[str, bytes]:
    idp = (0).to_bytes(4, "big")
    identity = (1).to_bytes(4, "big")
    account = (2).to_bytes(4, "big")
    out = {}
    purposes = {
        "identity_credential_creation": 0x00,
        "account_creation": 0x01,
        "id_recovery": 0x02,
        "account_credential_discovery": 0x03,
        "creation_of_zk_proof": 0x04,
    }
    for name, p1 in purposes.items():
        # Purposes 0x01 and 0x04 additionally take an account index.
        body = idp + identity + (account if p1 in (0x01, 0x04) else b"")
        out[f"p1_{p1:02x}_{name}_mainnet"] = apdu(p1, 0x00, body)
        out[f"p1_{p1:02x}_{name}_testnet"] = apdu(p1, 0x01, body)
    out["account_creation_without_account_index"] = apdu(0x01, 0x00, idp + identity)
    out["identity_creation_with_extra_account_index"] = apdu(
        0x00, 0x00, idp + identity + account
    )
    out["indices_max"] = apdu(0x01, 0x00, b"\xff\xff\xff\xff" * 3)
    out["truncated_identity_index"] = apdu(0x00, 0x00, idp + identity[:-1])
    out["empty_lc"] = apdu(0x00, 0x00)
    out["p1_unknown"] = apdu(0x07, 0x00, idp + identity)
    out["p2_unknown"] = apdu(0x00, 0x07, idp + identity)
    return out


def seeds_cbor_data_blob() -> dict[str, bytes]:
    out = {
        "text_test": cbor_input(CBOR_TEXT_TEST, read_content=True),
        "text_test_header_only": cbor_input(CBOR_TEXT_TEST, read_content=False),
        "text_1byte_length": cbor_input(CBOR_TEXT_1BYTE_LEN, read_content=True),
        "uint_inline": cbor_input(CBOR_UINT_INLINE, read_content=True),
        "uint_1byte_argument": cbor_input(CBOR_UINT_1BYTE, read_content=True),
        "uint_8byte_argument": cbor_input(CBOR_UINT_8BYTE, read_content=True),
        "negative_int_inline": cbor_input(CBOR_NINT_INLINE, read_content=True),
        "noncanonical_uint": cbor_input(CBOR_NONCANONICAL, read_content=True),
        "indefinite_length_text": cbor_input(CBOR_INDEFINITE, read_content=True),
        # Declared-length vs physical-length disagreement (finding V-077).
        "declared_longer_than_physical": cbor_input(
            CBOR_TEXT_TEST, read_content=True, declared=0xFF
        ),
        "declared_shorter_than_physical": cbor_input(
            CBOR_TEXT_1BYTE_LEN, read_content=True, declared=2
        ),
        "declared_zero": cbor_input(CBOR_TEXT_TEST, read_content=True, declared=0),
        "declared_one": cbor_input(CBOR_TEXT_TEST, read_content=True, declared=1),
        # Header widths whose argument bytes are absent.
        "one_byte_length_missing_argument": cbor_input(h("78"), read_content=True),
        "two_byte_length_missing_argument": cbor_input(h("7901"), read_content=True),
        "four_byte_length_missing_argument": cbor_input(h("7a000001"), read_content=True),
        "eight_byte_length_missing_argument": cbor_input(h("7b00000000000000"), read_content=True),
        # Major types the parser refuses (byte string, array, map, tag, simple/float).
        "byte_string": cbor_input(h("4474657374"), read_content=True),
        "array": cbor_input(h("82010f"), read_content=True),
        "map": cbor_input(h("a1616101"), read_content=True),
        "tagged": cbor_input(h("c11a514b67b0"), read_content=True),
        "simple_value": cbor_input(h("f5"), read_content=True),
        "empty_payload": cbor_input(b"", read_content=True),
        # Longest text a memo can carry: 2-byte header plus 255 payload bytes clamps to the
        # 255-byte physical window the harness passes on.
        "text_max_payload": cbor_input(
            bytes([0x78, 0xFF]) + b"M" * 0xFF, read_content=True, declared=0xFF
        ),
    }
    # Two-byte length form, canonical for a value above 255.
    out["text_two_byte_length"] = cbor_input(
        bytes([0x79, 0x01, 0x00]) + b"T" * 0x80, read_content=True, declared=0xFF
    )
    return out


# The signed trusted-name descriptor a live Ledger trusted-name API response carries
# (tests/standalone/fixtures/trusted_name/ledger_api_descriptor.json). Seeding the real TLV
# means the parser starts from a payload whose tag schema, lengths and hash coverage are all
# already correct, so mutation explores the rules rather than rediscovering the format.
TRUSTED_NAME_DESCRIPTOR = h(
    "0101030201037001077101062032336738714b4e54764b45356d325a74376a6d"
    "5335466938506172576961537a7a6e35785068795433315447546f6d51507556"
    "23010122202032336738714b4e54764b45356d325a74376a6d533546693850617"
    "2576961"
)[:0xFF]


def seeds_set_trusted_name() -> dict[str, bytes]:
    """standalone_set_trusted_name_fuzzer: a SET descriptor followed by a VERIFY path."""
    full_path = PATH_NEW_HARDENED
    return {
        # The real descriptor, accepted by PKI, then each verify-address path format.
        "descriptor_accepted_full_path": trusted_name_input(
            TRUSTED_NAME_DESCRIPTOR, full_path, verify_p1=0x02
        ),
        "descriptor_accepted_legacy_path": trusted_name_input(
            TRUSTED_NAME_DESCRIPTOR, bytes(8), verify_p1=0x00
        ),
        "descriptor_accepted_new_path": trusted_name_input(
            TRUSTED_NAME_DESCRIPTOR, bytes(12), verify_p1=0x01
        ),
        # Each PKI verdict: a rejected signature must leave no binding behind.
        "pki_missing_certificate": trusted_name_input(
            TRUSTED_NAME_DESCRIPTOR, full_path, verify_p1=0x02, pki_status=1
        ),
        "pki_wrong_usage": trusted_name_input(
            TRUSTED_NAME_DESCRIPTOR, full_path, verify_p1=0x02, pki_status=2
        ),
        "pki_wrong_curve": trusted_name_input(
            TRUSTED_NAME_DESCRIPTOR, full_path, verify_p1=0x02, pki_status=3
        ),
        "pki_wrong_signature": trusted_name_input(
            TRUSTED_NAME_DESCRIPTOR, full_path, verify_p1=0x02, pki_status=4
        ),
        # No stored challenge: verify_challenge() must refuse the descriptor.
        "challenge_not_seeded": trusted_name_input(
            TRUSTED_NAME_DESCRIPTOR, full_path, verify_p1=0x02, seed_challenge=False
        ),
        # The legacy BLS-derived-address path, with nothing bound.
        "verify_without_set": trusted_name_input(b"", full_path, verify_p1=0x02, skip_set=True),
        # Rejected review screen, and a rejected descriptor followed by a verify.
        "descriptor_accepted_rejected_review": trusted_name_input(
            TRUSTED_NAME_DESCRIPTOR, full_path, verify_p1=0x02, approve=False
        ),
        # Boundaries: no descriptor, one truncated mid-tag, and a lone tag byte.
        "empty_descriptor": trusted_name_input(b"", full_path, verify_p1=0x02),
        "descriptor_truncated": trusted_name_input(
            TRUSTED_NAME_DESCRIPTOR[:-1], full_path, verify_p1=0x02
        ),
        "descriptor_one_tag": trusted_name_input(b"\x01", full_path, verify_p1=0x02),
        "descriptor_length_overruns": trusted_name_input(b"\x01\x7f", full_path, verify_p1=0x02),
    }


def seeds_apdu_dispatch() -> dict[str, bytes]:
    """standalone_apdu_dispatch_fuzzer: length-delimited raw frames through parser+dispatcher."""
    transfer = header(KIND_TRANSFER) + ADDRESS + AMOUNT_MAX
    memo_initial = (
        PATH_LEGACY
        + header(KIND_TRANSFER_WITH_MEMO)
        + ADDRESS
        + len(CBOR_TEXT_TEST).to_bytes(2, "big")
    )
    return {
        # A complete single-frame instruction, and the parameterless queries.
        "sign_transfer": dispatch_input([raw_frame(0x02, 0x00, 0x00, PATH_LEGACY + transfer)]),
        "get_public_key": dispatch_input([raw_frame(0x01, 0x00, 0x01, PATH_LEGACY)]),
        "verify_address": dispatch_input([raw_frame(0x00, 0x02, 0x00, PATH_NEW_HARDENED)]),
        "get_app_name": dispatch_input([raw_frame(0x21, 0x00, 0x00)]),
        "get_app_version": dispatch_input([raw_frame(0x40, 0x00, 0x00)]),
        "get_challenge": dispatch_input([raw_frame(0x23, 0x00, 0x00)]),
        # The whole three-packet memo-transfer flow, in one input.
        "memo_transfer_full_flow": dispatch_input(
            [
                raw_frame(0x32, 0x01, 0x00, memo_initial),
                raw_frame(0x32, 0x02, 0x00, CBOR_TEXT_TEST),
                raw_frame(0x32, 0x03, 0x00, AMOUNT_MAX),
            ]
        ),
        # The instruction-switching guard: a second frame changes INS mid-flow.
        "instruction_switch": dispatch_input(
            [
                raw_frame(0x32, 0x01, 0x00, memo_initial),
                raw_frame(0x02, 0x00, 0x00, PATH_LEGACY + transfer),
            ]
        ),
        # A continuation frame arriving with no flow open.
        "continuation_without_initial": dispatch_input(
            [raw_frame(0x32, 0x03, 0x00, AMOUNT_MAX)]
        ),
        # Frame-level boundaries no other target can express.
        "wrong_cla": dispatch_input([raw_frame(0x02, 0x00, 0x00, PATH_LEGACY, cla=0x00)]),
        "unknown_ins": dispatch_input([raw_frame(0xFE, 0x00, 0x00, b"\x00")]),
        "empty_frame": dispatch_input([b""]),
        "header_only_four_bytes": dispatch_input([bytes([0xE0, 0x02, 0x00, 0x00])]),
        "truncated_header": dispatch_input([bytes([0xE0, 0x02, 0x00])]),
        "lc_greater_than_payload": dispatch_input([bytes([0xE0, 0x02, 0x00, 0x00, 0x40, 0x01])]),
        "lc_less_than_payload": dispatch_input([bytes([0xE0, 0x02, 0x00, 0x00, 0x01, 0x01, 0x02])]),
        "lc_zero_with_cdata_instruction": dispatch_input(
            [bytes([0xE0, 0x02, 0x00, 0x00, 0x00])]
        ),
        "p1_p2_set_on_parameterless": dispatch_input([raw_frame(0x21, 0x07, 0x09)]),
        "three_frames_two_instructions": dispatch_input(
            [
                raw_frame(0x21, 0x00, 0x00),
                raw_frame(0x01, 0x00, 0x01, PATH_LEGACY),
                raw_frame(0x40, 0x00, 0x00),
            ]
        ),
    }


TARGETS: dict[str, "callable"] = {
    "standalone_apdu_dispatch_fuzzer": seeds_apdu_dispatch,
    "standalone_cbor_data_blob_fuzzer": seeds_cbor_data_blob,
    "standalone_deploy_module_fuzzer": seeds_deploy_module,
    "standalone_export_pk_legacy_path_fuzzer": seeds_export_pk_legacy,
    "standalone_export_pk_new_path_fuzzer": seeds_export_pk_new,
    "standalone_get_public_key_fuzzer": seeds_get_public_key,
    "standalone_init_contract_fuzzer": seeds_init_contract,
    "standalone_sign_configure_baker_fuzzer": seeds_configure_baker,
    "standalone_sign_configure_delegation_fuzzer": seeds_configure_delegation,
    "standalone_sign_credential_deployment_fuzzer": seeds_credential_deployment,
    "standalone_sign_public_information_for_ip_fuzzer": seeds_public_information_for_ip,
    "standalone_sign_register_data_fuzzer": seeds_register_data,
    "standalone_set_trusted_name_fuzzer": seeds_set_trusted_name,
    "standalone_sign_transfer_fuzzer": seeds_sign_transfer,
    "standalone_sign_transfer_to_public_fuzzer": seeds_transfer_to_public,
    "standalone_sign_transfer_with_memo_fuzzer": seeds_transfer_with_memo,
    "standalone_sign_transfer_with_schedule_and_memo_fuzzer": seeds_transfer_with_schedule_and_memo,
    "standalone_sign_transfer_with_schedule_fuzzer": seeds_transfer_with_schedule,
    "standalone_sign_update_credential_fuzzer": seeds_update_credential,
    "standalone_update_contract_fuzzer": seeds_update_contract,
    "standalone_verify_address_fuzzer": seeds_verify_address,
}


# --------------------------------------------------------------------------------------
# Dictionaries
# --------------------------------------------------------------------------------------
# libFuzzer applies dictionary tokens as byte-level mutations, so the useful tokens are the
# magic constants a parser compares against and cannot discover by chance: transaction kinds,
# the fixed P1/P2 values that select a state, the packed-path node-count and coin-type words,
# the length fields, and the CBOR initial bytes.  The whole 60-byte account header is included
# as a single token so a mutator can splice a valid header in one step.
DICT_LENGTHS = {
    "len_u16_zero": b"\x00\x00",
    "len_u16_max": b"\xff\xff",
    "len_u32_zero": bytes(4),
    "len_u32_max": b"\xff\xff\xff\xff",
    "len_u64_zero": bytes(8),
    "len_u64_max": b"\xff" * 8,
}

# Packed derivation path: a node count then that many big-endian uint32 nodes.  The node
# counts are the depths tests/standalone/ uses; the node values are the coin types and the
# Concordium legacy purpose, which a mutator would otherwise have to guess.
DICT_PATH = {
    "path_nodes_5": b"\x05",
    "path_nodes_6": b"\x06",
    "path_nodes_8": b"\x08",
    "path_nodes_zero": b"\x00",
    "path_nodes_max": b"\xff",
    "path_node_1105": (1105).to_bytes(4, "big"),
    "path_node_44": (44).to_bytes(4, "big"),
    "path_node_919": (919).to_bytes(4, "big"),
    "path_node_1_testnet": (1).to_bytes(4, "big"),
    "path_node_44_hardened": (HARDENED | 44).to_bytes(4, "big"),
    "path_node_919_hardened": (HARDENED | 919).to_bytes(4, "big"),
    "path_node_1_hardened": (HARDENED | 1).to_bytes(4, "big"),
}

# The whole 60-byte account-transaction header, so a mutator can splice a valid one in a
# single step, plus its expiry field on its own.
DICT_ACCOUNT_HEADER = {
    "hdr_account_transaction": ACCOUNT_HEADER,
    "hdr_expiry": h("0000000063de5da7"),
    "hdr_sender": ACCOUNT_HEADER[:32],
}

DICT_TX_KINDS = {
    "kind_deploy_module": bytes([KIND_DEPLOY_MODULE]),
    "kind_init_contract": bytes([KIND_INIT_CONTRACT]),
    "kind_update_contract": bytes([KIND_UPDATE_CONTRACT]),
    "kind_transfer": bytes([KIND_TRANSFER]),
    "kind_transfer_to_public": bytes([KIND_TRANSFER_TO_PUBLIC]),
    "kind_transfer_with_schedule": bytes([KIND_TRANSFER_WITH_SCHEDULE]),
    "kind_update_credentials": bytes([KIND_UPDATE_CREDENTIALS]),
    "kind_register_data": bytes([KIND_REGISTER_DATA]),
    "kind_transfer_with_memo": bytes([KIND_TRANSFER_WITH_MEMO]),
    "kind_transfer_with_schedule_and_memo": bytes([KIND_TRANSFER_WITH_SCHEDULE_AND_MEMO]),
    "kind_configure_baker": bytes([KIND_CONFIGURE_BAKER]),
    "kind_configure_delegation": bytes([KIND_CONFIGURE_DELEGATION]),
}

DICT_CBOR = {
    "cbor_uint_inline_max": b"\x17",
    "cbor_uint_1byte": b"\x18",
    "cbor_uint_2byte": b"\x19",
    "cbor_uint_4byte": b"\x1a",
    "cbor_uint_8byte": b"\x1b",
    "cbor_nint_inline": b"\x20",
    "cbor_nint_1byte": b"\x38",
    "cbor_byte_string": b"\x40",
    "cbor_text_inline_empty": b"\x60",
    "cbor_text_inline_max": b"\x77",
    "cbor_text_1byte": b"\x78",
    "cbor_text_2byte": b"\x79",
    "cbor_text_4byte": b"\x7a",
    "cbor_text_8byte": b"\x7b",
    "cbor_indefinite_text": b"\x7f",
    "cbor_array": b"\x80",
    "cbor_map": b"\xa0",
    "cbor_tag": b"\xc0",
    "cbor_break": b"\xff",
    "cbor_text_test": CBOR_TEXT_TEST,
}


def dict_p1_p2(name_to_value: dict[str, int]) -> dict[str, bytes]:
    return {name: bytes([value]) for name, value in name_to_value.items()}


# Fixed P1/P2 values per target, transcribed from tests/standalone/application_client/
# command_sender.py (classes P1 and P2).
DICT_P1_P2: dict[str, dict[str, bytes]] = {
    "standalone_cbor_data_blob_fuzzer": {},
    "standalone_deploy_module_fuzzer": dict_p1_p2({"p1_initial": 0x00, "p1_source": 0x01}),
    "standalone_export_pk_legacy_path_fuzzer": dict_p1_p2(
        {
            "p1_standard": 0x00,
            "p1_alternative_display": 0x01,
            "p1_prfkey_and_idcredsec": 0x02,
            "p2_export_bls_key": 0x02,
        }
    ),
    "standalone_export_pk_new_path_fuzzer": dict_p1_p2(
        {
            "p1_identity_credential_creation": 0x00,
            "p1_account_creation": 0x01,
            "p1_id_recovery": 0x02,
            "p1_account_credential_discovery": 0x03,
            "p1_creation_of_zk_proof": 0x04,
            "p2_mainnet": 0x00,
            "p2_testnet": 0x01,
        }
    ),
    "standalone_get_public_key_fuzzer": dict_p1_p2(
        {"p1_confirm": 0x00, "p1_no_confirm": 0x01, "p2_no_sign": 0x00, "p2_sign": 0x01}
    ),
    "standalone_init_contract_fuzzer": dict_p1_p2(
        {"p1_initial": 0x00, "p1_name": 0x01, "p1_params": 0x02}
    ),
    "standalone_sign_configure_baker_fuzzer": dict_p1_p2(
        {
            "p1_header_and_bitmap": 0x00,
            "p1_capital_restake_open_keys": 0x01,
            "p1_aggregation_key": 0x02,
            "p1_url_length": 0x03,
            "p1_url_chunk": 0x04,
            "p1_commission_rates": 0x05,
            "p1_suspended": 0x06,
        }
    ),
    "standalone_sign_configure_delegation_fuzzer": dict_p1_p2({"p1_none": 0x00}),
    "standalone_sign_credential_deployment_fuzzer": dict_p1_p2(
        {
            "p1_initial_packet": 0x00,
            "p1_verification_key": 0x01,
            "p1_signature_threshold": 0x02,
            "p1_ar_identity": 0x03,
            "p1_credential_dates": 0x04,
            "p1_attribute_tag": 0x05,
            "p1_attribute_value": 0x06,
            "p1_length_of_proofs": 0x07,
            "p1_proofs": 0x08,
            "p1_new_or_existing": 0x09,
            "p1_verification_key_length": 0x0A,
        }
    ),
    "standalone_sign_public_information_for_ip_fuzzer": dict_p1_p2(
        {"p1_initial": 0x00, "p1_ar_chunk": 0x01, "p1_threshold": 0x02}
    ),
    "standalone_sign_register_data_fuzzer": dict_p1_p2(
        {"p1_initial": 0x00, "p1_payload": 0x01}
    ),
    "standalone_sign_transfer_fuzzer": dict_p1_p2(
        {"p1_none": 0x00, "p2_none": 0x00, "p2_tx_fee_display": 0x01}
    ),
    "standalone_sign_transfer_to_public_fuzzer": dict_p1_p2(
        {"p1_initial": 0x00, "p1_remaining_amount": 0x01, "p1_proof": 0x02}
    ),
    "standalone_sign_transfer_with_memo_fuzzer": dict_p1_p2(
        {
            "p1_initial": 0x01,
            "p1_memo": 0x02,
            "p1_amount": 0x03,
            "p2_none": 0x00,
            "p2_tx_fee_display": 0x01,
        }
    ),
    "standalone_sign_transfer_with_schedule_and_memo_fuzzer": dict_p1_p2(
        {
            "p1_scheduled_amounts": 0x01,
            "p1_initial": 0x02,
            "p1_memo": 0x03,
            "p2_none": 0x00,
            "p2_tx_fee_display": 0x01,
        }
    ),
    "standalone_sign_transfer_with_schedule_fuzzer": dict_p1_p2(
        {
            "p1_initial": 0x00,
            "p1_scheduled_amounts": 0x01,
            "p2_none": 0x00,
            "p2_tx_fee_display": 0x01,
        }
    ),
    "standalone_sign_update_credential_fuzzer": dict_p1_p2(
        {
            "p1_none": 0x00,
            "p1_verification_key": 0x01,
            "p1_signature_threshold": 0x02,
            "p1_ar_identity": 0x03,
            "p1_credential_dates": 0x04,
            "p1_attribute_tag": 0x05,
            "p1_attribute_value": 0x06,
            "p1_length_of_proofs": 0x07,
            "p1_proofs": 0x08,
            "p1_verification_key_length": 0x0A,
            "p2_credential_initial": 0x00,
            "p2_credential_index": 0x01,
            "p2_credential": 0x02,
            "p2_credential_id_count": 0x03,
            "p2_credential_id": 0x04,
            "p2_threshold": 0x05,
        }
    ),
    "standalone_update_contract_fuzzer": dict_p1_p2(
        {"p1_initial": 0x00, "p1_name": 0x01, "p1_params": 0x02}
    ),
    "standalone_verify_address_fuzzer": dict_p1_p2(
        {
            "p1_legacy_path": 0x00,
            "p1_new_path": 0x01,
            "p1_full_path": 0x02,
            "p2_mainnet": 0x00,
            "p2_testnet": 0x01,
        }
    ),
}

# Targets whose command data carries a CBOR memo / register-data blob.
CBOR_TARGETS = {
    "standalone_cbor_data_blob_fuzzer",
    "standalone_sign_register_data_fuzzer",
    "standalone_sign_transfer_with_memo_fuzzer",
    "standalone_sign_transfer_with_schedule_and_memo_fuzzer",
}

# Targets whose command data carries the 60-byte account-transaction header and therefore a
# transaction-kind byte.  The other handlers either take only a derivation path and per-field
# packets (credential deployment, public info for IP, get public key, verify address) or take
# neither (export private key, the CBOR blob target).
ACCOUNT_HEADER_TARGETS = {
    # The dispatch target frames whole transactions, so it needs both the header and the kinds.
    "standalone_apdu_dispatch_fuzzer",
    "standalone_deploy_module_fuzzer",
    "standalone_init_contract_fuzzer",
    "standalone_sign_configure_baker_fuzzer",
    "standalone_sign_configure_delegation_fuzzer",
    "standalone_sign_register_data_fuzzer",
    "standalone_sign_transfer_fuzzer",
    "standalone_sign_transfer_to_public_fuzzer",
    "standalone_sign_transfer_with_memo_fuzzer",
    "standalone_sign_transfer_with_schedule_and_memo_fuzzer",
    "standalone_sign_transfer_with_schedule_fuzzer",
    "standalone_sign_update_credential_fuzzer",
    "standalone_update_contract_fuzzer",
}

# Targets whose command data contains a packed derivation path.
PACKED_PATH_TARGETS = ACCOUNT_HEADER_TARGETS | {
    "standalone_get_public_key_fuzzer",
    # Its VERIFY_ADDRESS half takes a path, in each of the three P1 formats.
    "standalone_set_trusted_name_fuzzer",
    "standalone_sign_credential_deployment_fuzzer",
    "standalone_sign_public_information_for_ip_fuzzer",
    "standalone_verify_address_fuzzer",
}

DICT_EXTRA: dict[str, dict[str, bytes]] = {
    "standalone_sign_configure_baker_fuzzer": {
        "bitmap_capital": h("0001"),
        "bitmap_restake": h("0002"),
        "bitmap_open_status": h("0004"),
        "bitmap_keys": h("0008"),
        "bitmap_url": h("0010"),
        "bitmap_commissions": h("00e0"),
        "bitmap_suspended": h("0100"),
        "bitmap_capital_restake_open_keys": h("000f"),
        "bitmap_all": h("01ff"),
        "open_status_open": b"\x00",
        "open_status_closed_for_new": b"\x01",
        "open_status_closed_for_all": b"\x02",
    },
    "standalone_sign_configure_delegation_fuzzer": {
        "bitmap_capital": h("0001"),
        "bitmap_restake": h("0002"),
        "bitmap_target": h("0004"),
        "bitmap_all": h("0007"),
        "delegation_target_passive": b"\x00",
        "delegation_target_baker": b"\x01",
    },
    "standalone_sign_transfer_with_schedule_fuzzer": {"schedule_pair": SCHEDULE_PAIR},
    "standalone_sign_transfer_with_schedule_and_memo_fuzzer": {"schedule_pair": SCHEDULE_PAIR},
    "standalone_sign_credential_deployment_fuzzer": {
        "credential_dates": CRED_DATES,
        "attribute_tag_and_length": CRED_ATTRIBUTE_TAG,
    },
    "standalone_sign_update_credential_fuzzer": {
        "credential_dates": CRED_DATES,
        "attribute_tag_and_length": CRED_ATTRIBUTE_TAG,
    },
    # Every INS the dispatcher routes, plus the CLA and the frame shapes that fail the parser,
    # so the mutator can build and reshape whole frames rather than stumble onto valid ones.
    "standalone_apdu_dispatch_fuzzer": {
        # Transcribed from src/apdu/dispatcher.h.
        "cla": b"\xe0",
        "ins_verify_address": b"\x00",
        "ins_get_public_key": b"\x01",
        "ins_sign_transfer": b"\x02",
        "ins_transfer_with_schedule": b"\x03",
        "ins_credential_deployment": b"\x04",
        "ins_export_private_key_legacy": b"\x05",
        "ins_deploy_module": b"\x06",
        "ins_init_contract": b"\x07",
        "ins_update_contract": b"\x08",
        "ins_transfer_to_public": b"\x12",
        "ins_configure_delegation": b"\x17",
        "ins_configure_baker": b"\x18",
        "ins_public_info_for_ip": b"\x20",
        "ins_get_app_name": b"\x21",
        "ins_set_trusted_name": b"\x22",
        "ins_get_challenge": b"\x23",
        "ins_sign_update_credential": b"\x31",
        "ins_transfer_with_memo": b"\x32",
        "ins_transfer_with_schedule_and_memo": b"\x34",
        "ins_register_data": b"\x35",
        "ins_export_private_key_new": b"\x37",
        "ins_app_version": b"\x40",
        # Whole frames: an empty-Lc query, and a four-byte header with no Lc at all.
        "frame_get_app_name": b"\xe0\x21\x00\x00",
        "frame_header_no_lc": b"\xe0\x02\x00\x00",
        "frame_lc_zero": b"\xe0\x02\x00\x00\x00",
    },
    # The app's trusted-name TLV tags (tests/standalone/trusted_name_helper.py), so the parser
    # sees plausible tag bytes instead of needing to guess each one.
    "standalone_set_trusted_name_fuzzer": {
        "tag_structure_type": b"\x01",
        "tag_version": b"\x02",
        "tag_not_valid_after": b"\x10",
        "tag_challenge": b"\x12",
        "tag_signer_key_id": b"\x13",
        "tag_signer_algorithm": b"\x14",
        "tag_der_signature": b"\x15",
        "tag_trusted_name": b"\x20",
        "tag_address": b"\x22",
        "tag_chain_id": b"\x23",
        "tag_trusted_name_type": b"\x70",
        "tag_trusted_name_source": b"\x71",
        "tag_nft_id": b"\x72",
        "tag_source_contract": b"\x73",
        # Tag-length pairs that appear in every real descriptor.
        "tlv_structure_type_trusted_name": b"\x01\x01\x03",
        "tlv_version_zero": b"\x02\x01\x03",
        "tlv_chain_id_8_bytes": b"\x23\x01\x01",
        "der_signature_header": b"\x15\x47\x30\x45",
        # The whole signed descriptor, splice-able as one token.
        "signed_descriptor": TRUSTED_NAME_DESCRIPTOR,
    },
}


def dictionary_for(target: str) -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    entries.update(DICT_LENGTHS)
    if target in PACKED_PATH_TARGETS:
        entries.update(DICT_PATH)
    if target in ACCOUNT_HEADER_TARGETS:
        entries.update(DICT_ACCOUNT_HEADER)
        entries.update(DICT_TX_KINDS)
    entries.update(DICT_P1_P2.get(target, {}))
    if target in CBOR_TARGETS:
        entries.update(DICT_CBOR)
    entries.update(DICT_EXTRA.get(target, {}))
    return entries


def render_dictionary(target: str, entries: dict[str, bytes]) -> str:
    lines = [
        f"# libFuzzer dictionary for {target}.",
        "# Generated by fuzzing/tools/generate_seed_corpus.py - do not edit by hand.",
        "",
    ]
    for name, value in entries.items():
        escaped = "".join(f"\\x{byte:02x}" for byte in value)
        lines.append(f'{name}="{escaped}"')
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit non-zero if the tracked seeds differ from the generated ones",
    )
    args = parser.parse_args()

    stale = []
    total = 0
    tokens = 0
    for target, builder in sorted(TARGETS.items()):
        wanted = builder()
        target_dir = SEEDS_ROOT / target
        entries = dictionary_for(target)
        rendered = render_dictionary(target, entries)
        dict_path = DICTS_ROOT / f"{target}.dict"
        total += len(wanted)
        tokens += len(entries)

        for name, blob in wanted.items():
            assert blob, f"{target}/{name} is empty"

        if args.check:
            for name, blob in wanted.items():
                dest = target_dir / f"{name}.bin"
                if not dest.exists() or dest.read_bytes() != blob:
                    stale.append(str(dest.relative_to(REPO_ROOT)))
            existing = {p.name for p in target_dir.glob("*.bin")} if target_dir.exists() else set()
            for extra in sorted(existing - {f"{n}.bin" for n in wanted}):
                stale.append(str((target_dir / extra).relative_to(REPO_ROOT)))
            if not dict_path.exists() or dict_path.read_text() != rendered:
                stale.append(str(dict_path.relative_to(REPO_ROOT)))
            continue

        if target_dir.exists():
            shutil.rmtree(target_dir)
        target_dir.mkdir(parents=True)
        for name, blob in wanted.items():
            (target_dir / f"{name}.bin").write_bytes(blob)
        DICTS_ROOT.mkdir(parents=True, exist_ok=True)
        dict_path.write_text(rendered)

    if args.check:
        if stale:
            print("seed corpus is out of date; rerun generate_seed_corpus.py:", file=sys.stderr)
            for item in stale:
                print(f"  {item}", file=sys.stderr)
            return 1
        print(
            f"seed corpus up to date ({total} seeds, {tokens} dictionary tokens, "
            f"{len(TARGETS)} targets)"
        )
        return 0

    print(
        f"wrote {total} seeds under {SEEDS_ROOT} and {len(TARGETS)} dictionaries "
        f"({tokens} tokens) under {DICTS_ROOT}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
