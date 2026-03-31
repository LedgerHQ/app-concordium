# Set Trusted Name

Loads a **trusted name** into volatile device memory after **Nano PKI** + **TLV** verification.

The flow requires three steps:

1. **Load PKI certificate** — Ledger Live sends a Nano PKI certificate (KeyUsage = trusted\_name `0x04`) via the OS default APDU (`CLA 0xB0`, `INS 0x06`). This stores the public key the firmware will use for signature verification.
2. **GET\_CHALLENGE** — The host calls [Get Challenge](ins_get_challenge.md) (`INS 0x23`) to obtain a fresh random challenge. This challenge is embedded in the TLV descriptor by the backend/API.
3. **SET\_TRUSTED\_NAME** — The host sends the **TLV descriptor** (the `signedDescriptor` from the Ledger API) as CDATA.

The firmware:

1. Parses the **TLV payload** using the SDK `DEFINE_TLV_PARSER` pattern with progressive multi-hash of all fields except the signature tag.
2. Validates required fields: structure type (`0x03`), version, name, address, chain\_id, challenge, signer key ID, signer algorithm, and DER signature.
3. Verifies the **challenge** matches the value stored by GET\_CHALLENGE.
4. Finalizes the hash for the declared signer algorithm and verifies the **signature** via [`check_signature_with_pki`](https://github.com/LedgerHQ/ledger-secure-sdk/blob/master/lib_pki/ledger_pki.c) against the loaded PKI certificate.
5. On success, stores the **trusted name** string (tag `0x20`) and **address** (tag `0x22`) in globals, erases the challenge, and returns `0x9000`.

## Protocol description

- Single command (the PKI certificate is loaded via a separate OS-level APDU beforehand)

| CLA    | INS    | P1     | P2     | Lc     | CDATA                | Comment            |
| ------ | ------ | ------ | ------ | ------ | -------------------- | ------------------ |
| `0xE0` | `0x22` | `0x00` | `0x00` | `var`  | `<TLV payload>`      | Signed TLV descriptor |

`P1` and `P2` must be `0x00`. Other values are rejected.

## Command data (CDATA) — TLV format

CDATA is the raw **TLV payload** (binary form of the `signedDescriptor` hex string returned by the Ledger API). The TLV uses the standard Ledger trusted-name descriptor format:

| Tag    | Name                | Type         | Required | Description |
| ------ | ------------------- | ------------ | -------- | ----------- |
| `0x01` | Structure Type      | `uint8`      | yes      | Must be `0x03` (trusted name) |
| `0x02` | Version             | `uint8`      | yes      | Descriptor version |
| `0x70` | Trusted Name Type   | `uint8`      | yes      | Type of trusted name (e.g. `0x05` = wallet) |
| `0x71` | Trusted Name Source  | `uint8`      | yes      | Source namespace (e.g. `0x01` = CAL) |
| `0x20` | Trusted Name        | UTF-8 string | yes      | Human-readable name / display address (max 64 chars) |
| `0x23` | Chain ID            | `uint64`     | yes      | Network chain ID |
| `0x22` | Address             | bytes        | yes      | Blockchain address (e.g. owner public key) |
| `0x12` | Challenge           | `uint64`     | yes      | Must match the GET\_CHALLENGE response |
| `0x13` | Signer Key ID       | `uint16`     | yes      | `0x0000` (test) or `0x0007` (prod) |
| `0x14` | Signer Algorithm    | `uint8`      | yes      | `0x01` = ECDSA-SHA256 |
| `0x15` | DER Signature       | bytes        | yes      | 64–72 byte DER ECDSA/EdDSA signature |
| `0x72` | NFT ID              | bytes        | no       | Ignored if present |
| `0x73` | Source Contract      | bytes        | no       | Ignored if present |
| `0x10` | Not Valid After      | bytes        | no       | Ignored if present |

All fields except the DER Signature (tag `0x15`) are included in the progressive hash used for signature verification.

## Response

| Field | Length (bytes) | Description |
| ----- | -------------- | ----------- |
| RData | 0              | No response data |
| SW    | 2              | Status word (`0x9000` on success) |

## Errors

- Invalid `P1`/`P2` or empty CDATA → `0x6B03` (invalid param).
- TLV parse failure, missing required fields, wrong structure type → `0x6B03`.
- Challenge mismatch or no prior GET\_CHALLENGE → `0x6B03`.
- PKI signature verification failure → `0x6B03`.

## Interaction with Get Challenge

1. Call **GET\_CHALLENGE** (`INS 0x23`) → receive 8-byte random challenge.
2. Pass the challenge to the backend/API which embeds it in the TLV descriptor (tag `0x12`).
3. Call **SET\_TRUSTED\_NAME** (`INS 0x22`) with the signed TLV.
4. On success, the firmware erases the stored challenge (single-use).

A new GET\_CHALLENGE must be called before each SET\_TRUSTED\_NAME.

## Test / integration

The Ledger test API ([Concordium section](https://nft.api.live.ledger-test.com/docs/#/concordium/getV2ConcordiumOwnerPubkeyAddress)) returns a `signedDescriptor` hex string. Convert it to binary and send as CDATA.

For Speculos testing, pre-baked PKI certificates and the matching test private key are provided in `tests/trusted_name_helper.py`. See `tests/test_set_trusted_name.py` for the complete test flow.
