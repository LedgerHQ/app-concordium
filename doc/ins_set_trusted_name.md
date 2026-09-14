# Set Trusted Name

Loads a **trusted name** into volatile device memory after **Nano PKI** + **TLV** verification.

The flow requires three steps:

1. **Load PKI certificate** — Ledger Live sends a Nano PKI certificate (KeyUsage = trusted\_name `0x04`) via the OS default APDU (`CLA 0xB0`, `INS 0x06`). This stores the public key the firmware will use for signature verification.
2. **GET\_CHALLENGE** — The host calls [Get Challenge](ins_get_challenge.md) (`INS 0x23`) to obtain a fresh random challenge. This challenge is embedded in the TLV descriptor by the backend/API.
3. **SET\_TRUSTED\_NAME** — The host sends the **TLV descriptor** (the `signedDescriptor` from the Ledger API) as CDATA.

The firmware:

1. Parses the **TLV payload** using the SDK `DEFINE_TLV_PARSER` pattern with progressive multi-hash of all fields except the signature tag.
2. Validates required fields: structure type (`0x03`), version, name, address, chain\_id, challenge, signer key ID, signer algorithm, and DER signature.
3. Checks that the descriptor is **authorized for this use case**, not merely signed — see [Semantic authorization](#semantic-authorization) below.
4. Verifies the **challenge** matches the value stored by GET\_CHALLENGE.
5. Finalizes the hash for the declared signer algorithm and verifies the **signature** via [`check_signature_with_pki`](https://github.com/LedgerHQ/ledger-secure-sdk/blob/master/lib_pki/ledger_pki.c) against the loaded PKI certificate.
6. On success, stores the **trusted name** string (tag `0x20`), the **address** (tag `0x22`) and the **chain ID** (tag `0x23`) in globals, erases the challenge, and returns `0x9000`.

## Semantic authorization

A valid Ledger PKI signature proves the backend issued the descriptor; it does not say which use case it was issued for. Any Ledger-signed trusted name (an ENS name, an NFT collection, a wallet label) would otherwise be accepted here and later shown by VERIFY\_ADDRESS as the reviewed Concordium account. The firmware therefore also requires:

| Field | Requirement |
| ----- | ----------- |
| `0x02` Version | Exactly `0x03`, the current trusted-name spec version |
| `0x70` Trusted Name Type | `0x06` or `0x07` (context address). The SDK enum numbers `CONTEXT_ADDRESS` `0x06`; live Concordium descriptors carry `0x07` for `ccd_context_address`, so both are accepted. Every other type (EOA, smart contract, collection, token, wallet) is refused |
| `0x71` Trusted Name Source | Exactly `0x06` (dynamic resolver) |
| `0x23` Chain ID | `0` (mainnet) or `1` (testnet) |
| `0x72` NFT ID | Must be **absent**; its presence means the descriptor is not a plain account address |
| `0x73` Source Contract | Must be **absent**, same reason |
| `0x10` Not Valid After | If present, must be exactly four bytes (`major` ‖ `minor` ‖ `patch` as uint16 big-endian) and the running app version must not be past it. The cutoff is inclusive: a descriptor stamped `5.6.4` is honoured by app `5.6.4` and refused by `5.6.5` |

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
| `0x02` | Version             | `uint8`      | yes      | Descriptor version; must be `0x03` |
| `0x70` | Trusted Name Type   | `uint8`      | yes      | Must be a context address (`0x06` or `0x07`) |
| `0x71` | Trusted Name Source  | `uint8`      | yes      | Must be the dynamic resolver (`0x06`) |
| `0x20` | Trusted Name        | UTF-8 string | yes      | The canonical base58 account address (max 64 chars) |
| `0x23` | Chain ID            | `uint64`     | yes      | `0` (mainnet) or `1` (testnet) |
| `0x22` | Address             | bytes        | yes      | Owner Ed25519 public key, exactly 32 bytes |
| `0x12` | Challenge           | `uint64`     | yes      | Must match the GET\_CHALLENGE response |
| `0x13` | Signer Key ID       | `uint16`     | yes      | `0x0000` (test) or `0x0007` (prod) |
| `0x14` | Signer Algorithm    | `uint8`      | yes      | `0x01` = ECDSA-SHA256 |
| `0x15` | DER Signature       | bytes        | yes      | 64–72 byte DER ECDSA/EdDSA signature |
| `0x72` | NFT ID              | bytes        | no       | Rejected if present |
| `0x73` | Source Contract      | bytes        | no       | Rejected if present |
| `0x10` | Not Valid After      | 4 bytes      | no       | `major` ‖ `minor` ‖ `patch` (uint16 BE). Enforced against the running app version |

All fields except the DER Signature (tag `0x15`) are included in the progressive hash used for signature verification.

## Response

| Field | Length (bytes) | Description |
| ----- | -------------- | ----------- |
| RData | 0              | No response data |
| SW    | 2              | Status word (`0x9000` on success) |

## Errors

- Invalid `P1`/`P2` or empty CDATA → `0x6B03` (invalid param).
- TLV parse failure, missing required fields, wrong structure type → `0x6B03`.
- Unsupported version, non-context-address type, foreign name source, unknown chain ID, NFT tags present, malformed or reached validity cutoff → `0x6B03`.
- Challenge mismatch or no prior GET\_CHALLENGE → `0x6B03`.
- PKI signature verification failure → `0x6B03`.

## Interaction with Get Challenge

1. Call **GET\_CHALLENGE** (`INS 0x23`) → receive 8-byte random challenge.
2. Pass the challenge to the backend/API which embeds it in the TLV descriptor (tag `0x12`).
3. Call **SET\_TRUSTED\_NAME** (`INS 0x22`) with the signed TLV.
4. On success, the firmware erases the stored challenge (single-use).

A new GET\_CHALLENGE must be called before each SET\_TRUSTED\_NAME.

## Single use and VERIFY\_ADDRESS

The volatile binding is cleared after **VERIFY\_ADDRESS** (`INS 0x00`) has **used** it, whether the binding was accepted or refused, so a descriptor that did not match one path cannot be retried against another. A plain **VERIFY\_ADDRESS** (no prior successful **SET\_TRUSTED\_NAME**) does not touch this binding.

VERIFY\_ADDRESS always derives the account address on device and shows that; a descriptor never supplies the address on screen, it has to agree with it. Three checks must all pass, otherwise the command is refused with `0x6B0C` (`ERROR_TRUSTED_NAME_MISMATCH`):

1. Tag `0x23` (chain ID) matches the network of the path under review — `0` for a `44'/919'` path, `1` for `44'/1'`. A path with no coin type (the legacy `1105'` subtree) or an unknown one cannot be bound to a network and is refused in this lane.
2. Tag `0x22` is the Ed25519 public key of that path. This key is identity-level: it is the same for every credential counter under one identity, which is why it is not sufficient on its own.
3. Tag `0x20` equals the base58 account address the device derived for the reviewed **credential counter**. This is what makes the binding account-specific — a descriptor issued for counter 0 is refused when the review is for counter 1.

To show the trusted name again, run **GET\_CHALLENGE** → **SET\_TRUSTED\_NAME** → **VERIFY\_ADDRESS** again. A new **SET\_TRUSTED\_NAME** attempt clears any previous binding at command start; if that command fails, the binding stays empty until a later success.

## Test / integration

The Ledger test API ([Concordium section](https://nft.api.live.ledger-test.com/docs/#/concordium/getV2ConcordiumOwnerPubkeyAddress)) returns a `signedDescriptor` hex string. Convert it to binary and send as CDATA.

For Speculos testing, pre-baked PKI certificates and the matching test private key are provided in `tests/standalone/trusted_name_helper.py`. See `tests/standalone/test_set_trusted_name.py` for the complete test flow.
