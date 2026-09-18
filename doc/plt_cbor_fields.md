# PLT CBOR field specification

Canonical description of which CBOR keys and types the Ledger Concordium app parses for
Protocol Level Token (PLT) account transactions.

**Protocol target:** Concordium Protocol v9 · [CIS-7 specification](https://proposals.concordium.com/CIS/cis-7.html)  
**App scope:** v1 — single-operation transactions only (multi-op rejected).

---

## Transaction envelope

A PLT account transaction is split into two parts by the app:

### 1 — 60-byte account transaction header (not CBOR)

Sent in the INIT APDU, processed by `hashAccountTransactionHeaderAndKind()`.  
Fields are hashed into the transaction SHA-256 digest; none are CBOR-encoded.

| Field            | Size (bytes) | Offset | Encoding              | Notes                                  |
| ---------------- | ------------ | ------ | --------------------- | -------------------------------------- |
| `sender_address` | 32           | 0      | raw bytes             | Shown as base58check (55 chars) on screen |
| `nonce`          | 8            | 32     | big-endian uint64     | Not displayed                          |
| `energy_amount`  | 8            | 40     | big-endian uint64     | Shown as the "Max energy" screen — the only cost bound inside the hash |
| `payload_size`   | 4            | 48     | big-endian uint32     | Not displayed                          |
| `expiry_date`    | 8            | 52     | big-endian uint64 (UNIX seconds) | Not displayed             |
| `transaction_kind` | 1          | 60     | uint8 (must be `0x1B` = 27) | Identifies this as a PLT tx      |

### 2 — PLT-specific prefix (not CBOR)

Follows the account header in the INIT APDU, hashed into the transaction digest.

| Field              | Size (bytes)       | Encoding              | Notes                                         |
| ------------------ | ------------------ | --------------------- | --------------------------------------------- |
| `token_id_length`  | 1                  | uint8 (1–128)         | Length of the token ID byte string that follows |
| `token_id`         | `token_id_length`  | UTF-8 text            | Alphanumeric + `-`, `.`, `%`; shown directly on screen as the token ticker |
| `cbor_total_length`| 4                  | big-endian uint32 (1–512) | Total byte length of the CBOR payload delivered across all CONT frames |

### 3 — CBOR payload (across one or more CONT APDUs)

Raw CBOR bytes accumulated in the CONT frames, hashed incrementally.

---

## CBOR payload structure

The outer structure must be a **one-element array** containing a **single-key map**:

```
[ { "<opName>": { <fieldMap> } } ]
```

- Arrays with more than one element are rejected with `ERROR_PLT_MULTI_OP` (`0x6B10`), as is an op
  map holding more than one key.
- Unknown op names are rejected.
- Unknown field names within a recognized op map are rejected with `ERROR_PLT_CBOR_ERROR`
  (`0x6B0D`). Skipping one would leave its bytes in the signature with nothing on screen, and an
  unrecognised key can change what the operation means — the same argument the address map makes
  for BCR key `2`.

---

## Operations and fields

### `"transfer"`

Transfer tokens from the sender to a recipient.

| Field key     | Required | CBOR type                  | Description                                        |
| ------------- | -------- | -------------------------- | -------------------------------------------------- |
| `"amount"`    | yes      | tag 4 (decimal fraction)   | Amount to transfer; see [Amount encoding](#amount-encoding) |
| `"recipient"` | yes      | tag 40307 (account address)| Destination account; see [Address encoding](#address-encoding) |
| `"memo"`      | no       | tag-24 bstr (CBOR text)    | Optional payment reference; only the tag-24 CBOR-text form is accepted, see [Memo encoding](#memo-encoding) |

### `"mint"`

Issue new tokens to the sender (governance account). Requires the sender to be the governance account.

| Field key  | Required | CBOR type                | Description    |
| ---------- | -------- | ------------------------ | -------------- |
| `"amount"` | yes      | tag 4 (decimal fraction) | Amount to mint |

### `"burn"`

Destroy tokens from the sender's account. Requires the sender to be the governance account.

| Field key  | Required | CBOR type                | Description    |
| ---------- | -------- | ------------------------ | -------------- |
| `"amount"` | yes      | tag 4 (decimal fraction) | Amount to burn |

### `"addAllowList"` / `"removeAllowList"` / `"addDenyList"` / `"removeDenyList"`

Governance operations that manage per-account allow/deny list membership.

| Field key   | Required | CBOR type                  | Description              |
| ----------- | -------- | -------------------------- | ------------------------ |
| `"target"`  | yes      | tag 40307 (account address)| Account to add or remove |

### `"pause"` / `"unpause"`

Globally pause or resume all token transfers. The field map is empty: `{}`.

No additional fields.

---

## Type encodings

### Amount encoding

CIS-7 amounts use CBOR **tag 4** (decimal fraction):

```
#6.4([exponent: int, significand: uint])
```

- `exponent`: must be ≤ 0; range enforced by the app: −255 to 0. Stored as `int8_t`.
- `significand`: unsigned 64-bit integer (`uint64_t`).
- Display formula: `significand × 10^exponent`, formatted with `abs(exponent)` decimal places.
- Example: `#6.4([-6, 1500000])` → `"1.500000 UPEU"`.
- Amounts that do not conform to the token's declared decimals are a deserialization failure at the protocol level (the app does not enforce this; it displays whatever the CBOR contains).

### Address encoding

CIS-7 account addresses use CBOR **tag 40307** (BCR-2020-009 *crypto-address*), whose content is
a **map**, not a bare byte string:

```
tagged-account-address = #6.40307(untagged-account-address)

untagged-account-address = {
    ? 1: tagged-ccd-coininfo,    ; info  — optional
      3: bytes .size 32          ; data  — required, raw account address
}

tagged-ccd-coininfo = #6.40305(ccd-coininfo)   ; BCR-2020-007 coin-info
ccd-coininfo = { 1: 919 }                      ; 919 = SLIP-44 coin type for CCD
```

Both accepted forms on the wire:

```
; minimal, 39 bytes
40307({3: h'<32>'})
d9 9d 73  a1  03  58 20  <32 bytes>

; full, what the Concordium JS SDK emits by default — 48 bytes
40307({1: 40305({1: 919}), 3: h'<32>'})
d9 9d 73  a2  01  d9 9d 71  a1  01  19 03 97  03  58 20  <32 bytes>
```

- Key `3` (`data`) is mandatory: a 32-byte byte string holding the raw Concordium address. The app
  base58check-encodes it for display (55-character string).
- Key `1` (`info`) is optional — CIS-7 states decoders SHOULD treat a tagged address with no info
  field as a Concordium address. When present, the app requires exactly `40305({1: 919})`.
- Keys are matched by number, not position, so either serialization order is accepted.
- The app rejects: a bare byte string (pre-CIS-7 shape), a missing key `3`, a `data` field that is
  not 32 bytes, a coin type other than 919, an untagged coininfo map, a duplicated key `3`, and any
  other map key — including BCR key `2` (address type), which CIS-7 does not use. An unknown key
  could change what the address means, so it is refused rather than skipped.

### Memo encoding

`CborMemo` is a discriminated union ([`token_operations.rs`](https://github.com/Concordium/concordium-base/blob/main/rust-src/concordium_base/src/protocol_level_tokens/token_operations.rs)), and the discriminator is on the wire, so the device never guesses which variant it received:

```
bstr          ; CborMemo::Raw  — content is opaque bytes
#6.24(bstr)   ; CborMemo::Cbor — content is an encoded CBOR data item (RFC 8949 tag 24)
```

The node's test vectors for the bytes `01020304` give `4401020304` (Raw) and `d8184401020304` (Cbor).

**The app accepts only the `Cbor` variant, and only when the encoded item is a single definite-length CBOR text string that fills the whole byte string.** Everything else is refused with `ERROR_PLT_UNSUPPORTED_MEMO` (`0x6B12`), and refusal aborts signing:

| Memo | Result |
|------|--------|
| `#6.24(bstr)` wrapping one definite-length text string, all bytes renderable | decoded text is displayed |
| `bstr` (the `Raw` variant) | refused — opaque bytes have no faithful rendering |
| `#6.24(bstr)` wrapping a number, byte string, array or map | refused — could only be shown as something other than what was signed |
| encoded item followed by trailing bytes | refused — the extra bytes stay in the hash unseen |
| indefinite-length text string | refused — several chunks, no single canonical encoding |
| text containing `0x00`–`0x1F` or `0x7F` | refused — a NUL ends the display while the signature covers what follows |
| text longer than `PLT_MEMO_DISPLAY_SIZE - 1` | refused rather than trimmed |

- Maximum length: 256 bytes (protocol limit); `displayMemo` is sized for the whole envelope so an accepted memo is always shown in full.
- The same rules the native CCD memo path applies (`parse_complete_cbor`, `src/helpers/cbor_data_blob.c`): definite length only, no trailing bytes, renderable bytes only.

---

## What lives where: CBOR payload vs account header

| Information       | Location              | Hashed | Displayed via          |
| ----------------- | --------------------- | ------ | ---------------------- |
| Sender address    | Account header        | yes    | "Sender" screen        |
| Network           | Signing path (node 1) | n/a    | "Network" screen       |
| Nonce             | Account header        | yes    | not shown              |
| Max energy        | Account header        | yes    | "Max energy" screen    |
| Fee (µCCD)        | INIT APDU suffix (P2=0x01) | no | "Max fees" screen (optional; a host estimate outside the hash, shown in addition to "Max energy") |
| Expiry            | Account header        | yes    | not shown              |
| Token ID          | PLT prefix (after header) | yes | "Token" screen         |
| Operation type    | CBOR payload (op key) | yes    | "Operation" screen     |
| Amount            | CBOR payload          | yes    | "Amount" screen        |
| Recipient / Target| CBOR payload          | yes    | "Recipient"/"Target" screen |
| Memo              | CBOR payload          | yes    | "Memo" screen (transfer only) |

---

## Out of scope for v1

The following are explicitly not supported in the v1 app and are rejected:

| Item                            | Rejection behaviour                                    |
| ------------------------------- | ------------------------------------------------------ |
| Multi-operation arrays, or an op map with more than one key | `ERROR_PLT_MULTI_OP` (`0x6B10`)    |
| Unknown field name inside a recognised op map | `ERROR_PLT_CBOR_ERROR` (`0x6B0D`)        |
| CBOR payload > 512 bytes        | `ERROR_PLT_BUFFER_ERROR` (`0x6B0E`)                    |
| Token ID > 128 bytes            | `ERROR_PLT_DATA_ERROR` (`0x6B0F`)                      |
| Unknown operation names         | `ERROR_PLT_CBOR_ERROR` (`0x6B0D`) via parse failure    |
| Amount exponent < −255 or > 0   | Parse failure → `ERROR_PLT_CBOR_ERROR`                 |
| Address `data` (key 3) ≠ 32 bytes, absent, or unknown key in the address / coininfo map, or coin type ≠ 919 | Parse failure → `ERROR_PLT_CBOR_ERROR` |
