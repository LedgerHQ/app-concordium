# PLT (Protocol Level Token) signing

Sign a Concordium account transaction of kind **PLT** (`0x1B` = 27), which carries a
[CIS-7](https://proposals.concordium.com/CIS/cis-7.html) payload describing a single
token operation.  The payload is delivered as raw CBOR across one or more CONT APDUs so
that payloads larger than a single 255-byte APDU frame are supported.

## Protocol description

- Multiple commands: one INIT followed by one or more CONT

| INS    | P1     | P2     | CDATA                                                                                                                                                                                                                                                                  | Comment                                                                                                                                                     |
| ------ | ------ | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0x27` | `0x00` | `0x00` | `path_length[uint8]` <br> `path[uint32 × path_length]` (each node big-endian; hardened bit `0x80000000`) <br> `sender_address[uint256]` <br> `nonce[uint64]` (big-endian) <br> `energy_amount[uint64]` (big-endian) <br> `payload_size[uint32]` (big-endian) <br> `expiry_date[uint64]` (big-endian) <br> `transaction_kind[uint8]` (must be **`0x1B`** = 27) <br> `token_id_length[uint8]` (1–128) <br> `token_id[token_id_length bytes]` <br> `cbor_total_length[uint32]` (big-endian; 1–512) | INIT frame (no fee display). Resets internal state. Response is `0x9000` with no data. All fields through `cbor_total_length` are hashed (SHA-256) into the transaction. |
| `0x27` | `0x00` | `0x01` | *(same as P2=`0x00`)* `fee[uint64]` (big-endian µCCD) | INIT frame with fee display. Identical to P2=`0x00` except the CDATA has an extra 8-byte big-endian µCCD fee appended after `cbor_total_length`. The fee is **not hashed** and is shown as "Max fees" on the review screen. Send `0xFFFFFFFFFFFFFFFF` to omit the fee line while still using P2=`0x01`. |
| `0x27` | `0x01` | `0x00` | `cbor_chunk[1…255 bytes]`                                                                                                                                                                                                                                              | CONT frame. Raw CBOR bytes, up to 255 per call. Repeat until exactly `cbor_total_length` bytes have been delivered in total. Each intermediate CONT returns `0x9000` with no data; the **final** CONT (when the accumulated byte count equals `cbor_total_length`) returns `0x9000` with a **64-byte Ed25519 signature** as response data. |

> INIT P2 must be `0x00` (no fee) or `0x01` (fee display); any other value is rejected with `SWO_WRONG_P1_P2` (`0x6B00`).
> CONT P2 must be `0x00`.

## CBOR payload format (CIS-7)

The accumulated CBOR must be a one-element array containing a single-key map:

```
[ { "<opName>": { <fields> } } ]
```

Supported operations and their required fields:

| Operation key      | Fields                                              | Display label          |
| ------------------ | --------------------------------------------------- | ---------------------- |
| `"transfer"`       | `amount` (tag 4), `recipient` (tag 40307)[, `memo`] | Transfer               |
| `"mint"`           | `amount` (tag 4)                                    | Mint                   |
| `"burn"`           | `amount` (tag 4)                                    | Burn                   |
| `"addAllowList"`   | `target` (tag 40307)                               | Add to allow list      |
| `"removeAllowList"`| `target` (tag 40307)                               | Remove from allow list |
| `"addDenyList"`    | `target` (tag 40307)                               | Add to deny list       |
| `"removeDenyList"` | `target` (tag 40307)                               | Remove from deny list  |
| `"pause"`          | *(none)*                                           | Pause                  |
| `"unpause"`        | *(none)*                                           | Unpause                |

- **amount** — CBOR tag 4 (decimal fraction) wrapping `[exponent, significand]`. `exponent` must be ≤ 0; `significand` is an unsigned 64-bit integer.
- **recipient / target** — CBOR tag 40307 wrapping a map: `{? 1: 40305({1: 919}), 3: bstr .size 32}`. Key `3` (the raw account address) is mandatory; the coininfo field under key `1` is optional but, when present, must be `40305({1: 919})`. See [plt_cbor_fields.md](plt_cbor_fields.md#address-encoding).
- **memo** — a byte string (raw bytes) or tag-24 byte string (embedded CBOR). Up to 256 bytes; displayed as ASCII when all sampled bytes are printable, otherwise as a `0x…` hex prefix.

More than one operation in the outer array is rejected with `ERROR_PLT_MULTI_OP` (`0x6B10`).

## Error status words

| SW       | Constant                   | Condition                                                                                              |
| -------- | -------------------------- | ------------------------------------------------------------------------------------------------------ |
| `0x6B00` | `SWO_WRONG_P1_P2`          | INIT P2 ∉ {`0x00`, `0x01`}, or CONT P2 ≠ `0x00`                                                      |
| `0x6B01` | `ERROR_INVALID_STATE`      | CONT received before INIT, or INIT received mid-flow                                                   |
| `0x6B03` | `ERROR_INVALID_PARAM`      | P1 is neither `0x00` nor `0x01`                                                                        |
| `0x6B04` | `ERROR_INVALID_TRANSACTION`| `transaction_kind` ≠ `0x1B`                                                                            |
| `0x6A80` | `SWO_INCORRECT_DATA`       | INIT: trailing bytes when P2=`0x00`, or byte count after `cbor_total_length` ≠ 8 when P2=`0x01`       |
| `0x6B0D` | `ERROR_PLT_CBOR_ERROR`     | CONT chunk is empty, or its length would exceed the declared `cbor_total_length`                       |
| `0x6B0E` | `ERROR_PLT_BUFFER_ERROR`   | `cbor_total_length` is 0 or exceeds `APP_PLT_CBOR_MAX` (512)                                          |
| `0x6B0F` | `ERROR_PLT_DATA_ERROR`     | `token_id_length` is 0 or > 128                                                                        |
| `0x6B10` | `ERROR_PLT_MULTI_OP`       | CBOR outer array contains more than one operation                                                      |

## Display

The app performs **clear signing**: each field is shown in human-readable form before the user signs. The review screen always shows **Sender** (from the 60-byte transaction header), **Token** (the token ID string), and **Operation** (human-readable op name). Additional fields depend on the operation type:

| Operation       | Screens shown (in order)                                             |
| --------------- | -------------------------------------------------------------------- |
| `transfer`      | Sender · Token · Operation · Amount · Recipient · [Memo] · [Max fees] · Sign/Decline |
| `mint`          | Sender · Token · Operation · Amount · [Max fees] · Sign/Decline                       |
| `burn`          | Sender · Token · Operation · Amount · [Max fees] · Sign/Decline                       |
| `addAllowList`  | Sender · Token · Operation · Target · [Max fees] · Sign/Decline                       |
| `removeAllowList` | Sender · Token · Operation · Target · [Max fees] · Sign/Decline                     |
| `addDenyList`   | Sender · Token · Operation · Target · [Max fees] · Sign/Decline                       |
| `removeDenyList`| Sender · Token · Operation · Target · [Max fees] · Sign/Decline                       |
| `pause`         | Sender · Token · Operation · [Max fees] · Sign/Decline                                |
| `unpause`       | Sender · Token · Operation · [Max fees] · Sign/Decline                                |

Fields in brackets `[…]` appear only when the host provides the corresponding data.

**Formatting details:**
- **Amount** — displayed as `"<value> <tokenId>"` with the number of decimal places determined by the CBOR tag-4 exponent (e.g. `"1.500000 UPEU"`). Raw smallest units are never shown without decimal context.
- **Recipient / Target** — base58check-encoded 55-character Concordium address.
- **Memo** — up to 14 bytes; shown as ASCII if all sampled characters are printable, otherwise as `"0x<hex>"` prefix. Truncation indicated by displayed byte count.
- **Max fees** — only shown when the host sends the fee suffix (P2=`0x01` on INIT); formatted as CCD with 6 decimal places (e.g. `"0.000727 CCD"`). If the host sends `0xFFFFFFFFFFFFFFFF`, the fee line is suppressed.
- Long strings are paginated on Nano (scrollable); on Stax/Flex the review uses the standard pair-list layout.

## Sample INIT command disassembly

Example: path `m/1105/0/0/0/0/2/0/0` (depth 8), token ID `T` (1 byte), 4-byte CBOR payload.

| Field name          | Size (bytes) | Sample                                                                      |
| ------------------- | ------------ | --------------------------------------------------------------------------- |
| CLA                 | 1            | `0xe0`                                                                      |
| INS                 | 1            | `0x27`                                                                      |
| P1                  | 1            | `0x00` (INIT)                                                               |
| P2                  | 1            | `0x00`                                                                      |
| Lc                  | 1            | `0x4c` (76 bytes: 1 + 32 + 60 + 1 + 1 + 1 + 4)                            |
| Path length         | 1            | `0x08`                                                                      |
| Path                | 32           | `0x00000451` `0x00000000` `0x00000000` `0x00000000` `0x00000000` `0x00000002` `0x00000000` `0x00000000` |
| Sender address      | 32           | `0x20a84581_5bd43a19_99e90fbf_971537a7_0392eb38_f89e6bd3_2b3dd70e_1a9551d7` |
| Nonce               | 8            | `0x000000000000000a`                                                        |
| Energy amount       | 8            | `0x0000000000000064`                                                        |
| Payload size        | 4            | `0x00000000`                                                                |
| Expiry date         | 8            | `0x0000000063de5da7`                                                        |
| Transaction kind    | 1            | `0x1b` (27 — PLT)                                                           |
| Token ID length     | 1            | `0x01`                                                                      |
| Token ID            | 1            | `0x54` (`'T'`)                                                              |
| CBOR total length   | 4            | `0x00000004`                                                                |
