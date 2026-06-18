# Transfer transaction

A transaction to transfer CCD from one account to another.

## Protocol description

- Single command

| INS    | P1     | P2     | CDATA                                                                                                                                  | Comment                                                        |
| ------ | ------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `0x02` | `0x00` | `0x00` | `path_length[uint8]` <br> `path[uint32 * $path_length]` <br> `sender_address [uint256]` <br> `nonce [uint64]` <br> `energy_amount [uint64]` <br> `payload_size[uint32]` <br> `expiry_date[uint64]` <br> `transaction_kind[uint8]` <br> `recipient_address[uint256]` <br> `amount[uint64]` | The amount is in µCCD. The recipient address has to be base58. |
| `0x02` | `0x00` | `0x01` | `path_length[uint8]` <br> `path[uint32 * $path_length]` (each node big-endian; hardened bit `0x80000000`) <br> `sender_address [uint256]` <br> `nonce [uint64]` (big-endian) <br> `energy_amount [uint64]` (big-endian) <br> `payload_size[uint32]` (big-endian) <br> `expiry_date[uint64]` (big-endian) <br> `transaction_kind[uint8]` <br> `recipient_address [uint256]` <br> `amount[uint64]` (big-endian) <br> `display_fee_microccd[uint64]` (big-endian) | Identical to the `P2=0x00` CDATA layout, then **one more** field. **`display_fee_microccd`** is **for display only** and is **not** hashed into the transaction. The device shows it as **Max fees** unless the host sends **`0xFFFFFFFFFFFFFFFF`** (omit sentinel: no fee line; `P2` may still be `0x01`). With this `P2`, **`energy_amount`** is not shown on screen. Supported only on firmware that advertises the feature (see [ins_get_app_version.md](ins_get_app_version.md)). |

# Transfer with memo

A transaction to transfer CCD from one account to another, with a memo attached.
Uses the same INS number, but a different P1 for the initial call, and has a different transaction kind (22);

## Protocol description

- Multiple commands

| INS    | P1     | P2     | CDATA                                                                                                                                       | Comment                                 |
| ------ | ------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `0x32` | `0x01` | `0x00` | `path_length[uint8]` <br> `path[uint32 * $path_length]` (each node big-endian; hardened bit `0x80000000`) <br> `sender_address [uint256]` <br> `nonce [uint64]` (big-endian) <br> `energy_amount [uint64]` (big-endian) <br> `payload_size[uint32]` (big-endian) <br> `expiry_date[uint64]` (big-endian) <br> `transaction_kind[uint8]` (transfer-with-memo kind, e.g. `22` / `0x16`) <br> `recipient_address[uint256]` <br> `memo_length[uint16]` (big-endian; total CBOR memo size in bytes) | First packet of the flow. Recipient is shown as base58. **`memo_length`** is hashed; memo payload follows in **`P1=0x02`** APDUs. |
| `0x32` | `0x01` | `0x01` | `path_length[uint8]` <br> `path[uint32 * $path_length]` (each node big-endian; hardened bit `0x80000000`) <br> `sender_address [uint256]` <br> `nonce [uint64]` (big-endian) <br> `energy_amount [uint64]` (big-endian) <br> `payload_size[uint32]` (big-endian) <br> `expiry_date[uint64]` (big-endian) <br> `transaction_kind[uint8]` <br> `recipient_address[uint256]` <br> `memo_length[uint16]` (big-endian) <br> `display_fee_microccd[uint64]` (big-endian) | Same layout as `P2=0x00` for this `P1`, with **`display_fee_microccd`** (8 bytes) immediately after **`memo_length`** (from **v5.6.0**). **`display_fee_microccd`** is **for display only** and is **not** hashed. **Max fees** on screen unless **`0xFFFFFFFFFFFFFFFF`** (omit sentinel). With this `P2`, **`energy_amount`** is not shown. Same semantics as INS **`0x02`** / **`P2=0x01`** ([Transfer transaction](#transfer-transaction)); see [ins_get_app_version.md](ins_get_app_version.md). |
| `0x32` | `0x02` | `0x00` | `memo[1...255 bytes]`                                                                                                                       | The memo is assumed to be CBOR encoded. |
| `0x32` | `0x03` | `0x00` | `amount[uint64]`                                                                                                                            | The amount is in µCCD.                  |


## Sample command disassembly (first packet only). Actual for v5.5.x of the app

### `P2 = 0x00`

| Field name | Size (bytes) | Sample |
| ---------- | ------------ | ------ |
| CLA | 1 | `0xe0` |
| INS | 1 | `0x32` |
| P1 | 1 | `0x01` |
| P2 | 1 | `0x00` |
| Lc | 1 | `0x78` (120 bytes of CDATA for `path_length = 6`) |
| Path length | 1 | `0x06` |
| Path | 24 | `0x0000002c` `0x00000397` `0x00000000` `0x00000000` `0x00000000` `0x00000000` |
| Account sender | 32 | `0x20a84581_5bd43a19_99e90fbf_971537a7_0392eb38_f89e6bd3_b3dd70e_1a9551d7` |
| Nonce | 8 | `0x000000000000000a` |
| Energy amount | 8 | `0x0000000000000064` |
| Payload size | 4 | `0x00000029` |
| Expiry date | 8 | `00000000_00000000_63de5da7` |
| Tx kind | 1 | `0x16` (22 — transfer with memo) |
| Account receiver | 32 | `0x20a84581_5bd43a19_99e90fbf_971537a7_0392eb38_f89e6bd3_b3dd70e_1a9551d7` |
| Memo length | 2 | `0x0000` |

### `P2 = 0x01` (display fee suffix)

From **v5.6.0** onward, the first-packet layout for **`P2 = 0x01`** is the same as **`P2 = 0x00`** through **Memo length**, followed by **`display_fee_microccd`** (8 bytes, big-endian). **Lc** is **128** (`0x80`): 120 bytes for the fields above plus 8 for the fee field.

| Field name | Size (bytes) | Sample |
| ---------- | ------------ | ------ |
| CLA | 1 | `0xe0` |
| INS | 1 | `0x32` |
| P1 | 1 | `0x01` |
| P2 | 1 | `0x01` |
| Lc | 1 | `0x80` (128 bytes of CDATA) |
| Path length | 1 | `0x06` |
| Path | 24 | `0x0000002c` `0x00000397` `0x00000000` `0x00000000` `0x00000000` `0x00000000` |
| Account sender | 32 | `0x20a84581_5bd43a19_99e90fbf_971537a7_0392eb38_f89e6bd3_b3dd70e_1a9551d7` |
| Nonce | 8 | `0000_0000_0000_000a` |
| Energy amount | 8 | `0000_0000_0000_0064` |
| Payload size | 4 | `0x00000029` |
| Expiry date | 8 | `00000000_00000000_63de5da7` |
| Tx kind | 1 | `0x16` |
| Account receiver | 32 | `0x20a84581_5bd43a19_99e90fbf_971537a7_0392eb38_f89e6bd3_b3dd70e_1a9551d7` |
| Memo length | 2 | `0x0000` |
| Display fee (µCCD, big-endian, not hashed) | 8 | `0x0000000000002710` (example: 10 000 µCCD; or `0xFF…FF` to omit the fee line) |
