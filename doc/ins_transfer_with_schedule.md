# Transfer with schedule

A transaction to send CCD from one account to another with a schedule: each release of CCD can be set for a specific time.

## Protocol description

- Multiple commands

| INS    | P1     | P2     | CDATA                                                                                                                                                                                                                                                                                                                                                                                                 | Comment |
| ------ | ------ | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `0x03` | `0x00` | `0x00` | `path_length[uint8]` <br> `path[uint32 * $path_length]` (each node big-endian; hardened bit `0x80000000`) <br> `sender_address [uint256]` <br> `nonce [uint64]` (big-endian) <br> `energy_amount [uint64]` (big-endian) <br> `payload_size[uint32]` (big-endian) <br> `expiry_date[uint64]` (big-endian) <br> `transaction_kind[uint8]` (must be **`19`** / `0x13` — scheduled transfer) <br> `recipient_address[uint256]` <br> `scheduled_amounts_count[uint8]` | First packet. Recipient is shown as base58. **`scheduled_amounts_count`** is the total number of `(timestamp, amount)` pairs; pairs are sent in following APDUs (`P1=0x01`). |
| `0x03` | `0x00` | `0x01` | `path_length[uint8]` <br> `path[uint32 * $path_length]` (each node big-endian; hardened bit `0x80000000`) <br> `sender_address [uint256]` <br> `nonce [uint64]` (big-endian) <br> `energy_amount [uint64]` (big-endian) <br> `payload_size[uint32]` (big-endian) <br> `expiry_date[uint64]` (big-endian) <br> `transaction_kind[uint8]` <br> `recipient_address[uint256]` <br> `scheduled_amounts_count[uint8]` <br> `display_fee_microccd[uint64]` (big-endian) | Same layout as `P2=0x00` for this `P1`, with **`display_fee_microccd`** (8 bytes) immediately after **`scheduled_amounts_count`** (from **v5.6.0**). **`display_fee_microccd`** is **for display only** and is **not** hashed. **Max fees** on screen unless **`0xFFFFFFFFFFFFFFFF`** (omit sentinel). With this `P2`, **`energy_amount`** is not shown. Same semantics as [INS `0x02` / `P2=0x01`](ins_transfer.md#transfer-transaction); see [ins_get_app_version.md](ins_get_app_version.md). Further packets in this flow use **`P2=0x00`**. |
| `0x03` | `0x01` | `0x00` | `(timestamp[uint64] amount[uint64])` × *n* (each scalar big-endian) | Scheduled release rows. Up to **15** `(timestamp, amount)` pairs per packet; repeat until **`scheduled_amounts_count`** pairs have been sent in total. If more than 15 remain, send **15** in this packet. |

# Transfer with schedule with memo

A transfer with schedule **and** a memo. Same flow idea as [Transfer with memo](ins_transfer.md#transfer-with-memo), but INS is **`0x34`**, **`P1`** values differ, and **`transaction_kind`** must be **`24`** / `0x18`.

## Protocol description

- Multiple commands

| INS    | P1     | P2     | CDATA                                                                                                                                                                                                                                                                                                                                                                                                 | Comment |
| ------ | ------ | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `0x34` | `0x02` | `0x00` | `path_length[uint8]` <br> `path[uint32 * $path_length]` (each node big-endian; hardened bit `0x80000000`) <br> `sender_address [uint256]` <br> `nonce [uint64]` (big-endian) <br> `energy_amount [uint64]` (big-endian) <br> `payload_size[uint32]` (big-endian) <br> `expiry_date[uint64]` (big-endian) <br> `transaction_kind[uint8]` (must be **`24`** / `0x18`) <br> `recipient_address[uint256]` <br> `scheduled_amounts_count[uint8]` <br> `memo_length[uint16]` (big-endian; total CBOR memo size in bytes) | First packet. **`memo_length`** is hashed; memo bytes use **`P1=0x03`**. |
| `0x34` | `0x02` | `0x01` | `path_length[uint8]` <br> `path[uint32 * $path_length]` (each node big-endian; hardened bit `0x80000000`) <br> `sender_address [uint256]` <br> `nonce [uint64]` (big-endian) <br> `energy_amount [uint64]` (big-endian) <br> `payload_size[uint32]` (big-endian) <br> `expiry_date[uint64]` (big-endian) <br> `transaction_kind[uint8]` <br> `recipient_address[uint256]` <br> `scheduled_amounts_count[uint8]` <br> `memo_length[uint16]` (big-endian) <br> `display_fee_microccd[uint64]` (big-endian) | Same layout as `P2=0x00` for this `P1`, with **`display_fee_microccd`** (8 bytes) immediately after **`memo_length`** (from **v5.6.0**). Display-only / not hashed; **Max fees**; omit sentinel **`0xFFFFFFFFFFFFFFFF`**; **`energy_amount`** not shown on device. Memo / pair packets: **`P2=0x00`**. See [ins_get_app_version.md](ins_get_app_version.md). |
| `0x34` | `0x03` | `0x00` | `memo[1…255 bytes]` | CBOR memo payload. |
| `0x34` | `0x01` | `0x00` | `(timestamp[uint64] amount[uint64])` × *n* (each scalar big-endian) | Same rules as INS **`0x03`** / `P1=0x01` for pair batching (up to 15 per packet, etc.). |

## Sample command disassembly (first packet only)

Illustrative layout for **`path_length = 6`** (24-byte path). **Lc** = sum of all CDATA fields in that row.

### INS `0x03` — `P1 = 0x00`

#### `P2 = 0x00`

| Field name | Size (bytes) | Notes |
| ---------- | ------------ | ----- |
| CLA | 1 | `0xe0` |
| INS | 1 | `0x03` |
| P1 | 1 | `0x00` |
| P2 | 1 | `0x00` |
| Lc | 1 | `0x77` (119 bytes of CDATA) |
| Path length | 1 | `0x06` |
| Path | 24 | six `uint32` nodes, big-endian |
| Account header + kind | 61 | same 60-byte account transaction header + 1-byte `transaction_kind` as other transfers |
| Account receiver | 32 | raw recipient address bytes |
| Scheduled amounts count | 1 | total pair count for the whole flow |

#### `P2 = 0x01` (display fee — from **v5.6.0**)

Same fields and values as **`P2 = 0x00`** through **Scheduled amounts count**, followed by **`display_fee_microccd`** (8 bytes, big-endian). **Lc** is **127** (`0x7F`) = 119 + 8.

| Field name | Size (bytes) | Notes |
| ---------- | ------------ | ----- |
| CLA | 1 | `0xe0` |
| INS | 1 | `0x03` |
| P1 | 1 | `0x00` |
| P2 | 1 | `0x01` |
| Lc | 1 | `0x7F` (127 bytes of CDATA) |
| Path length | 1 | `0x06` |
| Path | 24 | six `uint32` nodes, big-endian |
| Account header + kind | 61 | same 60-byte header + `transaction_kind` **`0x13`** (19) |
| Account receiver | 32 | raw recipient address bytes |
| Scheduled amounts count | 1 | total pair count for the whole flow |
| Display fee (µCCD, big-endian, not hashed) | 8 | Example: `0x0000000000002710` (10 000 µCCD) or `0xFF…FF` to omit the fee line |

### INS `0x34` — `P1 = 0x02`

#### `P2 = 0x00`

| Field name | Size (bytes) | Notes |
| ---------- | ------------ | ----- |
| CLA | 1 | `0xe0` |
| INS | 1 | `0x34` |
| P1 | 1 | `0x02` |
| P2 | 1 | `0x00` |
| Lc | 1 | `0x79` (121 bytes of CDATA for `path_length = 6`) |
| Path length | 1 | `0x06` |
| Path | 24 | six `uint32` nodes |
| Account header + kind | 61 | `transaction_kind` = **24** |
| Account receiver | 32 | |
| Scheduled amounts count | 1 | |
| Memo length | 2 | big-endian; CBOR length |

#### `P2 = 0x01` (display fee — from **v5.6.0**)

Same fields and values as **`P2 = 0x00`** through **Memo length**, followed by **`display_fee_microccd`** (8 bytes, big-endian). **Lc** is **129** (`0x81`) = 121 + 8.

| Field name | Size (bytes) | Notes |
| ---------- | ------------ | ----- |
| CLA | 1 | `0xe0` |
| INS | 1 | `0x34` |
| P1 | 1 | `0x02` |
| P2 | 1 | `0x01` |
| Lc | 1 | `0x81` (129 bytes of CDATA) |
| Path length | 1 | `0x06` |
| Path | 24 | six `uint32` nodes |
| Account header + kind | 61 | `transaction_kind` = **`0x18`** (24) |
| Account receiver | 32 | |
| Scheduled amounts count | 1 | |
| Memo length | 2 | big-endian; CBOR length |
| Display fee (µCCD, big-endian, not hashed) | 8 | Example: `0x0000000000002710` or `0xFF…FF` to omit the fee line |
