# Transfer transaction

A transaction to transfer CCD from one account to another.

## Protocol description

- Single command

| INS    | P1     | P2     | CDATA                                                                                                                                  | Comment                                                        |
| ------ | ------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `0x02` | `0x00` | `0x00` | `path_length[uint8]` <br> `path[uint32 * $path_length]` <br> `sender_address [uint256]` <br> `nonce [uint64]` <br> `energy_amount [uint64]` <br> `payload_size[uint32]` <br> `expiry_date[uint64]` <br> `transaction_kind[uint8]` <br> `recipient_address[uint256]` <br> `amount[uint64]` | The amount is in µCCD. The recipient address has to be base58. |

| `0x02` | `0x00` | `0x01` | Same as `P2=0x00` row, then `display_fee_microccd [uint64]` big-endian | **Display-only** fee in µCCD (not hashed). Shown on device as **Max fees** when the value is not the omit sentinel. Use only with a firmware version that documents this extension (see [ins_get_app_version.md](ins_get_app_version.md)). Send `0xFFFFFFFFFFFFFFFF` to omit the extra fee line while keeping `P2=0x01`. Header **`energy_amount`** is **not** shown on the device. |

# Transfer with memo

A transaction to transfer CCD from one account to another, with a memo attached.
Uses the same INS number, but a different P1 for the initial call, and has a different transaction kind (22);

## Protocol description

- Multiple commands

| INS    | P1     | P2     | CDATA                                                                                                                                       | Comment                                 |
| ------ | ------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `0x32` | `0x01` | `0x00` | `path_length[uint8]` <br> `path[uint32 * $path_length]` <br> `sender_address [uint256]` <br> `nonce [uint64]` <br> `energy_amount [uint64]` <br> `payload_size[uint32]` <br> `expiry_date[uint64]` <br> `transaction_kind[uint8]` <br> `recipient_address[uint256]` <br> `memo_length[uint16]` | The recipient address has to be base58. |

| `0x32` | `0x01` | `0x01` | Same as `P2=0x00` row, then `display_fee_microccd [uint64]` big-endian | **Display-only** fee in µCCD (not hashed), on-device label **Max fees**. Same rules as the simple transfer command (INS `0x02`, [above](#transfer-transaction)). |
| `0x32` | `0x02` | `0x00` | `memo[1...255 bytes]`                                                                                                                       | The memo is assumed to be CBOR encoded. |
| `0x32` | `0x03` | `0x00` | `amount[uint64]`                                                                                                                            | The amount is in µCCD.                  |


## Sample command disassembly (first packet only). Actual for v5.5.x of the app


|Field name| Size(bytes) |Sample|
|-|-|-|
|CLS| 1|`0xe0`|
|INS|1|`0x32`|
|p1|1|`0x01`|
|p2|1|`0x00`|
|CL|1|`0x80`|
|Path_len|1|`0x06`|
|Path|32| `0x0000002c_00000397_00000000_00000000_00000000_00000000`|
|Account sender|32|`0x20a84581_5bd43a19_99e90fbf_971537a7_0392eb38_f89e6bd3_b3dd70e_1a9551d7`|
|Nonce|8|`0000_0000_0000_000a`|
|Energy amount|8|`0000_0000_0000_0064`|
|Payload size|4|`0x00000029`|
|Expiry date|8|`00000000_00000000_63de5da7`|
|Tx kind|1|`0x16`|
|Account receiver|32|`0x20a84581_5bd43a19_99e90fbf_971537a7_0392eb38_f89e6bd3_b3dd70e_1a9551d7`|
|Memo length|2|`0x0000`|
