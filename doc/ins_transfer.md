# Transfer transaction

A transaction to transfer GTU from one account to another.

## Protocol description

- Single command

| INS    | P1     | P2     | CDATA                                                                                                                                  | Comment                                                        |
| ------ | ------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `0x02` | `0x00` | `0x00` | `path_length[uint8]` <br> `path[uint32 * $path_length]` <br> `sender_address [uint256]` <br> `nonce [uint64]` <br> `energy_amount [uint64]` <br> `payload_size[uint32]` <br> `expiry_date[uint64]` <br> `transaction_kind[uint8]` <br> `recipient_address[uint256]` <br> `amount[uint64]` | The amount is in µGTU. The recipient address has to be base58. |

# Transfer with memo

A transaction to transfer GTU from one account to another, with a memo attached.
Uses the same INS number, but a different P1 for the initial call, and has a different transaction kind (22);

## Protocol description

- Multiple commands

| INS    | P1     | P2     | CDATA                                                                                                                                       | Comment                                 |
| ------ | ------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- |
| `0x02` | `0x01` | `0x00` |  `path_length[uint8]` <br> `path[uint32 * $path_length]` <br> `sender_address [uint256]` <br> `nonce [uint64]` <br> `energy_amount [uint64]` <br> `payload_size[uint32]` <br> `expiry_date[uint64]` <br> `transaction_kind[uint8]` <br> `recipient_address[uint256]` <br> `memo_length[uint16]` | The recipient address has to be base58. |
| `0x02` | `0x02` | `0x00` | `memo[1...255 bytes]`                                                                                                                       | The memo is assumed to be CBOR encoded. |
| `0x02` | `0x03` | `0x00` | `amount[uint64]`                                                                                                                            | The amount is in µGTU.                  |


## Sample command disassembly. Actual for v5.4.0 of the app


|Field name| Size(bytes) |Sample|
|-|-|-|
|CLS| 1|`0xe0`|
|INS|1|`0x02`|
|p1|1|`0x01`|
|p2|1|`0x00`|
|CL|1|`0x7e`|
|Path_len|1|`0x06`|
|Path|32| `0x0000002c_00000397_00000000_00000000_00000000_00000000`|
|Account sender|32|`0x20a84581_5bd43a19_99e90fbf_971537a7_0392eb38_f89e6bd3_b3dd70e_1a9551d7`|
|Nonce|8|`0000_0000_0000_000a`|
|Energy amount|8|`0000_0000_0000_0064`|
|Payload size|1|`0x29`|
|Expiry date|1|`00000000_63de5da7`|
|Tx kind|1|`0x03`|
|Account receiver|32|`0x20a84581_5bd43a19_99e90fbf_971537a7_0392eb38_f89e6bd3_b3dd70e_1a9551d7`|
|Amount|8|`ffff_ffff_ffff_ffff`|
