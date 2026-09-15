# UPDATE CONTRACT

Signs a Concordium `Update` account transaction (transaction kind `2`), which invokes a receive
function on an existing smart-contract instance.

The packet structure mirrors [`ins_init_contract.md`](ins_init_contract.md); the difference is in
the first packet, which identifies an existing instance by index and sub-index instead of naming a
module.

## Instruction

| CLA | INS | P1 | P2 | Lc |
| --- | --- | -- | -- | -- |
| `0xE0` | `0x08` | `0x00`, `0x01`, `0x02` | `0x00` | var |

## Packet sequence

| Order | P1 | Contents |
| ----- | -- | -------- |
| 1 | `0x00` | Derivation path, account-transaction header, transaction kind, amount, index, sub-index |
| 2..n | `0x01` | Receive name: 2-byte length prefix, then name bytes |
| n+1..m | `0x02` | Parameters: 2-byte length prefix, then parameter bytes |

`P1 = 0x00` is accepted only as the first packet of the flow.

### First packet (`P1 = 0x00`)

| Field name | Size (bytes) | Description |
| ---------- | ------------ | ----------- |
| Path length | 1 | Number of path nodes |
| Path | `4 x path_length` | Derivation path, one big-endian uint32 per node |
| Account sender | 32 | Sender address |
| Nonce | 8 | Account nonce |
| Energy amount | 8 | Signed energy limit; shown on the review screen |
| Payload size | 4 | Payload byte count |
| Expiry date | 8 | Transaction expiry |
| Tx kind | 1 | `0x02` (update contract) — refused with `ERROR_INVALID_TRANSACTION` otherwise |
| Amount | 8 | Big-endian uint64, microCCD sent with the invocation |
| Index | 8 | Big-endian uint64, contract instance index |
| Sub index | 8 | Big-endian uint64, contract instance sub-index |

### Name packets (`P1 = 0x01`)

The first name packet starts with a 2-byte big-endian length, then name bytes; later packets carry
name bytes only. A packet longer than the outstanding name length is refused with
`ERROR_INVALID_NAME_LENGTH`.

**The receive name must be displayable.** Every chunk is checked before it is hashed or copied,
and a chunk containing a NUL or any other non-renderable byte is refused with
`ERROR_INVALID_TRANSACTION`. This name is the entrypoint being invoked, so a name such as
`transfer\0_drain_wallet` reviewed as `transfer` would be a disguised method call.

A name of `CONTRACT_NAME_SIZE` or longer is replaced on screen by
`(too long to display - see hash)` rather than being truncated. The digest below still covers the
exact bytes.

### Parameter packets (`P1 = 0x02`)

The first parameter packet starts with a 2-byte big-endian length, then parameter bytes; later
packets carry parameter bytes only. A packet longer than the outstanding length is refused with
`ERROR_INVALID_PARAMS_LENGTH`.

Parameters are arbitrary binary of up to 64 KiB, so they are never rendered — only digested.

## Review screens

| Row | Value |
| --- | ----- |
| Amount | microCCD sent with the invocation, formatted as CCD |
| Index | Contract instance index |
| Sub index | Contract instance sub-index |
| Receive name | The name, or `(too long to display - see hash)` |
| Payload hash | SHA-256 over the name bytes and the parameter bytes |

Plus the rows every account transaction shows: sender, signed energy limit and network.

## Response

Signature over the transaction hash, returned after approval. See
[`error.md`](error.md) for the status words this instruction can return.
