# INIT CONTRACT

Signs a Concordium `InitContract` account transaction (transaction kind `1`), which instantiates a
smart contract from an already-deployed module.

## Instruction

| CLA | INS | P1 | P2 | Lc |
| --- | --- | -- | -- | -- |
| `0xE0` | `0x07` | `0x00`, `0x01`, `0x02` | `0x00` | var |

## Packet sequence

| Order | P1 | Contents |
| ----- | -- | -------- |
| 1 | `0x00` | Derivation path, account-transaction header, transaction kind, amount, module reference |
| 2..n | `0x01` | Contract name: 2-byte length prefix, then name bytes |
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
| Tx kind | 1 | `0x01` (init contract) — refused with `ERROR_INVALID_TRANSACTION` otherwise |
| Amount | 8 | Big-endian uint64, microCCD sent to the new instance |
| Module reference | 32 | Module to instantiate |

### Name packets (`P1 = 0x01`)

The first name packet starts with a 2-byte big-endian length, then name bytes; later packets carry
name bytes only. A packet longer than the outstanding name length is refused with
`ERROR_INVALID_NAME_LENGTH`.

**The name must be displayable.** Every chunk is checked before it is hashed or copied, and a
chunk containing a NUL or any other non-renderable byte is refused with
`ERROR_INVALID_TRANSACTION`. Without that check a name such as `init_transfer\0_drain` would be
reviewed as `init_transfer` while the signature covered every byte.

A name of `CONTRACT_NAME_SIZE` or longer is replaced on screen by
`(too long to display - see hash)` rather than being truncated — a shortened name would let a host
disguise which contract is being instantiated. The digest below still covers the exact bytes.

### Parameter packets (`P1 = 0x02`)

The first parameter packet starts with a 2-byte big-endian length, then parameter bytes; later
packets carry parameter bytes only. A packet longer than the outstanding length is refused with
`ERROR_INVALID_PARAMS_LENGTH`.

Parameters are arbitrary binary of up to 64 KiB, so they are never rendered — only digested.

## Review screens

| Row | Value |
| --- | ----- |
| Amount | microCCD sent to the instance, formatted as CCD |
| Module ref | Module reference, hex |
| Contract name | The name, or `(too long to display - see hash)` |
| Payload hash | SHA-256 over the name bytes and the parameter bytes |

Plus the rows every account transaction shows: sender, signed energy limit and network.

`Payload hash` covers the name as well as the parameters, so the signed name is represented even
when it is too long to render.

## Response

Signature over the transaction hash, returned after approval. See
[`error.md`](error.md) for the status words this instruction can return.
