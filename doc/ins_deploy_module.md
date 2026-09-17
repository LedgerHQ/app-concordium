# DEPLOY MODULE

Signs a Concordium `DeployModule` account transaction (transaction kind `0`), which uploads a
smart-contract module to the chain.

The module source is streamed in as many packets as its length requires. It is hashed twice: into
the transaction hash that gets signed, and separately into a SHA-256 digest that is shown on the
approval screen, so the user reviews a commitment to the code being deployed rather than only its
length.

## Instruction

| CLA | INS | P1 | P2 | Lc |
| --- | --- | -- | -- | -- |
| `0xE0` | `0x06` | `0x00`, `0x01` | `0x00` | var |

## Packet sequence

| Order | P1 | Contents |
| ----- | -- | -------- |
| 1 | `0x00` | Derivation path, account-transaction header, transaction kind, module version, source length |
| 2..n | `0x01` | Module source bytes, until `source length` bytes have been sent |

`P1 = 0x00` is accepted only as the first packet of the flow. A `P1 = 0x01` packet that arrives
when no source bytes are outstanding is refused with `ERROR_INVALID_STATE`.

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
| Tx kind | 1 | `0x00` (deploy module) — refused with `ERROR_INVALID_TRANSACTION` if it is anything else |
| Module version | 4 | Big-endian uint32, shown on the review screen |
| Source length | 4 | Big-endian uint32; total module source bytes to follow |

The account-transaction header is 60 bytes (`ACCOUNT_TRANSACTION_HEADER_LENGTH`), followed by the
1-byte transaction kind.

### Source packets (`P1 = 0x01`)

Raw module bytes, up to 255 per packet. A packet carrying more bytes than are still outstanding is
refused with `ERROR_INVALID_SOURCE_LENGTH`. Each packet is answered with `0x9000` and no UI; the
review appears once the final byte has been received.

## Review screens

| Row | Value |
| --- | ----- |
| Version | Module version from the first packet |
| Module hash | SHA-256 of the whole module source, hex |

Plus the rows every account transaction shows: sender, signed energy limit and network.

The module hash is the only honest on-device representation of the source: the module is far too
large to render, so the user is expected to compare this digest against the one their tooling
reports for the module being deployed.

## Response

Signature over the transaction hash, returned after approval. See
[`error.md`](error.md) for the status words this instruction can return.
