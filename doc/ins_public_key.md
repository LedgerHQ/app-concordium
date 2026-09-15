# Export public key

Provides the ability to export public-keys for accounts, and also for governance keys. The key to
be exported is defined by the key derivation path that is provided, which can either be for an
account or for a governance key.

## Protocol description

- Single command

| INS    | P1     | P2     | CDATA                 | Comment                                                |
| ------ | ------ | ------ | --------------------- | ------------------------------------------------------ |
| `0x01` | `0x00` | `0x00` | `path[uint32]x[5..8]` | Export of a public-key with user acceptance.           |
| `0x01` | `0x01` | `0x00` | `path[uint32]x[5..8]` | Export of a public-key without user acceptance.        |
| `0x01` | `0x00` | `0x01` | `path[uint32]x[5..8]` | Export of a signed public-key with user acceptance.    |
| `0x01` | `0x01` | `0x01` | `path[uint32]x[5..8]` | Export of a signed public-key without user acceptance. |

## Comparison screen and concurrent instructions

With user acceptance (`P1 = 0x00`) the flow is: a review screen asks the user to approve the
export, then the response is sent, and only then is the key shown for the user to compare
against what their host displays.

The app deliberately keeps accepting instructions while that comparison screen is up, since its
reply has already gone out. Accepting a new instruction clears and reuses the instruction context
the screen would otherwise be drawn from, so the identity string and public key are copied into
storage outside that context first and stay put until the user leaves the screen. Without the
copy a host could change the key the user is comparing against while they are looking at it.
