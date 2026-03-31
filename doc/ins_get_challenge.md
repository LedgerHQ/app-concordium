# Get Challenge

Generates a cryptographically secure random challenge and keeps it in device memory. The challenge is single-use: it is erased when [Set Trusted Name](ins_set_trusted_name.md) succeeds.

The host embeds this challenge in the TLV descriptor (tag `0x12`) so the firmware can verify freshness.

## Protocol description

- Single command

| CLA    | INS    | P1     | P2     | Lc     | CDATA | Comment        |
| ------ | ------ | ------ | ------ | ------ | ----- | -------------- |
| `0xE0` | `0x23` | `0x00` | `0x00` | `0x00` | `--`  | No command data |

## Response

| Field  | Length (bytes) | Description                                      |
| ------ | -------------- | ------------------------------------------------ |
| RData  | 8              | Random `uint64_t` in big-endian byte order       |
| SW     | 2              | Status word (`0x9000` on success)                |

## Behavior

- Each call generates a new random challenge and overwrites the previous one
- The challenge is stored in `global.trustedNamePki.stored_challenge` (instruction-context union; see `trustedNamePki.h`) until:
  - A new challenge is requested (overwritten), or
  - `eraseChallenge()` is called when SET\_TRUSTED\_NAME succeeds
- The challenge must be called **before** SET\_TRUSTED\_NAME; the firmware rejects descriptors with a mismatched or zero challenge
