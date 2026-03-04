# Get Challenge

Generates a cryptographically secure random challenge and keeps it in device memory. The challenge can be used only once. When the trusted name is loaded, the challenge must be erased.

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
- The challenge is stored in device memory until:
  - A new challenge is requested (overwritten), or
  - `eraseChallenge()` is called (e.g. when the trusted name is loaded)
