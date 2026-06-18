# Get application version

## Protocol description

- Single command

| INS    | P1     | P2     | CDATA                                                                                                                                  | Comment                                                        |
| ------ | ------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `0x40` | `0x00` | `0x00` | `--` |  |

Returns [MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION] as an array of three uint8.

