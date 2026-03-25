# Verify Address

Given an identity index and a credential counter/account index this function displays the associated account address.

Allows the user to approve or reject the address, determining whether the app returns success or rejection.

For an account address to match the one that is displayed, the account's primary credential must be made using the PRF-key exported by the same Ledger on the same identity index and credential counter.
The address is the credId's sh256 hash, and is displayed in base58.

## Protocol description

- Single command

| INS    | P1     | P2     | CDATA                                                             | Comment                                            |
| ------ | ------ | ------ | ----------------------------------------------------------------- | -------------------------------------------------- |
| `0x00` | `0x00` | `0x00` | `identity[uint32] credCounter[uint32]`                            | Legacy derivation path                             |
| `0x00` | `0x01` | `0x00` | `identityProvider[32 bytes] identity[uint32] credCounter[uint32]` | New MainNet derivation path with identity provider |
| `0x00` | `0x01` | `0x01` | `identityProvider[32 bytes] identity[uint32] credCounter[uint32]` | New TestNet derivation path with identity provider |
| `0x00` | `0x02` | `0x00` | var    | `<derivation-path>` | Derivation path as serialized bytes |

### Derivation-path serialization

`<derivation-path>` is serialized as `<n> <node 1> ... <node n>`:

| Field    | Size   | Description                                      |
| -------- | ------ | ------------------------------------------------ |
| `<n>`    | 1 byte | Depth of the derivation path                     |
| `<node>` | 4 bytes| Path node, big-endian `uint32` (hardened = `0x80000000 \| index`) |

For `P1` full-path mode there is no separate credential counter field in CDATA; the app uses the parsed path as given and `cred_counter == 0` in the BLS address step. Use `P1_NEW_PATH` / `P1_LEGACY_PATH` when you need an explicit `credCounter` in the APDU.

### Example

Account 8 derived at `44'/919'/403'/404'/8'`:

| Typed representation | Byte representation (hex) |
| -------------------- | ------------------------ |
| `0x05 0x8000002C 0x80000397 0x80000193 0x80000194 0x80000008` | `05 80 00 00 2C 80 00 03 97 80 00 01 94 80 00 01 94 80 00 00 08` |
