# Verify Address

Given an identity index and a credential counter/account index this function displays the associated account address.

Allows the user to approve or reject the address, determining whether the app returns success or rejection.

For an account address to match the one that is displayed, the account's primary credential must be made using the PRF-key exported by the same Ledger on the same identity index and credential counter.
The address is the credId's sh256 hash, and is displayed in base58.

The review has three rows:

| Row | Value |
| --- | ----- |
| `Identity` / `Derivation path` | `identityProvider/identity/credCounter` for the compact formats (`P1 = 0x00`, `P1 = 0x01`). For the full-path format (`P1 = 0x02`) the row is labelled `Derivation path` and shows every node of the path, e.g. `44'/919'/403'/404'/8'` — all of them reach key derivation, so showing only a fixed three would let a hidden suffix change the address behind an unchanged label |
| `Network` | `Mainnet`, `Testnet` or `Legacy (any network)`, from the coin type the path commits to. The host picks the network (via `P2`, or the coin-type node of a full path) and it changes the derived key, while mainnet and testnet addresses are encoded identically, so the address alone does not reveal it |
| `Address` | The base58 account address, always derived on device from the path and credential counter under review |

## Protocol description

- Single command

| INS    | P1     | P2     | CDATA                                                           | Comment                                                                        |
| ------ | ------ | ------ | --------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `0x00` | `0x00` | `0x00` | `identity[uint32] credCounter[uint32]`                          | Legacy derivation path. CDATA is exactly 8 bytes                               |
| `0x00` | `0x01` | `0x00` | `identityProvider[uint32] identity[uint32] credCounter[uint32]` | New MainNet derivation path with identity provider. CDATA is exactly 12 bytes  |
| `0x00` | `0x01` | `0x01` | `identityProvider[uint32] identity[uint32] credCounter[uint32]` | New TestNet derivation path with identity provider. CDATA is exactly 12 bytes  |
| `0x00` | `0x02` | `0x00` | `<derivation-path>` (variable length)                           | Derivation path as serialized bytes                                            |

The compact formats (`P1 = 0x00` and `P1 = 0x01`) carry plain, unhardened indices; the app applies the hardened bit itself. Values with bit 31 already set are rejected with `ERROR_INVALID_PATH`. Hardened nodes are only used in the `P1 = 0x02` serialization described below.

### Derivation-path serialization

`<derivation-path>` is serialized as `<n> <node 1> ... <node n>`:

| Field    | Size   | Description                                      |
| -------- | ------ | ------------------------------------------------ |
| `<n>`    | 1 byte | Depth of the derivation path                     |
| `<node>` | 4 bytes| Path node, big-endian `uint32` (hardened = `0x80000000 \| index`) |

For `P1 = 0x02` (full-path mode) there is no separate credential counter field in CDATA; the app uses the parsed path as given and `cred_counter == 0` in the BLS address step. Use `P1 = 0x01` / `P1 = 0x00` when you need an explicit `credCounter` in the APDU. A zero-node path is rejected with `ERROR_INVALID_PATH` (`0x6B02`); every other depth up to 8 is accepted and rendered in full on the review.

That last point holds only while no trusted-name descriptor is loaded. With one loaded, `P1 = 0x02` must carry the account signing path — 6 nodes, purpose `44'`, key role `0'` at node 4 — because that is the shape whose tag `0x22` key names a single credential counter, and it is the shape under which the descriptor's address is displayed without the device deriving one. A full path of any other shape is refused with `ERROR_TRUSTED_NAME_MISMATCH` (`0x6B0C`) and the descriptor is dropped. `P1 = 0x02` is the host's choice and carries no proof of what was sent, so the shape is checked rather than assumed.

### Example

Account 8 derived at `44'/919'/403'/404'/8'`:

| Typed representation | Byte representation (hex) |
| -------------------- | ------------------------ |
| `0x05 0x8000002C 0x80000397 0x80000193 0x80000194 0x80000008` | `05 80 00 00 2C 80 00 03 97 80 00 01 93 80 00 01 94 80 00 00 08` |
