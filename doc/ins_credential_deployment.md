# CREDENTIAL DEPLOYMENT

Signs a Concordium credential deployment — either as a standalone transaction that creates a new
account (or attaches a credential to an existing one), or as the credential payload embedded in an
[update-credential](#shared-with-update-credential) transaction.

This is the longest flow in the app. A credential is a large structure with several
variable-length lists, so it arrives as a sequence of packets selected by `P1`, each valid only in
the state the previous packet left behind. A packet sent out of order is refused with
`ERROR_INVALID_STATE`, so a host cannot skip a stage or replay one to overwrite a value that has
already been reviewed.

## Instruction

| CLA | INS | P1 | P2 | Lc |
| --- | --- | -- | -- | -- |
| `0xE0` | `0x04` | see below | `0x00` standalone, `0x02` embedded | var |

P2 is not validated: the handler only tests for `0x02` at the two points described under
[Shared with update credential](#shared-with-update-credential), and treats every other value as
the standalone case. Hosts send `0x00` for standalone deployments.

## Packet sequence

| Order | P1 | Contents |
| ----- | -- | -------- |
| 1 | `0x00` | Derivation path; initialises the transaction hash |
| 2 | `0x0A` | Number of verification keys (1 byte) |
| 3..n | `0x01` | One verification key per packet, repeated for each key |
| n+1 | `0x02` | Signature threshold, RegIdCred, identity-provider identity, anonymity-revocation threshold, AR list length |
| ... | `0x03` | One `arIdentity` / `encIdCredPubShare` pair per packet, repeated for each AR |
| ... | `0x04` | Credential `valid to` and `created at` dates |
| ... | `0x05` | Attribute tag and attribute value length |
| ... | `0x06` | Attribute value; `0x05` and `0x06` repeat for each revealed attribute |
| ... | `0x07` | Byte length of the proofs (4 bytes, big-endian) |
| ... | `0x08` | Proof bytes, 255 per packet until the length is exhausted |
| last | `0x09` | New-or-existing discriminator, then the new-account threshold or the existing account address |

Note `P1 = 0x0A` is out of numeric order: it was added after `0x01`–`0x09` were assigned.

### Final packet (`P1 = 0x09`)

| Field name | Size (bytes) | Description |
| ---------- | ------------ | ----------- |
| New or existing | 1 | `0` = new account, `1` = existing account |
| Threshold *or* address | 8 or 32 | 8 bytes of threshold data when `0`; a 32-byte account address when `1` |

## Review screens

Reviews are interleaved with the packet flow rather than all shown at the end, because several of
the fields are overwritten by later packets.

**Verification keys.** Each key is displayed as it arrives, and the flow parks in
`TX_CREDENTIAL_DEPLOYMENT_AWAITING_VERIFICATION_KEY_CONFIRM` until the user accepts it. No key
packet is accepted in that state, so a later key cannot overwrite the one on screen.

**Anonymity revokers.** Each AR packet overwrites the previous `arIdentity` /
`encIdCredPubShare` pair, so a list longer than one entry would leave the review showing only the
last pair while the signature covered them all. The review shows a running SHA-256 digest of the
whole AR list in receipt order instead; the entry count appears on the AR-threshold row.

**Revealed attributes.** Each attribute tag and value is displayed before signing, so the user
sees which identity attributes the credential discloses.

**Proofs** are hashed but never displayed: they are large and carry fresh randomness per
transaction, so there is nothing stable for a user to compare.

## Shared with update credential

`SIGN_UPDATE_CREDENTIAL` (`INS 0x31`) reuses this parser for the credentials it adds, signalled by
`P2 = 0x02`. Two behaviours differ in that mode:

- The 4-byte proof length is hashed only when `P2 = 0x02`.
- After the final proof packet, an added credential is displayed and requires an explicit
  confirmation before the flow continues. The embedded path never reaches the standalone
  deployment's final screen, so without that confirmation an added credential would be signed
  without ever being shown.

## Response

Signature over the transaction hash, returned after approval. See
[`error.md`](error.md) for the status words this instruction can return.
