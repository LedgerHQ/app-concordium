# Error Codes

This document lists all error codes that can be returned by the Concordium Ledger application.

## Success Codes

| Code   | Name      | Description |
|--------|-----------|-------------|
| `0x9000` | `SUCCESS` | Operation completed successfully |

## Error Categories

### APDU Protocol Errors

| Code   | Name                    | Description |
|--------|------------------------|-------------|
| `0x6985` | `SWO_CONDITIONS_NOT_SATISFIED` | Conditions of use not satisfied (`status_words.h`). User declined signing / approval (e.g. `sendUserRejectionNoIdle`). |
| `0x6E00` | `SWO_INVALID_CLA`        | Invalid CLA byte in APDU header (`status_words.h`) |
| `0x6D00` | `SWO_INVALID_INS`        | Invalid instruction byte in APDU header (`status_words.h`) |
| `0x6A87` | `SWO_WRONG_DATA_LENGTH`  | Incorrect data length (`status_words.h`) |
| `0x6A80` | `SWO_INCORRECT_DATA`     | Wrong data in command data (`status_words.h`): truncated or malformed transaction payload |

### Transaction and Parameter Errors

| Code   | Name                        | Description |
|--------|----------------------------|-------------|
| `0x6B01` | `ERROR_INVALID_STATE`      | Operation attempted in invalid state |
| `0x6B02` | `ERROR_INVALID_PATH`       | Invalid derivation path |
| `0x6B03` | `ERROR_INVALID_PARAM`      | Invalid parameter provided |
| `0x6B04` | `ERROR_INVALID_TRANSACTION` | Invalid transaction format or data |
| `0x6B05` | `ERROR_UNSUPPORTED_CBOR`   | Unsupported CBOR format or operation |
| `0x6B06` | `ERROR_BUFFER_OVERFLOW`    | Buffer overflow occurred |
| `0x6B07` | `ERROR_FAILED_CX_OPERATION` | Failed cryptographic operation |
| `0x6B08` | `ERROR_INVALID_SOURCE_LENGTH` | Invalid source length |
| `0x6B09` | `ERROR_INVALID_MODULE_REF` | Invalid module reference |
| `0x6B0A` | `ERROR_INVALID_NAME_LENGTH` | Invalid name length |
| `0x6B0B` | `ERROR_INVALID_PARAMS_LENGTH` | Invalid parameters length |
| `0x6B0C` | `ERROR_TRUSTED_NAME_MISMATCH` | A trusted-name descriptor does not bind to the account, network or path being reviewed (`VERIFY_ADDRESS`) |

### Device State Errors

| Code   | Name                | Description |
|--------|-------------------|-------------|
| `0x530C` | `ERROR_DEVICE_LOCKED` | Device is locked |

## Refusals of undisplayable text

Several fields are hashed into the signed transaction in full but rendered on screen as a C
string. An embedded NUL would end the display while the signature still covered everything after
it, and the remaining C0 controls and DEL have no faithful rendering either. Those bytes are
refused rather than drawn as something they are not, so the reviewed text and the signed text are
always the same thing.

Each chunk of a multi-packet field is checked as it arrives, before the bytes are hashed or copied
into a display buffer, so the refusal happens on the packet that carries the offending byte.

| Field | Instruction | Status word |
| ----- | ----------- | ----------- |
| Contract name | `INIT_CONTRACT` (`0x07`) | `0x6B04` `ERROR_INVALID_TRANSACTION` |
| Receive name | `UPDATE_CONTRACT` (`0x08`) | `0x6B04` `ERROR_INVALID_TRANSACTION` |
| Validator metadata URL | `CONFIGURE_BAKER` (`0x18`) | `0x6B04` `ERROR_INVALID_TRANSACTION` |
| CBOR memo text | `SIGN_TRANSFER_WITH_MEMO` (`0x32`), `SIGN_TRANSFER_WITH_SCHEDULE_AND_MEMO` (`0x34`) | `0x6B04` `ERROR_INVALID_TRANSACTION` |
| Registered data | `REGISTER_DATA` (`0x35`) | `0x6B04` `ERROR_INVALID_TRANSACTION` |

A memo or registered-data payload whose CBOR encoding is ambiguous or unsupported is refused with
`0x6B05` `ERROR_UNSUPPORTED_CBOR` instead.

These are returned through `send_rejection()`, which differs from a thrown status word in one way
that matters to a host: it releases the instruction latch as well as replying, so the refused flow
is over and the next APDU may start a different instruction. A host must not resend the remaining
packets of the refused transaction.


## Error Handling Guidelines

1. When an error occurs, the application will:
   - Return the appropriate error code
   - Clear sensitive data from memory
   - Return to a safe state

2. User rejection uses `SWO_CONDITIONS_NOT_SATISFIED` (`0x6985`) per Ledger SDK naming; it is a normal outcome when the user declines.

3. Device state errors may require user intervention (e.g., unlocking the device).

4. Buffer overflow errors (`0x6B06`, `ERROR_BUFFER_OVERFLOW`) indicate an internal fixed buffer limit (e.g. display or response buffer). Malformed or truncated **command data** (transaction payload) uses **`SWO_INCORRECT_DATA` (`0x6A80`)** from `status_words.h`.

5. Wrong APDU `Lc` at dispatch uses **`SWO_WRONG_DATA_LENGTH` (`0x6A87`)** from `status_words.h`.


