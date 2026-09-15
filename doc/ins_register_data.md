# Register data

A transaction to register some data on the chain.

## Protocol description

- Maximum supported data size is 256 bytes.
- Multiple commands

| INS    | P1     | P2     | CDATA                                                                                                           | Comment                                                                                                                                       |
| ------ | ------ | ------ | --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `0x35` | `0x00` | `0x00` | `path_length path[uint32]x[8] account_transaction_header[60 bytes] transaction_kind[uint8] data_length[uint16]` |                                                                                                                                               |
| `0x35` | `0x01` | `0x00` | `data[1...255 bytes]`                                                                                           | The data is assumed to be CBOR encoded, and should be sent in batches of up to 255 bytes (Either 1 batch, or a 255 byte batch + 1 byte batch) |

## Displayable-text requirement

The data is hashed into the signed transaction in full but shown on screen as text, so a payload
carrying an embedded NUL or a C0 control is refused rather than reviewed as its prefix. A CBOR
encoding that is ambiguous or unsupported is refused too. Each packet is checked as it arrives,
and the refusal ends the flow — see [Refusals of undisplayable text](error.md#refusals-of-undisplayable-text).
