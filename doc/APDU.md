# Application Protocol Data Unit (APDU)

The communication protocol used by this app to exchange [APDU](https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit) is very close to [ISO 7816-4](https://www.iso.org/standard/77180.html) with a few differences:

- `Lc` length is always exactly 1 byte
- No `Le` field in APDU command
- Maximum size of APDU command is 260 bytes: 5 bytes of header + 255 bytes of data
- Maximum size of APDU response is 260 bytes: 258 bytes of response data + 2 bytes of status word

Status words tend to be similar to common [APDU responses](https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses/) in the industry.

## Command APDU

| Field name | Length (bytes) | Description                                                           |
| ---------- | -------------- | --------------------------------------------------------------------- |
| CLA        | 1              | Instruction class - indicates the type of command                     |
| INS        | 1              | Instruction code - indicates the specific command                     |
| P1         | 1              | Instruction parameter 1 for the command                               |
| P2         | 1              | Instruction parameter 2 for the command                               |
| Lc         | 1              | The number of bytes of command data to follow (a value from 0 to 255) |
| CData      | var            | Command data with `Lc` bytes                                          |

## Response APDU

| Field name | Length (bytes) | Description                                                                  |
| ---------- | -------------- | ---------------------------------------------------------------------------- |
| RData      | var            | Response data (can be empty)                                                 |
| SW         | 2              | Status word containing command processing status (e.g. `0x9000` for success) |

## Instruction set

All commands use `CLA = 0xE0`.

| INS    | Name                                    | Packets | Reference                                                           |
| ------ | --------------------------------------- | ------- | ------------------------------------------------------------------- |
| `0x00` | Verify address                          | Single  | [verify_address.md](verify_address.md)                              |
| `0x01` | Get public key                          | Single  | [ins_public_key.md](ins_public_key.md)                              |
| `0x02` | Sign transfer                           | Single  | [ins_transfer.md](ins_transfer.md)                                  |
| `0x03` | Sign transfer with schedule             | Multi   | [ins_transfer_with_schedule.md](ins_transfer_with_schedule.md)      |
| `0x04` | Credential deployment                   | Multi   | —                                                                   |
| `0x05` | Export private key (legacy)             | Single  | [export_private_key.md](export_private_key.md)                      |
| `0x06` | Deploy module                           | Multi   | —                                                                   |
| `0x07` | Init contract                           | Multi   | —                                                                   |
| `0x08` | Update contract                         | Multi   | —                                                                   |
| `0x12` | Transfer to public                      | Multi   | [ins_transfer_to_public.md](ins_transfer_to_public.md)              |
| `0x17` | Configure delegation                    | Single  | [ins_configure_delegation.md](ins_configure_delegation.md)          |
| `0x18` | Configure baker                         | Multi   | [ins_configure_baker.md](ins_configure_baker.md)                    |
| `0x20` | Public info for IP                      | Multi   | [ins_public_info_for_ip.md](ins_public_info_for_ip.md)              |
| `0x21` | Get app name                            | Single  | —                                                                   |
| `0x22` | Set trusted name                        | Multi   | [ins_set_trusted_name.md](ins_set_trusted_name.md)                  |
| `0x23` | Get challenge                           | Single  | [ins_get_challenge.md](ins_get_challenge.md)                        |
| `0x27` | Sign PLT (Protocol Level Token)         | Multi   | [ins_sign_plt.md](ins_sign_plt.md)                                  |
| `0x31` | Sign update credential                  | Multi   | —                                                                   |
| `0x32` | Sign transfer with memo                 | Multi   | [ins_transfer.md](ins_transfer.md#transfer-with-memo)               |
| `0x34` | Sign transfer with schedule and memo    | Multi   | [ins_transfer_with_schedule.md](ins_transfer_with_schedule.md)      |
| `0x35` | Register data                           | Multi   | [ins_register_data.md](ins_register_data.md)                        |
| `0x37` | Export private key (new)                | Single  | [export_private_key.md](export_private_key.md)                      |
| `0x40` | Get app version                         | Single  | [ins_get_app_version.md](ins_get_app_version.md)                    |
