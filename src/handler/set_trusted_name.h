#pragma once

#include <parser.h>
#include <stdbool.h>
#include <stdint.h>

#define TRUSTED_NAME_MAX_LEN     64
#define TRUSTED_ADDRESS_MAX_SIZE 64

extern char g_trusted_name[TRUSTED_NAME_MAX_LEN + 1];
extern uint8_t g_trusted_address[TRUSTED_ADDRESS_MAX_SIZE];
extern uint8_t g_trusted_address_len;
extern bool g_trusted_name_valid;

/**
 * SET_TRUSTED_NAME -- CLA E0, INS 22, P1 00, P2 00.
 *
 * CDATA is a raw TLV payload (the signedDescriptor from the Ledger API).
 * The PKI certificate must already be loaded by Ledger Live via a separate
 * APDU before this call.
 *
 * Flow: GET_CHALLENGE -> host embeds challenge in TLV -> SET_TRUSTED_NAME.
 *
 * On success the trusted name string (tag 0x20) and address (tag 0x22) are
 * stored in globals and the challenge is erased.
 */
void trusted_name_send_set_error(uint16_t sw);

void handle_set_trusted_name(const command_t *cmd);
