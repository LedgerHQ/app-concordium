#pragma once

#include <parser.h>
#include <stdbool.h>

#include "instruction_context.h"

#define P1_SKIP_DISPLAY    0x01
#define P2_SIGN_PUBLIC_KEY 0x01

/**
 * INS_GET_PUBLIC_KEY: parse path from CDATA, optional on-device display, then export via UI / APDU.
 * P1/P2: see doc/ins_public_key.md
 */
void handle_get_public_key(const command_t *cmd, volatile unsigned int *flags);

/**
 * Derive the public key for the current path, write the APDU response (and optional signature),
 * and send. Used from the handler and from the export UI flow.
 */
void send_public_key(bool compare);
