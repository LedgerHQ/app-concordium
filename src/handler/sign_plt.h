#pragma once

#include <stdbool.h>
#include <parser.h>

/**
 * Handle INS 0x27 — PLT (Protocol Level Token) signing.
 *
 * P1=0x00 (INIT): parse derivation path + 60-byte account transaction header (kind must be
 *   PLT=27) + token-id + 4-byte CBOR total length (BE).
 * P1=0x01 (CONT): supply next raw CBOR slice; device hashes and buffers until
 *   received == cbor_total_length, then parses fields to the debug log and signs.
 *
 * isInitialCall resets internal state on the first APDU of a new instruction sequence.
 */
void handle_sign_plt(const command_t *cmd, volatile unsigned int *flags, bool isInitialCall);
