#pragma once

#include <stdint.h>

#include "instruction_context.h"
#include "tx_state.h"

/**
 * Current-command derivation path and tx hash / instruction state. Storage in `globals.c`.
 * Path is overwritten per APDU; for multi-step flows it is set at flow start.
 */
extern derivation_path_t global_derivation_path;
extern tx_state_t global_tx_state;

/** Sentinel for no active instruction (before first command) */
#define INSTRUCTION_NONE -1

/*
 * Concordium-specific status words (0x6B01–0x6B0C, 0x530C). ISO7816 reserves 6Bxx for
 * proprietary use; Ledger's status_words.h only defines SWO_WRONG_P1_P2 (0x6B00) in that range.
 * These values are part of the public host↔app contract — they are not aliases of other SWO_*.
 */
#define ERROR_INVALID_STATE         0x6B01
#define ERROR_INVALID_PATH          0x6B02
#define ERROR_INVALID_PARAM         0x6B03
#define ERROR_INVALID_TRANSACTION   0x6B04
#define ERROR_UNSUPPORTED_CBOR      0x6B05
#define ERROR_BUFFER_OVERFLOW       0x6B06
#define ERROR_FAILED_CX_OPERATION   0x6B07
#define ERROR_INVALID_SOURCE_LENGTH 0x6B08
#define ERROR_INVALID_NAME_LENGTH   0x6B0A
#define ERROR_INVALID_PARAMS_LENGTH 0x6B0B
#define ERROR_INVALID_MODULE_REF    0x6B09
#define ERROR_TRUSTED_NAME_MISMATCH 0x6B0C

#define ERROR_DEVICE_LOCKED 0x530C
