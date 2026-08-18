/*
 * Minimal stubs for unit tests that exercise helpers/cbor_data_blob.c.
 * Provides:
 *   - g_fuzzer_jmp_buf    used by the THROW macro in fuzzing/stubs/ledger/os.h
 *   - Global state vars   declared extern in globals.h / instruction_context.h /
 *                         handler/set_trusted_name.h
 */
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>

#include "ledger/cx.h"
#include "ledger/exceptions.h"
#include "ledger/parser.h"
#include "ledger/status_words.h"
#include "buffer.h"
#include "tlv_library.h"

#include "instruction_context.h"
#include "helpers/derivation_path.h"
#include "helpers/tx_state.h"
#include "handler/set_trusted_name.h"

jmp_buf g_fuzzer_jmp_buf;

instructionContext global;
derivation_path_t  global_derivation_path;
tx_state_t         global_tx_state;

char    g_trusted_name[TRUSTED_NAME_MAX_LEN + 1];
uint8_t g_trusted_address[TRUSTED_ADDRESS_MAX_SIZE];
uint8_t g_trusted_address_len;
bool    g_trusted_name_valid;

/* format.c (pulled in via numberHelpers.c → format.h) is self-contained; no extra stubs needed. */
