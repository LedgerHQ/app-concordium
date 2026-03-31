#pragma once

/**
 * PKI SET_TRUSTED_NAME (INS 0x22): TLV parse state + multi-hash (all supported
 * signer algorithms updated in parallel). Lives in instructionContext so it
 * shares RAM with other instruction flows instead of a large stack frame.
 */
#include <lcx_hash.h>

#include "buffer.h"
#include "tlv_library.h"
#include "trustedName.h"

typedef struct trustedNameMultiHashCtx_s {
    cx_sha256_t sha256;
    cx_sha3_t sha3_256;
    cx_sha3_t keccak_256;
    cx_ripemd160_t ripemd160;
    cx_sha512_t sha512;
} trustedNameMultiHashCtx_t;

/** Parsed TLV fields for SET_TRUSTED_NAME (INS 0x22). */
typedef struct trustedNameTlvExtracted_s {
    TLV_reception_t received_tags;

    uint8_t structure_type;
    uint8_t version;
    uint8_t trusted_name_type;
    uint8_t trusted_name_source;
    char name[TRUSTED_NAME_MAX_LEN + 1];
    buffer_t address;
    uint64_t chain_id;
    uint64_t challenge;
    uint16_t signer_key_id;
    uint8_t signer_algo;
    buffer_t signature;
} trustedNameTlvExtracted_t;

typedef struct trustedNamePkiContext_s {
    /**
     * Last GET_CHALLENGE value. Must survive SET_TRUSTED_NAME TLV/hash partial clears
     * (see trustedName.c clear_trusted_name_pki_working_state).
     *
     * This field lives in instructionContext `global`, a union shared with every other
     * instruction handler: any interleaved APDU that reuses `global` overwrites the challenge.
     * Another GET_CHALLENGE also replaces it. When a new command is handled with
     * currentInstruction == INSTRUCTION_NONE, app_main zeroes the entire union.
     * A broken host flow therefore loses the value expected by SET_TRUSTED_NAME
     * (verify_challenge fails).
     */
    uint64_t stored_challenge;
    trustedNameMultiHashCtx_t hash_ctx;
    trustedNameTlvExtracted_t tlv;
} trustedNamePkiContext_t;
