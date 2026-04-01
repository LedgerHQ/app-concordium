#include "globals.h"
#include "trustedName.h"
#include "challenge.h"
#include "buffer.h"
#include "ledger_pki.h"
#include "os_pki.h"
#include "tlv_library.h"
#include "lcx_hash.h"

char g_trusted_name[TRUSTED_NAME_MAX_LEN + 1];
uint8_t g_trusted_address[TRUSTED_ADDRESS_MAX_SIZE];
uint8_t g_trusted_address_len;
bool g_trusted_name_valid;

/* ── Signer algorithm enum (mirrors SDK tlv_use_case_trusted_name.h) ─────── */

typedef enum {
    SIGNER_ALGO_ECDSA_SHA256 = 0x01,
    SIGNER_ALGO_ECDSA_SHA3_256 = 0x02,
    SIGNER_ALGO_ECDSA_KECCAK_256 = 0x03,
    SIGNER_ALGO_ECDSA_RIPEMD160 = 0x04,
    SIGNER_ALGO_ECDSA_SHA512 = 0x16,
    SIGNER_ALGO_EDDSA_KECCAK_256 = 0x17,
    SIGNER_ALGO_EDDSA_SHA3_256 = 0x18,
} signer_algo_t;

/* ── Multi-hash: progressive hashing with all supported algorithms ───────── */

typedef struct {
    union {
        uint8_t _sha256[CX_SHA256_SIZE];
        uint8_t _sha3_256[CX_SHA3_256_SIZE];
        uint8_t _keccak_256[CX_KECCAK_256_SIZE];
        uint8_t _ripemd160[CX_RIPEMD160_SIZE];
        uint8_t _sha512[CX_SHA512_SIZE];
        uint8_t _offset_0;
    };
    buffer_t hash;
} multi_hash_finalized_t;

static void init_multi_hash(trustedNameMultiHashCtx_t *h) {
    CX_ASSERT(cx_sha256_init_no_throw(&h->sha256));
    CX_ASSERT(cx_sha3_init_no_throw(&h->sha3_256, CX_SHA3_256_SIZE * 8));
    CX_ASSERT(cx_keccak_init_no_throw(&h->keccak_256, CX_KECCAK_256_SIZE * 8));
    CX_ASSERT(cx_ripemd160_init_no_throw(&h->ripemd160));
    CX_ASSERT(cx_sha512_init_no_throw(&h->sha512));
}

static void update_multi_hash(trustedNameMultiHashCtx_t *h, buffer_t data) {
    CX_ASSERT(cx_hash_update((cx_hash_t *) &h->sha256, data.ptr, data.size));
    CX_ASSERT(cx_hash_update((cx_hash_t *) &h->sha3_256, data.ptr, data.size));
    CX_ASSERT(cx_hash_update((cx_hash_t *) &h->keccak_256, data.ptr, data.size));
    CX_ASSERT(cx_hash_update((cx_hash_t *) &h->ripemd160, data.ptr, data.size));
    CX_ASSERT(cx_hash_update((cx_hash_t *) &h->sha512, data.ptr, data.size));
}

static int finalize_multi_hash(trustedNameMultiHashCtx_t *h,
                               uint8_t signer_algo,
                               multi_hash_finalized_t *out) {
    cx_hash_t *hash;
    switch (signer_algo) {
        case SIGNER_ALGO_ECDSA_SHA256:
            hash = (cx_hash_t *) &h->sha256;
            out->hash.size = sizeof(out->_sha256);
            break;
        case SIGNER_ALGO_ECDSA_SHA3_256:
        case SIGNER_ALGO_EDDSA_SHA3_256:
            hash = (cx_hash_t *) &h->sha3_256;
            out->hash.size = sizeof(out->_sha3_256);
            break;
        case SIGNER_ALGO_ECDSA_KECCAK_256:
        case SIGNER_ALGO_EDDSA_KECCAK_256:
            hash = (cx_hash_t *) &h->keccak_256;
            out->hash.size = sizeof(out->_keccak_256);
            break;
        case SIGNER_ALGO_ECDSA_RIPEMD160:
            hash = (cx_hash_t *) &h->ripemd160;
            out->hash.size = sizeof(out->_ripemd160);
            break;
        case SIGNER_ALGO_ECDSA_SHA512:
            hash = (cx_hash_t *) &h->sha512;
            out->hash.size = sizeof(out->_sha512);
            break;
        default:
            PRINTF("Unknown signer algo %d\n", signer_algo);
            return -1;
    }
    out->hash.ptr = &out->_offset_0;
    out->hash.offset = 0;
    if (cx_hash_final(hash, &out->_offset_0) != CX_OK) {
        return -1;
    }
    return 0;
}

/* ── TLV extraction context ──────────────────────────────────────────────── */

#define SIGNER_KEY_ID_TEST 0x0000
#define SIGNER_KEY_ID_PROD 0x0007

#define STRUCTURE_TYPE_TRUSTED_NAME 0x03

#define DER_SIG_MIN 64
#define DER_SIG_MAX 72

/** Clears TLV + hash only; preserves GET_CHALLENGE value in global.trustedNamePki.stored_challenge.
 */
static void clear_trusted_name_pki_working_state(void) {
    explicit_bzero(&global.trustedNamePki.hash_ctx, sizeof(global.trustedNamePki.hash_ctx));
    explicit_bzero(&global.trustedNamePki.tlv, sizeof(global.trustedNamePki.tlv));
}

/* ── Individual tag handlers ─────────────────────────────────────────────── */

static bool h_structure_type(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx) {
    return get_uint8_t_from_tlv_data(data, &ctx->structure_type);
}

static bool h_version(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx) {
    return get_uint8_t_from_tlv_data(data, &ctx->version);
}

static bool h_name_type(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx) {
    return get_uint8_t_from_tlv_data(data, &ctx->trusted_name_type);
}

static bool h_name_source(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx) {
    return get_uint8_t_from_tlv_data(data, &ctx->trusted_name_source);
}

static bool h_trusted_name(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx) {
    return get_string_from_tlv_data(data, ctx->name, 1, sizeof(ctx->name));
}

static bool h_chain_id(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx) {
    return get_uint64_t_from_tlv_data(data, &ctx->chain_id);
}

static bool h_address(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx) {
    return get_buffer_from_tlv_data(data, &ctx->address, 1, 0);
}

static bool h_challenge(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx) {
    return get_uint64_t_from_tlv_data(data, &ctx->challenge);
}

static bool h_signer_key_id(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx) {
    return get_uint16_t_from_tlv_data(data, &ctx->signer_key_id);
}

static bool h_signer_algo(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx) {
    return get_uint8_t_from_tlv_data(data, &ctx->signer_algo);
}

static bool h_der_signature(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx) {
    return get_buffer_from_tlv_data(data, &ctx->signature, DER_SIG_MIN, DER_SIG_MAX);
}

static bool h_common(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx);

// clang-format off
#define CCD_TLV_TAGS(X)                                                                  \
    X(0x01, CCD_TAG_STRUCTURE_TYPE,      h_structure_type, ENFORCE_UNIQUE_TAG)            \
    X(0x02, CCD_TAG_VERSION,             h_version,        ENFORCE_UNIQUE_TAG)            \
    X(0x70, CCD_TAG_TRUSTED_NAME_TYPE,   h_name_type,      ENFORCE_UNIQUE_TAG)            \
    X(0x71, CCD_TAG_TRUSTED_NAME_SOURCE, h_name_source,    ENFORCE_UNIQUE_TAG)            \
    X(0x20, CCD_TAG_TRUSTED_NAME,        h_trusted_name,   ENFORCE_UNIQUE_TAG)            \
    X(0x23, CCD_TAG_CHAIN_ID,            h_chain_id,       ENFORCE_UNIQUE_TAG)            \
    X(0x22, CCD_TAG_ADDRESS,             h_address,        ENFORCE_UNIQUE_TAG)            \
    X(0x72, CCD_TAG_NFT_ID,              NULL,             ENFORCE_UNIQUE_TAG)            \
    X(0x73, CCD_TAG_SOURCE_CONTRACT,     NULL,             ENFORCE_UNIQUE_TAG)            \
    X(0x12, CCD_TAG_CHALLENGE,           h_challenge,      ENFORCE_UNIQUE_TAG)            \
    X(0x10, CCD_TAG_NOT_VALID_AFTER,     NULL,             ENFORCE_UNIQUE_TAG)            \
    X(0x13, CCD_TAG_SIGNER_KEY_ID,       h_signer_key_id,  ENFORCE_UNIQUE_TAG)            \
    X(0x14, CCD_TAG_SIGNER_ALGORITHM,    h_signer_algo,    ENFORCE_UNIQUE_TAG)            \
    X(0x15, CCD_TAG_DER_SIGNATURE,       h_der_signature,  ENFORCE_UNIQUE_TAG)
// clang-format on

DEFINE_TLV_PARSER(CCD_TLV_TAGS, &h_common, ccd_parse_tlv)

static bool h_common(const tlv_data_t *data, trustedNameTlvExtracted_t *ctx) {
    // ctx is required by the tlv_handler_cb_t contract; this function does not use it
    (void) ctx;
    if (data->tag != CCD_TAG_DER_SIGNATURE) {
        update_multi_hash(&global.trustedNamePki.hash_ctx, data->raw);
    }
    return true;
}

/* ── Post-parse validation ───────────────────────────────────────────────── */

static bool verify_fields(const trustedNameTlvExtracted_t *ctx) {
#ifdef TRUSTED_NAME_TEST_KEY
    uint16_t valid_key_id = SIGNER_KEY_ID_TEST;
#else
    uint16_t valid_key_id = SIGNER_KEY_ID_PROD;
#endif

    if (!TLV_CHECK_RECEIVED_TAGS(ctx->received_tags, CCD_TAG_STRUCTURE_TYPE)) {
        PRINTF("Missing structure type\n");
        return false;
    }
    if (ctx->structure_type != STRUCTURE_TYPE_TRUSTED_NAME) {
        PRINTF("Wrong structure type %d\n", ctx->structure_type);
        return false;
    }
    if (!TLV_CHECK_RECEIVED_TAGS(ctx->received_tags,
                                 CCD_TAG_VERSION,
                                 CCD_TAG_TRUSTED_NAME_TYPE,
                                 CCD_TAG_TRUSTED_NAME_SOURCE,
                                 CCD_TAG_TRUSTED_NAME,
                                 CCD_TAG_CHAIN_ID,
                                 CCD_TAG_ADDRESS,
                                 CCD_TAG_CHALLENGE,
                                 CCD_TAG_SIGNER_KEY_ID,
                                 CCD_TAG_SIGNER_ALGORITHM,
                                 CCD_TAG_DER_SIGNATURE)) {
        PRINTF("Missing required TLV fields\n");
        return false;
    }
    if (ctx->signer_key_id != valid_key_id) {
        PRINTF("Wrong signer key id %u (expected %u)\n", ctx->signer_key_id, valid_key_id);
        return false;
    }
    return true;
}

static bool verify_challenge(const trustedNameTlvExtracted_t *ctx) {
    uint64_t stored = getStoredChallenge();
    if (stored == 0) {
        PRINTF("No challenge stored (call GET_CHALLENGE first)\n");
        return false;
    }
    if (ctx->challenge != stored) {
        PRINTF("Challenge mismatch\n");
        return false;
    }
    return true;
}

static bool verify_signature(const trustedNameTlvExtracted_t *ctx) {
    multi_hash_finalized_t finalized;
    if (finalize_multi_hash(&global.trustedNamePki.hash_ctx, ctx->signer_algo, &finalized) != 0) {
        return false;
    }

    cx_curve_t curve;
    if (ctx->signer_algo == SIGNER_ALGO_EDDSA_SHA3_256 ||
        ctx->signer_algo == SIGNER_ALGO_EDDSA_KECCAK_256) {
        curve = CX_CURVE_Ed25519;
    } else {
        curve = CX_CURVE_SECP256K1;
    }

    uint8_t expected_ku = CERTIFICATE_PUBLIC_KEY_USAGE_TRUSTED_NAME;
    check_signature_with_pki_status_t st =
        check_signature_with_pki(finalized.hash, &expected_ku, &curve, ctx->signature);
    if (st != CHECK_SIGNATURE_WITH_PKI_SUCCESS) {
        PRINTF("PKI signature verification failed (%d)\n", st);
        return false;
    }
    return true;
}

static void sendSetTrustedNameError(uint16_t sw) {
    global_tx_state.currentInstruction = INSTRUCTION_NONE;
    io_send_sw(sw);
}

void handleSetTrustedName(const command_t *cmd) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t p2 = cmd->p2;
    uint8_t lc = cmd->lc;

    if (p1 != 0 || p2 != 0) {
        sendSetTrustedNameError(ERROR_INVALID_PARAM);
        return;
    }
    if (lc == 0 || cdata == NULL) {
        sendSetTrustedNameError(ERROR_INVALID_PARAM);
        return;
    }

    g_trusted_name_valid = false;

    buffer_t payload = {.ptr = cdata, .size = lc, .offset = 0};

    clear_trusted_name_pki_working_state();
    init_multi_hash(&global.trustedNamePki.hash_ctx);

    if (!ccd_parse_tlv(&payload,
                       &global.trustedNamePki.tlv,
                       &global.trustedNamePki.tlv.received_tags)) {
        PRINTF("TLV parse failed\n");
        clear_trusted_name_pki_working_state();
        sendSetTrustedNameError(ERROR_INVALID_PARAM);
        return;
    }

    if (!verify_fields(&global.trustedNamePki.tlv)) {
        clear_trusted_name_pki_working_state();
        sendSetTrustedNameError(ERROR_INVALID_PARAM);
        return;
    }

    if (!verify_challenge(&global.trustedNamePki.tlv)) {
        clear_trusted_name_pki_working_state();
        sendSetTrustedNameError(ERROR_INVALID_PARAM);
        return;
    }

    if (!verify_signature(&global.trustedNamePki.tlv)) {
        clear_trusted_name_pki_working_state();
        sendSetTrustedNameError(ERROR_INVALID_PARAM);
        return;
    }

    explicit_bzero(g_trusted_name, sizeof(g_trusted_name));
    size_t name_len = strlen(global.trustedNamePki.tlv.name);
    memmove(g_trusted_name, global.trustedNamePki.tlv.name, name_len);
    g_trusted_name[name_len] = '\0';

    explicit_bzero(g_trusted_address, sizeof(g_trusted_address));
    uint8_t addr_len = (global.trustedNamePki.tlv.address.size <= TRUSTED_ADDRESS_MAX_SIZE)
                           ? (uint8_t) global.trustedNamePki.tlv.address.size
                           : TRUSTED_ADDRESS_MAX_SIZE;
    memmove(g_trusted_address, global.trustedNamePki.tlv.address.ptr, addr_len);
    g_trusted_address_len = addr_len;

    g_trusted_name_valid = true;
    eraseChallenge();

    explicit_bzero(&global.trustedNamePki, sizeof(global.trustedNamePki));

    sendSuccess(0);
}
