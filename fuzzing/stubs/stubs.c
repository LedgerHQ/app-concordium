/*
 * Stub implementations for the Concordium Ledger app fuzzing harness.
 *
 * Provides:
 *   - jmp_buf g_fuzzer_jmp_buf  (THROW target)
 *   - Global state variables (globals.c replacement)
 *   - All Ledger SDK crypto stubs
 *   - All UI / display stubs
 *   - All APDU response stubs
 *   - base58_encode stub
 *   - TLV library stubs
 *   - buffer_t helpers
 *   - set_trusted_name stubs
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <setjmp.h>

/* Include our stubs in the right order */
#include "ledger/cx.h"
#include "ledger/exceptions.h"
#include "ledger/os_utils.h"
#include "ledger/parser.h"
#include "ledger/status_words.h"
#include "buffer.h"
#include "tlv_library.h"

/* App source headers (found via include paths set in CMakeLists.txt) */
#include "app_sizes.h"
#include "helpers/tx_state.h"
#include "derivation_path.h"
#include "instruction_context.h"
#include "apdu/apdu_response.h"
#include "helpers/concordium_crypto.h"
#include "helpers/base58check.h"
#include "ui/display.h"
#include "handler/set_trusted_name.h"

/* ── THROW jump buffer ────────────────────────────────────────────────── */
jmp_buf g_fuzzer_jmp_buf;

/* ── Global state (replaces globals.c) ───────────────────────────────── */
derivation_path_t global_derivation_path;
tx_state_t        global_tx_state;
instructionContext global;
accountSender_t   global_account_sender;

/* ── Trusted-name globals (replaces set_trusted_name.c definitions) ───── */
char    g_trusted_name[TRUSTED_NAME_MAX_LEN + 1];
uint8_t g_trusted_address[TRUSTED_ADDRESS_MAX_SIZE];
uint8_t g_trusted_address_len;
bool    g_trusted_name_valid;

/* ── APDU I/O buffer ──────────────────────────────────────────────────── */
uint8_t G_io_apdu_buffer[260];

/* ──────────────────────────────────────────────────────────────────────
 * Ledger SDK crypto stubs
 * ──────────────────────────────────────────────────────────────────────*/

cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    (void)hash;
    return CX_OK;
}

cx_err_t cx_hash_no_throw(cx_hash_t *hash, uint32_t mode,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_len) {
    (void)hash; (void)mode; (void)in; (void)in_len;
    if (out && out_len) memset(out, 0, out_len);
    return CX_OK;
}

size_t cx_hash_sha256(const uint8_t *in, size_t len, uint8_t *out, size_t out_len) {
    (void)in; (void)len;
    if (out && out_len >= CX_SHA256_SIZE) memset(out, 0, CX_SHA256_SIZE);
    return CX_SHA256_SIZE;
}

cx_err_t cx_hash_init(cx_hash_t *hash, cx_md_t hash_id) {
    (void)hash; (void)hash_id;
    return CX_OK;
}

cx_err_t cx_hash_update(cx_hash_t *hash, const uint8_t *in, size_t in_len) {
    (void)hash; (void)in; (void)in_len;
    return CX_OK;
}

cx_err_t cx_hash_final(cx_hash_t *hash, uint8_t *digest) {
    (void)hash;
    if (digest) memset(digest, 0, 32);
    return CX_OK;
}

size_t cx_hash_get_size(const cx_hash_t *ctx) {
    (void)ctx;
    return 32;
}

/* BN stubs */
cx_err_t cx_bn_lock(size_t word_nbytes, uint32_t flags) {
    (void)word_nbytes; (void)flags;
    return CX_OK;
}
cx_err_t cx_bn_unlock(void) { return CX_OK; }
cx_err_t cx_bn_alloc(cx_bn_t *x, size_t nbytes) {
    if (x) *x = 0;
    (void)nbytes;
    return CX_OK;
}
cx_err_t cx_bn_alloc_init(cx_bn_t *x, size_t nbytes,
                           const uint8_t *value, size_t value_nbytes) {
    if (x) *x = 0;
    (void)nbytes; (void)value; (void)value_nbytes;
    return CX_OK;
}
cx_err_t cx_bn_destroy(cx_bn_t *x) { (void)x; return CX_OK; }
cx_err_t cx_bn_set_u32(cx_bn_t x, uint32_t n) { (void)x; (void)n; return CX_OK; }
cx_err_t cx_bn_get_u32(const cx_bn_t x, uint32_t *n) {
    (void)x;
    if (n) *n = 0;
    return CX_OK;
}
cx_err_t cx_bn_export(const cx_bn_t x, uint8_t *bytes, size_t nbytes) {
    (void)x;
    if (bytes) memset(bytes, 0, nbytes);
    return CX_OK;
}
cx_err_t cx_bn_init(cx_bn_t x, const uint8_t *value, size_t value_nbytes) {
    (void)x; (void)value; (void)value_nbytes;
    return CX_OK;
}
cx_err_t cx_bn_copy(cx_bn_t a, const cx_bn_t b) { (void)a; (void)b; return CX_OK; }
cx_err_t cx_bn_mod_add(cx_bn_t r, const cx_bn_t a, const cx_bn_t b, const cx_bn_t n) {
    (void)r; (void)a; (void)b; (void)n;
    return CX_OK;
}
cx_err_t cx_bn_mod_invert_nprime(cx_bn_t r, const cx_bn_t a, const cx_bn_t n) {
    (void)r; (void)a; (void)n;
    return CX_OK;
}
cx_err_t cx_bn_cmp(const cx_bn_t a, const cx_bn_t b, int *diff) {
    (void)a; (void)b;
    if (diff) *diff = 0;
    return CX_OK;
}
cx_err_t cx_bn_cmp_u32(const cx_bn_t a, uint32_t b, int *diff) {
    (void)a; (void)b;
    if (diff) *diff = 0;
    return CX_OK;
}
cx_err_t cx_bn_nbytes(const cx_bn_t x, size_t *nbytes) {
    (void)x;
    if (nbytes) *nbytes = 32;
    return CX_OK;
}
cx_err_t cx_bn_is_odd(const cx_bn_t n, bool *odd) {
    (void)n;
    if (odd) *odd = false;
    return CX_OK;
}

/* EC point stubs */
cx_err_t cx_ecpoint_alloc(cx_ecpoint_t *P, cx_curve_t cv) {
    if (P) memset(P, 0, sizeof(*P));
    (void)cv;
    return CX_OK;
}
cx_err_t cx_ecpoint_destroy(cx_ecpoint_t *P) { (void)P; return CX_OK; }
cx_err_t cx_ecpoint_init(cx_ecpoint_t *P,
                         const uint8_t *x, size_t x_len,
                         const uint8_t *y, size_t y_len) {
    (void)P; (void)x; (void)x_len; (void)y; (void)y_len;
    return CX_OK;
}
cx_err_t cx_ecpoint_scalarmul_bn(cx_ecpoint_t *P, const cx_bn_t k) {
    (void)P; (void)k;
    return CX_OK;
}
cx_err_t cx_ecpoint_neg(cx_ecpoint_t *P) { (void)P; return CX_OK; }
cx_err_t cx_ecpoint_export_bn(const cx_ecpoint_t *P, cx_bn_t *x, cx_bn_t *y) {
    (void)P;
    if (x) *x = 0;
    if (y) *y = 0;
    return CX_OK;
}

/* ECFP stubs */
cx_err_t cx_ecfp_init_private_key_no_throw(cx_curve_t curve,
                                           const uint8_t *raw_key, size_t key_len,
                                           cx_ecfp_private_key_t *key) {
    (void)curve; (void)raw_key; (void)key_len;
    if (key) memset(key, 0, sizeof(*key));
    return CX_OK;
}
cx_err_t cx_ecfp_generate_pair_no_throw(cx_curve_t curve,
                                        cx_ecfp_public_key_t *pubkey,
                                        cx_ecfp_private_key_t *privkey,
                                        bool keep_privkey) {
    (void)curve; (void)keep_privkey;
    if (pubkey)  memset(pubkey,  0, sizeof(*pubkey));
    if (privkey) memset(privkey, 0, sizeof(*privkey));
    return CX_OK;
}
cx_err_t cx_eddsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                                cx_md_t hashID,
                                const uint8_t *hash, size_t hash_len,
                                uint8_t *sig, size_t sig_len) {
    (void)pvkey; (void)hashID; (void)hash; (void)hash_len;
    if (sig) memset(sig, 0, sig_len);
    return CX_OK;
}

/* apdu_parser stub */
bool apdu_parser(command_t *cmd, uint8_t *buf, size_t buf_len) {
    (void)cmd; (void)buf; (void)buf_len;
    return false;
}

/* ──────────────────────────────────────────────────────────────────────
 * concordium_crypto.c stubs (replaces entire src/helpers/concordium_crypto.c)
 * ──────────────────────────────────────────────────────────────────────*/

const uint8_t BLS_G1_ORDER[32] = {0};

void get_private_key(const derivation_path_t *path, cx_ecfp_private_key_t *privateKey) {
    (void)path;
    memset(privateKey, 0, sizeof(*privateKey));
}

void get_public_key(uint8_t *publicKeyArray) {
    memset(publicKeyArray, 0, KEY_LENGTH);
}

void get_extended_private_key(const derivation_path_t *path,
                              uint8_t *privateKey,
                              size_t privateKeySize,
                              uint8_t *chainCode,
                              size_t chainCodeSize) {
    (void)path;
    memset(privateKey, 0, privateKeySize);
    memset(chainCode, 0, chainCodeSize);
}

void sign(uint8_t *input, uint8_t *signatureOnInput) {
    (void)input;
    memset(signatureOnInput, 0, 64);
}

void hash(cx_hash_t *h, uint32_t mode,
          const unsigned char *in, unsigned int len,
          unsigned char *out, unsigned int out_len) {
    (void)h; (void)mode; (void)in; (void)len;
    if (out) memset(out, 0, out_len);
}

void update_hash(cx_hash_t *h, const unsigned char *in, unsigned int len) {
    (void)h; (void)in; (void)len;
}

void get_bls_private_key(const derivation_path_t *path, uint8_t *privateKey,
                         size_t privateKeySize) {
    (void)path;
    memset(privateKey, 0, privateKeySize);
}

/* ──────────────────────────────────────────────────────────────────────
 * base58_encode stub (replaces ledger SDK base58.h implementation)
 * ──────────────────────────────────────────────────────────────────────*/

int base58_encode(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    (void)in; (void)in_len;
    if (!out || out_len < 56) return -1;
    memset(out, 'A', 55);
    out[55] = '\0';
    return 0;
}

/* ──────────────────────────────────────────────────────────────────────
 * APDU response stubs (replaces src/apdu/apdu_response.c)
 * ──────────────────────────────────────────────────────────────────────*/

void send_user_rejection(void)          {}
void send_user_rejection_no_idle(void)  {}
void send_success_no_idle(void)         {}
void send_success_result_no_idle(uint8_t tx) { (void)tx; }
void send_success(uint8_t tx)           { (void)tx; }

/* ──────────────────────────────────────────────────────────────────────
 * UI / display stubs (replaces src/ui/display_*.c)
 * ──────────────────────────────────────────────────────────────────────*/

void uiComparePubkey(void)                                           {}
void uiGeneratePubkey(volatile unsigned int *flags)                  { (void)flags; }
void uiExportPrivateKey(volatile unsigned int *flags)                { (void)flags; }
void uiExportPrivateKeysNewPath(volatile unsigned int *flags)        { (void)flags; }

void startConfigureBakerCommissionDisplay(void)                      {}
void startConfigureBakerUrlDisplay(bool lastUrlPage)                 { (void)lastUrlPage; }
void startConfigureBakerSuspendedDisplay(void)                       {}
void startConfigureBakerDisplay(void)                                {}
void startConfigureDelegationDisplay(void)                           {}

void uiSignUpdateCredentialInitialDisplay(volatile unsigned int *flags)             { (void)flags; }
void uiSignUpdateCredentialIdDisplay(volatile unsigned int *flags)                  { (void)flags; }
void uiSignUpdateCredentialThresholdDisplay(volatile unsigned int *flags)           { (void)flags; }
void uiSignCredentialDeploymentVerificationKeyDisplay(volatile unsigned int *flags) { (void)flags; }
void uiSignCredentialDeploymentVerificationKeyFlowDisplay(volatile unsigned int *flags) { (void)flags; }
void uiSignCredentialDeploymentNewIntroDisplay(void)                 {}
void uiSignCredentialDeploymentNewDisplay(void)                      {}
void uiSignCredentialDeploymentExistingIntroDisplay(void)            {}
void uiSignCredentialDeploymentExistingDisplay(void)                 {}

void uiReviewPublicInformationForIpDisplay(void)                     {}
void uiSignPublicInformationForIpPublicKeyDisplay(void)              {}
void uiSignPublicInformationForIpCompleteDisplay(void)               {}
void uiSignPublicInformationForIpFinalDisplay(void)                  {}

void uiSignFlowSharedDisplay(void)                                   {}
void uiRegisterDataInitialDisplay(volatile unsigned int *flags)      { (void)flags; }
void uiRegisterDataPayloadDisplay(volatile unsigned int *flags)      { (void)flags; }

void startTransferDisplay(bool displayMemo, volatile unsigned int *flags) {
    (void)displayMemo; (void)flags;
}
void uiSignTransferToPublicDisplay(volatile unsigned int *flags)     { (void)flags; }
void startInitialScheduledTransferDisplay(bool displayMemo)          { (void)displayMemo; }
void uiSignScheduledTransferPairFlowSignDisplay(void)                {}
void uiSignScheduledTransferPairFlowDisplay(void)                    {}

void uiDeployModuleDisplay(void)                                     {}
void uiInitContractDisplay(void)                                     {}
void uiUpdateContractDisplay(void)                                   {}

void uiVerifyAddress(volatile unsigned int *flags)                   { (void)flags; }

/* ──────────────────────────────────────────────────────────────────────
 * set_trusted_name stubs (replaces src/handler/set_trusted_name.c definitions)
 * ──────────────────────────────────────────────────────────────────────*/

void trusted_name_send_set_error(uint16_t sw) { (void)sw; }
void clear_trusted_name_binding(void) {
    memset(g_trusted_name, 0, sizeof(g_trusted_name));
    memset(g_trusted_address, 0, sizeof(g_trusted_address));
    g_trusted_address_len = 0;
    g_trusted_name_valid  = false;
}
void handle_set_trusted_name(const command_t *cmd) { (void)cmd; }

/* ──────────────────────────────────────────────────────────────────────
 * TLV library stubs
 * ──────────────────────────────────────────────────────────────────────*/

bool _parse_tlv_internal(const _internal_tlv_handler_t *handlers,
                         uint8_t                        handlers_count,
                         tlv_handler_cb_t              *common_handler,
                         tag_to_flag_function_t        *tag_to_flag_function,
                         const buffer_t                *payload,
                         void                          *tlv_out,
                         TLV_reception_t               *received_tags_flags) {
    (void)handlers; (void)handlers_count; (void)common_handler;
    (void)tag_to_flag_function; (void)payload; (void)tlv_out;
    if (received_tags_flags) memset(received_tags_flags, 0, sizeof(*received_tags_flags));
    return false;
}

bool tlv_check_received_tags(TLV_reception_t received, const TLV_tag_t *tags, size_t tag_count) {
    (void)received; (void)tags; (void)tag_count;
    return true;
}
bool tlv_enforce_u8_value(const tlv_data_t *data, uint8_t expected_value) {
    (void)data; (void)expected_value;
    return false;
}
bool get_uint64_t_from_tlv_data(const tlv_data_t *data, uint64_t *value) {
    (void)data; if (value) *value = 0; return false;
}
bool get_uint32_t_from_tlv_data(const tlv_data_t *data, uint32_t *value) {
    (void)data; if (value) *value = 0; return false;
}
bool get_uint16_t_from_tlv_data(const tlv_data_t *data, uint16_t *value) {
    (void)data; if (value) *value = 0; return false;
}
bool get_uint8_t_from_tlv_data(const tlv_data_t *data, uint8_t *value) {
    (void)data; if (value) *value = 0; return false;
}
bool get_bool_from_tlv_data(const tlv_data_t *data, bool *value) {
    (void)data; if (value) *value = false; return false;
}
bool get_buffer_from_tlv_data(const tlv_data_t *data, buffer_t *out,
                               uint16_t min_size, uint16_t max_size) {
    (void)data; (void)min_size; (void)max_size;
    if (out) memset(out, 0, sizeof(*out));
    return false;
}
bool get_string_from_tlv_data(const tlv_data_t *data, char *out,
                               uint16_t min_length, uint16_t out_size) {
    (void)data; (void)min_length;
    if (out && out_size) out[0] = '\0';
    return false;
}

/* ──────────────────────────────────────────────────────────────────────
 * buffer_t helpers
 * ──────────────────────────────────────────────────────────────────────*/

bool buffer_read_u8(buffer_t *b, uint8_t *value) {
    if (!buffer_can_read(b, 1)) return false;
    *value = b->ptr[b->offset++];
    return true;
}

static uint16_t read_u16(const uint8_t *p, endianness_t e) {
    return (e == BE)
        ? (uint16_t)(((uint16_t)p[0] << 8) | p[1])
        : (uint16_t)(((uint16_t)p[1] << 8) | p[0]);
}
static uint32_t read_u32(const uint8_t *p, endianness_t e) {
    return (e == BE)
        ? ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3]
        : ((uint32_t)p[3]<<24)|((uint32_t)p[2]<<16)|((uint32_t)p[1]<<8)|(uint32_t)p[0];
}
static uint64_t read_u64(const uint8_t *p, endianness_t e) {
    if (e == BE)
        return ((uint64_t)read_u32(p, BE) << 32) | read_u32(p + 4, BE);
    return ((uint64_t)read_u32(p + 4, LE) << 32) | read_u32(p, LE);
}

bool buffer_read_u16(buffer_t *b, uint16_t *value, endianness_t endianness) {
    if (!buffer_can_read(b, 2)) return false;
    *value = read_u16(b->ptr + b->offset, endianness);
    b->offset += 2;
    return true;
}
bool buffer_read_u32(buffer_t *b, uint32_t *value, endianness_t endianness) {
    if (!buffer_can_read(b, 4)) return false;
    *value = read_u32(b->ptr + b->offset, endianness);
    b->offset += 4;
    return true;
}
bool buffer_read_u64(buffer_t *b, uint64_t *value, endianness_t endianness) {
    if (!buffer_can_read(b, 8)) return false;
    *value = read_u64(b->ptr + b->offset, endianness);
    b->offset += 8;
    return true;
}
bool buffer_read_bytes(buffer_t *b, uint8_t *out, size_t n) {
    if (!buffer_can_read(b, n)) return false;
    memcpy(out, b->ptr + b->offset, n);
    b->offset += n;
    return true;
}
bool buffer_copy(const buffer_t *b, uint8_t *out, size_t out_len) {
    size_t avail = (b->size > b->offset) ? (b->size - b->offset) : 0;
    if (avail > out_len) return false;
    memcpy(out, b->ptr + b->offset, avail);
    return true;
}
bool buffer_move(buffer_t *b, uint8_t *out, size_t out_len) {
    if (!buffer_can_read(b, out_len)) return false;
    memcpy(out, b->ptr + b->offset, out_len);
    b->offset += out_len;
    return true;
}
bool buffer_peek(const buffer_t *b, uint8_t *value) {
    if (!buffer_can_read(b, 1)) return false;
    *value = b->ptr[b->offset];
    return true;
}
bool buffer_peek_n(const buffer_t *b, size_t n, uint8_t *value) {
    if (!buffer_can_read(b, n + 1)) return false;
    *value = b->ptr[b->offset + n];
    return true;
}
bool buffer_write_u8(buffer_t *b, uint8_t value) {
    if (!buffer_can_read(b, 1)) return false;
    b->ptr[b->offset++] = value;
    return true;
}
bool buffer_write_u16(buffer_t *b, uint16_t value, endianness_t endianness) {
    if (!buffer_can_read(b, 2)) return false;
    uint8_t *p = b->ptr + b->offset;
    if (endianness == BE) { p[0] = value >> 8; p[1] = (uint8_t)value; }
    else                  { p[1] = value >> 8; p[0] = (uint8_t)value; }
    b->offset += 2;
    return true;
}
bool buffer_write_u32(buffer_t *b, uint32_t value, endianness_t endianness) {
    if (!buffer_can_read(b, 4)) return false;
    uint8_t *p = b->ptr + b->offset;
    if (endianness == BE) {
        p[0]=(uint8_t)(value>>24); p[1]=(uint8_t)(value>>16);
        p[2]=(uint8_t)(value>>8);  p[3]=(uint8_t)value;
    } else {
        p[3]=(uint8_t)(value>>24); p[2]=(uint8_t)(value>>16);
        p[1]=(uint8_t)(value>>8);  p[0]=(uint8_t)value;
    }
    b->offset += 4;
    return true;
}
bool buffer_write_u64(buffer_t *b, uint64_t value, endianness_t endianness) {
    if (endianness == BE) {
        if (!buffer_write_u32(b, (uint32_t)(value >> 32), BE)) return false;
        return buffer_write_u32(b, (uint32_t)value, BE);
    }
    if (!buffer_write_u32(b, (uint32_t)value, LE)) return false;
    return buffer_write_u32(b, (uint32_t)(value >> 32), LE);
}
bool buffer_write_bytes(buffer_t *b, const uint8_t *data, size_t n) {
    if (!buffer_can_read(b, n)) return false;
    memcpy(b->ptr + b->offset, data, n);
    b->offset += n;
    return true;
}
bool buffer_read_varint(buffer_t *b, uint64_t *value) {
    uint8_t first;
    if (!buffer_read_u8(b, &first)) return false;
    if (first < 0xFD) { *value = first; return true; }
    if (first == 0xFD) {
        uint16_t v;
        if (!buffer_read_u16(b, &v, LE)) return false;
        *value = v; return true;
    }
    if (first == 0xFE) {
        uint32_t v;
        if (!buffer_read_u32(b, &v, LE)) return false;
        *value = v; return true;
    }
    return buffer_read_u64(b, value, LE);
}
