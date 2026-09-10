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
/*
 * A quoted include is resolved against the including file's own directory first, so
 * "tlv_library.h" would always find the stub sitting next to this file - even in the target
 * that puts the SDK's lib_tlv ahead of stubs/ on the include path. The angle-bracket form
 * skips that rule and honours the -I order, which is what lets the trusted-name target
 * compile against the real TLV header while every other target keeps the stub.
 */
#ifdef FUZZ_REAL_TLV
#include <tlv_library.h>
#else
#include "tlv_library.h"
#endif
#include "fuzz_ui.h"
#ifdef FUZZ_REAL_TRUSTED_NAME
#include "ledger_pki.h"
#endif

/* App source headers (found via include paths set in CMakeLists.txt) */
#include "app_sizes.h"
#include "helpers/tx_state.h"
#include "derivation_path.h"
#include "globals.h"
#include "instruction_context.h"
#include "apdu/apdu_response.h"
#include "helpers/concordium_crypto.h"
#include "helpers/base58check.h"
#include "ui/display.h"
#include "handler/set_trusted_name.h"
#include "handler/sign_configure_baker.h"

/* ── THROW jump buffer ────────────────────────────────────────────────── */
jmp_buf g_fuzzer_jmp_buf;

/* ── Global state (replaces globals.c) ───────────────────────────────── */
derivation_path_t global_derivation_path;
tx_state_t        global_tx_state;
instructionContext global;
accountSender_t   global_account_sender;
comparePublicKey_t global_compare_public_key;

/*
 * ── Trusted-name globals (replaces set_trusted_name.c definitions) ─────
 *
 * standalone_set_trusted_name_fuzzer links the real src/handler/set_trusted_name.c, which
 * defines all of these itself (finding V-114).
 */
#ifndef FUZZ_REAL_TRUSTED_NAME
char    g_trusted_name[TRUSTED_NAME_MAX_LEN + 1];
uint8_t g_trusted_address[TRUSTED_ADDRESS_MAX_SIZE];
uint8_t g_trusted_address_len;
uint64_t g_trusted_chain_id;
bool    g_trusted_name_valid;
uint64_t g_stored_challenge;
#endif

/* ── APDU I/O buffer ──────────────────────────────────────────────────── */
uint8_t G_io_apdu_buffer[260];

/* ──────────────────────────────────────────────────────────────────────
 * Ledger SDK crypto stubs
 * ──────────────────────────────────────────────────────────────────────*/

/*
 * Read every source byte, the way the real cx_* hashing does.
 *
 * These stubs used to discard (in, in_len) entirely, so a handler that passed an out-of-bounds
 * or uninitialised range to update_hash produced no sanitizer report at all - nothing
 * dereferenced it. That hid precisely the class of bug these fuzzers exist to find, because in
 * production cx_hash_no_throw() consumes the whole range. The accumulator is volatile so the
 * reads cannot be optimised away.
 *
 * Only a zero length short-circuits: `hash(..., CX_LAST, NULL, 0, ...)` is a legitimate
 * finalise call. A NULL pointer with a non-zero length is dereferenced on purpose, since
 * production would fault there too and the sanitizer should say so.
 */
static volatile uint8_t g_fuzz_hash_sink;

static void fuzz_consume(const void *in, size_t len) {
    if (len == 0) {
        return;
    }
    const uint8_t *bytes = (const uint8_t *) in;
    uint8_t acc = g_fuzz_hash_sink;
    for (size_t i = 0; i < len; i++) {
        acc = (uint8_t) (acc + bytes[i]);
    }
    g_fuzz_hash_sink = acc;
}

cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    (void)hash;
    return CX_OK;
}

cx_err_t cx_hash_no_throw(cx_hash_t *hash, uint32_t mode,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_len) {
    (void)hash; (void)mode;
    fuzz_consume(in, in_len);
    if (out && out_len) memset(out, 0, out_len);
    return CX_OK;
}

size_t cx_hash_sha256(const uint8_t *in, size_t len, uint8_t *out, size_t out_len) {
    fuzz_consume(in, len);
    if (out && out_len >= CX_SHA256_SIZE) memset(out, 0, CX_SHA256_SIZE);
    return CX_SHA256_SIZE;
}

cx_err_t cx_hash_init(cx_hash_t *hash, cx_md_t hash_id) {
    (void)hash; (void)hash_id;
    return CX_OK;
}

cx_err_t cx_hash_update(cx_hash_t *hash, const uint8_t *in, size_t in_len) {
    (void)hash;
    fuzz_consume(in, in_len);
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

/*
 * The trusted-name descriptor is hashed with whichever algorithm its TLV names, so the real
 * handler needs every init the SDK offers. Only the trusted-name target links that handler.
 */
#ifdef FUZZ_REAL_TRUSTED_NAME
cx_err_t cx_keccak_init_no_throw(cx_sha3_t *hash, size_t size) {
    (void)hash; (void)size;
    return CX_OK;
}
cx_err_t cx_sha3_init_no_throw(cx_sha3_t *hash, size_t size) {
    (void)hash; (void)size;
    return CX_OK;
}
cx_err_t cx_sha512_init_no_throw(cx_sha512_t *hash) {
    (void)hash;
    return CX_OK;
}
cx_err_t cx_ripemd160_init_no_throw(cx_ripemd160_t *hash) {
    (void)hash;
    return CX_OK;
}

/* Verdict supplied by the harness; see ledger_pki.h. */
check_signature_with_pki_status_t g_fuzz_pki_status = CHECK_SIGNATURE_WITH_PKI_WRONG_SIGNATURE;

check_signature_with_pki_status_t check_signature_with_pki(const buffer_t hash,
                                                          const uint8_t *expected_key_usage,
                                                          const cx_curve_t *expected_curve,
                                                          const buffer_t signature) {
    (void)expected_key_usage; (void)expected_curve;
    /* Production reads both ranges; an out-of-bounds hash or signature must be reported. */
    fuzz_consume(hash.ptr, hash.size);
    fuzz_consume(signature.ptr, signature.size);
    return g_fuzz_pki_status;
}
#endif /* FUZZ_REAL_TRUSTED_NAME */

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

/*
 * apdu_parser stub.
 *
 * standalone_apdu_dispatch_fuzzer links the SDK's real lib_standard_app/parser.c and so
 * defines this symbol itself; every other target keeps the always-false stub, since it never
 * feeds raw frames (finding V-096).
 */
#ifndef FUZZ_REAL_APDU_PARSER
bool apdu_parser(command_t *cmd, uint8_t *buf, size_t buf_len) {
    (void)cmd; (void)buf; (void)buf_len;
    return false;
}
#endif

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
    (void)h; (void)mode;
    fuzz_consume(in, len);
    if (out) memset(out, 0, out_len);
}

void update_hash(cx_hash_t *h, const unsigned char *in, unsigned int len) {
    (void)h;
    fuzz_consume(in, len);
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
void send_rejection(uint16_t sw)        { (void)sw; }

/*
 * io_send_sw / io_send_response_pointer are reached only through the real dispatcher and the
 * query handlers it routes to, which standalone_apdu_dispatch_fuzzer links (finding V-096).
 * The response pointer stub reads its whole range: a handler that hands the transport an
 * out-of-bounds or uninitialised buffer must be reported, and production would transmit it.
 */
int io_send_sw(uint16_t sw) {
    (void)sw;
    return 0;
}

int io_send_response_pointer(const void *ptr, size_t len, uint16_t sw) {
    (void)sw;
    fuzz_consume(ptr, len);
    return 0;
}

cx_err_t cx_rng_no_throw(uint8_t *buffer, size_t len) {
    if (buffer && len) memset(buffer, 0, len);
    return CX_OK;
}

/* ──────────────────────────────────────────────────────────────────────
 * UI / display stubs (replaces src/ui/display_*.c)
 *
 * These draw nothing, but they do record which approve/reject callback the real entry point
 * registers, so a harness can answer it - see fuzz_ui.h and fuzz_answer_pending_ui() below
 * (finding V-102). Where the production function chooses between two callbacks, the choice is
 * reproduced here from the same globals display_nbgl.c reads, with a comment naming the line.
 * ──────────────────────────────────────────────────────────────────────*/

fuzz_ui_action_t g_fuzz_pending_ui_action = FUZZ_UI_NONE;

/* Declared normally in sign_configure_baker.h; only the baker target links its definition. */
extern bool hasCommissionRate(void) __attribute__((weak));

static void fuzz_park(fuzz_ui_action_t action) {
    g_fuzz_pending_ui_action = action;
}

void uiComparePubkey(void)                             { fuzz_park(FUZZ_UI_CONFIRM_ONLY); }
void uiGeneratePubkey(volatile unsigned int *flags)    { (void)flags; fuzz_park(FUZZ_UI_CONFIRM_ONLY); }
void uiExportPrivateKey(volatile unsigned int *flags)  { (void)flags; fuzz_park(FUZZ_UI_EXPORT_PRIVATE_KEY); }
void uiExportPrivateKeysNewPath(volatile unsigned int *flags) {
    (void)flags;
    fuzz_park(FUZZ_UI_EXPORT_PRIVATE_KEYS_NEW_PATH);
}

/*
 * The configure-baker screens park a stage while more packets are expected and only present
 * the signing screen once nothing is left to review (display_nbgl.c:376, :550, :482).
 */
void startConfigureBakerCommissionDisplay(void) {
    fuzz_park(global.signConfigureBaker.hasSuspended ? FUZZ_UI_CONFIGURE_BAKER_STAGE
                                                     : FUZZ_UI_SIGN_TRANSACTION);
}
void startConfigureBakerUrlDisplay(bool lastUrlPage) {
    bool more = !lastUrlPage || global.signConfigureBaker.hasSuspended ||
                (hasCommissionRate && hasCommissionRate());
    fuzz_park(more ? FUZZ_UI_CONFIGURE_BAKER_STAGE : FUZZ_UI_SIGN_TRANSACTION);
}
void startConfigureBakerSuspendedDisplay(void)         { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }
void startConfigureBakerDisplay(void) {
    bool more = global.signConfigureBaker.hasMetadataUrl ||
                global.signConfigureBaker.hasSuspended ||
                (hasCommissionRate && hasCommissionRate());
    fuzz_park(more ? FUZZ_UI_CONFIGURE_BAKER_STAGE : FUZZ_UI_SIGN_TRANSACTION);
}
void startConfigureDelegationDisplay(void)             { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }

void uiSignUpdateCredentialInitialDisplay(volatile unsigned int *flags)   { (void)flags; fuzz_park(FUZZ_UI_SUCCESS_NO_IDLE); }
void uiSignUpdateCredentialIdDisplay(volatile unsigned int *flags)        { (void)flags; fuzz_park(FUZZ_UI_SUCCESS_NO_IDLE); }
void uiSignUpdateCredentialThresholdDisplay(volatile unsigned int *flags) { (void)flags; fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }
void uiSignCredentialDeploymentVerificationKeyDisplay(volatile unsigned int *flags)     { (void)flags; fuzz_park(FUZZ_UI_NEXT_VERIFICATION_KEY); }
void uiSignCredentialDeploymentVerificationKeyFlowDisplay(volatile unsigned int *flags) { (void)flags; fuzz_park(FUZZ_UI_NEXT_VERIFICATION_KEY); }
void uiSignUpdateCredentialAddedCredentialDisplay(volatile unsigned int *flags) { (void)flags; fuzz_park(FUZZ_UI_ADDED_CREDENTIAL); }
void uiSignCredentialDeploymentAttributeDisplay(volatile unsigned int *flags)   { (void)flags; fuzz_park(FUZZ_UI_CREDENTIAL_ATTRIBUTE); }
void uiSignCredentialDeploymentNewIntroDisplay(void)      { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }
void uiSignCredentialDeploymentNewDisplay(void)           { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }
void uiSignCredentialDeploymentExistingIntroDisplay(void) { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }
void uiSignCredentialDeploymentExistingDisplay(void)      { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }

void uiReviewPublicInformationForIpDisplay(void)          { fuzz_park(FUZZ_UI_SUCCESS_NO_IDLE); }
void uiSignPublicInformationForIpPublicKeyDisplay(void)   { fuzz_park(FUZZ_UI_SUCCESS_NO_IDLE); }
void uiSignPublicInformationForIpCompleteDisplay(void)    { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }
void uiSignPublicInformationForIpFinalDisplay(void)       { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }

void uiSignFlowSharedDisplay(void)                        { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }
void uiRegisterDataInitialDisplay(volatile unsigned int *flags) { (void)flags; fuzz_park(FUZZ_UI_SUCCESS_NO_IDLE); }
/* display_nbgl.c:1180 - a payload chunk still to come only asks for the next packet. */
void uiRegisterDataPayloadDisplay(volatile unsigned int *flags) {
    (void)flags;
    fuzz_park(global.withDataBlob.signRegisterData.dataLength > 0 ? FUZZ_UI_SUCCESS_NO_IDLE
                                                                  : FUZZ_UI_SIGN_TRANSACTION);
}

void startTransferDisplay(bool displayMemo, volatile unsigned int *flags) {
    (void)displayMemo; (void)flags;
    fuzz_park(FUZZ_UI_SIGN_TRANSACTION);
}
void uiSignTransferToPublicDisplay(volatile unsigned int *flags) { (void)flags; fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }
void startInitialScheduledTransferDisplay(bool displayMemo) {
    (void)displayMemo;
    fuzz_park(FUZZ_UI_INITIAL_SCHEDULED_TRANSFER);
}
void uiSignScheduledTransferPairFlowSignDisplay(void)     { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }
void uiSignScheduledTransferPairFlowDisplay(void)         { fuzz_park(FUZZ_UI_NEXT_SCHEDULED_PAIR); }

void uiDeployModuleDisplay(void)                          { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }
void uiInitContractDisplay(void)                          { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }
void uiUpdateContractDisplay(void)                        { fuzz_park(FUZZ_UI_SIGN_TRANSACTION); }

void uiVerifyAddress(volatile unsigned int *flags)        { (void)flags; fuzz_park(FUZZ_UI_CONFIRM_ONLY); }

/* ──────────────────────────────────────────────────────────────────────
 * Answering a parked review screen (finding V-102)
 *
 * Each continuation lives in a handler translation unit that only some targets link, so they
 * are declared weak and checked before use: in a target that cannot reach a given screen the
 * symbol is simply absent, and that screen can never have been parked either.
 * ──────────────────────────────────────────────────────────────────────*/

extern void buildAndSignTransactionHash(void)        __attribute__((weak));
extern void confirmInitialScheduledTransfer(void)    __attribute__((weak));
extern void processNextScheduledAmount(uint8_t *buf) __attribute__((weak));
extern void confirmConfigureBakerStage(void)         __attribute__((weak));
extern void processNextVerificationKey(void)         __attribute__((weak));
extern void confirmAddedCredential(void)             __attribute__((weak));
extern void confirmCredentialAttribute(void)         __attribute__((weak));
extern void exportPrivateKey(void)                   __attribute__((weak));
extern void sendPrivateKeysNewPath(void)             __attribute__((weak));
extern void rejectPrivateKeysNewPath(void)           __attribute__((weak));

/*
 * display_nbgl.c:121 - a rejection on an intermediate screen must end the whole flow, or a
 * later packet could resume it and walk the user to the signing screen anyway.
 */
static void fuzz_reject_staged_review(void) {
    global_tx_state.currentInstruction = INSTRUCTION_NONE;
    send_user_rejection();
}

void fuzz_answer_pending_ui(bool approve) {
    fuzz_ui_action_t action = g_fuzz_pending_ui_action;
    g_fuzz_pending_ui_action = FUZZ_UI_NONE;

    switch (action) {
        case FUZZ_UI_NONE:
            return;

        case FUZZ_UI_SIGN_TRANSACTION: /* review_choice_sign */
            if (!approve) {
                send_user_rejection();
            } else if (buildAndSignTransactionHash) {
                buildAndSignTransactionHash();
            }
            return;

        case FUZZ_UI_INITIAL_SCHEDULED_TRANSFER:
            if (!approve) {
                send_user_rejection();
            } else if (confirmInitialScheduledTransfer) {
                confirmInitialScheduledTransfer();
            }
            return;

        case FUZZ_UI_NEXT_SCHEDULED_PAIR: /* processNextScheduledAmountWrapper */
            if (!approve) {
                send_user_rejection();
            } else if (processNextScheduledAmount) {
                processNextScheduledAmount(
                    global.withDataBlob.signTransferWithScheduleContext.buffer);
            }
            return;

        case FUZZ_UI_SUCCESS_NO_IDLE:
            if (!approve) {
                fuzz_reject_staged_review();
            } else {
                send_success_no_idle();
            }
            return;

        case FUZZ_UI_CONFIGURE_BAKER_STAGE:
            if (!approve) {
                fuzz_reject_staged_review();
            } else if (confirmConfigureBakerStage) {
                confirmConfigureBakerStage();
            }
            return;

        case FUZZ_UI_NEXT_VERIFICATION_KEY:
            if (!approve) {
                fuzz_reject_staged_review();
            } else if (processNextVerificationKey) {
                processNextVerificationKey();
            }
            return;

        case FUZZ_UI_ADDED_CREDENTIAL:
            if (!approve) {
                send_user_rejection();
            } else if (confirmAddedCredential) {
                confirmAddedCredential();
            }
            return;

        case FUZZ_UI_CREDENTIAL_ATTRIBUTE:
            if (!approve) {
                send_user_rejection();
            } else if (confirmCredentialAttribute) {
                confirmCredentialAttribute();
            }
            return;

        case FUZZ_UI_EXPORT_PRIVATE_KEY:
            if (!approve) {
                send_user_rejection();
            } else if (exportPrivateKey) {
                exportPrivateKey();
            }
            return;

        case FUZZ_UI_EXPORT_PRIVATE_KEYS_NEW_PATH:
            /* The reject side wipes derived key material, so it is the interesting half. */
            if (!approve) {
                if (rejectPrivateKeysNewPath) {
                    rejectPrivateKeysNewPath();
                }
            } else if (sendPrivateKeysNewPath) {
                sendPrivateKeysNewPath();
            }
            return;

        case FUZZ_UI_CONFIRM_ONLY:
            if (!approve) {
                send_user_rejection();
            } else {
                send_success_no_idle();
            }
            return;
    }
}

/* ──────────────────────────────────────────────────────────────────────
 * set_trusted_name stubs (replaces src/handler/set_trusted_name.c definitions)
 *
 * Compiled only for the targets that do not link the real handler. With these in place the
 * TLV parser, the per-tag callbacks, the duplicate/required-tag rules, the challenge
 * comparison and the PKI dispatch were unreachable from every target in the suite
 * (finding V-114).
 * ──────────────────────────────────────────────────────────────────────*/

#ifndef FUZZ_REAL_TRUSTED_NAME
void trusted_name_send_set_error(uint16_t sw) { (void)sw; }
void clear_trusted_name_binding(void) {
    memset(g_trusted_name, 0, sizeof(g_trusted_name));
    memset(g_trusted_address, 0, sizeof(g_trusted_address));
    g_trusted_address_len = 0;
    g_trusted_chain_id    = 0;
    g_trusted_name_valid  = false;
}
void handle_set_trusted_name(const command_t *cmd) { (void)cmd; }
#endif

/* ──────────────────────────────────────────────────────────────────────
 * TLV library stubs
 *
 * The trusted-name target links the SDK's real lib_tlv/tlv_library.c instead, so that the
 * app's DER/TLV schema is actually parsed rather than always rejected.
 * ──────────────────────────────────────────────────────────────────────*/

#ifndef FUZZ_REAL_TLV
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
#endif /* FUZZ_REAL_TLV */

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
