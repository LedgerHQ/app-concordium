#include "globals.h"

#include <string.h>

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "apdu/apdu_response.h"
#include "concordium_crypto.h"
#include "app_sizes.h"
#include "derivation_path.h"
#include "display.h"
#include "get_public_key.h"
#include "numberHelpers.h"

static exportPublicKeyContext_t *ctx = &global.exportPublicKeyContext;
static tx_state_t *tx_state = &global_tx_state;

void handle_get_public_key(const command_t *cmd, volatile unsigned int *flags) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t p2 = cmd->p2;
    uint8_t lc = cmd->lc;

    /* A review of this instruction is on screen and unanswered. Re-entering would repin the
     * path below and redraw the screen, swapping what the user is about to consent to for
     * something the host chose afterwards - display and signature would still agree, so the
     * pin cannot catch it; only refusing can. Unreachable while the SDK withholds APDUs during
     * a pending reply (os_io_handle_ux_event_reject_apdu), which is why it is cheap to keep. */
    if (global_public_key_review_pending) {
        PRINTF("GET_PUBLIC_KEY refused: a review of it is waiting for the user\n");
        /* io_send_sw, not send_rejection: that one also drops the instruction latch, and the
         * pending review is what the latch is holding. A free latch makes app_main() zero
         * `global` before the next command, so another instruction would own the union that
         * this review still reads its on-screen text and `signPublicKey` from. Refusing must
         * leave the review owning its state. */
        io_send_sw(ERROR_INVALID_STATE);
        return;
    }

    parse_derivation_path(cdata, lc);
    derivation_path_t *dp = &global_derivation_path;

    /* Pin the path this request is about, before anything can parse over it. Every derivation
     * below - the key drawn on screen and the key sent on Accept - reads the pin, so the
     * reviewed path and the derived path are one object rather than two reads of a global. */
    memmove(&global_reviewed_path, dp, sizeof(global_reviewed_path));

    // If P2 == P2_SIGN_PUBLIC_KEY, then the public-key is signed by its corresponding private key,
    // and appended to the returned public-key. This is used when it is needed to provide
    // proof of the knowledge of the corresponding private key.
    ctx->signPublicKey = p2 == P2_SIGN_PUBLIC_KEY;

    // If P1 == P1_SKIP_DISPLAY, then we skip displaying the key being exported. This is used when
    // it is not important for the user to validate the key.
    if (p1 == P1_SKIP_DISPLAY) {
        send_public_key(false);
        return;
    }

    /* Display uses unhardened path indices; parse_derivation_path leaves hardened nodes for
     * crypto. */
    unharden_derivation_path(dp);

    if (dp->len == GOVERNANCE_KEY_PATH_LENGTH && dp->nodes[0] == LEGACY_PURPOSE &&
        dp->nodes[PATH_INDEX_IDENTITY_PROVIDER] != GOVERNANCE_IDENTITY_INDEX) {
        THROW(ERROR_INVALID_PATH);
    }

    const bool governance =
        (dp->len == GOVERNANCE_KEY_PATH_LENGTH && dp->nodes[0] == LEGACY_PURPOSE &&
         dp->nodes[PATH_INDEX_IDENTITY_PROVIDER] == GOVERNANCE_IDENTITY_INDEX);

    if (governance) {
        if (sizeof(ctx->display) < GOVERNANCE_DISPLAY_MIN_LEN) {
            THROW(ERROR_BUFFER_OVERFLOW);
        }
        uint32_t level = dp->nodes[PATH_INDEX_IDENTITY];
        switch (level) {
            case 0:
                memmove(ctx->display, "Gov. root", GOV_ROOT_LEN);
                break;
            case 1:
                memmove(ctx->display, "Gov. level 1", GOV_LEVEL_LEN);
                break;
            case 2:
                memmove(ctx->display, "Gov. level 2", GOV_LEVEL_LEN);
                break;
            default:
                THROW(ERROR_INVALID_PATH);
        }
    } else if (dp->variant == DERIVATION_PATH_VARIANT_NEW) {
        path_display_new(ctx->display,
                         sizeof(ctx->display),
                         dp->nodes[PATH_INDEX_IDENTITY_PROVIDER],
                         dp->nodes[PATH_INDEX_IDENTITY],
                         dp->nodes[PATH_INDEX_ACCOUNT_NEW]);
    } else if (dp->variant == DERIVATION_PATH_VARIANT_LEGACY) {
        path_display_legacy(ctx->display,
                            sizeof(ctx->display),
                            dp->nodes[PATH_INDEX_IDENTITY_LEGACY],
                            dp->nodes[PATH_INDEX_ACCOUNT_LEGACY]);
    } else {
        /* Non-standard purpose: same legacy-style display as before (indices 4 and 6). */
        path_display_legacy(ctx->display,
                            sizeof(ctx->display),
                            dp->nodes[PATH_INDEX_IDENTITY_LEGACY],
                            dp->nodes[PATH_INDEX_ACCOUNT_LEGACY]);
    }

    harden_derivation_path(dp);

    uint8_t publicKey[KEY_LENGTH];
    get_public_key(&global_reviewed_path, publicKey);
    to_paginated_hex(publicKey, sizeof(publicKey), ctx->publicKey, sizeof(ctx->publicKey));

    // Claim the review before drawing it; send_public_key() releases it once answered.
    global_public_key_review_pending = true;
    uiGeneratePubkey(flags);
}

/**
 * Derive the public-key for the given path, and then write it to
 * the APDU buffer to be returned to the caller.
 */
void send_public_key(bool compare) {
    /* Answering the review releases it. Done here rather than only on the way back to the idle
     * screen because the compare branch below deliberately leaves its screen up and lets new
     * instructions run; holding the claim until then would block them. */
    global_public_key_review_pending = false;

    /* The pinned path, not global_derivation_path: this runs from the approval callback, so the
     * global may have been parsed over since the review was drawn. */
    uint8_t publicKey[KEY_LENGTH];
    get_public_key(&global_reviewed_path, publicKey);

    // tx is holding the offset in the buffer we have written to. It is a convention to call this tx
    // for Ledger apps.
    uint8_t tx = 0;

    // Write the public-key to the APDU buffer.
    for (uint8_t i = 0; i < sizeof(publicKey); i++) {
        G_io_apdu_buffer[i] = publicKey[i];
        tx++;
    }

    if (ctx->signPublicKey) {
        uint8_t signedPublicKey[ED25519_SIGNATURE_LENGTH];
        sign(&global_reviewed_path, publicKey, signedPublicKey);
        if (sizeof(signedPublicKey) > sizeof(G_io_apdu_buffer) - tx) {
            THROW(ERROR_BUFFER_OVERFLOW);
        }
        memmove(G_io_apdu_buffer + tx, signedPublicKey, sizeof(signedPublicKey));
        tx += sizeof(signedPublicKey);
    }

    // Send back success response including the public-key (and signature, if wanted).
    if (compare) {
        // Show the public-key so that the user can verify the public-key.
        send_success_result_no_idle(tx);

        // Snapshot what the comparison screen shows into storage outside the instruction union.
        // The next instruction is accepted while that screen is still up (see below) and zeroes
        // the union, so a host could otherwise change the key the user is comparing against.
        _Static_assert(sizeof(global_compare_public_key.display) == sizeof(ctx->display),
                       "comparison identity snapshot must match exportPublicKeyContext");
        _Static_assert(sizeof(global_compare_public_key.publicKey) == sizeof(ctx->publicKey),
                       "comparison key snapshot must match exportPublicKeyContext");
        memmove(global_compare_public_key.display, ctx->display, sizeof(ctx->display));
        to_paginated_hex(publicKey,
                         sizeof(publicKey),
                         global_compare_public_key.publicKey,
                         sizeof(global_compare_public_key.publicKey));

        // Allow for receiving a new instruction even while comparing public keys.
        tx_state->currentInstruction = INSTRUCTION_NONE;
        uiComparePubkey();

    } else {
        send_success(tx);
    }
}
