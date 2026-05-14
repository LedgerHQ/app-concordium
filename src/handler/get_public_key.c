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

    parse_derivation_path(cdata, lc);
    derivation_path_t *dp = &global_derivation_path;

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
    get_public_key(publicKey);
    to_paginated_hex(publicKey, sizeof(publicKey), ctx->publicKey, sizeof(ctx->publicKey));

    uiGeneratePubkey(flags);
}

/**
 * Derive the public-key for the given path, and then write it to
 * the APDU buffer to be returned to the caller.
 */
void send_public_key(bool compare) {
    uint8_t publicKey[KEY_LENGTH];
    get_public_key(publicKey);

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
        sign(publicKey, signedPublicKey);
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
        to_paginated_hex(publicKey, sizeof(publicKey), ctx->publicKey, sizeof(ctx->publicKey));
        // Allow for receiving a new instruction even while comparing public keys.
        tx_state->currentInstruction = INSTRUCTION_NONE;
        uiComparePubkey();

    } else {
        send_success(tx);
    }
}
