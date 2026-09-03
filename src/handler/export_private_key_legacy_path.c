#include "globals.h"

#include <string.h>

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "display.h"
#include "apdu/apdu_response.h"
#include "concordium_crypto.h"
#include "derivation_path.h"
#include "format.h"
#include "numberHelpers.h"

#include "export_private_key_legacy_path.h"

static exportPrivateKeyContext_t *ctx = &global.exportPrivateKeyContext;

void handle_export_private_key_legacy_path(const command_t *cmd, volatile unsigned int *flags) {
    uint8_t *dataBuffer = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t p2 = cmd->p2;
    uint8_t lc = cmd->lc;

    if ((p1 != P1_LEGACY_PRF_KEY_AND_ID_CRED_SEC && p1 != P1_LEGACY_PRF_KEY &&
         p1 != P1_LEGACY_PRF_KEY_RECOVERY) ||
        (p2 != P2_LEGACY_KEY && p2 != P2_LEGACY_SEED)) {
        THROW(ERROR_INVALID_PARAM);
    }

    ctx->isNewPath = false;
    uint32_t identity;
    if (lc < 4) {
        THROW(ERROR_INVALID_PATH);
    }
    identity = U4BE(dataBuffer, 0);
    if ((identity & HARDENED_BIT) != 0) {
        THROW(ERROR_INVALID_PATH);
    }

    derivation_path_t *dp = &global_derivation_path;
    init_derivation_path(dp);
    dp->len = 5;
    dp->nodes[0] = LEGACY_PURPOSE;
    dp->nodes[1] = LEGACY_COIN_TYPE;
    dp->nodes[2] = ACCOUNT_SUBTREE;
    dp->nodes[3] = NORMAL_ACCOUNTS;
    dp->nodes[4] = identity;
    harden_derivation_path(dp);

    ctx->exportBoth = p1 == P1_LEGACY_PRF_KEY_AND_ID_CRED_SEC;
    ctx->exportSeed = p2 == P2_LEGACY_SEED;

    size_t offset = 0;
    memmove(ctx->display_credid + offset, "ID#", 3);
    offset += 3;
    bin_to_dec(ctx->display_credid + offset, sizeof(ctx->display_credid) - offset, identity);

    memmove(ctx->display_credid_title, "Credentials ID", EXPORT_PRIVATE_KEY_CREDID_TITLE_LEN);
    memmove(ctx->display_review_operation,
            "Review operation",
            EXPORT_PRIVATE_KEY_REVIEW_OPERATION_LEN);
    memmove(ctx->display_sign, "Sign operation", EXPORT_PRIVATE_KEY_SIGN_OPERATION_LEN);

    switch (p1) {
        case P1_LEGACY_PRF_KEY_AND_ID_CRED_SEC:
            memmove(ctx->display_sign_verb,
                    "to create credentials?",
                    sizeof("to create credentials?"));
            memmove(ctx->display_review_verb,
                    "to create credentials",
                    sizeof("to create credentials"));
            break;
        case P1_LEGACY_PRF_KEY_RECOVERY:
            memmove(ctx->display_sign_verb,
                    "to recover credentials?",
                    sizeof("to recover credentials?"));
            memmove(ctx->display_review_verb,
                    "to recover credentials",
                    sizeof("to recover credentials"));
            break;
        case P1_LEGACY_PRF_KEY:
            memmove(ctx->display_sign_verb,
                    "to decrypt credentials?",
                    sizeof("to decrypt credentials?"));
            memmove(ctx->display_review_verb,
                    "to decrypt credentials",
                    sizeof("to decrypt credentials"));
            break;
        default:
            THROW(SWO_INCORRECT_P1_P2);
    }
    uiExportPrivateKey(flags);
}

/**
 * Legacy export paths are restricted so signing keys cannot be exported.
 */
static void exportPrivateKeySeed(void) {
    cx_ecfp_private_key_t privateKey;
    BEGIN_TRY {
        TRY {
            derivation_path_t *dp = &global_derivation_path;
            const uint8_t lastSubPathIndex = PATH_INDEX_LEGACY_EXPORT_KEY;
            const uint8_t key_count = ctx->exportBoth ? 2U : 1U;
            uint8_t tx = 0;

            for (uint8_t k = 0; k < key_count; k++) {
                uint8_t lastSubPath = (k == 0) ? LEGACY_PRF_KEY : LEGACY_ID_CRED_SEC;
                dp->nodes[lastSubPathIndex] = lastSubPath;
                dp->len = (uint8_t) (lastSubPathIndex + 1);
                harden_derivation_path(dp);
                get_private_key(dp, &privateKey);
                for (int i = 0; i < KEY_LENGTH; i++) {
                    G_io_apdu_buffer[tx++] = privateKey.d[i];
                }
            }

            send_success(tx);
        }
        FINALLY {
            explicit_bzero(&privateKey, sizeof(privateKey));
        }
    }
    END_TRY;
}

static void exportPrivateKeyBls(void) {
    uint8_t privateKey[KEY_LENGTH];
    BEGIN_TRY {
        TRY {
            derivation_path_t *dp = &global_derivation_path;
            const uint8_t lastSubPathIndex = PATH_INDEX_LEGACY_EXPORT_KEY;
            const uint8_t key_count = ctx->exportBoth ? 2U : 1U;
            uint8_t tx = 0;

            for (uint8_t k = 0; k < key_count; k++) {
                uint8_t lastSubPath = (k == 0) ? LEGACY_PRF_KEY : LEGACY_ID_CRED_SEC;
                dp->nodes[lastSubPathIndex] = lastSubPath;
                dp->len = (uint8_t) (lastSubPathIndex + 1);
                harden_derivation_path(dp);
                get_bls_private_key(dp, privateKey, sizeof(privateKey));
                if (tx + sizeof(privateKey) > sizeof(G_io_apdu_buffer)) {
                    THROW(ERROR_BUFFER_OVERFLOW);
                }
                memmove(G_io_apdu_buffer + tx, privateKey, sizeof(privateKey));
                tx += sizeof(privateKey);
            }

            send_success(tx);
        }
        FINALLY {
            explicit_bzero(privateKey, sizeof(privateKey));
        }
    }
    END_TRY;
}

void exportPrivateKey(void) {
    if (ctx->exportSeed) {
        exportPrivateKeySeed();
    } else {
        exportPrivateKeyBls();
    }
}
