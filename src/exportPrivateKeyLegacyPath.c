#include "globals.h"
#include "format.h"
#include "numberHelpers.h"
#include "exportPrivateKey.h"

// This class allows for the export of a number of very specific private keys.
// These private keys are made exportable as they are used in computations that
// are not feasible to carry out on the Ledger device. The key derivation paths
// that are allowed are restricted so that it is not possible to export keys
// that are used for signing.
static const uint32_t HARDENED_OFFSET = 0x80000000;
static exportPrivateKeyContext_t *ctx = &global.exportPrivateKeyContext;

void exportPrivateKeySeed(void) {
    cx_ecfp_private_key_t privateKey;
    BEGIN_TRY {
        TRY {
            uint8_t lastSubPath = LEGACY_PRF_KEY;
            uint8_t lastSubPathIndex = 5;
            ctx->path[lastSubPathIndex] = lastSubPath | HARDENED_OFFSET;
            getPrivateKey(ctx->path, lastSubPathIndex + 1, &privateKey);
            uint8_t tx = 0;
            for (int i = 0; i < 32; i++) {
                G_io_apdu_buffer[tx++] = privateKey.d[i];
            }

            if (ctx->exportBoth) {
                lastSubPath = LEGACY_ID_CRED_SEC;
                ctx->path[lastSubPathIndex] = lastSubPath | HARDENED_OFFSET;
                getPrivateKey(ctx->path, lastSubPathIndex + 1, &privateKey);
                for (int i = 0; i < 32; i++) {
                    G_io_apdu_buffer[tx++] = privateKey.d[i];
                }
            }

            sendSuccess(tx);
        }
        FINALLY {
            explicit_bzero(&privateKey, sizeof(privateKey));
        }
    }
    END_TRY;
}

void exportPrivateKeyBls(void) {
    uint8_t privateKey[COMMON_PRIVATE_KEY_SIZE];
    BEGIN_TRY {
        TRY {
            uint8_t lastSubPath = LEGACY_PRF_KEY;
            uint8_t lastSubPathIndex = 5;

            ctx->path[lastSubPathIndex] = lastSubPath | HARDENED_OFFSET;
            getBlsPrivateKey(ctx->path, lastSubPathIndex + 1, privateKey, sizeof(privateKey));
            uint8_t tx = 0;
            if (sizeof(privateKey) > sizeof(G_io_apdu_buffer)) {
                THROW(ERROR_BUFFER_OVERFLOW);
            }
            memmove(G_io_apdu_buffer, privateKey, sizeof(privateKey));
            tx += sizeof(privateKey);

            if (ctx->exportBoth) {
                lastSubPath = LEGACY_ID_CRED_SEC;
                ctx->path[lastSubPathIndex] = lastSubPath | HARDENED_OFFSET;
                getBlsPrivateKey(ctx->path, lastSubPathIndex + 1, privateKey, sizeof(privateKey));
                if (sizeof(privateKey) + tx > sizeof(G_io_apdu_buffer)) {
                    THROW(ERROR_BUFFER_OVERFLOW);
                }
                memmove(G_io_apdu_buffer + tx, privateKey, sizeof(privateKey));
                tx += sizeof(privateKey);
            }

            sendSuccess(tx);
        }
        FINALLY {
            explicit_bzero(&privateKey, sizeof(privateKey));
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

void handleExportPrivateKeyLegacyPath(uint8_t *dataBuffer,
                                      uint8_t p1,
                                      uint8_t p2,
                                      uint8_t lc,
                                      volatile unsigned int *flags) {
    if ((p1 != P1_LEGACY_PRF_KEY_AND_ID_CRED_SEC && p1 != P1_LEGACY_PRF_KEY &&
         p1 != P1_LEGACY_PRF_KEY_RECOVERY) ||
        (p2 != P2_LEGACY_KEY && p2 != P2_LEGACY_SEED)) {
        THROW(ERROR_INVALID_PARAM);
    }
    size_t offset = 0;

    ctx->isNewPath = false;
    uint8_t remainingDataLength = lc - offset;
    uint32_t identity;
    if (remainingDataLength < 4) {
        THROW(ERROR_INVALID_PATH);
    }
    identity = U4BE(dataBuffer, offset);
    uint32_t *keyDerivationPath;
    size_t pathLength;
    keyDerivationPath = (uint32_t[5]){LEGACY_PURPOSE | HARDENED_OFFSET,
                                      LEGACY_COIN_TYPE | HARDENED_OFFSET,
                                      ACCOUNT_SUBTREE | HARDENED_OFFSET,
                                      NORMAL_ACCOUNTS | HARDENED_OFFSET,
                                      identity | HARDENED_OFFSET};
    pathLength = 5;
    memmove(ctx->path, keyDerivationPath, pathLength * sizeof(uint32_t));
    ctx->pathLength = pathLength * sizeof(uint32_t);

    ctx->exportBoth = p1 == P1_LEGACY_PRF_KEY_AND_ID_CRED_SEC;
    ctx->exportSeed = p2 == P2_LEGACY_SEED;

    // Reset the offset to 0
    offset = 0;

    memmove(ctx->display_credid + offset, "ID#", 3);
    offset += 3;
    bin2dec(ctx->display_credid + offset, sizeof(ctx->display_credid) - offset, identity);

    memmove(ctx->display_credid_title, "Credentials ID", EXPORT_PRIVATE_KEY_CREDID_TITLE_LEN);
    memmove(ctx->display_review_operation,
            "Review operation",
            EXPORT_PRIVATE_KEY_REVIEW_OPERATION_LEN);
    memmove(ctx->display_sign, "Sign operation", EXPORT_PRIVATE_KEY_SIGN_OPERATION_LEN);

    if (p1 == P1_LEGACY_PRF_KEY_AND_ID_CRED_SEC) {
        memmove(ctx->display_sign_verb, "to create credentials?", EXPORT_PRIVATE_KEY_SIGN_VERB_LEN);
        memmove(ctx->display_review_verb,
                "to create credentials",
                EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN);
    } else if (p1 == P1_LEGACY_PRF_KEY_RECOVERY) {
        memmove(ctx->display_sign_verb,
                "to recover credentials?",
                EXPORT_PRIVATE_KEY_SIGN_VERB_LEN);
        memmove(ctx->display_review_verb,
                "to recover credentials",
                EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN);
    } else if (p1 == P1_LEGACY_PRF_KEY) {
        memmove(ctx->display_sign_verb,
                "to decrypt credentials?",
                EXPORT_PRIVATE_KEY_SIGN_VERB_LEN);
        memmove(ctx->display_review_verb,
                "to decrypt credentials",
                EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN);
    }

    uiExportPrivateKey(flags);
}
