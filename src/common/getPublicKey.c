#include "globals.h"

static keyDerivationPath_t *keyPath = &path;
static exportPublicKeyContext_t *ctx = &global.exportPublicKeyContext;
static tx_state_t *tx_state = &global_tx_state;
static const uint32_t HARDENED_OFFSET = 0x80000000;

instructionContext global;

/**
 * Derive the public-key for the given path, and then write it to
 * the APDU buffer to be returned to the caller.
 */
void sendPublicKey(bool compare) {
    uint8_t publicKey[KEY_LENGTH];
    getPublicKey(publicKey);

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
        sendSuccessResultNoIdle(tx);
        toPaginatedHex(publicKey, sizeof(publicKey), ctx->publicKey, sizeof(ctx->publicKey));
        // Allow for receiving a new instruction even while comparing public keys.
        tx_state->currentInstruction = INSTRUCTION_NONE;
        uiComparePubkey();

    } else {
        sendSuccess(tx);
    }
}

void handleGetPublicKey(uint8_t *cdata,
                        uint8_t p1,
                        uint8_t p2,
                        uint8_t lc,
                        volatile unsigned int *flags) {
    parseKeyDerivationPath(cdata, lc);

    // If P2 == P2_SIGN_PUBLIC_KEY, then the public-key is signed by its corresponding private key,
    // and appended to the returned public-key. This is used when it is needed to provide
    // proof of the knowledge of the corresponding private key.
    ctx->signPublicKey = p2 == P2_SIGN_PUBLIC_KEY;

    // If P1 == P1_SKIP_DISPLAY, then we skip displaying the key being exported. This is used when
    // it is not important for the user to validate the key.
    if (p1 == P1_SKIP_DISPLAY) {
        sendPublicKey(false);
    } else {
        // If the key path is of length GOVERNANCE_KEY_PATH_LENGTH, then it is a request for a
        // governance key. Also it has to be in the governance subtree, which starts with 1.
        if (keyPath->pathLength == GOVERNANCE_KEY_PATH_LENGTH &&
            keyPath->rawKeyDerivationPath[0] == LEGACY_PURPOSE) {
            if (keyPath->rawKeyDerivationPath[PATH_INDEX_IDENTITY_PROVIDER] !=
                GOVERNANCE_IDENTITY_INDEX) {
                THROW(ERROR_INVALID_PATH);
            }

            uint32_t purpose = keyPath->rawKeyDerivationPath[PATH_INDEX_IDENTITY];
            if (sizeof(ctx->display) < GOVERNANCE_DISPLAY_MIN_LEN) {
                THROW(ERROR_BUFFER_OVERFLOW);
            }

            switch (purpose) {
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
        } else {
            if (keyPath->rawKeyDerivationPath[0] == NEW_PURPOSE ||
                keyPath->rawKeyDerivationPath[0] == (NEW_PURPOSE | HARDENED_OFFSET)) {
                uint32_t identityProviderIndex =
                    keyPath->rawKeyDerivationPath[PATH_INDEX_IDENTITY_PROVIDER];
                uint32_t identityIndex = keyPath->rawKeyDerivationPath[PATH_INDEX_IDENTITY];
                uint32_t accountIndex = keyPath->rawKeyDerivationPath[PATH_INDEX_ACCOUNT_NEW];
                getIdentityAccountDisplayNewPath(ctx->display,
                                                 sizeof(ctx->display),
                                                 identityProviderIndex,
                                                 identityIndex,
                                                 accountIndex);
            } else {
                uint32_t identityIndex = keyPath->rawKeyDerivationPath[PATH_INDEX_IDENTITY_LEGACY];
                uint32_t accountIndex = keyPath->rawKeyDerivationPath[PATH_INDEX_ACCOUNT_LEGACY];
                getIdentityAccountDisplay(ctx->display,
                                          sizeof(ctx->display),
                                          identityIndex,
                                          accountIndex);
            }
        }
        uiGeneratePubkey(flags);
    }
}
