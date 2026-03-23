#include "globals.h"
#include "format.h"
#include "numberHelpers.h"
#include "exportPrivateKey.h"
#include "util/derivation_path.h"

// This class allows for the export of a number of very specific private keys. These private keys
// are made exportable as they are used in computations that are not feasible to carry out on the
// Ledger device. The key derivation paths that are allowed are restricted so that it is not
// possible to export keys that are used for signing.
static exportPrivateKeyContext_t *ctx = &global.exportPrivateKeyContext;

/**
 * Append decimal representation via bin2dec (digits + trailing NUL). If more text follows, the NUL
 * is dropped from the cursor so the buffer can be concatenated safely.
 */
static size_t append_dec(uint8_t *buf, size_t cap, size_t off, uint64_t n, bool more_follows) {
    size_t step = bin2dec(buf + off, cap - off, n);
    return off + step - (more_follows ? 1U : 0U);
}

/** Append export key-type segment(s) to a 4-node base path (identity + idp filled). Unhardened;
 * caller hardens. */
static bool append_export_key_type(derivation_path_t *dp,
                                   uint8_t derivationPathKeyType,
                                   uint32_t account) {
    switch (derivationPathKeyType) {
        case NEW_ID_CRED_SEC:
        case NEW_PRF_KEY:
        case NEW_SIGNATURE_BLINDING_RANDOMNESS:
            if (dp->len >= DERIVATION_PATH_NODES_MAX) {
                return false;
            }
            dp->nodes[dp->len++] = derivationPathKeyType;
            return true;
        case NEW_COMMITMENT_RANDOMNESS:
            if (dp->len + 2 > DERIVATION_PATH_NODES_MAX) {
                return false;
            }
            dp->nodes[dp->len++] = NEW_COMMITMENT_RANDOMNESS;
            dp->nodes[dp->len++] = account;
            return true;
        default:
            PRINTF("Invalid derivation path key type: %d\n", derivationPathKeyType);
            return false;
    }
}

int exportNewPathPrivateKeysForPurpose(uint8_t purpose,
                                       uint8_t networkDesignation,
                                       uint32_t identityProvider,
                                       uint32_t identity,
                                       uint32_t account,
                                       uint8_t *outputPrivateKey,
                                       size_t outputPrivateKeySize) {
    cx_ecfp_private_key_t tempPrivateKeyEd25519;
    uint8_t tempPrivateKey[KEY_LENGTH];

    uint8_t keysToExport[MAX_KEYS_TO_EXPORT] = {0, 0, 0};
    uint8_t keysToExportLength = 0;

    uint32_t coin_type;
    switch (networkDesignation) {
        case P2_MAINNET:
            coin_type = NEW_MAINNET_COIN_TYPE;
            break;
        case P2_TESTNET:
            coin_type = NEW_TESTNET_COIN_TYPE;
            break;
        default:
            PRINTF("Invalid network type: %d\n", networkDesignation);
            THROW(ERROR_INVALID_PARAM);
    }

    switch (purpose) {
        case P1_IDENTITY_CREDENTIAL_CREATION:
            keysToExport[keysToExportLength++] = NEW_ID_CRED_SEC;
            keysToExport[keysToExportLength++] = NEW_PRF_KEY;
            keysToExport[keysToExportLength++] = NEW_SIGNATURE_BLINDING_RANDOMNESS;
            break;
        case P1_ACCOUNT_CREATION:
            keysToExport[keysToExportLength++] = NEW_PRF_KEY;
            keysToExport[keysToExportLength++] = NEW_ID_CRED_SEC;
            keysToExport[keysToExportLength++] = NEW_COMMITMENT_RANDOMNESS;
            break;
        case P1_ID_RECOVERY:
            keysToExport[keysToExportLength++] = NEW_ID_CRED_SEC;
            keysToExport[keysToExportLength++] = NEW_SIGNATURE_BLINDING_RANDOMNESS;
            break;
        case P1_ACCOUNT_CREDENTIAL_DISCOVERY:
            keysToExport[keysToExportLength++] = NEW_PRF_KEY;
            break;
        case P1_CREATION_OF_ZK_PROOF:
            keysToExport[keysToExportLength++] = NEW_COMMITMENT_RANDOMNESS;
            break;
        default:
            PRINTF("Invalid purpose: %d\n", purpose);
            THROW(ERROR_INVALID_PARAM);
    }

    // check if the buffer is big enough
    if (keysToExportLength * LENGTH_AND_PRIVATE_KEY_SIZE > outputPrivateKeySize) {
        PRINTF("There is not enough space for the keys in the output buffer\n");
        THROW(ERROR_BUFFER_OVERFLOW);
    }

    uint8_t tx = 0;

    // iterate over the keys to export
    for (int keyIndex = 0; keyIndex < keysToExportLength; keyIndex++) {
        derivation_path_t subpath;
        init_derivation_path(&subpath);
        subpath.len = 4;
        subpath.nodes[0] = NEW_PURPOSE;
        subpath.nodes[1] = coin_type;
        subpath.nodes[2] = identityProvider;
        subpath.nodes[3] = identity;

        if (!append_export_key_type(&subpath, keysToExport[keyIndex], account)) {
            PRINTF("The derivation path length is too long\n");
            THROW(ERROR_BUFFER_OVERFLOW);
        }

        harden_derivation_path(&subpath);

        outputPrivateKey[tx++] = KEY_LENGTH;
        if (keysToExport[keyIndex] == NEW_COMMITMENT_RANDOMNESS) {
            // export raw key
            getPrivateKey(&subpath, &tempPrivateKeyEd25519);
            for (int i = 0; i < KEY_LENGTH; i++) {
                tempPrivateKey[i] = tempPrivateKeyEd25519.d[i];
            }
        } else {
            // export bls key
            getBlsPrivateKey(&subpath, tempPrivateKey, sizeof(tempPrivateKey));
        }

        for (int i = 0; i < KEY_LENGTH; i++) {
            outputPrivateKey[tx] = tempPrivateKey[i];
            tx++;
        }
    }
    explicit_bzero(&tempPrivateKey, sizeof(tempPrivateKey));
    explicit_bzero(&tempPrivateKeyEd25519, sizeof(tempPrivateKeyEd25519));
    return tx;
}

void handleExportPrivateKeyNewPath(uint8_t *dataBuffer,
                                   uint8_t p1,
                                   uint8_t p2,
                                   uint8_t lc,
                                   volatile unsigned int *flags) {
    /////// validate p1 parameter //////
    if ((p1 != P1_IDENTITY_CREDENTIAL_CREATION && p1 != P1_ACCOUNT_CREATION &&
         p1 != P1_ID_RECOVERY && p1 != P1_ACCOUNT_CREDENTIAL_DISCOVERY &&
         p1 != P1_CREATION_OF_ZK_PROOF)) {
        THROW(ERROR_INVALID_PARAM);
    }

    /////// validate p2 parameter //////
    if ((p2 != P2_MAINNET && p2 != P2_TESTNET)) {
        THROW(ERROR_INVALID_PARAM);
    }

    size_t offset = 0;
    uint8_t remainingDataLength = lc;

    ////// Extract the identity provider //////
    if (remainingDataLength < 4) {
        THROW(ERROR_INVALID_PATH);
    }
    uint32_t identityProvider = U4BE(dataBuffer, offset);
    offset += 4;
    remainingDataLength -= 4;

    ////// Extract the identity //////
    if (remainingDataLength < 4) {
        THROW(ERROR_INVALID_PATH);
    }
    uint32_t identity = U4BE(dataBuffer, offset);
    offset += 4;
    remainingDataLength -= 4;

    ////// Extract the account //////
    uint32_t account = 0xFFFFFFFF;
    if (p1 == P1_ACCOUNT_CREATION || p1 == P1_CREATION_OF_ZK_PROOF) {
        if (remainingDataLength < 4) {
            THROW(ERROR_INVALID_PATH);
        }
        account = U4BE(dataBuffer, offset);
    }

    ctx->privateKeysLength =
        (uint8_t) exportNewPathPrivateKeysForPurpose(p1,
                                                     p2,
                                                     identityProvider,
                                                     identity,
                                                     account,
                                                     ctx->outputPrivateKeys,
                                                     sizeof(ctx->outputPrivateKeys));

    ////// Set up the display //////
    const bool need_account_suffix = (p1 == P1_ACCOUNT_CREATION || p1 == P1_CREATION_OF_ZK_PROOF);

    memmove(ctx->display_credid, "IDP#", 4);
    offset = 4;
    offset = append_dec(ctx->display_credid,
                        sizeof(ctx->display_credid),
                        offset,
                        identityProvider,
                        true);
    memmove(ctx->display_credid + offset, " ID#", 4);
    offset += 4;
    offset = append_dec(ctx->display_credid,
                        sizeof(ctx->display_credid),
                        offset,
                        identity,
                        need_account_suffix);

    memmove(ctx->display_review_operation,
            "Review operation",
            EXPORT_PRIVATE_KEY_REVIEW_OPERATION_LEN);

    memmove(ctx->display_credid_title, "Credentials ID", EXPORT_PRIVATE_KEY_CREDID_TITLE_LEN);

    memmove(ctx->display_sign, "Sign operation", EXPORT_PRIVATE_KEY_SIGN_OPERATION_LEN);

    if (p1 == P1_IDENTITY_CREDENTIAL_CREATION) {
        memmove(ctx->display_review_verb,
                "to create credentials",
                EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN);
        memmove(ctx->display_sign_verb, "to create credentials?", EXPORT_PRIVATE_KEY_SIGN_VERB_LEN);
    } else if (p1 == P1_ACCOUNT_CREATION) {
        memmove(ctx->display_review_verb, "to create account", EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN);
        memmove(ctx->display_sign_verb, "to create account?", EXPORT_PRIVATE_KEY_SIGN_VERB_LEN);
    } else if (p1 == P1_ID_RECOVERY) {
        memmove(ctx->display_review_verb,
                "to recover credentials",
                EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN);
        memmove(ctx->display_sign_verb,
                "to recover credentials?",
                EXPORT_PRIVATE_KEY_SIGN_VERB_LEN);
    } else if (p1 == P1_ACCOUNT_CREDENTIAL_DISCOVERY) {
        memmove(ctx->display_review_verb,
                "to discover credentials",
                EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN);
        memmove(ctx->display_sign_verb,
                "to discover credentials?",
                EXPORT_PRIVATE_KEY_SIGN_VERB_LEN);
    } else if (p1 == P1_CREATION_OF_ZK_PROOF) {
        memmove(ctx->display_review_verb, "to create ZK proof", EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN);
        memmove(ctx->display_sign_verb, "to create ZK proof?", EXPORT_PRIVATE_KEY_SIGN_VERB_LEN);
    }

    if (need_account_suffix) {
        if (offset + 9 > sizeof(ctx->display_credid)) {
            THROW(ERROR_BUFFER_OVERFLOW);
        }
        memmove(ctx->display_credid + offset, " ACCOUNT#", 9);
        offset += 9;
        (void) append_dec(ctx->display_credid, sizeof(ctx->display_credid), offset, account, false);
    }

    uiExportPrivateKeysNewPath(flags);
}

void sendPrivateKeysNewPath(void) {
    memmove(G_io_apdu_buffer, ctx->outputPrivateKeys, ctx->privateKeysLength);
    sendSuccess(ctx->privateKeysLength);
    explicit_bzero(ctx->outputPrivateKeys, sizeof(ctx->outputPrivateKeys));
    ctx->privateKeysLength = 0;
}
