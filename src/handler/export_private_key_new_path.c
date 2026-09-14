#include "globals.h"

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "apdu/apdu_response.h"
#include "concordium_crypto.h"
#include "format.h"
#include "display.h"
#include "numberHelpers.h"

#include "export_private_key_new_path.h"
#include "derivation_path.h"

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
    size_t step = bin_to_dec(buf + off, cap - off, n);
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
    uint8_t tempPrivateKey[ED25519_EXTENDED_PRIVATE_KEY_LENGTH];

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

    uint8_t tx = 0;
    // Distinguishes the success path from an unwind inside TRY. Must be volatile: it is
    // written inside TRY and read in FINALLY, i.e. potentially across a longjmp.
    volatile bool exportComplete = false;

    BEGIN_TRY {
        TRY {
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

                // The wire format is a 1-byte length prefix followed by the key, so the
                // exported length must always fit in a uint8_t.
                size_t exportedKeyLength;
                if (keysToExport[keyIndex] == NEW_COMMITMENT_RANDOMNESS) {
                    exportedKeyLength = ED25519_EXTENDED_PRIVATE_KEY_LENGTH;
                    if (tx + 1 + exportedKeyLength > outputPrivateKeySize) {
                        PRINTF("There is not enough space for the keys in the output buffer\n");
                        THROW(ERROR_BUFFER_OVERFLOW);
                    }

                    outputPrivateKey[tx++] = (uint8_t) exportedKeyLength;
                    get_extended_private_key(&subpath,
                                             tempPrivateKey,
                                             KEY_LENGTH,
                                             tempPrivateKey + KEY_LENGTH,
                                             KEY_LENGTH);
                } else {
                    exportedKeyLength = KEY_LENGTH;
                    if (tx + 1 + exportedKeyLength > outputPrivateKeySize) {
                        PRINTF("There is not enough space for the keys in the output buffer\n");
                        THROW(ERROR_BUFFER_OVERFLOW);
                    }

                    outputPrivateKey[tx++] = (uint8_t) exportedKeyLength;
                    get_bls_private_key(&subpath, tempPrivateKey, sizeof(tempPrivateKey));
                }

                for (size_t i = 0; i < exportedKeyLength; i++) {
                    outputPrivateKey[tx] = tempPrivateKey[i];
                    tx++;
                }
            }
            exportComplete = true;
        }
        // No CATCH clause on purpose: a THROW inside a CATCH runs after CLOSE_TRY has
        // popped this context, so it would unwind straight past FINALLY and skip the
        // wipes below. Letting END_TRY re-throw keeps a single cleanup path.
        FINALLY {
            explicit_bzero(tempPrivateKey, sizeof(tempPrivateKey));
            if (!exportComplete) {
                // A partial export leaves plaintext key material in the output buffer,
                // which is otherwise only wiped on the success path in
                // sendPrivateKeysNewPath.
                explicit_bzero(outputPrivateKey, outputPrivateKeySize);
            }
        }
    }
    END_TRY;

    return tx;
}

void handle_export_private_key_new_path(const command_t *cmd, volatile unsigned int *flags) {
    uint8_t *dataBuffer = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t p2 = cmd->p2;
    uint8_t lc = cmd->lc;

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
    if ((identityProvider & HARDENED_BIT) != 0) {
        THROW(ERROR_INVALID_PATH);
    }
    offset += 4;
    remainingDataLength -= 4;

    ////// Extract the identity //////
    if (remainingDataLength < 4) {
        THROW(ERROR_INVALID_PATH);
    }
    uint32_t identity = U4BE(dataBuffer, offset);
    if ((identity & HARDENED_BIT) != 0) {
        THROW(ERROR_INVALID_PATH);
    }
    offset += 4;
    remainingDataLength -= 4;

    ////// Extract the account //////
    uint32_t account = 0xFFFFFFFF;
    if (p1 == P1_ACCOUNT_CREATION || p1 == P1_CREATION_OF_ZK_PROOF) {
        if (remainingDataLength < 4) {
            THROW(ERROR_INVALID_PATH);
        }
        account = U4BE(dataBuffer, offset);
        if ((account & HARDENED_BIT) != 0) {
            THROW(ERROR_INVALID_PATH);
        }
    }

    // Retain only the non-secret request parameters. The keys themselves are derived in
    // sendPrivateKeysNewPath(), i.e. after the user approves, so that no exportable private
    // material exists in RAM while the review screen is displayed or if the user rejects.
    ctx->newPathPurpose = p1;
    ctx->newPathNetwork = p2;
    ctx->newPathIdentityProvider = identityProvider;
    ctx->newPathIdentity = identity;
    ctx->newPathAccount = account;
    explicit_bzero(ctx->outputPrivateKeys, sizeof(ctx->outputPrivateKeys));
    ctx->privateKeysLength = 0;

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

    // The operation releases reusable private key material to the host, so the review must say
    // so rather than describing it as signing.
    memmove(ctx->display_review_operation, "Export private keys", sizeof("Export private keys"));

    memmove(ctx->display_credid_title, "Credentials ID", EXPORT_PRIVATE_KEY_CREDID_TITLE_LEN);

    memmove(ctx->display_sign, "Approve export", sizeof("Approve export"));

    // P2 selects the network, which changes the coin type and therefore which keys are derived.
    memmove(ctx->display_detail_title, "Network", sizeof("Network"));
    if (p2 == P2_MAINNET) {
        memmove(ctx->display_detail, "Mainnet", sizeof("Mainnet"));
    } else {
        memmove(ctx->display_detail, "Testnet", sizeof("Testnet"));
    }

    if (p1 == P1_IDENTITY_CREDENTIAL_CREATION) {
        memmove(ctx->display_review_verb, "to create credentials", sizeof("to create credentials"));
        memmove(ctx->display_sign_verb, "to create credentials?", sizeof("to create credentials?"));
        memmove(ctx->display_key_types,
                "IdCredSec, PRF key, blinding",
                sizeof("IdCredSec, PRF key, blinding"));
    } else if (p1 == P1_ACCOUNT_CREATION) {
        memmove(ctx->display_review_verb, "to create account", sizeof("to create account"));
        memmove(ctx->display_sign_verb, "to create account?", sizeof("to create account?"));
        memmove(ctx->display_key_types,
                "PRF key, IdCredSec, commitment",
                sizeof("PRF key, IdCredSec, commitment"));
    } else if (p1 == P1_ID_RECOVERY) {
        memmove(ctx->display_review_verb,
                "to recover credentials",
                sizeof("to recover credentials"));
        memmove(ctx->display_sign_verb,
                "to recover credentials?",
                sizeof("to recover credentials?"));
        memmove(ctx->display_key_types, "IdCredSec, blinding", sizeof("IdCredSec, blinding"));
    } else if (p1 == P1_ACCOUNT_CREDENTIAL_DISCOVERY) {
        memmove(ctx->display_review_verb,
                "to discover credentials",
                sizeof("to discover credentials"));
        memmove(ctx->display_sign_verb,
                "to discover credentials?",
                sizeof("to discover credentials?"));
        memmove(ctx->display_key_types, "PRF key", sizeof("PRF key"));
    } else if (p1 == P1_CREATION_OF_ZK_PROOF) {
        memmove(ctx->display_review_verb, "to create ZK proof", sizeof("to create ZK proof"));
        memmove(ctx->display_sign_verb, "to create ZK proof?", sizeof("to create ZK proof?"));
        memmove(ctx->display_key_types, "Commitment randomness", sizeof("Commitment randomness"));
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
    // Derivation happens here, not in the handler: the user has now approved the export.
    ctx->privateKeysLength =
        (uint8_t) exportNewPathPrivateKeysForPurpose(ctx->newPathPurpose,
                                                     ctx->newPathNetwork,
                                                     ctx->newPathIdentityProvider,
                                                     ctx->newPathIdentity,
                                                     ctx->newPathAccount,
                                                     ctx->outputPrivateKeys,
                                                     sizeof(ctx->outputPrivateKeys));

    memmove(G_io_apdu_buffer, ctx->outputPrivateKeys, ctx->privateKeysLength);
    send_success(ctx->privateKeysLength);
    explicit_bzero(ctx->outputPrivateKeys, sizeof(ctx->outputPrivateKeys));
    ctx->privateKeysLength = 0;
}

void rejectPrivateKeysNewPath(void) {
    explicit_bzero(ctx->outputPrivateKeys, sizeof(ctx->outputPrivateKeys));
    ctx->privateKeysLength = 0;
    send_user_rejection();
}
