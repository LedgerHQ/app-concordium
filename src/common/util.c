#include "globals.h"

static tx_state_t *tx_state = &global_tx_state;
static keyDerivationPath_t *keyPath = &path;
static accountSender_t *accountSender = &global_account_sender;
static const uint32_t HARDENED_OFFSET = 0x80000000;

int parseKeyDerivationPath(uint8_t *cdata, uint8_t dataLength) {
    if (dataLength < 1) {
        THROW(ERROR_INVALID_PATH);
    }
    keyPath->pathLength = cdata[0];

    // Concordium does not use key paths with a length greater than MAX_KEY_PATH_LENGTH,
    // so if that was received, then throw an error.
    if (keyPath->pathLength > MAX_KEY_PATH_LENGTH) {
        THROW(ERROR_INVALID_PATH);
    }

    if (dataLength < 1 + (BYTES_PER_PATH_ELEMENT * keyPath->pathLength)) {
        THROW(ERROR_INVALID_PATH);
    }

    // Each part of a key path is a uint32, parse through each part of the
    // derivation path. All paths are hardened, but we save a non-hardened
    // version that can be displayed if needed.
    for (int i = 0; i < keyPath->pathLength; ++i) {
        uint32_t node = U4BE(cdata, 1 + (i * BYTES_PER_PATH_ELEMENT));
        keyPath->rawKeyDerivationPath[i] = node;
        keyPath->keyDerivationPath[i] = node | HARDENED_OFFSET;
    }

    return 1 + (BYTES_PER_PATH_ELEMENT * keyPath->pathLength);
}

/**
 * Generic method for hashing and validating header and type for a transaction.
 * Use hashAccountTransactionHeaderAndKind or hashUpdateHeaderAndType
 * instead of using this method directly.
 */
int hashHeaderAndType(uint8_t *cdata, uint8_t dataLength, uint8_t headerLength, uint8_t validType) {
    if (dataLength < headerLength + 1) {
        THROW(ERROR_INVALID_TRANSACTION);
    }
    updateHash((cx_hash_t *) &tx_state->hash, cdata, headerLength);
    cdata += headerLength;

    uint8_t type = cdata[0];
    if (type != validType) {
        THROW(ERROR_INVALID_TRANSACTION);
    }
    updateHash((cx_hash_t *) &tx_state->hash, cdata, 1);

    return headerLength + 1;
}

/**
 * Adds the account transaction header and the transaction kind to the hash. The
 * transaction kind is verified to have the supplied value to prevent processing
 * invalid transactions.
 *
 * A side effect of this method is that the sender address from the transaction header
 * is parsed and saved in a global variable, so that it is available to be displayed
 * for all account transactions.
 */
int hashAccountTransactionHeaderAndKind(uint8_t *cdata,
                                        uint8_t dataLength,
                                        uint8_t validTransactionKind) {
    // Parse the account sender address from the transaction header, so it can be shown.
    size_t outputSize = sizeof(accountSender->sender);
    if (base58check_encode(cdata, ADDRESS_LENGTH, accountSender->sender, &outputSize) == -1) {
        // The received address bytes are not a valid base58 encoding.
        THROW(ERROR_INVALID_TRANSACTION);
    }
    accountSender->sender[BASE58_ADDRESS_LENGTH] = '\0';

    return hashHeaderAndType(cdata,
                             dataLength,
                             ACCOUNT_TRANSACTION_HEADER_LENGTH,
                             validTransactionKind);
}

/**
 * Adds the update header and the update type to the hash. The update
 * type is verified to have the supplied value to prevent processing
 * invalid transactions.
 */
int hashUpdateHeaderAndType(uint8_t *cdata, uint8_t dataLength, uint8_t validUpdateType) {
    return hashHeaderAndType(cdata, dataLength, UPDATE_HEADER_LENGTH, validUpdateType);
}

int handleHeaderAndToAddress(uint8_t *cdata,
                             uint8_t dataLength,
                             uint8_t kind,
                             uint8_t *recipientDst,
                             size_t recipientSize,
                             uint8_t *feesDst,
                             size_t feesSize) {
    // Parse the key derivation path, which should always be the first thing received
    // in a command to the Ledger application.
    int keyPathLength = parseKeyDerivationPath(cdata, dataLength);
    cdata += keyPathLength;
    uint8_t remainingDataLength = dataLength - keyPathLength;

    // Initialize the hash that will be the hash of the whole transaction, which is what will be
    // signed if the user approves.
    if (cx_sha256_init(&tx_state->hash) != CX_SHA256) {
        THROW(ERROR_FAILED_CX_OPERATION);
    }
    int headerLength = hashAccountTransactionHeaderAndKind(cdata, remainingDataLength, kind);

    // extract energy amount from header
    uint64_t energy_amount_u64 = U8BE(cdata, ENERGY_OFFSET_IN_HEADER);

    amountToGtuDisplay((uint8_t *) feesDst, feesSize, energy_amount_u64);

    cdata += headerLength;
    remainingDataLength -= headerLength;

    // Extract the recipient address and add to the hash.
    uint8_t toAddress[ADDRESS_LENGTH];
    if (remainingDataLength < ADDRESS_LENGTH) {
        THROW(ERROR_INVALID_TRANSACTION);
    }
    memmove(toAddress, cdata, ADDRESS_LENGTH);
    updateHash((cx_hash_t *) &tx_state->hash, toAddress, ADDRESS_LENGTH);

    // The recipient address is in a base58 format, so we need to encode it to be
    // able to display in a human-readable way.
    if (base58check_encode(toAddress, sizeof(toAddress), recipientDst, &recipientSize) == -1) {
        // The received address bytes are not a valid base58 encoding.
        THROW(ERROR_INVALID_TRANSACTION);
    }
    recipientDst[BASE58_ADDRESS_LENGTH] = '\0';
    return keyPathLength + headerLength + ADDRESS_LENGTH;
}

void sendUserRejection(void) {
    sendUserRejectionNoIdle();
    ui_menu_main();
}

void sendUserRejectionNoIdle(void) {
    G_io_apdu_buffer[0] = ERROR_REJECTED_BY_USER >> 8;
    G_io_apdu_buffer[1] = ERROR_REJECTED_BY_USER & 0xFF;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, ERROR_RESPONSE_LENGTH);
}

void sendSuccess(uint8_t tx) {
    G_io_apdu_buffer[tx++] = SUCCESS >> 8;
    G_io_apdu_buffer[tx++] = SUCCESS & 0xFF;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    ui_menu_main();
}

void sendSuccessNoIdle(void) {
    sendSuccessResultNoIdle(0);
}

void sendSuccessResultNoIdle(uint8_t tx) {
    G_io_apdu_buffer[tx++] = SUCCESS >> 8;
    G_io_apdu_buffer[tx++] = SUCCESS & 0xFF;
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
}

void getIdentityAccountDisplay(uint8_t *dst,
                               size_t dstLength,
                               uint32_t identityIndex,
                               uint32_t accountIndex) {
    int offset = numberToText(dst, dstLength, identityIndex);
    memmove(dst + offset, "/", 1);
    offset += 1;
    bin2dec(dst + offset, dstLength - offset, accountIndex);
}

void getIdentityAccountDisplayNewPath(uint8_t *dst,
                                      size_t dstLength,
                                      uint32_t identityProviderIndex,
                                      uint32_t identityIndex,
                                      uint32_t accountIndex) {
    // Convert identityProviderIndex to text and store it in dst
    int offset = numberToText(dst, dstLength, identityProviderIndex);
    memmove(dst + offset, "/", 1);
    offset += 1;

    // Convert identityIndex to text and append it to dst
    offset += numberToText(dst + offset, dstLength - offset, identityIndex);
    memmove(dst + offset, "/", 1);
    offset += 1;

    // Convert accountIndex to text and append it to dst
    bin2dec(dst + offset, dstLength - offset, accountIndex);
}

/**
 * Used to validate that an error result code from a Ledger library call
 * is equal CX_OK. If it is not CX_OK, then throw an ERROR_FAILED_CX_OPERATION
 * error that should be sent back to the callee.
 */
void ensureNoError(cx_err_t errorCode) {
    if (errorCode != CX_OK) {
        THROW(ERROR_FAILED_CX_OPERATION);
    }
}

void getPrivateKey(uint32_t *keyPathInput,
                   uint8_t keyPathLength,
                   cx_ecfp_private_key_t *privateKey) {
    uint8_t privateKeyData[ED25519_SIGNATURE_LENGTH];

    // Invoke the device methods for generating a private key.
    // Wrap in try/finally to ensure that private key information is cleaned up, even if a system
    // call fails.
    BEGIN_TRY {
        TRY {
            ensureNoError(os_derive_bip32_with_seed_no_throw(HDW_ED25519_SLIP10,
                                                             CX_CURVE_Ed25519,
                                                             keyPathInput,
                                                             keyPathLength,
                                                             privateKeyData,
                                                             NULL,
                                                             (unsigned char *) "ed25519 seed",
                                                             ED25519_SEED_LENGTH));
            ensureNoError(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519,
                                                            privateKeyData,
                                                            KEY_LENGTH,
                                                            privateKey));
        }
        FINALLY {
            // Clean up the private key seed data, so that we cannot leak it.
            explicit_bzero(&privateKeyData, sizeof(privateKeyData));
        }
    }
    END_TRY;
}

void getPublicKey(uint8_t *publicKeyArray) {
    cx_ecfp_private_key_t privateKey;
    cx_ecfp_public_key_t publicKey;

    // Wrap in try/finally to ensure private key information is cleaned up, even if the system call
    // fails.
    BEGIN_TRY {
        TRY {
            getPrivateKey(keyPath->keyDerivationPath, keyPath->pathLength, &privateKey);
            // Invoke the device method for generating a public-key pair.
            ensureNoError(
                cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519, &publicKey, &privateKey, 1));
        }
        FINALLY {
            // Clean up the private key as we are done using it, so that we cannot leak it.
            explicit_bzero(&privateKey, sizeof(privateKey));
        }
    }
    END_TRY;

    // Build the public-key bytes in the expected format.
    for (int i = 0; i < KEY_LENGTH; i++) {
        publicKeyArray[i] = publicKey.W[ED25519_PUBLIC_KEY_CURVE_SIZE - i];
    }
    if ((publicKey.W[KEY_LENGTH] & 1) != 0) {
        publicKeyArray[KEY_LENGTH - 1] |= ED25519_SIGN_COMPRESSED_BIT;
    }
}

// Generic method that signs the input with the key given by the derivation path that
// has been loaded into keyPath.
void sign(uint8_t *input, uint8_t *signatureOnInput) {
    cx_ecfp_private_key_t privateKey;

    BEGIN_TRY {
        TRY {
            getPrivateKey(keyPath->keyDerivationPath, keyPath->pathLength, &privateKey);
            ensureNoError(cx_eddsa_sign_no_throw(&privateKey,
                                                 CX_SHA512,
                                                 input,
                                                 KEY_LENGTH,
                                                 signatureOnInput,
                                                 ED25519_SIGNATURE_LENGTH));
        }
        FINALLY {
            // Clean up the private key, so that we cannot leak it.
            explicit_bzero(&privateKey, sizeof(privateKey));
        }
    }
    END_TRY;
}

// BLS12-381 key generation constants
#define l_CONST        48  // ceil((3 * ceil(log2(BLS_G1_ORDER))) / 16)
#define BLS_KEY_LENGTH 32
#define SEED_LENGTH    32

/** BLS12-381 subgroup G1's order (shared with verifyAddress.c) */
const uint8_t BLS_G1_ORDER[32] = {0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8,
                                  0x08, 0x09, 0xa1, 0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe,
                                  0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01};

void hash(cx_hash_t *hashContext,
          uint32_t mode,
          const unsigned char *in,
          unsigned int len,
          unsigned char *out,
          unsigned int out_len) {
    ensureNoError(cx_hash_no_throw(hashContext, mode, in, len, out, out_len));
}

void updateHash(cx_hash_t *hashContext, const unsigned char *in, unsigned int len) {
    hash(hashContext, 0, in, len, NULL, 0);
}

// We must declare the functions for the static analyzer to be happy. Ideally we would have
// access to the declarations from the Ledger SDK.
void cx_hkdf_extract(const cx_md_t hash_id,
                     const unsigned char *ikm,
                     unsigned int ikm_len,
                     unsigned char *salt,
                     unsigned int salt_len,
                     unsigned char *prk);
void cx_hkdf_expand(const cx_md_t hash_id,
                    const unsigned char *prk,
                    unsigned int prk_len,
                    unsigned char *info,
                    unsigned int info_len,
                    unsigned char *okm,
                    unsigned int okm_len);

static const uint8_t l_bytes[2] = {0, l_CONST};

/** This implements the bls key generation algorithm specified in
 * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.3, The optional
 * parameter key_info is hardcoded to an empty string. Uses sha256 as the hash function. The
 * generated key has length 32, and dst should have at least that length, or the function throws an
 * error.
 */
void blsKeygen(const uint8_t *seed, size_t seedLength, uint8_t *dst, size_t dstLength) {
    if (dstLength < BLS_KEY_LENGTH) {
        THROW(ERROR_BUFFER_OVERFLOW);
    } else if (seedLength != SEED_LENGTH) {
        THROW(ERROR_INVALID_TRANSACTION);
    }

    uint8_t sk[l_CONST];
    uint8_t prk[KEY_LENGTH];
    uint8_t salt[KEY_LENGTH] = {66, 76, 83, 45, 83, 73, 71, 45, 75, 69,
                                89, 71, 69, 78, 45, 83, 65, 76, 84, 45};  // "BLS-SIG-KEYGEN-SALT-"
    size_t saltSize = BLS_SALT_INITIAL_LENGTH;
    uint8_t ikm[SEED_LENGTH + 1];

    memcpy(ikm, seed, SEED_LENGTH);
    ikm[SEED_LENGTH] = 0;
    cx_err_t error = 0;
    do {
        error = cx_hash_sha256(salt, saltSize, salt, sizeof(salt));
        if (error == 0) {
            THROW(ERROR_FAILED_CX_OPERATION);
        }
        saltSize = sizeof(salt);
        cx_hkdf_extract(CX_SHA256, ikm, sizeof(ikm), salt, sizeof(salt), prk);
        cx_hkdf_expand(CX_SHA256,
                       prk,
                       sizeof(prk),
                       (unsigned char *) l_bytes,
                       sizeof(l_bytes),
                       sk,
                       sizeof(sk));

        ensureNoError(cx_math_modm_no_throw(sk, sizeof(sk), BLS_G1_ORDER, sizeof(BLS_G1_ORDER)));
    } while (cx_math_is_zero(sk, sizeof(sk)));

    // Skip the first 16 bytes, because they are 0 due to calculating modulo BLS_G1_ORDER
    // (and sk has 48 bytes).
    memmove(dst, sk + l_CONST - BLS_KEY_LENGTH, BLS_KEY_LENGTH);
}

void getBlsPrivateKey(uint32_t *keyPathInput,
                      uint8_t keyPathLength,
                      uint8_t *privateKey,
                      size_t privateKeySize) {
    cx_ecfp_private_key_t privateKeySeed;
    BEGIN_TRY {
        TRY {
            getPrivateKey(keyPathInput, keyPathLength, &privateKeySeed);
            blsKeygen(privateKeySeed.d, sizeof(privateKeySeed.d), privateKey, privateKeySize);
        }
        FINALLY {
            explicit_bzero(&privateKeySeed, sizeof(privateKeySeed));
        }
    }
    END_TRY;
}

#define U64_RATIO_SEPARATOR     " / "
#define U64_RATIO_SEPARATOR_LEN 3

size_t hashAndLoadU64Ratio(uint8_t *cdata, uint8_t *dst, uint8_t sizeOfDst) {
    uint64_t numerator = U8BE(cdata, 0);
    uint64_t denominator = U8BE(cdata, 8);
    updateHash((cx_hash_t *) &tx_state->hash, cdata, U64_RATIO_BYTES);
    int numLength = numberToText(dst, sizeOfDst, numerator);
    memmove(dst + numLength, U64_RATIO_SEPARATOR, U64_RATIO_SEPARATOR_LEN);
    numberToText(dst + numLength + U64_RATIO_SEPARATOR_LEN,
                 sizeOfDst - (numLength + U64_RATIO_SEPARATOR_LEN),
                 denominator);
    return U64_RATIO_BYTES;
}
