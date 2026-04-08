#include "globals.h"

#include <os.h>
#include <cx.h>

#include "cx_hkdf.h"

#include "concordium_crypto.h"

static void ensureNoError(cx_err_t errorCode) {
    if (errorCode != CX_OK) {
        THROW(ERROR_FAILED_CX_OPERATION);
    }
}

const uint8_t BLS_G1_ORDER[32] = {0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8,
                                  0x08, 0x09, 0xa1, 0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe,
                                  0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01};

#define l_CONST        48  // ceil((3 * ceil(log2(BLS_G1_ORDER))) / 16)
#define BLS_KEY_LENGTH 32
#define SEED_LENGTH    32

static const uint8_t l_bytes[2] = {0, l_CONST};

static void blsKeygen(const uint8_t *seed, size_t seedLength, uint8_t *dst, size_t dstLength) {
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

    memmove(dst, sk + l_CONST - BLS_KEY_LENGTH, BLS_KEY_LENGTH);
}

void get_private_key(const derivation_path_t *path, cx_ecfp_private_key_t *privateKey) {
    uint8_t privateKeyData[ED25519_SIGNATURE_LENGTH];

    BEGIN_TRY {
        TRY {
            ensureNoError(os_derive_bip32_with_seed_no_throw(HDW_ED25519_SLIP10,
                                                             CX_CURVE_Ed25519,
                                                             (uint32_t *) path->nodes,
                                                             path->len,
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
            explicit_bzero(&privateKeyData, sizeof(privateKeyData));
        }
    }
    END_TRY;
}

void get_public_key(uint8_t *publicKeyArray) {
    cx_ecfp_private_key_t privateKey;
    cx_ecfp_public_key_t publicKey;

    BEGIN_TRY {
        TRY {
            get_private_key(&global_derivation_path, &privateKey);
            ensureNoError(
                cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519, &publicKey, &privateKey, 1));
        }
        FINALLY {
            explicit_bzero(&privateKey, sizeof(privateKey));
        }
    }
    END_TRY;

    for (int i = 0; i < KEY_LENGTH; i++) {
        publicKeyArray[i] = publicKey.W[ED25519_PUBLIC_KEY_CURVE_SIZE - i];
    }
    if ((publicKey.W[KEY_LENGTH] & 1) != 0) {
        publicKeyArray[KEY_LENGTH - 1] |= ED25519_SIGN_COMPRESSED_BIT;
    }
}

void sign(uint8_t *input, uint8_t *signatureOnInput) {
    cx_ecfp_private_key_t privateKey;

    BEGIN_TRY {
        TRY {
            get_private_key(&global_derivation_path, &privateKey);
            ensureNoError(cx_eddsa_sign_no_throw(&privateKey,
                                                 CX_SHA512,
                                                 input,
                                                 KEY_LENGTH,
                                                 signatureOnInput,
                                                 ED25519_SIGNATURE_LENGTH));
        }
        FINALLY {
            explicit_bzero(&privateKey, sizeof(privateKey));
        }
    }
    END_TRY;
}

void hash(cx_hash_t *hashContext,
          uint32_t mode,
          const unsigned char *in,
          unsigned int len,
          unsigned char *out,
          unsigned int out_len) {
    ensureNoError(cx_hash_no_throw(hashContext, mode, in, len, out, out_len));
}

void update_hash(cx_hash_t *hashContext, const unsigned char *in, unsigned int len) {
    hash(hashContext, 0, in, len, NULL, 0);
}

void get_bls_private_key(const derivation_path_t *path,
                         uint8_t *privateKey,
                         size_t privateKeySize) {
    cx_ecfp_private_key_t privateKeySeed;
    BEGIN_TRY {
        TRY {
            get_private_key(path, &privateKeySeed);
            blsKeygen(privateKeySeed.d, sizeof(privateKeySeed.d), privateKey, privateKeySize);
        }
        FINALLY {
            explicit_bzero(&privateKeySeed, sizeof(privateKeySeed));
        }
    }
    END_TRY;
}
