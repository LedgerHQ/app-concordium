#include "globals.h"

#include "apdu/helpers.h"
#include "util/derivation_path.h"

/** BN lock count for cx_bn_lock when working with BLS G1 */
#define BN_LOCK_COUNT 16

static verifyAddressContext_t *ctx = &global.verifyAddressContext;

// gX and gY are the coordinates of g, which is the first part of the onchainCommitmentKey.
static const uint8_t gX[BLS_G1_COORD_SIZE] = {
    0x11, 0x4c, 0xbf, 0xe4, 0x4a, 0x02, 0xc6, 0xb1, 0xf7, 0x87, 0x11, 0x17, 0x6d, 0x5f, 0x43, 0x72,
    0x95, 0x36, 0x7a, 0xa4, 0xf2, 0xa8, 0xc2, 0x55, 0x1e, 0xe1, 0x0d, 0x25, 0xa0, 0x3a, 0xdc, 0x69,
    0xd6, 0x1a, 0x33, 0x2a, 0x05, 0x89, 0x71, 0x91, 0x9d, 0xad, 0x73, 0x12, 0xe1, 0xfc, 0x94, 0xc5};
static const uint8_t gY[BLS_G1_COORD_SIZE] = {
    0x18, 0x6a, 0xf3, 0x21, 0x19, 0x54, 0x39, 0x13, 0xb2, 0x6a, 0x46, 0x2a, 0x02, 0x31, 0xe4, 0xbf,
    0x5f, 0xde, 0xe0, 0xb5, 0x2c, 0x91, 0x6f, 0x68, 0x85, 0x44, 0x87, 0xe8, 0x11, 0x2c, 0x1f, 0x27,
    0x74, 0x35, 0xfc, 0x07, 0x6f, 0x3a, 0xda, 0xd5, 0x6d, 0x18, 0xd8, 0x6a, 0x65, 0x99, 0xb5, 0x42};

/*
 * Calculates the credId from the given prf key and credential counter.
 * The size of the computed credId is 48 bytes.
 */
cx_err_t getCredId(uint8_t *prf,
                   size_t prfSize,
                   uint32_t credCounter,
                   uint8_t *credId,
                   size_t credIdSize) {
    cx_err_t error = 0;

    // get bn lock to allow working with binary numbers and elliptic curves
    error = cx_bn_lock(BN_LOCK_COUNT, 0);
    if (error != 0) {
        return error;
    }

    // Initialize binary numbers
    cx_bn_t credIdExponentBn, tmpBn, rBn, ccBn, prfBn;
    CX_CHECK(cx_bn_alloc(&credIdExponentBn, KEY_LENGTH));
    CX_CHECK(cx_bn_alloc(&tmpBn, KEY_LENGTH));
    CX_CHECK(cx_bn_alloc_init(&prfBn, KEY_LENGTH, prf, prfSize));
    CX_CHECK(cx_bn_alloc_init(&rBn, KEY_LENGTH, BLS_G1_ORDER, sizeof(BLS_G1_ORDER)));
    CX_CHECK(cx_bn_alloc(&ccBn, KEY_LENGTH));
    CX_CHECK(cx_bn_set_u32(ccBn, credCounter));

    // Apply cred counter offset
    CX_CHECK(cx_bn_mod_add(tmpBn, prfBn, ccBn, rBn));

    // Inverse of (prf + cred_counter) is the exponent for calculating the credId
    CX_CHECK(cx_bn_mod_invert_nprime(credIdExponentBn, tmpBn, rBn));

    // clean up binary numbers
    CX_CHECK(cx_bn_destroy(&tmpBn));
    CX_CHECK(cx_bn_destroy(&rBn));
    CX_CHECK(cx_bn_destroy(&prfBn));
    CX_CHECK(cx_bn_destroy(&ccBn));

    // initialize elliptic curve point given by global commitmentKey
    cx_ecpoint_t commitmentKey;
    CX_CHECK(cx_ecpoint_alloc(&commitmentKey, CX_CURVE_BLS12_381_G1));
    CX_CHECK(cx_ecpoint_init(&commitmentKey, gX, sizeof(gX), gY, sizeof(gY)));

    //  multiply commitmentKey with credIdExponent
    CX_CHECK(cx_ecpoint_scalarmul_bn(&commitmentKey, credIdExponentBn));
    CX_CHECK(cx_bn_destroy(&credIdExponentBn));

    // calculate credId which is the compressed version of commitmentKey * credIdExponent
    cx_bn_t x, y, negy;
    CX_CHECK(cx_bn_alloc(&x, BLS_G1_COORD_SIZE));
    CX_CHECK(cx_bn_alloc(&y, BLS_G1_COORD_SIZE));
    CX_CHECK(cx_bn_alloc(&negy, BLS_G1_COORD_SIZE));

    CX_CHECK(cx_ecpoint_export_bn(&commitmentKey, &x, &y));
    CX_CHECK(cx_bn_export(x, credId, credIdSize));

    // Calculate negation of the point to get -y
    CX_CHECK(cx_ecpoint_neg(&commitmentKey));
    CX_CHECK(cx_ecpoint_export_bn(&commitmentKey, &x, &negy));

    int diff;
    CX_CHECK(cx_bn_cmp(y, negy, &diff));

    // cleanup binary numbers
    CX_CHECK(cx_bn_destroy(&x));
    CX_CHECK(cx_bn_destroy(&y));
    CX_CHECK(cx_bn_destroy(&negy));
    CX_CHECK(cx_ecpoint_destroy(&commitmentKey));

    credId[0] |= 0x80;  // Indicate this is on compressed form
    if (diff > 0) {
        credId[0] |= 0x20;  // Indicate that y > -y
    }

    // CX_CHECK label to goto in case of an error
end:
    cx_bn_unlock();
    return error;
}

/**
 * Parse APDU CDATA into a PRF key derivation path based on P1/P2.
 *
 * @param cdata           APDU command data
 * @param p1              Path format: P1_LEGACY_PATH, P1_NEW_PATH, or P1_FULL_PATH
 * @param p2              Network selector (P2_MAINNET_DEFAULT or P2_TESTNET for P1_NEW_PATH)
 * @param lc              Length of cdata
 * @param derivation_path Output buffer for the parsed derivation path. Path is not hardened.
 * @param cred_counter    Output credential counter (legacy / new path).
 *
 * @throws SWO_WRONG_P1_P2 if p1/p2 combination is invalid
 */
static void parse_key_path(uint8_t *cdata,
                           uint8_t p1,
                           uint8_t p2,
                           uint8_t lc,
                           derivation_path_t *derivation_path,
                           uint32_t *cred_counter) {
    bool p2_is_valid = true;

    switch (p1) {
        case P1_LEGACY_PATH:
            p2_is_valid = (p2 == P2_MAINNET_DEFAULT);
            if (p2_is_valid) parse_derivation_path_legacy(lc, cdata, derivation_path, cred_counter);
            break;

        case P1_NEW_PATH:
            if (p2 == P2_MAINNET_DEFAULT) {
                parse_derivation_path_new(lc, cdata, MAINNET, derivation_path, cred_counter);
            } else if (p2 == P2_TESTNET) {
                parse_derivation_path_new(lc, cdata, TESTNET, derivation_path, cred_counter);
            } else {
                p2_is_valid = false;
            }
            break;

        case P1_FULL_PATH:
            p2_is_valid = (p2 == P2_MAINNET_DEFAULT);
            if (p2_is_valid) parse_derivation_path_full(lc, cdata, derivation_path);
            break;

        default:
            p2_is_valid = false;
            break;
    }

    if (!p2_is_valid) THROW(SWO_WRONG_P1_P2);
}

void handleVerifyAddress(uint8_t *cdata,
                         uint8_t p1,
                         uint8_t p2,
                         uint8_t lc,
                         volatile unsigned int *flags) {
    derivation_path_t *derivation_path = &ctx->derivation_path;
    init_derivation_path(derivation_path);
    uint32_t cred_counter = 0;
    parse_key_path(cdata, p1, p2, lc, derivation_path, &cred_counter);

    switch (derivation_path->variant) {
        case DERIVATION_PATH_VARIANT_NEW:
            getIdentityAccountDisplayNewPath(ctx->display,
                                             sizeof(ctx->display),
                                             derivation_path->nodes[2],
                                             derivation_path->nodes[3],
                                             cred_counter);
            break;

        case DERIVATION_PATH_VARIANT_LEGACY:
            getIdentityAccountDisplayLegacyPath(ctx->display,
                                                sizeof(ctx->display),
                                                derivation_path->nodes[4],
                                                cred_counter);
            break;

        case DERIVATION_PATH_VARIANT_FULL:
            unharden_derivation_path(derivation_path);
            getIdentityAccountDisplayNewPath(ctx->display,
                                             sizeof(ctx->display),
                                             derivation_path->nodes[2],
                                             derivation_path->nodes[3],
                                             derivation_path->nodes[4]);

            break;

        default:
            break;
    }

    uint8_t credId[BLS_G1_COORD_SIZE];
    uint8_t prf[KEY_LENGTH];

    /* getBlsPrivateKey expects hardened path (0x80000000 | node); parsers output unhardened */
    harden_derivation_path(derivation_path);

    BEGIN_TRY {
        TRY {
            getBlsPrivateKey(derivation_path, prf, sizeof(prf));
            cx_err_t error = getCredId(prf, sizeof(prf), cred_counter, credId, sizeof(credId));

            if (error != 0) {
                THROW(ERROR_INVALID_STATE);
            }
        }
        FINALLY {
            explicit_bzero(prf, sizeof(prf));
        }
    }
    END_TRY;

    uint8_t accountAddress[ADDRESS_LENGTH];
    size_t hash_size = 0;
    hash_size = cx_hash_sha256(credId, sizeof(credId), accountAddress, sizeof(accountAddress));
    if (hash_size != CX_SHA256_SIZE) {
        THROW(ERROR_FAILED_CX_OPERATION);
    }
    size_t addressLength = sizeof(ctx->address);

    base58check_encode(accountAddress, sizeof(accountAddress), ctx->address, &addressLength);
    ctx->address[BASE58_ADDRESS_LENGTH] = '\0';

    uiVerifyAddress(flags);
}
