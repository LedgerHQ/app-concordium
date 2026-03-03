#include "globals.h"

#include "apdu/helpers.h"
#include "util/hardened.h"
#define LEGACY_ACCOUNT_SUBTREE 0
#define LEGACY_NORMAL_ACCOUNTS 0

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

static void parse_legacy_path(uint8_t lc,
                              uint8_t *cdata,
                              uint32_t *prf_key_path,
                              uint32_t *cred_counter) {
    check_lc(lc, 8);

    size_t offset = 0;
    uint32_t identity = read_u32_be(cdata, &offset);
    *cred_counter = read_u32_be(cdata, &offset);

    prf_key_path[0] = LEGACY_PURPOSE;
    prf_key_path[1] = LEGACY_COIN_TYPE;
    prf_key_path[2] = LEGACY_ACCOUNT_SUBTREE;
    prf_key_path[3] = LEGACY_NORMAL_ACCOUNTS;
    prf_key_path[4] = identity;
    prf_key_path[5] = LEGACY_PRF_KEY;
}

static void parse_new_path(uint8_t lc,
                           uint8_t *cdata,
                           bool mainnet,
                           uint32_t *prf_key_path,
                           uint32_t *cred_counter) {
    check_lc(lc, 12);

    uint32_t offset = 0;
    uint32_t identity_provider = read_u32_be(cdata, &offset);
    uint32_t identity = read_u32_be(cdata, &offset);
    *cred_counter = read_u32_be(cdata, &offset);

    uint32_t coin_type = mainnet ? NEW_MAINNET_COIN_TYPE : NEW_TESTNET_COIN_TYPE;

    prf_key_path[0] = NEW_PURPOSE;
    prf_key_path[1] = coin_type;
    prf_key_path[2] = identity_provider;
    prf_key_path[3] = identity;
    prf_key_path[4] = NEW_PRF_KEY;
}

static void parse_full_path_input(uint8_t lc,
                                  uint8_t *cdata,
                                  uint32_t *prf_key_path,
                                  uint32_t *cred_counter) {
    if (lc >= 4 * 6 || lc % 4 != 0) {
        PRINTF("Wrong data length: lc must be a multiple of 4 and at most 24, actual lc: %d\n", lc);
        THROW(SWO_WRONG_DATA_LENGTH);
    }

    uint32_t offset = 0;

    //
    for (size_t i = 0; i < (lc / 4) - 1; i++) {
        prf_key_path[i] = read_u32_be(cdata, &offset);
    }
    *cred_counter = read_u32_be(cdata, &offset);
}

/**
 * Parse APDU CDATA into a PRF key derivation path based on P1/P2.
 *
 * @param cdata     APDU command data
 * @param p1        Path format: P1_LEGACY_PATH, P1_NEW_PATH, or P1_FULL_PATH
 * @param p2        Network selector (P2_MAINNET_DEFAULT or P2_TESTNET for P1_NEW_PATH)
 * @param lc        Length of cdata
 * @param prfKeyPath Output buffer for the parsed derivation path
 *
 * @throws SWO_WRONG_P1_P2 if p1/p2 combination is invalid
 */
static bool parse_key_path(uint8_t *cdata,
                           uint8_t p1,
                           uint8_t p2,
                           uint8_t lc,
                           uint32_t *prf_key_path_out,
                           uint32_t *cred_counter_out) {
    bool is_legacy_path = false;
    bool valid = true;

    switch (p1) {
        case P1_LEGACY_PATH:
            is_legacy_path = true;
            valid = (p2 == P2_MAINNET_DEFAULT);
            if (valid) parse_legacy_path(lc, cdata, prf_key_path_out, cred_counter_out);
            break;

        case P1_NEW_PATH:
            if (p2 == P2_MAINNET_DEFAULT) {
                parse_new_path(lc, cdata, MAINNET, prf_key_path_out, cred_counter_out);
            } else if (p2 == P2_TESTNET) {
                parse_new_path(lc, cdata, TESTNET, prf_key_path_out, cred_counter_out);
            } else {
                valid = false;
            }
            break;

        case P1_FULL_PATH:
            valid = (p2 == P2_MAINNET_DEFAULT);
            if (valid) parse_full_path_input(lc, cdata, prf_key_path_out, cred_counter_out);
            break;

        default:
            valid = false;
            break;
    }

    if (!valid) THROW(SWO_WRONG_P1_P2);
    return is_legacy_path;
}

void handleVerifyAddress(uint8_t *cdata,
                         uint8_t p1,
                         uint8_t p2,
                         uint8_t lc,
                         volatile unsigned int *flags) {
    uint32_t prf_key_path_out[MAX_DERIVATION_PATH_LENGTH] = {0};
    uint32_t cred_counter_out = 0;

    bool is_legacy_path = parse_key_path(cdata, p1, p2, lc, prf_key_path_out, &cred_counter_out);

    if (is_legacy_path) {
        getIdentityAccountDisplay(ctx->display,
                                  sizeof(ctx->display),
                                  prf_key_path_out[4],
                                  cred_counter_out);
    } else {
        getIdentityAccountDisplayNewPath(ctx->display,
                                         sizeof(ctx->display),
                                         prf_key_path_out[2],
                                         prf_key_path_out[3],
                                         cred_counter_out);
    }

    uint8_t prf_key_path_len = is_legacy_path ? 6 : 5;

    uint8_t credId[BLS_G1_COORD_SIZE];
    uint8_t prf[KEY_LENGTH];

    for (size_t i = 0; i < prf_key_path_len; i++) {
        set_hardened(&prf_key_path_out[i]);
    }
    BEGIN_TRY {
        TRY {
            getBlsPrivateKey(prf_key_path_out, prf_key_path_len, prf, sizeof(prf));
            cx_err_t error = getCredId(prf, sizeof(prf), cred_counter_out, credId, sizeof(credId));

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
