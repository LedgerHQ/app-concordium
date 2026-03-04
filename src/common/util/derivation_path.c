#include "derivation_path.h"
#include "apdu/helpers.h"
#include <stddef.h>
#include <exceptions.h>
#include <os_print.h>

static inline void check_lc_for_full_path(uint8_t lc) {
    if (lc < 1 + KEY_PATH_NODE_BYTES * MIN_KEY_PATH_LENGTH) {
        PRINTF("Wrong data length: lc must be >= %d , actual %d",
               1 + KEY_PATH_NODE_BYTES * MIN_KEY_PATH_LENGTH,
               lc);
        THROW(SWO_WRONG_DATA_LENGTH);
    }
    if ((lc - 1) % 4 != 0) {
        PRINTF("Wrong data length: lc must be 4n + 1, actual %d", lc);
        THROW(SWO_WRONG_DATA_LENGTH);
    }
    if ((lc - 1) % 4 != 0) {
        PRINTF("Wrong data length: lc must be <= %d",
               1 + KEY_PATH_NODE_BYTES * MAX_KEY_PATH_LENGTH,
               lc);
        THROW(SWO_WRONG_DATA_LENGTH);
    }
}

static inline uint8_t get_path_len(uint8_t lc) {
    check_lc_for_full_path(lc);
    return (lc - 1) / 4;
}

void parse_derivation_path_full(uint8_t lc,
                                uint8_t *cdata,
                                derivation_path_t *derivation_path_out) {
    derivation_path_out->len = get_path_len(lc);

    size_t offset = 0;
    for (size_t i = 0; i < derivation_path_out->len; i++) {
        derivation_path_out->nodes[i] = read_u32_be(cdata, &offset);
    }

    derivation_path_out->variant = DERIVATION_PATH_VARIANT_FULL;
}

void parse_derivation_path_new(uint8_t lc,
                               uint8_t *cdata,
                               bool mainnet,
                               derivation_path_t *derivation_path_out,
                               uint32_t *cred_counter_out) {
    check_lc(lc, 12);

    uint32_t offset = 0;
    uint32_t identity_provider = read_u32_be(cdata, &offset);
    uint32_t identity = read_u32_be(cdata, &offset);
    *cred_counter_out = read_u32_be(cdata, &offset);

    derivation_path_out->len = DERIVATION_PATH_NEW_LEN;

    derivation_path_out->nodes[0] = NEW_PURPOSE;
    derivation_path_out->nodes[1] = mainnet ? NEW_MAINNET_COIN_TYPE : NEW_TESTNET_COIN_TYPE;
    derivation_path_out->nodes[2] = identity_provider;
    derivation_path_out->nodes[3] = identity;
    derivation_path_out->nodes[4] = NEW_PRF_KEY;

    derivation_path_out->variant = DERIVATION_PATH_VARIANT_NEW;
}

void parse_derivation_path_legacy(uint8_t lc,
                                  uint8_t *cdata,
                                  derivation_path_t *derivation_path_out,
                                  uint32_t *cred_counter_out) {
    check_lc(lc, 8);

    size_t offset = 0;
    uint32_t identity = read_u32_be(cdata, &offset);
    *cred_counter_out = read_u32_be(cdata, &offset);

    derivation_path_out->len = DERIVATION_PATH_LEGACY_LEN;

    derivation_path_out->nodes[0] = LEGACY_PURPOSE;
    derivation_path_out->nodes[1] = LEGACY_COIN_TYPE;
    derivation_path_out->nodes[2] = LEGACY_ACCOUNT_SUBTREE;
    derivation_path_out->nodes[3] = LEGACY_NORMAL_ACCOUNTS;
    derivation_path_out->nodes[4] = identity;
    derivation_path_out->nodes[5] = LEGACY_PRF_KEY;

    derivation_path_out->variant = DERIVATION_PATH_VARIANT_LEGACY;
}

void harden_derivation_path(derivation_path_t *path) {
    for (size_t i = 0; i < path->len; i++) {
        path->nodes[i] |= HARDENED_BIT;
    }
}
