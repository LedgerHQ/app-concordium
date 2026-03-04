#include "derivation_path.h"
#include "apdu/helpers.h"
#include <stddef.h>
#include <exceptions.h>
#include <os_print.h>

/* Format: <n> <node 1> ... <node n>; byte 0 is depth, nodes start at byte 1 */
void parse_derivation_path_full(uint8_t lc,
                                uint8_t *cdata,
                                derivation_path_t *derivation_path_out) {
    size_t offset = 0;
    offset = read_u8(cdata, offset, &derivation_path_out->len);

    for (size_t i = 0; i < derivation_path_out->len; i++) {
        offset = read_u32_be(cdata, offset, &derivation_path_out->nodes[i]);
        PRINTF("Path node: 0x%x\n ", derivation_path_out->nodes[i]);
    }
    check_lc(lc, offset);

    derivation_path_out->variant = DERIVATION_PATH_VARIANT_FULL;
}

void parse_derivation_path_new(uint8_t lc,
                               uint8_t *cdata,
                               bool mainnet,
                               derivation_path_t *derivation_path_out,
                               uint32_t *cred_counter_out) {
    size_t offset = 0;
    uint32_t identity_provider = 0;
    offset = read_u32_be(cdata, offset, &identity_provider);
    uint32_t identity = 0;
    offset = read_u32_be(cdata, offset, &identity);
    offset = read_u32_be(cdata, offset, cred_counter_out);
    check_lc(lc, offset);

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
    size_t offset = 0;
    uint32_t identity;
    offset = read_u32_be(cdata, offset, &identity);
    offset = read_u32_be(cdata, offset, cred_counter_out);
    check_lc(lc, offset);

    derivation_path_out->len = DERIVATION_PATH_LEGACY_LEN;

    derivation_path_out->nodes[0] = LEGACY_PURPOSE;
    derivation_path_out->nodes[1] = LEGACY_COIN_TYPE;
    derivation_path_out->nodes[2] = LEGACY_ACCOUNT_SUBTREE;
    derivation_path_out->nodes[3] = LEGACY_NORMAL_ACCOUNTS;
    derivation_path_out->nodes[4] = identity;
    derivation_path_out->nodes[5] = LEGACY_PRF_KEY;

    derivation_path_out->variant = DERIVATION_PATH_VARIANT_LEGACY;
}
