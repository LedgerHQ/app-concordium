#include "derivation_path.h"
#include "apdu/helpers.h"
#include "globals.h"
#include "numberHelpers.h"

#include <stddef.h>
#include <string.h>
#include <exceptions.h>

size_t parse_derivation_path_from_buffer(uint8_t *cdata,
                                         size_t max_len,
                                         derivation_path_t *derivation_path_out) {
    if (max_len < 1) {
        THROW(ERROR_INVALID_PATH);
    }
    uint8_t depth = cdata[0];
    if (depth > DERIVATION_PATH_NODES_MAX) {
        THROW(ERROR_INVALID_PATH);
    }
    size_t need = 1 + (size_t) depth * BYTES_PER_PATH_ELEMENT;
    if (max_len < need) {
        THROW(ERROR_INVALID_PATH);
    }

    size_t offset = 0;
    offset = read_u8(cdata, offset, &derivation_path_out->len);

    for (size_t i = 0; i < derivation_path_out->len; i++) {
        offset = read_u32_be(cdata, offset, &derivation_path_out->nodes[i]);
    }

    derivation_path_out->variant = DERIVATION_PATH_VARIANT_FULL;
    return offset;
}

void parse_derivation_path_full(uint8_t lc,
                                uint8_t *cdata,
                                derivation_path_t *derivation_path_out) {
    size_t consumed = parse_derivation_path_from_buffer(cdata, lc, derivation_path_out);
    check_lc(lc, (uint8_t) consumed);
}

void parse_derivation_path_new(uint8_t lc,
                               uint8_t *cdata,
                               bool mainnet,
                               derivation_path_t *derivation_path_out,
                               uint32_t *cred_counter_out) {
    if (lc < 12) {
        THROW(SWO_INCORRECT_DATA);
    }
    size_t offset = 0;
    uint32_t identity_provider = 0;
    offset = read_u32_be(cdata, offset, &identity_provider);
    if ((identity_provider & HARDENED_BIT) != 0) {
        THROW(ERROR_INVALID_PATH);
    }
    uint32_t identity = 0;
    offset = read_u32_be(cdata, offset, &identity);
    if ((identity & HARDENED_BIT) != 0) {
        THROW(ERROR_INVALID_PATH);
    }
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
    if (lc < 8) {
        THROW(SWO_INCORRECT_DATA);
    }
    size_t offset = 0;
    uint32_t identity;
    offset = read_u32_be(cdata, offset, &identity);
    if ((identity & HARDENED_BIT) != 0) {
        THROW(ERROR_INVALID_PATH);
    }
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

void detect_derivation_path_variant(derivation_path_t *derivation_path) {
    if (derivation_path->len == 0) {
        derivation_path->variant = DERIVATION_PATH_VARIANT_INVALID;
        return;
    }
    uint32_t purpose = derivation_path->nodes[0] & ~HARDENED_BIT;
    if (purpose == LEGACY_PURPOSE) {
        derivation_path->variant = DERIVATION_PATH_VARIANT_LEGACY;
    } else if (purpose == NEW_PURPOSE) {
        derivation_path->variant = DERIVATION_PATH_VARIANT_NEW;
    } else {
        derivation_path->variant = DERIVATION_PATH_VARIANT_FULL;
    }
}

size_t parse_derivation_path(uint8_t *cdata, uint8_t dataLength) {
    derivation_path_t *dp = &global_derivation_path;
    init_derivation_path(dp);
    /* Path is a prefix; use parse_derivation_path_from_buffer (not parse_derivation_path_full,
     * which requires lc == path length for path-only CDATA — see VERIFY_ADDRESS). */
    size_t consumed = parse_derivation_path_from_buffer(cdata, dataLength, dp);
    detect_derivation_path_variant(dp);
    /* All nodes are hardened for crypto; UI that needs indices must unharden_derivation_path first.
     */
    harden_derivation_path(dp);
    return consumed;
}

void path_display_legacy(uint8_t *dst,
                         size_t dstLength,
                         uint32_t identityIndex,
                         uint32_t accountIndex) {
    size_t offset = number_to_text(dst, dstLength, identityIndex);
    if (offset >= dstLength) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    memmove(dst + offset, "/", 1);
    offset += 1;
    bin_to_dec(dst + offset, dstLength - offset, accountIndex);
}

void path_display_new(uint8_t *dst,
                      size_t dstLength,
                      uint32_t identityProviderIndex,
                      uint32_t identityIndex,
                      uint32_t accountIndex) {
    size_t offset = number_to_text(dst, dstLength, identityProviderIndex);
    if (offset >= dstLength) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    memmove(dst + offset, "/", 1);
    offset += 1;

    offset += number_to_text(dst + offset, dstLength - offset, identityIndex);
    if (offset >= dstLength) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    memmove(dst + offset, "/", 1);
    offset += 1;

    bin_to_dec(dst + offset, dstLength - offset, accountIndex);
}
