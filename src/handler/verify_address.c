#include "globals.h"

#include <string.h>

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "apdu/apdu_response.h"
#include "apdu/helpers.h"
#include "concordium_crypto.h"
#include "app_sizes.h"
#include "base58check.h"
#include "derivation_path.h"
#include "set_trusted_name.h"

#include "verify_address.h"

static verifyAddressContext_t *ctx = &global.verifyAddressContext;

/** BN lock count for cx_bn_lock when working with BLS G1 */
#define BN_LOCK_COUNT 16

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
 * @return SWO_SUCCESS, or the status word the command must be refused with.
 */
static uint16_t parse_key_path(uint8_t *cdata,
                               uint8_t p1,
                               uint8_t p2,
                               uint8_t lc,
                               derivation_path_t *derivation_path,
                               uint32_t *cred_counter) {
    switch (p1) {
        case P1_LEGACY_PATH:
            if (p2 != P2_MAINNET_DEFAULT) return SWO_WRONG_P1_P2;
            parse_derivation_path_legacy(lc, cdata, derivation_path, cred_counter);
            return SWO_SUCCESS;

        case P1_NEW_PATH:
            if (p2 == P2_MAINNET_DEFAULT) {
                parse_derivation_path_new(lc, cdata, MAINNET, derivation_path, cred_counter);
            } else if (p2 == P2_TESTNET) {
                parse_derivation_path_new(lc, cdata, TESTNET, derivation_path, cred_counter);
            } else {
                return SWO_WRONG_P1_P2;
            }
            return SWO_SUCCESS;

        case P1_FULL_PATH:
            if (p2 != P2_MAINNET_DEFAULT) return SWO_WRONG_P1_P2;
            parse_derivation_path_full(lc, cdata, derivation_path);
            /* The parser only bounds depth and buffer length, so a zero-node path would otherwise
             * derive from the master key and review as an all-zero label. Everything else the host
             * sends is accepted, but the review renders the whole path (see path_display_full), so
             * no node can change the address behind an unchanged screen. */
            if (derivation_path->len == 0) return ERROR_INVALID_PATH;
            return SWO_SUCCESS;

        default:
            return SWO_WRONG_P1_P2;
    }
}

/**
 * PKI lane: prove the signed descriptor describes exactly the account being reviewed.
 *
 * The descriptor's PKI signature is trusted, so none of these can be forged; what they add is that
 * a *valid* descriptor cannot be presented against a different account than the one it was issued
 * for. Always required:
 *
 *  - tag 0x23 (chain id) must match the network of the reviewed path, so a testnet descriptor
 *    cannot be shown for a mainnet address or vice versa;
 *  - tag 0x22 must be the Ed25519 public key of the reviewed path.
 *
 * What pins the descriptor to a single account then depends on which path the host sent, because
 * tag 0x22 is the key of whatever path is under review:
 *
 *  - a full path *of the signing shape* m/44'/coin'/idp'/identity'/0'/credCounter' puts the
 *    credential counter at node 5, so tag 0x22 already differs per account. Nothing further is
 *    needed and the review shows the certified address. The shape is checked by
 *    full_path_names_one_account; a full path of any other shape is refused, because the host
 *    picks P1 and the variant alone proves nothing about what it sent.
 *  - the compact formats review the identity-level PRF path, whose key every credential counter
 *    shares. There the derived address is the only value that tells them apart, so tag 0x20 has to
 *    equal it.
 *
 * @param bind_derived_address  Require tag 0x20 to equal ctx->address. When false, tag 0x20 is
 *                              copied into ctx->address for the review instead.
 * @return SWO_SUCCESS, or the status word the command must be refused with.
 */
static uint16_t pki_bind_descriptor(const uint8_t *derived_ed25519_pub,
                                    derivation_path_network_t network,
                                    bool bind_derived_address) {
    uint64_t expected_chain_id;
    switch (network) {
        case DERIVATION_PATH_NETWORK_MAINNET:
            expected_chain_id = CCD_CHAIN_ID_MAINNET;
            break;
        case DERIVATION_PATH_NETWORK_TESTNET:
            expected_chain_id = CCD_CHAIN_ID_TESTNET;
            break;
        default:
            /* The legacy subtree carries no coin type and a custom path may carry an unknown one,
             * so the descriptor's authenticated network cannot be tied to the path. Refuse rather
             * than assume a network on the user's behalf. */
            PRINTF("Path has no network to bind the descriptor chain id to\n");
            return ERROR_TRUSTED_NAME_MISMATCH;
    }
    if (g_trusted_chain_id != expected_chain_id) {
        PRINTF("Descriptor chain id does not match the reviewed network\n");
        return ERROR_TRUSTED_NAME_MISMATCH;
    }
    if (g_trusted_address_len != KEY_LENGTH) {
        return ERROR_TRUSTED_NAME_MISMATCH;
    }
    if (memcmp(derived_ed25519_pub, g_trusted_address, KEY_LENGTH) != 0) {
        PRINTF("Descriptor tag 0x22 is not the owner key of the reviewed path\n");
        return ERROR_TRUSTED_NAME_MISMATCH;
    }
    if (bind_derived_address) {
        /* Both are NUL-terminated: g_trusted_name by SET_TRUSTED_NAME, ctx->address by
         * bls_compute_address, which has already run for this credential counter. */
        if (strncmp(g_trusted_name, ctx->address, sizeof(ctx->address)) != 0) {
            PRINTF("Descriptor tag 0x20 is not the address derived for this credential counter\n");
            return ERROR_TRUSTED_NAME_MISMATCH;
        }
        return SWO_SUCCESS;
    }

    _Static_assert(sizeof(((verifyAddressContext_t *) 0)->address) == sizeof(g_trusted_name),
                   "Certified name must fit the reviewed address buffer");
    memmove(ctx->address, g_trusted_name, sizeof(ctx->address));
    return SWO_SUCCESS;
}

/** Set the label of the path row; `label` is a compile-time constant that fits the buffer. */
static void set_path_display_label(const char *label) {
    size_t length = strlen(label);
    if (length >= sizeof(ctx->display_label)) {
        length = sizeof(ctx->display_label) - 1;
    }
    explicit_bzero(ctx->display_label, sizeof(ctx->display_label));
    memmove(ctx->display_label, label, length);
}

/**
 * PRF → credId → SHA256(credId) → base58-check into ctx->address (cryptography only).
 */
static void bls_compute_address(uint32_t cred_counter) {
    derivation_path_t *derivation_path = &global_derivation_path;
    uint8_t credId[BLS_G1_COORD_SIZE];
    uint8_t prf[KEY_LENGTH];

    BEGIN_TRY {
        TRY {
            get_bls_private_key(derivation_path, prf, sizeof(prf));
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
    base58check_encode(accountAddress,
                       sizeof(accountAddress),
                       (unsigned char *) ctx->address,
                       &addressLength);
    ctx->address[BASE58_ADDRESS_LENGTH] = '\0';
}

/* Shape of the account signing path m/44'/coin'/idp'/identity'/0'/credCounter'.
 * Node 4 is the key-role selector, 0' being the signing role; node 5 is the credential counter. */
#define SIGNING_PATH_LEN             6
#define SIGNING_PATH_INDEX_PURPOSE   0
#define SIGNING_PATH_INDEX_KEY_ROLE  4
#define SIGNING_PATH_KEY_ROLE_SIGN   0

/*
 * Does this full path have the shape that lets tag 0x22 name a single account?
 *
 * parse_derivation_path_from_buffer stamps every full path DERIVATION_PATH_VARIANT_FULL without
 * inspecting it (derivation_path.c:33), so the variant on its own means only that the host chose
 * P1 = 0x02. The argument for trusting the descriptor's address holds for the signing path and
 * nothing else: send the 5-node PRF path under P1_FULL_PATH instead and tag 0x22 becomes the
 * identity-level key that every credential counter shares, so a descriptor issued for counter 0
 * would match while the address on screen is the host's, never derived and never checked.
 *
 * Called after harden_derivation_path, hence the masks. The coin-type node needs no check here:
 * an unknown one leaves the path with no network, which pki_bind_descriptor already refuses.
 */
static bool full_path_names_one_account(const derivation_path_t *derivation_path) {
    return derivation_path->len == SIGNING_PATH_LEN &&
           (derivation_path->nodes[SIGNING_PATH_INDEX_PURPOSE] & ~HARDENED_BIT) == NEW_PURPOSE &&
           (derivation_path->nodes[SIGNING_PATH_INDEX_KEY_ROLE] & ~HARDENED_BIT) ==
               SIGNING_PATH_KEY_ROLE_SIGN;
}

void handle_verify_address(const command_t *cmd, volatile unsigned int *flags) {
    uint8_t *cdata = cmd->data;
    uint8_t p1 = cmd->p1;
    uint8_t p2 = cmd->p2;
    uint8_t lc = cmd->lc;

    derivation_path_t *derivation_path = &global_derivation_path;
    init_derivation_path(derivation_path);
    uint32_t cred_counter = 0;

    explicit_bzero(ctx->address, sizeof(ctx->address));
    explicit_bzero(ctx->display, sizeof(ctx->display));

    uint16_t sw = parse_key_path(cdata, p1, p2, lc, derivation_path, &cred_counter);
    if (sw != SWO_SUCCESS) {
        send_rejection(sw);
        return;
    }

    /* P2 (or the coin-type node of a full path) picks the network, and the network changes the
     * derived key, so it belongs on the review next to the address it produced. */
    derivation_path_network_t network = derivation_path_network(derivation_path);
    path_display_network(ctx->network, sizeof(ctx->network), derivation_path);

    switch (derivation_path->variant) {
        case DERIVATION_PATH_VARIANT_NEW:
            set_path_display_label("Identity");
            path_display_new(ctx->display,
                             sizeof(ctx->display),
                             derivation_path->nodes[PATH_INDEX_IDENTITY_PROVIDER],
                             derivation_path->nodes[PATH_INDEX_IDENTITY],
                             cred_counter);
            break;

        case DERIVATION_PATH_VARIANT_LEGACY:
            set_path_display_label("Identity");
            path_display_legacy(ctx->display,
                                sizeof(ctx->display),
                                derivation_path->nodes[PATH_INDEX_IDENTITY_LEGACY],
                                cred_counter);
            break;

        case DERIVATION_PATH_VARIANT_FULL:
            /* The host chooses the depth and every node, and all of them reach key derivation, so
             * the whole path is shown. Labelling three selected nodes "idp/identity/account" hid
             * any suffix past node 4 and printed zeroes for nodes a short path never sent. */
            set_path_display_label("Derivation path");
            path_display_full(ctx->display, sizeof(ctx->display), derivation_path);
            break;

        default:
            set_path_display_label("Identity");
            break;
    }

    /* get_bls_private_key / get_public_key expect hardened path; parsers output unhardened */
    harden_derivation_path(derivation_path);

    /* A full path reaches key derivation as sent, so tag 0x22 binds the descriptor to that exact
     * path -- for the signing path hosts use, m/44'/coin'/idp'/identity'/0'/credCounter', that
     * already names one credential counter. Deriving an address here would have to treat a signing
     * path as a PRF path, which is a different key and belongs to no account. The compact formats
     * instead review the PRF path, whose key every counter shares, so there the derived address is
     * what tells them apart and it is the review. */
    bool descriptor_names_account =
        g_trusted_name_valid && derivation_path->variant == DERIVATION_PATH_VARIANT_FULL;

    /* The shape has to be checked, not assumed, and a full path that fails the check has to be
     * refused rather than fall through to the derive-and-compare lane: that lane would run
     * get_bls_private_key over a path that is not a PRF path, with cred_counter fixed at 0 --
     * producing counter 0's address for a PRF path sent here (so a counter-0 descriptor would
     * match) and a meaningless address for anything else. Neither is something to show. */
    if (descriptor_names_account && !full_path_names_one_account(derivation_path)) {
        PRINTF("Full path is not an account signing path; descriptor cannot name an account\n");
        clear_trusted_name_binding();
        explicit_bzero(ctx->address, sizeof(ctx->address));
        send_rejection(ERROR_TRUSTED_NAME_MISMATCH);
        return;
    }

    if (!descriptor_names_account) {
        bls_compute_address(cred_counter);
    }

    if (g_trusted_name_valid) {
        uint8_t derived_ed25519_pub[KEY_LENGTH];
        get_public_key(&global_derivation_path, derived_ed25519_pub);
        sw = pki_bind_descriptor(derived_ed25519_pub, network, !descriptor_names_account);
        explicit_bzero(derived_ed25519_pub, sizeof(derived_ed25519_pub));
        /* Single-use either way: a descriptor refused against this path must not stay available
         * for the host to retry against another one. */
        clear_trusted_name_binding();
        if (sw != SWO_SUCCESS) {
            explicit_bzero(ctx->address, sizeof(ctx->address));
            send_rejection(sw);
            return;
        }
    }
    uiVerifyAddress(flags);
}
