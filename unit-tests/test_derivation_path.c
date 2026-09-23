/*
 * Derivation-path classification and display - findings V-057 and V-029.
 *
 * V-057: both 44'/919' (mainnet) and 44'/1' (testnet) are authorized prefixes and Concordium
 *        encodes both networks' addresses with the same version byte, so the address on screen
 *        does not reveal which chain is being signed for. The network has to be shown.
 * V-029: a serialized path from the host reaches key derivation node by node, so every node has
 *        to be on screen - and shown hardened, because that is the form used for derivation
 *        regardless of how the host sent it.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "globals.h"
#include "helpers/app_sizes.h"
#include "helpers/derivation_path.h"
#include "throw_harness.h"

#define PATH_DISPLAY_SIZE 128

static derivation_path_t make_path(const uint32_t *nodes, uint8_t len, bool hardened) {
    derivation_path_t path;
    init_derivation_path(&path);
    path.len = len;
    for (uint8_t i = 0; i < len; i++) {
        path.nodes[i] = hardened ? (nodes[i] | HARDENED_BIT) : nodes[i];
    }
    return path;
}

/* ---------------------------------------------------------------- V-057 --- */

static void test_mainnet_is_classified_and_labelled(void **state) {
    (void) state;
    const uint32_t nodes[] = {NEW_PURPOSE, NEW_MAINNET_COIN_TYPE, 0, 0, 0};
    derivation_path_t path = make_path(nodes, 5, false);
    assert_int_equal(derivation_path_network(&path), DERIVATION_PATH_NETWORK_MAINNET);

    uint8_t label[NETWORK_DISPLAY_SIZE] = {0};
    path_display_network(label, sizeof(label), &path);
    assert_string_equal((char *) label, NETWORK_DISPLAY_MAINNET);
}

static void test_testnet_is_classified_and_labelled(void **state) {
    (void) state;
    const uint32_t nodes[] = {NEW_PURPOSE, NEW_TESTNET_COIN_TYPE, 0, 0, 0};
    derivation_path_t path = make_path(nodes, 5, false);
    assert_int_equal(derivation_path_network(&path), DERIVATION_PATH_NETWORK_TESTNET);

    uint8_t label[NETWORK_DISPLAY_SIZE] = {0};
    path_display_network(label, sizeof(label), &path);
    assert_string_equal((char *) label, NETWORK_DISPLAY_TESTNET);
}

static void test_mainnet_and_testnet_labels_differ(void **state) {
    (void) state;
    /* The point of the finding: these two must never review identically. */
    const uint32_t main_nodes[] = {NEW_PURPOSE, NEW_MAINNET_COIN_TYPE, 0, 0, 0};
    const uint32_t test_nodes[] = {NEW_PURPOSE, NEW_TESTNET_COIN_TYPE, 0, 0, 0};
    derivation_path_t mainnet = make_path(main_nodes, 5, false);
    derivation_path_t testnet = make_path(test_nodes, 5, false);

    uint8_t a[NETWORK_DISPLAY_SIZE] = {0};
    uint8_t b[NETWORK_DISPLAY_SIZE] = {0};
    path_display_network(a, sizeof(a), &mainnet);
    path_display_network(b, sizeof(b), &testnet);
    assert_string_not_equal((char *) a, (char *) b);
}

static void test_classification_ignores_the_hardened_bit(void **state) {
    (void) state;
    /* Parsers harden nodes before derivation, so the same path must classify the same either
     * way - otherwise the network label depends on where in the flow it is read. */
    const uint32_t nodes[] = {NEW_PURPOSE, NEW_MAINNET_COIN_TYPE, 0, 0, 0};
    derivation_path_t plain = make_path(nodes, 5, false);
    derivation_path_t hard = make_path(nodes, 5, true);
    assert_int_equal(derivation_path_network(&plain), derivation_path_network(&hard));
    assert_int_equal(derivation_path_network(&hard), DERIVATION_PATH_NETWORK_MAINNET);
}

static void test_legacy_subtree_is_network_neutral(void **state) {
    (void) state;
    /* 1105' has no network node, so it is labelled as neutral rather than guessed at. */
    const uint32_t nodes[] = {LEGACY_PURPOSE, 0, 0, 0, 7, 1};
    derivation_path_t path = make_path(nodes, 6, true);
    assert_int_equal(derivation_path_network(&path), DERIVATION_PATH_NETWORK_LEGACY);

    uint8_t label[NETWORK_DISPLAY_SIZE] = {0};
    path_display_network(label, sizeof(label), &path);
    assert_string_equal((char *) label, NETWORK_DISPLAY_LEGACY);
}

static void test_unknown_coin_type_is_not_assumed_to_be_mainnet(void **state) {
    (void) state;
    const uint32_t nodes[] = {NEW_PURPOSE, 4242, 0, 0, 0};
    derivation_path_t path = make_path(nodes, 5, false);
    assert_int_equal(derivation_path_network(&path), DERIVATION_PATH_NETWORK_UNKNOWN);

    uint8_t label[NETWORK_DISPLAY_SIZE] = {0};
    path_display_network(label, sizeof(label), &path);
    assert_string_equal((char *) label, NETWORK_DISPLAY_UNKNOWN);
}

static void test_path_too_short_for_a_coin_type_is_unknown(void **state) {
    (void) state;
    const uint32_t nodes[] = {NEW_PURPOSE};
    derivation_path_t path = make_path(nodes, 1, false);
    assert_int_equal(derivation_path_network(&path), DERIVATION_PATH_NETWORK_UNKNOWN);
}

static void test_empty_path_is_unknown(void **state) {
    (void) state;
    derivation_path_t path;
    init_derivation_path(&path);
    assert_int_equal(derivation_path_network(&path), DERIVATION_PATH_NETWORK_UNKNOWN);
}

static void test_every_network_label_fits_its_buffer(void **state) {
    (void) state;
    /* The display buffer is NETWORK_DISPLAY_SIZE everywhere it is used, and the label has to be
     * NUL-terminated inside it - the header asserts this at compile time, this checks it holds
     * for the longest label at run time too. */
    const uint32_t nodes[] = {LEGACY_PURPOSE, 0};
    derivation_path_t path = make_path(nodes, 2, false);
    uint8_t label[NETWORK_DISPLAY_SIZE];
    memset(label, 'x', sizeof(label));
    path_display_network(label, sizeof(label), &path);
    assert_true(strlen((char *) label) < NETWORK_DISPLAY_SIZE);
}

/* ---------------------------------------------------------------- V-029 --- */

static void test_full_path_shows_every_node_hardened(void **state) {
    (void) state;
    const uint32_t nodes[] = {44, 919, 403, 404, 8};
    derivation_path_t path = make_path(nodes, 5, true);
    uint8_t display[PATH_DISPLAY_SIZE] = {0};
    path_display_full(display, sizeof(display), &path);
    assert_string_equal((char *) display, "44'/919'/403'/404'/8'");
}

static void test_full_path_display_is_identical_whether_or_not_nodes_are_hardened(void **state) {
    (void) state;
    /* The confusion the finding describes: the hardened bit is a derivation detail, not a
     * different path, so it must not change what the user reads. */
    const uint32_t nodes[] = {44, 919, 403, 404, 8};
    derivation_path_t plain = make_path(nodes, 5, false);
    derivation_path_t hard = make_path(nodes, 5, true);

    uint8_t a[PATH_DISPLAY_SIZE] = {0};
    uint8_t b[PATH_DISPLAY_SIZE] = {0};
    path_display_full(a, sizeof(a), &plain);
    path_display_full(b, sizeof(b), &hard);
    assert_string_equal((char *) a, (char *) b);
}

static void test_full_path_renders_the_largest_node_value(void **state) {
    (void) state;
    /* 0xFFFFFFFF with the hardened bit stripped is 0x7FFFFFFF; a node sent unhardened at
     * 0xFFFFFFFF must not render as 4294967295, which no derivation would ever use. */
    const uint32_t nodes[] = {0x7FFFFFFFU};
    derivation_path_t path = make_path(nodes, 1, true);
    uint8_t display[PATH_DISPLAY_SIZE] = {0};
    path_display_full(display, sizeof(display), &path);
    assert_string_equal((char *) display, "2147483647'");
}

static void test_full_path_of_one_node_has_no_separator(void **state) {
    (void) state;
    const uint32_t nodes[] = {44};
    derivation_path_t path = make_path(nodes, 1, true);
    uint8_t display[PATH_DISPLAY_SIZE] = {0};
    path_display_full(display, sizeof(display), &path);
    assert_string_equal((char *) display, "44'");
}

static void test_full_path_truncates_rather_than_overflowing(void **state) {
    (void) state;
    /* A caller buffer smaller than the worst case must not be written past. */
    const uint32_t nodes[] = {44, 919, 403, 404, 8, 9, 10, 11};
    derivation_path_t path = make_path(nodes, DERIVATION_PATH_NODES_MAX, true);
    uint8_t display[8];
    memset(display, 'x', sizeof(display));
    path_display_full(display, sizeof(display), &path);
    /* Still a valid C string inside the buffer. */
    assert_true(strlen((char *) display) < sizeof(display));
}

static void test_zero_length_buffers_are_a_no_op(void **state) {
    (void) state;
    const uint32_t nodes[] = {44, 919};
    derivation_path_t path = make_path(nodes, 2, true);
    uint8_t canary = 'Z';
    path_display_full(&canary, 0, &path);
    path_display_network(&canary, 0, &path);
    assert_int_equal(canary, 'Z');
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_mainnet_is_classified_and_labelled),
        cmocka_unit_test(test_testnet_is_classified_and_labelled),
        cmocka_unit_test(test_mainnet_and_testnet_labels_differ),
        cmocka_unit_test(test_classification_ignores_the_hardened_bit),
        cmocka_unit_test(test_legacy_subtree_is_network_neutral),
        cmocka_unit_test(test_unknown_coin_type_is_not_assumed_to_be_mainnet),
        cmocka_unit_test(test_path_too_short_for_a_coin_type_is_unknown),
        cmocka_unit_test(test_empty_path_is_unknown),
        cmocka_unit_test(test_every_network_label_fits_its_buffer),
        cmocka_unit_test(test_full_path_shows_every_node_hardened),
        cmocka_unit_test(test_full_path_display_is_identical_whether_or_not_nodes_are_hardened),
        cmocka_unit_test(test_full_path_renders_the_largest_node_value),
        cmocka_unit_test(test_full_path_of_one_node_has_no_separator),
        cmocka_unit_test(test_full_path_truncates_rather_than_overflowing),
        cmocka_unit_test(test_zero_length_buffers_are_a_no_op),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
