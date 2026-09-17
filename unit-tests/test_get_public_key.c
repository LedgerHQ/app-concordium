/*
 * GET_PUBLIC_KEY review binding: the key that leaves the device on Accept must be the key the
 * review described.
 *
 * `uiGeneratePubkey()` parks a review and returns, so the derivation runs in the approval
 * callback - long after the handler parsed the path. `global_derivation_path` is rewritten by
 * every parse and lives outside `instructionContext`, so `explicit_bzero(&global, ...)` never
 * touches it: a second request landing while the review is up used to repoint it, and the
 * pending Accept then derived a key for a path the user never saw. Two things close that, and
 * both are asserted here:
 *
 *   - the handler pins the parsed path in `global_reviewed_path`, and every derivation - the key
 *     drawn on screen, the key sent on Accept, the signature over it - reads the pin;
 *   - `global_public_key_review_pending` refuses a second GET_PUBLIC_KEY while a review of it is
 *     unanswered, so the host cannot choose which of two paths the user consents to.
 *
 * The refusal answers with `io_send_sw()` rather than `send_rejection()`, and that is asserted
 * too: `send_rejection()` drops the instruction latch, which would leave the next command free
 * to make app_main() zero `global` and own the union the review still reads its text and
 * `signPublicKey` from.
 *
 * On device an APDU never arrives while a reply is pending - the SDK answers it 0x6901 in
 * os_io_handle_ux_event_reject_apdu - so none of this is reachable through Ragger, and a test
 * there would only be asserting the SDK's gate. These call the handler and the approval
 * callback directly, which is the layer the guard lives at. The claim's release on rejection
 * runs in menu_bagl.c / menu_nbgl.c, which do not build on the host; that half is
 * test_public_key_review_claim_is_released_after_a_refusal in tests/standalone/test_pubkey_cmd.py.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "fuzz_ui.h"
#include "globals.h"
#include "handler/get_public_key.h"
#include "helpers/derivation_path.h"
#include "stub_probes.h"
#include "throw_harness.h"

#define P1_DISPLAY 0x00
#define P2_PLAIN   0x00

/* m/44'/919'/0'/0'/0' and m/44'/919'/1'/2'/3' - both authorized new-format account paths, so
 * the difference between them is the identity provider, identity and account the review names. */
static const uint32_t PATH_A[] = {NEW_PURPOSE, NEW_MAINNET_COIN_TYPE, 0, 0, 0};
static const uint32_t PATH_B[] = {NEW_PURPOSE, NEW_MAINNET_COIN_TYPE, 1, 2, 3};

#define PATH_LEN 5
/* Wire form: <depth:u8> <node:u32be> * depth. */
#define PATH_WIRE_SIZE (1 + PATH_LEN * BYTES_PER_PATH_ELEMENT)

static void serialize_path(const uint32_t *nodes, uint8_t out[PATH_WIRE_SIZE]) {
    out[0] = PATH_LEN;
    for (uint8_t i = 0; i < PATH_LEN; i++) {
        size_t o = 1 + (size_t) i * BYTES_PER_PATH_ELEMENT;
        out[o + 0] = (uint8_t) (nodes[i] >> 24);
        out[o + 1] = (uint8_t) (nodes[i] >> 16);
        out[o + 2] = (uint8_t) (nodes[i] >> 8);
        out[o + 3] = (uint8_t) (nodes[i]);
    }
}

/*
 * Field-wise, not memcmp: derivation_path_t is padded and init_derivation_path() does not zero
 * the padding, so a byte compare can fail on two paths that are equal.
 */
static void assert_path_is(const derivation_path_t *actual, const uint32_t *expected_nodes) {
    assert_int_equal(actual->len, PATH_LEN);
    assert_int_equal(actual->variant, DERIVATION_PATH_VARIANT_NEW);
    for (uint8_t i = 0; i < PATH_LEN; i++) {
        /* parse_derivation_path() hardens every node before any derivation sees it. */
        assert_int_equal(actual->nodes[i], expected_nodes[i] | HARDENED_BIT);
    }
}

/*
 * The state app_main() guarantees before a first APDU, for the globals this handler touches.
 * fuzzing/src/fuzz_state.h does the same job for the fuzz harnesses; it is not on this target's
 * include path, and a test that needs only these four is clearer stating them.
 */
static void given_idle_app(void) {
    memset(&global, 0, sizeof(global));
    memset(&global_derivation_path, 0, sizeof(global_derivation_path));
    memset(&global_reviewed_path, 0, sizeof(global_reviewed_path));
    global_public_key_review_pending = false;
    global_tx_state.currentInstruction = INS_GET_PUBLIC_KEY;
    g_fuzz_pending_ui_action = FUZZ_UI_NONE;
    stub_probes_reset();
}

/* One GET_PUBLIC_KEY command, the way app_main() would hand it to the handler. */
static void when_requested(uint8_t p1, uint8_t p2, const uint32_t *nodes) {
    uint8_t wire[PATH_WIRE_SIZE];
    serialize_path(nodes, wire);

    volatile unsigned int flags = 0;
    command_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.cla = 0xE0;
    cmd.ins = INS_GET_PUBLIC_KEY;
    cmd.p1 = p1;
    cmd.p2 = p2;
    cmd.lc = (uint8_t) sizeof(wire);
    cmd.data = wire;

    ASSERT_NO_THROW(handle_get_public_key(&cmd, &flags));
}

/* ------------------------------------------------------- the pin ---------- */

static void test_accept_derives_from_the_reviewed_path(void **state) {
    (void) state;
    given_idle_app();

    when_requested(P1_DISPLAY, P2_SIGN_PUBLIC_KEY, PATH_A);
    assert_int_equal(g_fuzz_pending_ui_action, FUZZ_UI_PUBLIC_KEY_CONFIRM);
    assert_true(global_public_key_review_pending);
    assert_path_is(&global_reviewed_path, PATH_A);

    /* What a second parse does, whoever performs it: the global the handler read is now a
     * different path, while the review on screen still names PATH_A. */
    ASSERT_NO_THROW({
        uint8_t wire_b[PATH_WIRE_SIZE];
        serialize_path(PATH_B, wire_b);
        parse_derivation_path(wire_b, sizeof(wire_b));
    });
    assert_path_is(&global_derivation_path, PATH_B);
    assert_path_is(&global_reviewed_path, PATH_A);

    /* Approve, exactly as review_public_key_choice() does. */
    stub_probes_reset();
    ASSERT_NO_THROW(fuzz_answer_pending_ui(true));

    assert_true(g_stub_public_key_called);
    assert_path_is(&g_stub_public_key_path, PATH_A);
    assert_true(g_stub_sign_called);
    assert_path_is(&g_stub_sign_path, PATH_A);
}

static void test_the_screen_and_the_reply_derive_from_one_path(void **state) {
    (void) state;
    given_idle_app();

    /* The key printed into the review comes from the pin too, so display and reply cannot
     * disagree even if the pin itself were wrong. */
    when_requested(P1_DISPLAY, P2_PLAIN, PATH_A);
    assert_true(g_stub_public_key_called);
    assert_path_is(&g_stub_public_key_path, PATH_A);
    assert_false(g_stub_sign_called); /* P2 did not ask for a signature */
}

/* ------------------------------------------------- the review claim ------- */

static void test_second_request_is_refused_while_a_review_is_pending(void **state) {
    (void) state;
    given_idle_app();

    when_requested(P1_DISPLAY, P2_PLAIN, PATH_A);
    assert_true(global_public_key_review_pending);

    stub_probes_reset();
    when_requested(P1_DISPLAY, P2_PLAIN, PATH_B);

    /* Refused, and refused without deriving anything. */
    assert_true(g_stub_send_sw_called);
    assert_int_equal(g_stub_last_sw, ERROR_INVALID_STATE);
    assert_false(g_stub_public_key_called);

    /* The review is untouched: same pin, still pending, still holding the instruction latch.
     * The latch is the regression guard - send_rejection() would have cleared it, and a free
     * latch lets the next command zero `global` under the screen. */
    assert_path_is(&global_reviewed_path, PATH_A);
    assert_true(global_public_key_review_pending);
    assert_int_equal(global_tx_state.currentInstruction, INS_GET_PUBLIC_KEY);
    assert_int_equal(g_fuzz_pending_ui_action, FUZZ_UI_PUBLIC_KEY_CONFIRM);

    /* And approving after the refusal still exports what the review described. */
    stub_probes_reset();
    ASSERT_NO_THROW(fuzz_answer_pending_ui(true));
    assert_true(g_stub_public_key_called);
    assert_path_is(&g_stub_public_key_path, PATH_A);
}

static void test_accepting_releases_the_claim(void **state) {
    (void) state;
    given_idle_app();

    when_requested(P1_DISPLAY, P2_PLAIN, PATH_A);
    ASSERT_NO_THROW(fuzz_answer_pending_ui(true));
    assert_false(global_public_key_review_pending);

    /* So the next request is served rather than refused, and pins its own path. */
    global_tx_state.currentInstruction = INS_GET_PUBLIC_KEY;
    stub_probes_reset();
    when_requested(P1_DISPLAY, P2_PLAIN, PATH_B);

    assert_false(g_stub_send_sw_called);
    assert_true(global_public_key_review_pending);
    assert_path_is(&global_reviewed_path, PATH_B);
}

static void test_skip_display_claims_no_review(void **state) {
    (void) state;
    given_idle_app();

    /* P1_SKIP_DISPLAY answers inside the handler, so there is no window to protect and no
     * claim to leave behind - one that leaked would refuse every later request. */
    when_requested(P1_SKIP_DISPLAY, P2_PLAIN, PATH_A);

    assert_int_equal(g_fuzz_pending_ui_action, FUZZ_UI_NONE);
    assert_false(global_public_key_review_pending);
    assert_true(g_stub_public_key_called);
    assert_path_is(&g_stub_public_key_path, PATH_A);

    stub_probes_reset();
    when_requested(P1_SKIP_DISPLAY, P2_PLAIN, PATH_B);
    assert_false(g_stub_send_sw_called);
    assert_path_is(&g_stub_public_key_path, PATH_B);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_accept_derives_from_the_reviewed_path),
        cmocka_unit_test(test_the_screen_and_the_reply_derive_from_one_path),
        cmocka_unit_test(test_second_request_is_refused_while_a_review_is_pending),
        cmocka_unit_test(test_accepting_releases_the_claim),
        cmocka_unit_test(test_skip_display_claims_no_review),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
