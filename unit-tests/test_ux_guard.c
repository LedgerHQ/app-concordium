/*
 * A status word thrown by a UI approval callback must become a reply, not an app exit.
 *
 * dispatch_guarded() in app_main.c converts a thrown status word into a reply, but it wraps
 * apdu_dispatcher() and nothing else. An approval callback runs from the BOLOS UX loop after
 * that TRY context is gone, so a THROW from one unwinds to the SDK handler in
 * standalone_app_main(), which exits the app - finding V-006 reached from the approve button
 * rather than from an APDU. Nearly every continuation can get there: buildAndSignTransactionHash()
 * and processNextScheduledAmount() throw directly, send_public_key() throws on a response that
 * would not fit, confirmAttribute() and confirmAddedCredential() throw on a spent list, and the
 * rest reach the cx_* helpers. ux_run_guarded() is what the display backends put in front of
 * them.
 *
 * The behaviour asserted here is dispatch_guarded()'s, because a caught callback has to leave
 * the same state behind: the host answered, the context union wiped and the instruction released
 * so a later packet cannot resume a half-reviewed transaction, and a BOLOS system exception
 * still propagating, since those are faults the SDK has to see.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "apdu/dispatcher.h"
#include "globals.h"
#include "helpers/ux_guard.h"
#include "stub_probes.h"
#include "throw_harness.h"

/* Marks how far a continuation got, so "it ran" and "it was cut short" are distinguishable. */
static bool g_ran;
static bool g_reached_end;

static void given_a_flow_in_progress(void) {
    memset(&global, 0xA5, sizeof(global)); /* recognisable, so a missed wipe is visible */
    global_tx_state.currentInstruction = INS_GET_PUBLIC_KEY;
    g_ran = false;
    g_reached_end = false;
    stub_probes_reset();
}

static void assert_flow_was_cleared(void) {
    static const uint8_t zeros[sizeof(global)] = {0};
    assert_memory_equal(&global, zeros, sizeof(global));
    assert_int_equal(global_tx_state.currentInstruction, INSTRUCTION_NONE);
}

/* ------------------------------------------------------ continuations ---- */

static void continuation_that_succeeds(void) {
    g_ran = true;
    g_reached_end = true;
}

static void continuation_that_throws_a_status_word(void) {
    g_ran = true;
    THROW(ERROR_BUFFER_OVERFLOW);
    g_reached_end = true; /* unreachable */
}

static void continuation_that_throws_a_system_exception(void) {
    g_ran = true;
    THROW(0x05); /* below MAX_SYSTEM_EXCEPTION: a genuine BOLOS fault */
    g_reached_end = true; /* unreachable */
}

/* --------------------------------------------------------------- tests --- */

static void test_a_thrown_status_word_is_answered_not_thrown_on(void **state) {
    (void) state;
    given_a_flow_in_progress();

    /* The assertion the whole file exists for: nothing escapes to the SDK handler. */
    ASSERT_NO_THROW(ux_run_guarded(continuation_that_throws_a_status_word));

    assert_true(g_ran);
    assert_false(g_reached_end);
    assert_true(g_stub_send_sw_called);
    assert_int_equal(g_stub_last_sw, ERROR_BUFFER_OVERFLOW);
}

static void test_a_caught_callback_ends_the_flow(void **state) {
    (void) state;
    given_a_flow_in_progress();

    ASSERT_NO_THROW(ux_run_guarded(continuation_that_throws_a_status_word));

    /* Same disposal as dispatch_guarded(): no half-parsed transaction left to resume. */
    assert_flow_was_cleared();
}

static void test_a_system_exception_still_propagates(void **state) {
    (void) state;
    given_a_flow_in_progress();

    /* EXCEPTION_IO_RESET and friends are not input validation; swallowing one would leave the
     * SDK believing an I/O reset never happened. */
    ASSERT_THROWS(ux_run_guarded(continuation_that_throws_a_system_exception), 0x05);

    assert_true(g_ran);
    assert_false(g_stub_send_sw_called);
}

static void test_a_successful_callback_is_left_alone(void **state) {
    (void) state;
    given_a_flow_in_progress();

    ASSERT_NO_THROW(ux_run_guarded(continuation_that_succeeds));

    assert_true(g_reached_end);
    /* The guard replies and disposes only on a catch - the continuation owns the happy path,
     * including flows that deliberately keep their screen up and the instruction latched. */
    assert_false(g_stub_send_sw_called);
    assert_int_equal(global_tx_state.currentInstruction, INS_GET_PUBLIC_KEY);
}

static void test_a_null_continuation_is_a_no_op(void **state) {
    (void) state;
    given_a_flow_in_progress();

    /* Registration sites pass weakly-linked continuations; a target that does not link one gets
     * NULL, and calling it would fault rather than report anything. */
    ASSERT_NO_THROW(ux_run_guarded(NULL));

    assert_false(g_stub_send_sw_called);
    assert_int_equal(global_tx_state.currentInstruction, INS_GET_PUBLIC_KEY);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_a_thrown_status_word_is_answered_not_thrown_on),
        cmocka_unit_test(test_a_caught_callback_ends_the_flow),
        cmocka_unit_test(test_a_system_exception_still_propagates),
        cmocka_unit_test(test_a_successful_callback_is_left_alone),
        cmocka_unit_test(test_a_null_continuation_is_a_no_op),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
