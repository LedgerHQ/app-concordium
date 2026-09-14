#pragma once

/*
 * THROW support for host unit tests.
 *
 * THROW is os_longjmp on device; fuzzing/stubs/ledger/exceptions.h redirects it to
 * g_fuzzer_jmp_buf. That buffer is only valid after a setjmp, so a test that reaches a THROW
 * without one jumps through an uninitialised buffer. These macros put the setjmp in place and
 * turn the outcome into an assertion, which also makes "this input is refused by status word,
 * not by killing the app" a thing a test can state directly - the distinction finding V-006
 * was about.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include <setjmp.h>
#include <cmocka.h>

#include "ledger/exceptions.h"

/** Run `stmt`, failing the test if it THROWs. */
#define ASSERT_NO_THROW(stmt)                                            \
    do {                                                                 \
        int _thrown = setjmp(g_fuzzer_jmp_buf);                          \
        if (_thrown == 0) {                                              \
            stmt;                                                        \
        } else {                                                         \
            fail_msg("unexpected THROW(%#06x) from: %s", _thrown, #stmt); \
        }                                                                \
    } while (0)

/** Run `stmt`, failing the test unless it THROWs `expected_sw`. */
#define ASSERT_THROWS(stmt, expected_sw)                                      \
    do {                                                                      \
        int _thrown = setjmp(g_fuzzer_jmp_buf);                               \
        if (_thrown == 0) {                                                   \
            stmt;                                                             \
            fail_msg("expected THROW(%#06x) from: %s", (expected_sw), #stmt); \
        } else {                                                              \
            assert_int_equal(_thrown, (int) (expected_sw));                   \
        }                                                                     \
    } while (0)
