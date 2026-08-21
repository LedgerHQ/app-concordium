/*
 * Unit tests for src/handler/sign_plt.c — PLT (Protocol Level Token) signing handler.
 *
 * Tests the APDU state machine: token-id length validation, cbor_total_length
 * boundary conditions, CONT accumulation arithmetic, and state machine transitions.
 * CBOR parsing correctness (all 9 op types) is covered by the ragger Python tests.
 *
 * Build: see unit-tests/CMakeLists.txt (test_sign_plt target).
 * Run:   ctest -R test_sign_plt   or  ./unit-tests/build/test_sign_plt
 */

#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <cmocka.h>

#include "ledger/exceptions.h"
#include "ledger/status_words.h"
#include "ledger/parser.h"

#include "globals.h"
#include "instruction_context.h"
#include "helpers/app_sizes.h"
#include "handler/sign_plt.h"

/* ── Constants ────────────────────────────────────────────────────────────── */

/*
 * Path m/1105/0/0/0/0/2/0/0 in wire format (depth byte + 8 × 4-byte components).
 * Matches the path used in the ragger tests.
 */
static const uint8_t VALID_PATH[33] = {
    0x08,
    0x00, 0x00, 0x04, 0x51, /* 1105 */
    0x00, 0x00, 0x00, 0x00, /* 0    */
    0x00, 0x00, 0x00, 0x00, /* 0    */
    0x00, 0x00, 0x00, 0x00, /* 0    */
    0x00, 0x00, 0x00, 0x00, /* 0    */
    0x00, 0x00, 0x00, 0x02, /* 2    */
    0x00, 0x00, 0x00, 0x00, /* 0    */
    0x00, 0x00, 0x00, 0x00, /* 0    */
};

/* 60-byte account transaction header (all zeros). */
static const uint8_t VALID_HEADER[60] = {0};

/*
 * Minimal valid CBOR for [{"pause":{}}] — 9 bytes.
 * Used for the CONT arithmetic tests where the CBOR must parse successfully.
 *   0x81  array(1)
 *   0xa1  map(1)
 *   0x65  text(5)
 *   "pause"
 *   0xa0  map(0) = {}
 */
static const uint8_t CBOR_PAUSE[9] = {
    0x81, 0xa1, 0x65, 0x70, 0x61, 0x75, 0x73, 0x65, 0xa0
};

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static int per_test_setup(void **state) {
    (void)state;
    memset(&global, 0, sizeof(global));
    memset(&global_tx_state, 0, sizeof(global_tx_state));
    return 0;
}

/*
 * Build a PLT INIT APDU and call handle_sign_plt with isInitialCall=true.
 *
 * The token_id_len_byte is placed literally in the APDU (may be 0 or > 128 to
 * test boundary conditions).  actual_token_id_bytes controls how many bytes are
 * actually appended after the length byte (must equal token_id_len_byte for
 * success cases; may be 0 for error-path tests where the handler throws before
 * reading the token data).
 *
 * Returns the THROW value, or 0 if handle_sign_plt returned normally.
 */
static int call_init(uint8_t token_id_len_byte,
                     uint8_t actual_token_id_bytes,
                     uint32_t cbor_total) {
    /* Max buffer: path(33) + header(60) + kind(1) + len(1) + token(128) + cbor_total(4) */
    uint8_t buf[33 + 60 + 1 + 1 + 128 + 4];
    size_t off = 0;

    memcpy(buf + off, VALID_PATH, sizeof(VALID_PATH));
    off += sizeof(VALID_PATH);

    memcpy(buf + off, VALID_HEADER, sizeof(VALID_HEADER));
    off += sizeof(VALID_HEADER);

    buf[off++] = 0x1B; /* PLT transaction kind */
    buf[off++] = token_id_len_byte;

    /* Fill token_id bytes with a recognisable pattern. */
    memset(buf + off, 'T', actual_token_id_bytes);
    off += actual_token_id_bytes;

    buf[off++] = (uint8_t)((cbor_total >> 24) & 0xFF);
    buf[off++] = (uint8_t)((cbor_total >> 16) & 0xFF);
    buf[off++] = (uint8_t)((cbor_total >> 8) & 0xFF);
    buf[off++] = (uint8_t)(cbor_total & 0xFF);

    volatile unsigned int flags = 0;
    command_t cmd;
    cmd.p1   = 0x00; /* PLT_P1_INIT */
    cmd.p2   = 0x00;
    cmd.lc   = (uint8_t)off;
    cmd.data = buf;

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        handle_sign_plt(&cmd, &flags, /*isInitialCall=*/true);
    }
    return rc;
}

/* Send one CONT frame (P1=0x01) with the given data; returns THROW value or 0. */
static int call_cont(const uint8_t *data, uint8_t lc, bool is_initial) {
    volatile unsigned int flags = 0;
    command_t cmd;
    cmd.p1   = 0x01; /* PLT_P1_CONT */
    cmd.p2   = 0x00;
    cmd.lc   = lc;
    cmd.data = (uint8_t *)data;

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        handle_sign_plt(&cmd, &flags, is_initial);
    }
    return rc;
}

/* ── Token-ID length boundary tests ──────────────────────────────────────── */

static void test_token_id_len_zero(void **state) {
    (void)state;
    assert_int_equal(call_init(0, 0, 4), ERROR_PLT_DATA_ERROR);
}

static void test_token_id_len_one(void **state) {
    (void)state;
    assert_int_equal(call_init(1, 1, 4), 0); /* accepted */
}

static void test_token_id_len_128(void **state) {
    (void)state;
    assert_int_equal(call_init(128, 128, 4), 0); /* accepted (max allowed) */
}

static void test_token_id_len_129(void **state) {
    (void)state;
    assert_int_equal(call_init(129, 0, 4), ERROR_PLT_DATA_ERROR);
}

/* ── CBOR total-length boundary tests ────────────────────────────────────── */

static void test_cbor_total_zero(void **state) {
    (void)state;
    assert_int_equal(call_init(1, 1, 0), ERROR_PLT_BUFFER_ERROR);
}

static void test_cbor_total_one(void **state) {
    (void)state;
    assert_int_equal(call_init(1, 1, 1), 0); /* accepted */
}

static void test_cbor_total_512(void **state) {
    (void)state;
    assert_int_equal(call_init(1, 1, APP_PLT_CBOR_MAX), 0); /* accepted (max) */
}

static void test_cbor_total_513(void **state) {
    (void)state;
    assert_int_equal(call_init(1, 1, APP_PLT_CBOR_MAX + 1), ERROR_PLT_BUFFER_ERROR);
}

/* ── CONT accumulation arithmetic tests ──────────────────────────────────── */

static void test_cont_exact_split(void **state) {
    (void)state;
    /* INIT with cbor_total = sizeof(CBOR_PAUSE) = 9 bytes. */
    assert_int_equal(call_init(1, 1, sizeof(CBOR_PAUSE)), 0);

    /* First chunk: 5 bytes — intermediate, no error. */
    assert_int_equal(call_cont(CBOR_PAUSE, 5, false), 0);

    /* Second chunk: remaining 4 bytes — triggers parse_plt_cbor() on valid CBOR → success. */
    assert_int_equal(call_cont(CBOR_PAUSE + 5, (uint8_t)(sizeof(CBOR_PAUSE) - 5), false), 0);
}

static void test_cont_empty_chunk(void **state) {
    (void)state;
    assert_int_equal(call_init(1, 1, 4), 0);
    /* lc=0 is rejected before the arithmetic check. */
    assert_int_equal(call_cont(CBOR_PAUSE, 0, false), ERROR_PLT_CBOR_ERROR);
}

static void test_cont_overflow_by_one(void **state) {
    (void)state;
    /* INIT declares cbor_total=4; CONT sends 5 bytes. */
    assert_int_equal(call_init(1, 1, 4), 0);

    uint8_t extra[5] = {0};
    assert_int_equal(call_cont(extra, 5, false), ERROR_PLT_CBOR_ERROR);
}

/* ── State machine tests ──────────────────────────────────────────────────── */

static void test_state_cont_before_init(void **state) {
    (void)state;
    /* isInitialCall=true resets state to TX_PLT_INITIAL; then P1=CONT sees wrong state. */
    assert_int_equal(call_cont(CBOR_PAUSE, 4, /*isInitialCall=*/true), ERROR_INVALID_STATE);
}

static void test_state_double_init_resets(void **state) {
    (void)state;
    /* First INIT succeeds and moves state to TX_PLT_CBOR. */
    assert_int_equal(call_init(1, 1, 4), 0);

    /* Second INIT with isInitialCall=true resets state and is accepted again. */
    assert_int_equal(call_init(1, 1, 4), 0);
}

static void test_state_p1_invalid(void **state) {
    (void)state;
    volatile unsigned int flags = 0;
    uint8_t dummy = 0x00;
    command_t cmd = {.p1 = 0x02, .p2 = 0x00, .lc = 1, .data = &dummy};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        handle_sign_plt(&cmd, &flags, /*isInitialCall=*/true);
    }
    assert_int_equal(rc, ERROR_INVALID_PARAM);
}

/* ── Entry point ──────────────────────────────────────────────────────────── */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_token_id_len_zero,       per_test_setup),
        cmocka_unit_test_setup(test_token_id_len_one,        per_test_setup),
        cmocka_unit_test_setup(test_token_id_len_128,        per_test_setup),
        cmocka_unit_test_setup(test_token_id_len_129,        per_test_setup),
        cmocka_unit_test_setup(test_cbor_total_zero,         per_test_setup),
        cmocka_unit_test_setup(test_cbor_total_one,          per_test_setup),
        cmocka_unit_test_setup(test_cbor_total_512,          per_test_setup),
        cmocka_unit_test_setup(test_cbor_total_513,          per_test_setup),
        cmocka_unit_test_setup(test_cont_exact_split,        per_test_setup),
        cmocka_unit_test_setup(test_cont_empty_chunk,        per_test_setup),
        cmocka_unit_test_setup(test_cont_overflow_by_one,    per_test_setup),
        cmocka_unit_test_setup(test_state_cont_before_init,  per_test_setup),
        cmocka_unit_test_setup(test_state_double_init_resets, per_test_setup),
        cmocka_unit_test_setup(test_state_p1_invalid,        per_test_setup),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
