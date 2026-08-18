/*
 * Unit tests for helpers/cbor_data_blob.c — tinycbor-based CBOR parser with APDU accumulation.
 *
 * Tests readCborInitial / readCborContent for all supported major types (0=uint, 1=negint,
 * 3=text), all header sizes (1–9 bytes), multi-APDU splits, and error paths.
 * Blobs exceeding MAX_CBOR_BLOB_SIZE (the protocol limit) throw SWO_INCORRECT_DATA.
 *
 * Build via unit-tests/CMakeLists.txt; run with ctest or directly.
 */

#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <cmocka.h>

/* Fuzzer stubs provide the THROW-compatible setjmp target. */
#include "ledger/exceptions.h"
#include "ledger/status_words.h"

#include "globals.h"              /* ERROR_UNSUPPORTED_CBOR, cborContext_t via instruction_context */
#include "helpers/cbor_data_blob.h"
#include "helpers/app_sizes.h"   /* MAX_CBOR_STRING_SIZE */

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static cborContext_t *setup_ctx(uint16_t cborLength) {
    cborContext_t *ctx = &global.withDataBlob.cborContext;
    memset(ctx, 0, sizeof(*ctx));
    ctx->cborLength = cborLength;
    return ctx;
}

/* Per-test setup: wipe global state so tests are fully isolated. */
static int per_test_setup(void **state) {
    (void) state;
    memset(&global, 0, sizeof(global));
    return 0;
}

/* ── Unsigned integer tests ───────────────────────────────────────────────── */

static void test_uint_embedded(void **state) {
    (void) state;
    cborContext_t *ctx = setup_ctx(1);  /* 1-byte CBOR: major=0, ai=5 → value 5 */
    uint8_t cbor[] = {0x05};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        assert_int_equal(ctx->cborLength, 0);
        assert_string_equal((char *) ctx->display, "5");
    } else {
        fail_msg("Unexpected THROW 0x%04x", rc);
    }
}

static void test_uint_one_extra_byte(void **state) {
    (void) state;
    /* major=0, ai=24, length-field=0x2A → value 42 */
    cborContext_t *ctx = setup_ctx(2);
    uint8_t cbor[] = {0x18, 0x2A};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        assert_string_equal((char *) ctx->display, "42");
    } else {
        fail_msg("Unexpected THROW 0x%04x", rc);
    }
}

static void test_uint_two_extra_bytes(void **state) {
    (void) state;
    /* major=0, ai=25, uint16=0x0100 → value 256 */
    cborContext_t *ctx = setup_ctx(3);
    uint8_t cbor[] = {0x19, 0x01, 0x00};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        assert_string_equal((char *) ctx->display, "256");
    } else {
        fail_msg("Unexpected THROW 0x%04x", rc);
    }
}

static void test_uint_max_u64(void **state) {
    (void) state;
    /* major=0, ai=27, uint64=0xFFFFFFFFFFFFFFFF → "18446744073709551615" */
    cborContext_t *ctx = setup_ctx(9);
    uint8_t cbor[] = {0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        assert_string_equal((char *) ctx->display, "18446744073709551615");
    } else {
        fail_msg("Unexpected THROW 0x%04x", rc);
    }
}

/* ── Negative integer tests ───────────────────────────────────────────────── */

static void test_negint_embedded(void **state) {
    (void) state;
    /* major=1, ai=0 → -(0+1) = -1 */
    cborContext_t *ctx = setup_ctx(1);
    uint8_t cbor[] = {0x20};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        assert_string_equal((char *) ctx->display, "-1");
    } else {
        fail_msg("Unexpected THROW 0x%04x", rc);
    }
}

static void test_negint_one_extra_byte(void **state) {
    (void) state;
    /* major=1, ai=24, length-field=0x1F → -(31+1) = -32 */
    cborContext_t *ctx = setup_ctx(2);
    uint8_t cbor[] = {0x38, 0x1F};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        assert_string_equal((char *) ctx->display, "-32");
    } else {
        fail_msg("Unexpected THROW 0x%04x", rc);
    }
}

/* ── Text string tests ────────────────────────────────────────────────────── */

static void test_text_embedded_length(void **state) {
    (void) state;
    /* major=3, ai=3 → 3-byte string "ABC"; total CBOR = 4 bytes */
    cborContext_t *ctx = setup_ctx(4);
    uint8_t cbor[] = {0x63, 'A', 'B', 'C'};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        assert_int_equal(ctx->cborLength, 0);
        assert_int_equal(ctx->displayLen, 3);
        assert_string_equal((char *) ctx->display, "ABC");
    } else {
        fail_msg("Unexpected THROW 0x%04x", rc);
    }
}

static void test_text_one_extra_byte_header(void **state) {
    (void) state;
    /* major=3, ai=24, length=3 → "ABC"; total CBOR = 5 bytes */
    cborContext_t *ctx = setup_ctx(5);
    uint8_t cbor[] = {0x78, 0x03, 'A', 'B', 'C'};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        assert_string_equal((char *) ctx->display, "ABC");
    } else {
        fail_msg("Unexpected THROW 0x%04x", rc);
    }
}

static void test_text_empty(void **state) {
    (void) state;
    /* major=3, ai=0 → empty string; total CBOR = 1 byte */
    cborContext_t *ctx = setup_ctx(1);
    uint8_t cbor[] = {0x60};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        assert_int_equal(ctx->displayLen, 0);
        assert_string_equal((char *) ctx->display, "");
    } else {
        fail_msg("Unexpected THROW 0x%04x", rc);
    }
}

static void test_text_exact_display_capacity(void **state) {
    (void) state;
    /*
     * Text exactly MAX_CBOR_STRING_SIZE bytes long: should fit without trimming.
     * CBOR: 0x78 0xFF + 255 bytes; total = 257 bytes.
     */
    uint16_t total = 2u + MAX_CBOR_STRING_SIZE;
    cborContext_t *ctx = setup_ctx(total);

    uint8_t cbor[2 + MAX_CBOR_STRING_SIZE];
    cbor[0] = 0x78;
    cbor[1] = (uint8_t) MAX_CBOR_STRING_SIZE;
    memset(cbor + 2, 'X', MAX_CBOR_STRING_SIZE);

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        /*
         * readCborInitial / readCborContent take uint8_t (max 255 bytes per call).
         * Send first 255 bytes (header + 253 content bytes), then remaining 2 content bytes.
         */
        readCborInitial(cbor, 255);
        readCborContent(cbor + 255, 2);

        assert_int_equal(ctx->cborLength, 0);
        assert_int_equal(ctx->displayLen, MAX_CBOR_STRING_SIZE);
        assert_int_equal(ctx->display[MAX_CBOR_STRING_SIZE], '\0');
        /* All content bytes should be present (no trim). */
        for (int i = 0; i < MAX_CBOR_STRING_SIZE; i++) {
            if (ctx->display[i] != 'X') {
                fail_msg("display[%d] = 0x%02x, expected 'X'", i, ctx->display[i]);
            }
        }
    } else {
        fail_msg("Unexpected THROW 0x%04x", rc);
    }
}

static void test_text_trimmed(void **state) {
    (void) state;
    /*
     * Text blob of 259 bytes (3-byte header + 256 content) exceeds MAX_CBOR_BLOB_SIZE
     * (257). The accumulation model cannot trim: once the buffer overflows,
     * readCborContent throws SWO_INCORRECT_DATA.
     * CBOR: 0x79 0x01 0x00 + 256 bytes; total = 259 bytes.
     */
    uint16_t content_len = MAX_CBOR_STRING_SIZE + 1;
    uint16_t total = 3u + content_len;  /* 3-byte header */
    setup_ctx(total);

    uint8_t header[3] = {0x79, (uint8_t)(content_len >> 8), (uint8_t)(content_len & 0xff)};
    uint8_t content[MAX_CBOR_STRING_SIZE];
    memset(content, 'A', sizeof(content));

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(header, sizeof(header));
        /* After header (3 bytes), adding 255 content bytes → 258 > MAX_CBOR_BLOB_SIZE (257). */
        readCborContent(content, MAX_CBOR_STRING_SIZE);
        fail_msg("Expected SWO_INCORRECT_DATA but no THROW occurred");
    } else {
        assert_int_equal(rc, SWO_INCORRECT_DATA);
    }
}

static void test_text_500_bytes(void **state) {
    (void) state;
    /*
     * Text blob of 503 bytes (3-byte header + 500 content) exceeds MAX_CBOR_BLOB_SIZE
     * (257). The accumulation buffer overflows and readCborContent throws SWO_INCORRECT_DATA.
     * CBOR header: 0x79 0x01 0xF4 (major=3, ai=25, uint16=500); total = 503 bytes.
     */
    uint16_t content_len = 500;
    uint16_t total = 3u + content_len;
    setup_ctx(total);

    uint8_t header[3] = {0x79, (uint8_t)(content_len >> 8), (uint8_t)(content_len & 0xff)};
    uint8_t content[MAX_CBOR_STRING_SIZE];
    memset(content, 'A', sizeof(content));

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(header, sizeof(header));
        /* After header (3 bytes), adding 255 content bytes → 258 > MAX_CBOR_BLOB_SIZE (257). */
        readCborContent(content, MAX_CBOR_STRING_SIZE);
        fail_msg("Expected SWO_INCORRECT_DATA but no THROW occurred");
    } else {
        assert_int_equal(rc, SWO_INCORRECT_DATA);
    }
}

/* ── Multi-APDU split tests ───────────────────────────────────────────────── */

static void test_text_content_split_across_apdus(void **state) {
    (void) state;
    /*
     * "Hello, World!" split: header+first-part in readCborInitial, remainder
     * in two readCborContent calls.
     * CBOR: 0x6D + 13 bytes; total = 14 bytes.
     */
    cborContext_t *ctx = setup_ctx(14);

    /* First APDU: header + "Hello, " (7 bytes) */
    uint8_t first[] = {0x6D, 'H', 'e', 'l', 'l', 'o', ',', ' '};
    /* Second APDU: "World" */
    uint8_t second[] = {'W', 'o', 'r', 'l', 'd'};
    /* Third APDU: "!" */
    uint8_t third[] = {'!'};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(first, sizeof(first));
        assert_int_equal(ctx->cborLength, 6);  /* 14 - 8 = 6 remaining */

        readCborContent(second, sizeof(second));
        assert_int_equal(ctx->cborLength, 1);

        readCborContent(third, sizeof(third));
        assert_int_equal(ctx->cborLength, 0);
        assert_string_equal((char *) ctx->display, "Hello, World!");
    } else {
        fail_msg("Unexpected THROW 0x%04x", rc);
    }
}

static void test_header_spans_apdu_boundary(void **state) {
    (void) state;
    /*
     * 2-byte CBOR header split: first APDU has only the initial byte (0x78);
     * second APDU has the length byte + content.
     * String "ABC" with 2-byte header: 0x78 0x03 'A' 'B' 'C'; total = 5 bytes.
     */
    cborContext_t *ctx = setup_ctx(5);

    uint8_t first[]  = {0x78};
    uint8_t second[] = {0x03, 'A', 'B', 'C'};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(first, sizeof(first));
        assert_int_equal(ctx->cborLength, 4);  /* 5 - 1 = 4 remaining */

        readCborContent(second, sizeof(second));
        assert_int_equal(ctx->cborLength, 0);
        assert_string_equal((char *) ctx->display, "ABC");
    } else {
        fail_msg("Unexpected THROW 0x%04x", rc);
    }
}

/* ── Error path tests ─────────────────────────────────────────────────────── */

static void test_error_data_exceeds_cbor_length(void **state) {
    (void) state;
    /* readCborInitial: dataLength (3) > cborLength (2) → SWO_INCORRECT_DATA */
    setup_ctx(2);
    uint8_t cbor[] = {0x62, 'A', 'B'};  /* 3 bytes but cborLength = 2 */

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        fail_msg("Expected SWO_INCORRECT_DATA but no THROW occurred");
    } else {
        assert_int_equal(rc, SWO_INCORRECT_DATA);
    }
}

static void test_error_unsupported_cbor_type(void **state) {
    (void) state;
    /* CBOR array (major=4): 0x80 → ERROR_UNSUPPORTED_CBOR */
    setup_ctx(1);
    uint8_t cbor[] = {0x80};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        fail_msg("Expected ERROR_UNSUPPORTED_CBOR but no THROW occurred");
    } else {
        assert_int_equal(rc, ERROR_UNSUPPORTED_CBOR);
    }
}

static void test_error_unsupported_indefinite_length(void **state) {
    (void) state;
    /* CBOR indefinite-length text string (ai=31): 0x7F → ERROR_UNSUPPORTED_CBOR */
    setup_ctx(1);
    uint8_t cbor[] = {0x7F};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        fail_msg("Expected ERROR_UNSUPPORTED_CBOR but no THROW occurred");
    } else {
        assert_int_equal(rc, ERROR_UNSUPPORTED_CBOR);
    }
}

static void test_error_integer_with_trailing_bytes(void **state) {
    (void) state;
    /*
     * CBOR uint value=5 is 1 byte, but cborLength declares 2 bytes. The accumulation
     * model detects trailing bytes only after all bytes arrive and parse_complete_cbor
     * is called: cbor_value_get_next_byte points past the integer but not past the buffer
     * end → SWO_INCORRECT_DATA.
     */
    setup_ctx(2);
    uint8_t cbor[] = {0x05, 0xFF};  /* 1-byte uint + 1 trailing byte */

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        fail_msg("Expected SWO_INCORRECT_DATA but no THROW occurred");
    } else {
        assert_int_equal(rc, SWO_INCORRECT_DATA);
    }
}

static void test_error_text_length_mismatch(void **state) {
    (void) state;
    /*
     * CBOR text header claims 10 bytes of content, but cborLength says only 3
     * bytes remain after the header. finish_header() verifies value == cborLength.
     * Header: 0x78 0x0A (major=3, ai=24, length=10); total CBOR declared = 5.
     * After header (2 bytes) consumed: cborLength = 3, but value = 10 → mismatch.
     */
    setup_ctx(5);
    uint8_t cbor[] = {0x78, 0x0A, 'A', 'B', 'C'};

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(cbor, sizeof(cbor));
        fail_msg("Expected SWO_INCORRECT_DATA but no THROW occurred");
    } else {
        assert_int_equal(rc, SWO_INCORRECT_DATA);
    }
}

static void test_error_content_exceeds_cbor_length(void **state) {
    (void) state;
    /*
     * readCborContent: contentLength (5) > cborLength (3) → SWO_INCORRECT_DATA.
     * First call sets up text streaming correctly; second sends too many bytes.
     */
    cborContext_t *ctx = setup_ctx(7);  /* 2-byte header + 5-byte content */
    uint8_t header[] = {0x78, 0x05};
    uint8_t too_much[6];
    memset(too_much, 'A', sizeof(too_much));  /* 6 bytes > 5 remaining */

    int rc = setjmp(g_fuzzer_jmp_buf);
    if (rc == 0) {
        readCborInitial(header, sizeof(header));
        /* cborLength is now 5 */
        assert_int_equal(ctx->cborLength, 5);
        readCborContent(too_much, sizeof(too_much));  /* should throw */
        fail_msg("Expected SWO_INCORRECT_DATA but no THROW occurred");
    } else {
        assert_int_equal(rc, SWO_INCORRECT_DATA);
    }
}

/* ── Entry point ──────────────────────────────────────────────────────────── */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_uint_embedded,                  per_test_setup),
        cmocka_unit_test_setup(test_uint_one_extra_byte,            per_test_setup),
        cmocka_unit_test_setup(test_uint_two_extra_bytes,           per_test_setup),
        cmocka_unit_test_setup(test_uint_max_u64,                   per_test_setup),
        cmocka_unit_test_setup(test_negint_embedded,                per_test_setup),
        cmocka_unit_test_setup(test_negint_one_extra_byte,          per_test_setup),
        cmocka_unit_test_setup(test_text_embedded_length,           per_test_setup),
        cmocka_unit_test_setup(test_text_one_extra_byte_header,     per_test_setup),
        cmocka_unit_test_setup(test_text_empty,                     per_test_setup),
        cmocka_unit_test_setup(test_text_exact_display_capacity,    per_test_setup),
        cmocka_unit_test_setup(test_text_trimmed,                   per_test_setup),
        cmocka_unit_test_setup(test_text_500_bytes,                 per_test_setup),
        cmocka_unit_test_setup(test_text_content_split_across_apdus, per_test_setup),
        cmocka_unit_test_setup(test_header_spans_apdu_boundary,     per_test_setup),
        cmocka_unit_test_setup(test_error_data_exceeds_cbor_length, per_test_setup),
        cmocka_unit_test_setup(test_error_unsupported_cbor_type,    per_test_setup),
        cmocka_unit_test_setup(test_error_unsupported_indefinite_length, per_test_setup),
        cmocka_unit_test_setup(test_error_integer_with_trailing_bytes, per_test_setup),
        cmocka_unit_test_setup(test_error_text_length_mismatch,     per_test_setup),
        cmocka_unit_test_setup(test_error_content_exceeds_cbor_length, per_test_setup),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
