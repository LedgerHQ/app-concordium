/*
 * Unit tests for helpers/cbor_data_blob.c - tinycbor parsing over APDU accumulation.
 *
 * The blob is accumulated whole and parsed once, so the checks below fall into two groups:
 *
 *   Accumulation: readCborInitial / readCborContent across APDU boundaries, including a header
 *   split mid-way and content arriving in several packets, plus the buffer and declared-length
 *   guards that still refuse by THROW.
 *
 *   Review integrity - findings V-077, V-100, V-104, V-004/V-025. Everything the screen cannot
 *   render faithfully is refused, because the blob is hashed in full:
 *     V-100: a non-canonical argument lets one value arrive as several distinct byte strings
 *            that all review identically, so the screen cannot say which one is being signed.
 *     V-077: an item is complete once its argument is read, so trailing bytes must be refused -
 *            they stayed in the transaction hash while the review showed just the value.
 *     V-104: the review carries the major type in words, so a numeric and a text value that
 *            render the same are told apart.
 *     V-004/V-025: text with bytes no screen can render is refused, not drawn as something else.
 *
 * Each refusal case also asserts *how* it is refused. A status word is answered to the host; a
 * THROW would have taken the app down before the guard added for V-006.
 *
 * Build via unit-tests/CMakeLists.txt; run with ctest or directly.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "globals.h"
#include "helpers/app_sizes.h"
#include "helpers/cbor_data_blob.h"
#include "ledger/status_words.h"
#include "throw_harness.h"

#define CTX (&global.withDataBlob.cborContext)

/** Put the parser back to the state a signing handler leaves before the first CBOR byte. */
static void seed(uint16_t declared_cbor_length) {
    memset(&global, 0, sizeof(global));
    CTX->cborLength = declared_cbor_length;
}

/** Run readCborInitial over a mutable copy, since the parser takes a non-const pointer. */
static uint16_t run(const uint8_t *bytes, uint8_t length) {
    /* MAX_DATA_SIZE exceeds UINT8_MAX, so a uint8_t length always fits. */
    uint8_t buffer[MAX_DATA_SIZE];
    memcpy(buffer, bytes, length);
    uint16_t sw = 0xFFFF;
    ASSERT_NO_THROW(sw = readCborInitial(buffer, length));
    return sw;
}

/* ------------------------------------------------ accepted encodings ------ */

static void test_uint_inline(void **state) {
    (void) state;
    /* 0x05: unsigned 5 carried inline in the short count - canonical by construction. */
    const uint8_t cbor[] = {0x05};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
    assert_int_equal(CTX->cborLength, 0);
    assert_string_equal((char *) CTX->display, "5");
    assert_string_equal(CTX->typeLabel, "Unsigned integer");
}

static void test_uint_one_byte_argument(void **state) {
    (void) state;
    /* 0x182A: 42 does not fit the inline short count, so one byte is its canonical form. */
    const uint8_t cbor[] = {0x18, 0x2A};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
    assert_string_equal((char *) CTX->display, "42");
}

static void test_uint_max_u64(void **state) {
    (void) state;
    /* 0x1B + eight 0xFF: UINT64_MAX needs the widest form, so it is canonical. */
    const uint8_t cbor[] = {0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
    assert_string_equal((char *) CTX->display, "18446744073709551615");
}

static void test_negint_inline(void **state) {
    (void) state;
    /* 0x20 is -1: major type 1, argument 0 inline. */
    const uint8_t cbor[] = {0x20};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
    assert_string_equal((char *) CTX->display, "-1");
    assert_string_equal(CTX->typeLabel, "Negative integer");
}

static void test_negint_one_byte_argument(void **state) {
    (void) state;
    /* 0x381F: argument 31 → -(31 + 1) = -32. */
    const uint8_t cbor[] = {0x38, 0x1F};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
    assert_string_equal((char *) CTX->display, "-32");
}

static void test_text_inline_length(void **state) {
    (void) state;
    /* 0x63 + "ABC": length 3 carried inline. */
    const uint8_t cbor[] = {0x63, 'A', 'B', 'C'};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
    assert_int_equal(CTX->cborLength, 0);
    assert_int_equal(CTX->displayLen, 3);
    assert_string_equal((char *) CTX->display, "ABC");
    assert_string_equal(CTX->typeLabel, "Text");
}

static void test_text_one_byte_length(void **state) {
    (void) state;
    /* 0x78 0x18 + 24 bytes: 24 is the smallest length needing the one-byte form. */
    uint8_t cbor[2 + 24];
    cbor[0] = 0x78;
    cbor[1] = 24;
    memset(cbor + 2, 'A', 24);
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
    assert_int_equal(CTX->displayLen, 24);
}

static void test_text_empty(void **state) {
    (void) state;
    const uint8_t cbor[] = {0x60};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
    assert_int_equal(CTX->displayLen, 0);
    assert_string_equal((char *) CTX->display, "");
}

/* --------------------------------------------------------- V-100 --------- */

static void test_one_byte_form_of_a_small_value_is_refused(void **state) {
    (void) state;
    /* 0x1801 encodes 1 in the one-byte form; 0x01 already encodes it. */
    const uint8_t cbor[] = {0x18, 0x01};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

static void test_two_byte_form_of_a_one_byte_value_is_refused(void **state) {
    (void) state;
    const uint8_t cbor[] = {0x19, 0x00, 0x01};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

static void test_four_byte_form_of_a_one_byte_value_is_refused(void **state) {
    (void) state;
    const uint8_t cbor[] = {0x1A, 0x00, 0x00, 0x00, 0x01};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

static void test_eight_byte_form_of_a_one_byte_value_is_refused(void **state) {
    (void) state;
    const uint8_t cbor[] = {0x1B, 0, 0, 0, 0, 0, 0, 0, 0x01};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

static void test_shortest_form_for_a_large_value_is_accepted(void **state) {
    (void) state;
    /* 0x1818 is 24 - the smallest value that does NOT fit the inline short count, so the
     * one-byte form is its canonical encoding and must be accepted. This is the boundary the
     * canonicality check turns on. */
    const uint8_t cbor[] = {0x18, 0x18};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
    assert_string_equal((char *) CTX->display, "24");
}

static void test_two_byte_form_for_a_value_above_255_is_accepted(void **state) {
    (void) state;
    /* 0x190100 is 256: does not fit one byte, so two bytes is canonical. */
    const uint8_t cbor[] = {0x19, 0x01, 0x00};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
    assert_string_equal((char *) CTX->display, "256");
}

static void test_non_canonical_text_length_is_refused(void **state) {
    (void) state;
    /* 0x7803 encodes length 3 in the one-byte form; 0x63 already encodes it. */
    const uint8_t cbor[] = {0x78, 0x03, 'A', 'B', 'C'};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

/* --------------------------------------------------------- V-077 --------- */

static void test_trailing_byte_after_integer_is_refused(void **state) {
    (void) state;
    /* Canonical unsigned 24 followed by one byte the review would never show. */
    const uint8_t cbor[] = {0x18, 0x18, 0xFF};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

static void test_trailing_byte_after_inline_integer_is_refused(void **state) {
    (void) state;
    const uint8_t cbor[] = {0x01, 0xFF};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

static void test_trailing_byte_after_text_is_refused(void **state) {
    (void) state;
    /* Canonical text "ABC" plus a byte outside the item. */
    const uint8_t cbor[] = {0x63, 'A', 'B', 'C', 0xFF};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

/* --------------------------------------------------------- V-104 --------- */

static void test_text_and_number_do_not_review_identically(void **state) {
    (void) state;
    /* Canonical text "1" (0x61 0x31) renders the same glyph as unsigned 1, so the type label is
     * the only thing separating two different signed byte strings on screen. */
    const uint8_t text[] = {0x61, '1'};
    seed(sizeof(text));
    assert_int_equal(run(text, sizeof(text)), SWO_SUCCESS);
    assert_string_equal((char *) CTX->display, "1");
    assert_string_equal(CTX->typeLabel, "Text");

    const uint8_t number[] = {0x01};
    seed(sizeof(number));
    assert_int_equal(run(number, sizeof(number)), SWO_SUCCESS);
    assert_string_equal((char *) CTX->display, "1");
    assert_string_equal(CTX->typeLabel, "Unsigned integer");
}

/* ---------------------------------------------------- V-004 / V-025 ------ */

static void test_embedded_nul_in_text_is_refused(void **state) {
    (void) state;
    /* The NUL ends the C string on screen while the signature still covers "BC". */
    const uint8_t cbor[] = {0x63, 'A', 0x00, 'C'};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

static void test_control_byte_in_text_is_refused(void **state) {
    (void) state;
    const uint8_t cbor[] = {0x63, 'A', 0x1F, 'C'};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

static void test_del_byte_in_text_is_refused(void **state) {
    (void) state;
    const uint8_t cbor[] = {0x63, 'A', 0x7F, 'C'};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

/* -------------------------------------------- unsupported shapes --------- */

static void test_indefinite_length_is_refused(void **state) {
    (void) state;
    /* Short count 31 is the streaming form: a sequence of chunks with no single canonical
     * encoding, so the review could not name one byte string being authorised. */
    const uint8_t cbor[] = {0x7F};
    seed(sizeof(cbor));
    assert_int_not_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
}

static void test_unsupported_major_type_is_refused(void **state) {
    (void) state;
    /* Major type 4 (array): only 0, 1 and 3 are supported. */
    const uint8_t cbor[] = {0x80};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_UNSUPPORTED_CBOR);
}

static void test_truncated_length_argument_is_refused(void **state) {
    (void) state;
    /* Declares a two-byte argument but supplies one byte of it. */
    const uint8_t cbor[] = {0x19, 0x01};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

static void test_text_shorter_than_its_declared_length_is_refused(void **state) {
    (void) state;
    /* Header claims 10 content bytes; only 3 arrive within the declared total. */
    const uint8_t cbor[] = {0x78, 0x0A, 'A', 'B', 'C'};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

/* -------------------------------------------------- accumulation --------- */

static void test_text_content_split_across_apdus(void **state) {
    (void) state;
    /* "Hello, World!" arriving as header+prefix, then two more packets. */
    seed(14);

    uint8_t first[] = {0x6D, 'H', 'e', 'l', 'l', 'o', ',', ' '};
    uint8_t second[] = {'W', 'o', 'r', 'l', 'd'};
    uint8_t third[] = {'!'};

    ASSERT_NO_THROW({
        assert_int_equal(readCborInitial(first, sizeof(first)), SWO_SUCCESS);
        assert_int_equal(CTX->cborLength, 6);

        assert_int_equal(readCborContent(second, sizeof(second)), SWO_SUCCESS);
        assert_int_equal(CTX->cborLength, 1);

        assert_int_equal(readCborContent(third, sizeof(third)), SWO_SUCCESS);
        assert_int_equal(CTX->cborLength, 0);
    });
    assert_string_equal((char *) CTX->display, "Hello, World!");
    assert_string_equal(CTX->typeLabel, "Text");
}

static void test_header_spans_apdu_boundary(void **state) {
    (void) state;
    /* The two-byte header is split: only 0x78 arrives in the first packet. Nothing can be
     * decoded until the whole blob is in, which is exactly what accumulation buys. */
    seed(2 + 24);

    uint8_t first[] = {0x78};
    uint8_t second[1 + 24];
    second[0] = 24;
    memset(second + 1, 'A', 24);

    ASSERT_NO_THROW({
        assert_int_equal(readCborInitial(first, sizeof(first)), SWO_SUCCESS);
        assert_int_equal(CTX->cborLength, 1 + 24);

        assert_int_equal(readCborContent(second, sizeof(second)), SWO_SUCCESS);
        assert_int_equal(CTX->cborLength, 0);
    });
    assert_int_equal(CTX->displayLen, 24);
}

static void test_text_at_exact_display_capacity(void **state) {
    (void) state;
    /*
     * MAX_CBOR_STRING_SIZE bytes of text - the largest blob the protocol allows - split over
     * two packets because a single APDU chunk caps at 255 bytes.
     */
    const uint16_t total = 2u + MAX_CBOR_STRING_SIZE;
    seed(total);

    uint8_t cbor[2 + MAX_CBOR_STRING_SIZE];
    cbor[0] = 0x78;
    cbor[1] = (uint8_t) MAX_CBOR_STRING_SIZE;
    memset(cbor + 2, 'X', MAX_CBOR_STRING_SIZE);

    ASSERT_NO_THROW({
        assert_int_equal(readCborInitial(cbor, 255), SWO_SUCCESS);
        assert_int_equal(readCborContent(cbor + 255, (uint8_t) (total - 255)), SWO_SUCCESS);
    });

    assert_int_equal(CTX->cborLength, 0);
    assert_int_equal(CTX->displayLen, MAX_CBOR_STRING_SIZE);
    assert_int_equal(CTX->display[MAX_CBOR_STRING_SIZE], '\0');
    for (int i = 0; i < MAX_CBOR_STRING_SIZE; i++) {
        if (CTX->display[i] != 'X') {
            fail_msg("display[%d] = 0x%02x, expected 'X'", i, CTX->display[i]);
        }
    }
}

/* ------------------------------------------------- structural guards ----- */

static void test_empty_input_is_refused_without_killing_the_app(void **state) {
    (void) state;
    /* No byte to read a header from. This path still THROWs, and the guard added in app_main
     * for V-006 is what keeps it from ending the session - assert the value, not a crash. */
    uint8_t buffer[1] = {0};
    seed(1);
    ASSERT_THROWS(readCborInitial(buffer, 0), SWO_INCORRECT_DATA);
}

static void test_zero_declared_length_is_refused(void **state) {
    (void) state;
    /* cborLength is the protocol-declared total from a previous APDU; zero means the host said
     * there is no payload, so no header may be consumed. */
    uint8_t buffer[] = {0x01};
    seed(0);
    ASSERT_THROWS(readCborInitial(buffer, sizeof(buffer)), SWO_INCORRECT_DATA);
}

static void test_initial_chunk_longer_than_declared_total_is_refused(void **state) {
    (void) state;
    /* Three physical bytes against a declared total of two. */
    uint8_t buffer[] = {0x62, 'A', 'B'};
    seed(2);
    ASSERT_THROWS(readCborInitial(buffer, sizeof(buffer)), SWO_INCORRECT_DATA);
}

static void test_content_chunk_longer_than_remaining_is_refused(void **state) {
    (void) state;
    /* The header leaves five bytes outstanding; the host sends six. */
    uint8_t header[] = {0x78, 0x05};
    uint8_t too_much[6];
    memset(too_much, 'A', sizeof(too_much));

    seed(7);
    ASSERT_NO_THROW(assert_int_equal(readCborInitial(header, sizeof(header)), SWO_SUCCESS));
    assert_int_equal(CTX->cborLength, 5);
    ASSERT_THROWS(readCborContent(too_much, sizeof(too_much)), SWO_INCORRECT_DATA);
}

static void test_blob_beyond_the_buffer_is_refused(void **state) {
    (void) state;
    /*
     * A 3-byte header plus 256 content bytes is 259, past MAX_CBOR_BLOB_SIZE (257). The
     * accumulation buffer guard refuses it rather than truncating, so nothing can be signed
     * that the review never held.
     */
    const uint16_t content_len = MAX_CBOR_STRING_SIZE + 1;
    seed((uint16_t) (3u + content_len));

    uint8_t header[3] = {0x79, (uint8_t) (content_len >> 8), (uint8_t) (content_len & 0xff)};
    uint8_t content[MAX_CBOR_STRING_SIZE];
    memset(content, 'A', sizeof(content));

    ASSERT_NO_THROW(assert_int_equal(readCborInitial(header, sizeof(header)), SWO_SUCCESS));
    /* 3 + 255 = 258 > 257. */
    ASSERT_THROWS(readCborContent(content, MAX_CBOR_STRING_SIZE), SWO_INCORRECT_DATA);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_uint_inline),
        cmocka_unit_test(test_uint_one_byte_argument),
        cmocka_unit_test(test_uint_max_u64),
        cmocka_unit_test(test_negint_inline),
        cmocka_unit_test(test_negint_one_byte_argument),
        cmocka_unit_test(test_text_inline_length),
        cmocka_unit_test(test_text_one_byte_length),
        cmocka_unit_test(test_text_empty),

        cmocka_unit_test(test_one_byte_form_of_a_small_value_is_refused),
        cmocka_unit_test(test_two_byte_form_of_a_one_byte_value_is_refused),
        cmocka_unit_test(test_four_byte_form_of_a_one_byte_value_is_refused),
        cmocka_unit_test(test_eight_byte_form_of_a_one_byte_value_is_refused),
        cmocka_unit_test(test_shortest_form_for_a_large_value_is_accepted),
        cmocka_unit_test(test_two_byte_form_for_a_value_above_255_is_accepted),
        cmocka_unit_test(test_non_canonical_text_length_is_refused),

        cmocka_unit_test(test_trailing_byte_after_integer_is_refused),
        cmocka_unit_test(test_trailing_byte_after_inline_integer_is_refused),
        cmocka_unit_test(test_trailing_byte_after_text_is_refused),

        cmocka_unit_test(test_text_and_number_do_not_review_identically),

        cmocka_unit_test(test_embedded_nul_in_text_is_refused),
        cmocka_unit_test(test_control_byte_in_text_is_refused),
        cmocka_unit_test(test_del_byte_in_text_is_refused),

        cmocka_unit_test(test_indefinite_length_is_refused),
        cmocka_unit_test(test_unsupported_major_type_is_refused),
        cmocka_unit_test(test_truncated_length_argument_is_refused),
        cmocka_unit_test(test_text_shorter_than_its_declared_length_is_refused),

        cmocka_unit_test(test_text_content_split_across_apdus),
        cmocka_unit_test(test_header_spans_apdu_boundary),
        cmocka_unit_test(test_text_at_exact_display_capacity),

        cmocka_unit_test(test_empty_input_is_refused_without_killing_the_app),
        cmocka_unit_test(test_zero_declared_length_is_refused),
        cmocka_unit_test(test_initial_chunk_longer_than_declared_total_is_refused),
        cmocka_unit_test(test_content_chunk_longer_than_remaining_is_refused),
        cmocka_unit_test(test_blob_beyond_the_buffer_is_refused),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
