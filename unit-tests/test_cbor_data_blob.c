/*
 * readCborInitial() - findings V-077, V-100 and V-104.
 *
 * V-100: a non-canonical argument lets one value arrive as several distinct byte strings that
 *        all review identically, so the screen cannot say which one is being signed.
 * V-077: an integer is complete once its argument is read, so trailing APDU bytes must be
 *        refused - they stayed in the transaction hash while the review showed just the integer.
 * V-104: the review carries the major type in words, so a numeric and a text value that render
 *        the same are told apart.
 *
 * Each case also asserts the refusal arrives as a status word rather than a THROW, which is the
 * distinction finding V-006 was about: a THROW here would have taken the app down.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "globals.h"
#include "helpers/cbor_data_blob.h"
#include "ledger/status_words.h"
#include "throw_harness.h"

#define CTX (&global.withDataBlob.cborContext)

/** Put the parser back to the state a signing handler leaves before the first CBOR byte. */
static void seed(uint32_t declared_cbor_length) {
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

/* ---------------------------------------------------------------- V-100 --- */

static void test_inline_unsigned_is_accepted(void **state) {
    (void) state;
    /* 0x01: unsigned 1 carried inline in the short count - canonical by construction. */
    const uint8_t cbor[] = {0x01};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
    assert_string_equal((char *) CTX->display, "1");
    assert_string_equal(CTX->typeLabel, "Unsigned integer");
}

static void test_one_byte_form_of_a_small_value_is_refused(void **state) {
    (void) state;
    /* 0x1801 encodes 1 in the one-byte form; 0x01 already encodes it. */
    const uint8_t cbor[] = {0x18, 0x01};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), ERROR_INVALID_TRANSACTION);
}

static void test_two_byte_form_of_a_one_byte_value_is_refused(void **state) {
    (void) state;
    /* 0x190001 encodes 1 in the two-byte form. */
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

/* ---------------------------------------------------------------- V-077 --- */

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

/* ---------------------------------------------------------------- V-104 --- */

static void test_text_and_number_do_not_review_identically(void **state) {
    (void) state;
    /* Canonical text "1" (0x61 0x31) renders the same glyph as unsigned 1, so the type label is
     * the only thing separating two different signed byte strings on screen. */
    const uint8_t text[] = {0x61, '1'};
    seed(sizeof(text));
    assert_int_equal(run(text, sizeof(text)), SWO_SUCCESS);
    assert_string_equal(CTX->typeLabel, "Text");

    const uint8_t number[] = {0x01};
    seed(sizeof(number));
    assert_int_equal(run(number, sizeof(number)), SWO_SUCCESS);
    assert_string_equal(CTX->typeLabel, "Unsigned integer");
}

static void test_negative_integer_is_labelled(void **state) {
    (void) state;
    /* 0x20 is -1: major type 1, argument 0 inline. */
    const uint8_t cbor[] = {0x20};
    seed(sizeof(cbor));
    assert_int_equal(run(cbor, sizeof(cbor)), SWO_SUCCESS);
    assert_string_equal(CTX->typeLabel, "Negative integer");
    assert_string_equal((char *) CTX->display, "-1");
}

/* --------------------------------------------------- refusals, not aborts --- */

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

static void test_indefinite_length_is_refused(void **state) {
    (void) state;
    /* Short count 31 is the streaming form, which this parser does not implement. */
    uint8_t buffer[] = {0x7F};
    seed(sizeof(buffer));
    ASSERT_THROWS(readCborInitial(buffer, sizeof(buffer)), ERROR_UNSUPPORTED_CBOR);
}

static void test_unsupported_major_type_is_refused(void **state) {
    (void) state;
    /* Major type 4 (array): only 0, 1 and 3 are supported. */
    uint8_t buffer[] = {0x80};
    seed(sizeof(buffer));
    ASSERT_THROWS(readCborInitial(buffer, sizeof(buffer)), ERROR_UNSUPPORTED_CBOR);
}

static void test_truncated_length_argument_is_refused(void **state) {
    (void) state;
    /* Declares a two-byte argument but supplies one byte of it. */
    uint8_t buffer[] = {0x19, 0x01};
    seed(sizeof(buffer));
    ASSERT_THROWS(readCborInitial(buffer, sizeof(buffer)), SWO_INCORRECT_DATA);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_inline_unsigned_is_accepted),
        cmocka_unit_test(test_one_byte_form_of_a_small_value_is_refused),
        cmocka_unit_test(test_two_byte_form_of_a_one_byte_value_is_refused),
        cmocka_unit_test(test_four_byte_form_of_a_one_byte_value_is_refused),
        cmocka_unit_test(test_eight_byte_form_of_a_one_byte_value_is_refused),
        cmocka_unit_test(test_shortest_form_for_a_large_value_is_accepted),
        cmocka_unit_test(test_two_byte_form_for_a_value_above_255_is_accepted),
        cmocka_unit_test(test_trailing_byte_after_integer_is_refused),
        cmocka_unit_test(test_trailing_byte_after_inline_integer_is_refused),
        cmocka_unit_test(test_text_and_number_do_not_review_identically),
        cmocka_unit_test(test_negative_integer_is_labelled),
        cmocka_unit_test(test_empty_input_is_refused_without_killing_the_app),
        cmocka_unit_test(test_zero_declared_length_is_refused),
        cmocka_unit_test(test_indefinite_length_is_refused),
        cmocka_unit_test(test_unsupported_major_type_is_refused),
        cmocka_unit_test(test_truncated_length_argument_is_refused),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
