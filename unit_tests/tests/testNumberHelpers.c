#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <stdint.h>  // uint*_t
#include <stddef.h>  // size_t

#include <cmocka.h>

#include "numberHelpers.c"

static void test_lengthOfNumbers() {
    assert_int_equal(lengthOfNumber(0), 1);
    assert_int_equal(lengthOfNumber(1), 1);
    assert_int_equal(lengthOfNumber(9), 1);
    assert_int_equal(lengthOfNumber(10), 2);
    assert_int_equal(lengthOfNumber(11), 2);
    assert_int_equal(lengthOfNumber(57), 2);
    assert_int_equal(lengthOfNumber(99), 2);
    assert_int_equal(lengthOfNumber(100), 3);
    assert_int_equal(lengthOfNumber(101), 3);
    assert_int_equal(lengthOfNumber(369), 3);
    assert_int_equal(lengthOfNumber(999), 3);
    assert_int_equal(lengthOfNumber(1000), 4);
    assert_int_equal(lengthOfNumber(1001), 4);
}

static void test_numberToText() {
    uint8_t text[4];
    numberToText(text, 2001);
    assert_string_equal(text, "2001");
    numberToText(text, 4041);
    assert_string_equal(text, "4041");
}

static void test_numberToText_shorter_number() {
    uint8_t text[4];
    numberToText(text, 46);
    assert_string_equal(text, "46");

    numberToText(text, 100);
    assert_string_equal(text, "100");

    numberToText(text, 23);
    assert_string_equal(text, "230");

    numberToText(text, 1);
    assert_string_equal(text, "130");
}
/*
static void test_numberToText_longer_number() {
    uint8_t text[4];
    // This should fail, because the text is not long enough
    int result = numberToText(text, 12041);
    assert_int_equal(result, -1);
}
*/
static void test_bin2dec() {
    uint8_t text[4];
    bin2dec(text, 2001);
    assert_string_equal(text, "2001");
    bin2dec(text, 4041);
    assert_string_equal(text, "4041");
}

static void test_bin2dec_shorter_number() {
    uint8_t text[4];
    bin2dec(text, 46);
    assert_string_equal(text, "46");

    bin2dec(text, 100);
    assert_string_equal(text, "100");

    bin2dec(text, 23);
    assert_string_equal(text, "23");

    bin2dec(text, 1);
    assert_string_equal(text, "1");

    bin2dec(text, 0);
    assert_string_equal(text, "0");
}
/*
static void test_bin2dec_longer_number() {
    uint8_t text[4];
    // This should fail, because the text is not long enough
    int result = bin2dec(text, 12041);
    assert_int_equal(result, -1);
}
*/
static void test_decimalAmountToGtuDisplay() {
    uint8_t text[6];
    decimalAmountToGtuDisplay(text, 2100112);
    assert_string_equal(text, "100112");
    decimalAmountToGtuDisplay(text, 4041);
    assert_string_equal(text, "004041");
    decimalAmountToGtuDisplay(text, 1);
    assert_string_equal(text, "000001");
    decimalAmountToGtuDisplay(text, 0);
    assert_string_equal(text, "000000");
}

static void test_amountToGtuDisplay_zero() {
    uint8_t text[20];
    amountToGtuDisplay(text, 0);
    assert_string_equal(text, "0");
}

static void test_amountToGtuDisplay_no_microGtu() {
    uint8_t text[20];
    amountToGtuDisplay(text, 105000000);
    assert_string_equal(text, "105");
    amountToGtuDisplay(text, 27000000);
    assert_string_equal(text, "27");
    amountToGtuDisplay(text, 1000000);
    assert_string_equal(text, "1");
}

static void test_amountToGtuDisplay_only_microGtu() {
    uint8_t text[20];
    amountToGtuDisplay(text, 5400);
    assert_string_equal(text, "0.0054");
    amountToGtuDisplay(text, 1);
    assert_string_equal(text, "0.000001");
    amountToGtuDisplay(text, 4041);
    assert_string_equal(text, "0.004041");
    amountToGtuDisplay(text, 112428);
    assert_string_equal(text, "0.112428");
}

static void test_amountToGtuDisplay_mixed() {
    uint8_t text[20];
    amountToGtuDisplay(text, 2100112);
    assert_string_equal(text, "2.100112");
    amountToGtuDisplay(text, 5001000);
    assert_string_equal(text, "5.001");
}

static void test_amountToGtuDisplay_with_thousand_separator() {
    uint8_t text[21];
    amountToGtuDisplay(text, 1200000000);
    assert_string_equal(text, "1,200");
    amountToGtuDisplay(text, 720005200122);
    assert_string_equal(text, "720,005.200122");
    amountToGtuDisplay(text, 1111111111111111);
    assert_string_equal(text, "1,111,111,111.111111");
}

static void test_toPaginatedHex() {
    char text[70];
    uint8_t bytes[] = { 171, 34, 31, 72, 83, 171, 34, 29, 72, 83, 34, 29, 31, 72, 34, 29, 31, 72, 34, 29, 31, 72 };
    toPaginatedHex(bytes, 22, text);
    assert_string_equal(text, "ab221f4853ab221d 4853221d1f48221d 1f48221d1f48");
}

static void test_toPaginatedHex_stops_after_given_length() {
    char text[12];
    text[11] = 100;
    uint8_t bytes[] = { 171, 34, 31, 72, 83, 170, 34, 1, 1, 1 };
    toPaginatedHex(bytes, 5, text);
    assert_string_equal(text, "ab221f4853");
    assert_int_equal(text[10], '\0');
    assert_int_equal(text[11], 100);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_lengthOfNumbers),
        cmocka_unit_test(test_numberToText),
        cmocka_unit_test(test_numberToText_shorter_number),
        // cmocka_unit_test(test_numberToText_longer_number),
        cmocka_unit_test(test_bin2dec),
        cmocka_unit_test(test_bin2dec_shorter_number),
        // cmocka_unit_test(test_bin2dec_longer_number),
        cmocka_unit_test(test_decimalAmountToGtuDisplay),
        cmocka_unit_test(test_amountToGtuDisplay_only_microGtu),
        cmocka_unit_test(test_amountToGtuDisplay_no_microGtu),
        cmocka_unit_test(test_amountToGtuDisplay_with_thousand_separator),
        cmocka_unit_test(test_amountToGtuDisplay_mixed),
        cmocka_unit_test(test_amountToGtuDisplay_zero),
        cmocka_unit_test(test_toPaginatedHex),
        cmocka_unit_test(test_toPaginatedHex_stops_after_given_length),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
