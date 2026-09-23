/*
 * Timestamp rendering - finding V-070.
 *
 * A scheduled release time is signed in milliseconds, so showing only whole seconds let 1000
 * distinct signed values share one review. appendMilliseconds() always writes three digits,
 * because ".1" would be indistinguishable from 100 ms.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "globals.h"
#include "helpers/time.h"
#include "throw_harness.h"

/* timeToDisplayText needs at least 20 bytes; ".mmm" needs 4 more plus a terminator. */
#define STAMP_SIZE 32

static size_t render(long long epoch_seconds, uint8_t *dst, size_t dstLength) {
    tm broken;
    assert_int_equal(secondsToTm(epoch_seconds, &broken), 0);
    int offset = 0;
    ASSERT_NO_THROW(offset = timeToDisplayText(broken, dst, dstLength));
    assert_true(offset > 0);
    return (size_t) offset;
}

static void test_seconds_are_rendered_zero_padded(void **state) {
    (void) state;
    uint8_t dst[STAMP_SIZE] = {0};
    /* 2021-01-02 03:04:05 UTC */
    render(1609556645LL, dst, sizeof(dst));
    assert_string_equal((char *) dst, "2021-01-02 03:04:05");
}

static void test_epoch_is_rendered(void **state) {
    (void) state;
    uint8_t dst[STAMP_SIZE] = {0};
    render(0LL, dst, sizeof(dst));
    assert_string_equal((char *) dst, "1970-01-01 00:00:00");
}

static void test_one_millisecond_reads_as_three_digits(void **state) {
    (void) state;
    uint8_t dst[STAMP_SIZE] = {0};
    render(0LL, dst, sizeof(dst));
    /* The case from the finding: ".1" would read as 100 ms. */
    ASSERT_NO_THROW(appendMilliseconds(dst, sizeof(dst), 1));
    assert_string_equal((char *) dst, "1970-01-01 00:00:00.001");
}

static void test_hundred_milliseconds_is_distinct_from_one(void **state) {
    (void) state;
    uint8_t dst[STAMP_SIZE] = {0};
    render(0LL, dst, sizeof(dst));
    ASSERT_NO_THROW(appendMilliseconds(dst, sizeof(dst), 100));
    assert_string_equal((char *) dst, "1970-01-01 00:00:00.100");
}

static void test_zero_milliseconds_is_still_shown(void **state) {
    (void) state;
    uint8_t dst[STAMP_SIZE] = {0};
    render(0LL, dst, sizeof(dst));
    /* Shown rather than omitted, so a reviewer can tell the field was present. */
    ASSERT_NO_THROW(appendMilliseconds(dst, sizeof(dst), 0));
    assert_string_equal((char *) dst, "1970-01-01 00:00:00.000");
}

static void test_maximum_milliseconds(void **state) {
    (void) state;
    uint8_t dst[STAMP_SIZE] = {0};
    render(0LL, dst, sizeof(dst));
    ASSERT_NO_THROW(appendMilliseconds(dst, sizeof(dst), 999));
    assert_string_equal((char *) dst, "1970-01-01 00:00:00.999");
}

static void test_out_of_range_milliseconds_is_refused(void **state) {
    (void) state;
    uint8_t dst[STAMP_SIZE] = {0};
    render(0LL, dst, sizeof(dst));
    /* 1000 ms is a malformed timestamp, not a second. */
    ASSERT_THROWS(appendMilliseconds(dst, sizeof(dst), 1000), ERROR_INVALID_TRANSACTION);
}

static void test_milliseconds_will_not_overflow_the_buffer(void **state) {
    (void) state;
    uint8_t dst[STAMP_SIZE] = {0};
    render(0LL, dst, sizeof(dst));
    /* ".mmm" plus a terminator needs five bytes past the offset. */
    ASSERT_THROWS(appendMilliseconds(dst, 23, 1), ERROR_BUFFER_OVERFLOW);
}

static void test_undersized_timestamp_buffer_is_refused(void **state) {
    (void) state;
    tm broken;
    assert_int_equal(secondsToTm(0LL, &broken), 0);
    uint8_t dst[8] = {0};
    ASSERT_THROWS(timeToDisplayText(broken, dst, sizeof(dst)), ERROR_BUFFER_OVERFLOW);
}

static void test_negative_year_is_refused(void **state) {
    (void) state;
    /* A negative tm_year wrapped to a huge uint64_t and produced an unbounded digit string. */
    uint8_t dst[STAMP_SIZE] = {0};
    tm broken = {0};
    broken.tm_year = -1;
    ASSERT_THROWS(timeToDisplayText(broken, dst, sizeof(dst)), ERROR_INVALID_TRANSACTION);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_seconds_are_rendered_zero_padded),
        cmocka_unit_test(test_epoch_is_rendered),
        cmocka_unit_test(test_one_millisecond_reads_as_three_digits),
        cmocka_unit_test(test_hundred_milliseconds_is_distinct_from_one),
        cmocka_unit_test(test_zero_milliseconds_is_still_shown),
        cmocka_unit_test(test_maximum_milliseconds),
        cmocka_unit_test(test_out_of_range_milliseconds_is_refused),
        cmocka_unit_test(test_milliseconds_will_not_overflow_the_buffer),
        cmocka_unit_test(test_undersized_timestamp_buffer_is_refused),
        cmocka_unit_test(test_negative_year_is_refused),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
