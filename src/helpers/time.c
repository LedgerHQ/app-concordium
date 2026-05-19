/*
 *  The code in the function secondsToTm is from the musl project
 * (https://git.musl-libc.org/cgit/musl/), specifically taken from
 * https://git.musl-libc.org/cgit/musl/tree/src/time/__secs_to_tm.c. The code has been edited
 * slightly in the following way:
 *   - renamed the method to 'seconds_to_tm'.
 *   - since we do not have access to <time.h> we use a local version with a copy
 *     of the required 'tm' struct.
 *  The musl LICENSE is provided in licenses/musl-MIT.txt
 */
#include "globals.h"
#include "time.h"

#include <limits.h>

#include <os.h>

#include "numberHelpers.h"

/* 2000-03-01 (mod 400 year, immediately after feb29 */
#define LEAPOCH (946684800LL + 86400 * (31 + 29))

#define DAYS_PER_400Y (365 * 400 + 97)
#define DAYS_PER_100Y (365 * 100 + 24)
#define DAYS_PER_4Y   (365 * 4 + 1)

int secondsToTm(long long t, tm *out) {
    long long days, secs;
    int remdays, remsecs, remyears;
    int qc_cycles, c_cycles, q_cycles;
    int years, months;
    int wday, yday, leap;
    static const char days_in_month[] = {31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29};

    /* Reject time_t values whose year would overflow int */
    if (t < INT_MIN * 31622400LL || t > INT_MAX * 31622400LL) return -1;

    secs = t - LEAPOCH;
    days = secs / 86400;
    remsecs = secs % 86400;
    if (remsecs < 0) {
        remsecs += 86400;
        days--;
    }

    wday = (3 + days) % 7;
    if (wday < 0) wday += 7;

    qc_cycles = days / DAYS_PER_400Y;
    remdays = days % DAYS_PER_400Y;
    if (remdays < 0) {
        remdays += DAYS_PER_400Y;
        qc_cycles--;
    }

    c_cycles = remdays / DAYS_PER_100Y;
    if (c_cycles == 4) c_cycles--;
    remdays -= c_cycles * DAYS_PER_100Y;

    q_cycles = remdays / DAYS_PER_4Y;
    if (q_cycles == 25) q_cycles--;
    remdays -= q_cycles * DAYS_PER_4Y;

    remyears = remdays / 365;
    if (remyears == 4) remyears--;
    remdays -= remyears * 365;

    leap = !remyears && (q_cycles || !c_cycles);
    yday = remdays + 31 + 28 + leap;
    if (yday >= 365 + leap) yday -= 365 + leap;

    years = remyears + 4 * q_cycles + 100 * c_cycles + 400 * qc_cycles;

    for (months = 0; days_in_month[months] <= remdays; months++) remdays -= days_in_month[months];

    if (years > INT_MAX - 100 || years < INT_MIN + 100) return -1;

    out->tm_year = years + 100;
    out->tm_mon = months + 2;
    if (out->tm_mon >= 12) {
        out->tm_mon -= 12;
        out->tm_year++;
    }
    out->tm_mday = remdays + 1;
    out->tm_wday = wday;
    out->tm_yday = yday;

    out->tm_hour = remsecs / 3600;
    out->tm_min = remsecs / 60 % 60;
    out->tm_sec = remsecs % 60;

    return 0;
}

#define MIN_TWO_DIGIT_DECIMAL    10
#define TIMESTAMP_DISPLAY_LENGTH 20  // "YYYY-MM-DD HH:MM:SS" + '\0'

/**
 * Helper function for prepending numbers that are
 * less than 10 with a '0', so that 5 results in 05.
 */
static int prefixWithZero(uint8_t *dst, size_t dstLength, int value) {
    if (value < MIN_TWO_DIGIT_DECIMAL) {
        if (dstLength < 1) {
            THROW(ERROR_BUFFER_OVERFLOW);
        }
        memmove(dst, "0", 1);
        return 1;
    }
    return 0;
}

int timeToDisplayText(tm time, uint8_t *dst, size_t dstLength) {
    // Reject negative or zero tm_year: a negative value silently wraps to a huge
    // uint64_t when passed to number_to_text, producing an unbounded digit string.
    if (time.tm_year <= 0) {
        THROW(ERROR_INVALID_TRANSACTION);
    }

    if (dstLength < TIMESTAMP_DISPLAY_LENGTH) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }

    size_t offset = number_to_text(dst, dstLength, (uint64_t) (time.tm_year + 1900));

    if (offset >= dstLength) THROW(ERROR_BUFFER_OVERFLOW);
    memmove(dst + offset, "-", 1);
    offset += 1;

    offset += prefixWithZero(dst + offset, dstLength - offset, time.tm_mon + 1);
    offset += number_to_text(dst + offset, dstLength - offset, time.tm_mon + 1);

    if (offset >= dstLength) THROW(ERROR_BUFFER_OVERFLOW);
    memmove(dst + offset, "-", 1);
    offset += 1;

    offset += prefixWithZero(dst + offset, dstLength - offset, time.tm_mday);
    offset += number_to_text(dst + offset, dstLength - offset, time.tm_mday);

    if (offset >= dstLength) THROW(ERROR_BUFFER_OVERFLOW);
    memmove(dst + offset, " ", 1);
    offset += 1;

    offset += prefixWithZero(dst + offset, dstLength - offset, time.tm_hour);
    offset += number_to_text(dst + offset, dstLength - offset, time.tm_hour);

    if (offset >= dstLength) THROW(ERROR_BUFFER_OVERFLOW);
    memmove(dst + offset, ":", 1);
    offset += 1;

    offset += prefixWithZero(dst + offset, dstLength - offset, time.tm_min);
    offset += number_to_text(dst + offset, dstLength - offset, time.tm_min);

    if (offset >= dstLength) THROW(ERROR_BUFFER_OVERFLOW);
    memmove(dst + offset, ":", 1);
    offset += 1;

    offset += prefixWithZero(dst + offset, dstLength - offset, time.tm_sec);
    offset += bin_to_dec(dst + offset, dstLength - offset, time.tm_sec);

    return (int) offset;
}
