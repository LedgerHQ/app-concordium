#pragma once

#include <stdint.h>
#include <stddef.h>

typedef struct {
    int tm_sec;  /* seconds,  range 0 to 59          */
    int tm_min;  /* minutes, range 0 to 59           */
    int tm_hour; /* hours, range 0 to 23             */
    int tm_mday; /* day of the month, range 1 to 31  */
    int tm_mon;  /* month, range 0 to 11             */
    int tm_year; /* The number of years since 1900   */
    int tm_wday; /* day of the week, range 0 to 6    */
    int tm_yday; /* day in the year, range 0 to 365  */
} tm;

/**
 * Converts seconds since epoch to a time struct.
 */
int secondsToTm(long long t, tm *out);

/**
 * Writes a time struct to dst as human readable text in
 * the format yyyy-mm-dd hh:mm:ss.
 */
int timeToDisplayText(tm time, uint8_t *dst, size_t dstLength);

/**
 * Append ".mmm" to a timestamp already written by timeToDisplayText.
 *
 * The scheduled-release timestamp is signed in milliseconds, so showing only whole seconds let
 * 1000 distinct signed values share one review. Always three digits, so 1 ms reads ".001"
 * rather than ".1" - the latter is indistinguishable from 100 ms.
 *
 * The append point is taken from the string in `dst`, not from a caller-supplied offset. This
 * used to accept one, and the natural value to pass - timeToDisplayText's return - counts the
 * NUL terminator, so ".mmm" landed one byte past the end of the string: within the buffer, so
 * nothing overflowed and nothing failed, but the milliseconds never reached the screen.
 *
 * @param dst NUL-terminated buffer holding the formatted timestamp
 * @param dstLength bytes available in `dst`; needs 5 free after the timestamp
 * @param milliseconds 0-999; anything larger is a malformed timestamp and is refused
 */
void appendMilliseconds(uint8_t *dst, size_t dstLength, uint16_t milliseconds);
