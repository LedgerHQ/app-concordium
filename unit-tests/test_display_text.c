/*
 * is_displayable_text() - findings V-004 and V-025.
 *
 * Host-supplied text is hashed into the signed transaction in full but drawn as a C string, so
 * an embedded NUL ends the display while the signature still covers everything after it: the
 * user approves bytes that were never shown. The other C0 controls and DEL have no faithful
 * rendering either.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <setjmp.h>
#include <cmocka.h>

#include "helpers/display_text.h"

static void test_plain_ascii_is_displayable(void **state) {
    (void) state;
    const uint8_t text[] = "Payment for invoice 42";
    assert_true(is_displayable_text(text, strlen((const char *) text)));
}

static void test_embedded_nul_is_refused(void **state) {
    (void) state;
    /* The case from the finding: everything after the NUL is signed but never drawn. */
    const uint8_t text[] = {'p', 'a', 'i', 'd', 0x00, 'n', 'o', 't'};
    assert_false(is_displayable_text(text, sizeof(text)));
}

static void test_trailing_nul_is_refused(void **state) {
    (void) state;
    /* A NUL at the very end is still a byte that was signed and not shown. */
    const uint8_t text[] = {'h', 'i', 0x00};
    assert_false(is_displayable_text(text, sizeof(text)));
}

static void test_every_c0_control_is_refused(void **state) {
    (void) state;
    for (unsigned int byte = 0x00; byte < 0x20; byte++) {
        uint8_t text[3] = {'a', (uint8_t) byte, 'b'};
        assert_false(is_displayable_text(text, sizeof(text)));
    }
}

static void test_del_is_refused(void **state) {
    (void) state;
    const uint8_t text[] = {'a', 0x7F, 'b'};
    assert_false(is_displayable_text(text, sizeof(text)));
}

static void test_printable_boundaries_are_accepted(void **state) {
    (void) state;
    /* 0x20 (space) and 0x7E (~) are the ends of the printable range. */
    const uint8_t low[] = {0x20};
    const uint8_t high[] = {0x7E};
    assert_true(is_displayable_text(low, sizeof(low)));
    assert_true(is_displayable_text(high, sizeof(high)));
}

static void test_high_bytes_are_accepted(void **state) {
    (void) state;
    /* UTF-8 continuation bytes are >= 0x80 and are not rejected: the check is about bytes with
     * no faithful rendering, not about validating UTF-8. Documents the actual contract. */
    const uint8_t utf8[] = {0xC3, 0xA9};  /* e-acute */
    assert_true(is_displayable_text(utf8, sizeof(utf8)));
}

static void test_zero_length_is_displayable(void **state) {
    (void) state;
    /* An empty memo has nothing hidden in it, so it must not be refused. */
    const uint8_t text[] = {'x'};
    assert_true(is_displayable_text(text, 0));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_plain_ascii_is_displayable),
        cmocka_unit_test(test_embedded_nul_is_refused),
        cmocka_unit_test(test_trailing_nul_is_refused),
        cmocka_unit_test(test_every_c0_control_is_refused),
        cmocka_unit_test(test_del_is_refused),
        cmocka_unit_test(test_printable_boundaries_are_accepted),
        cmocka_unit_test(test_high_bytes_are_accepted),
        cmocka_unit_test(test_zero_length_is_displayable),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
