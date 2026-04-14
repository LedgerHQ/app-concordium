#include "fee_display.h"

#include <string.h>

#include <os.h>
#include <parser.h>

#include "numberHelpers.h"

void fee_display_apply_u64(uint8_t *dst_str,
                           size_t dst_str_len,
                           bool *has_fee_display,
                           const uint8_t fee_be[FEE_DISPLAY_U64_SIZE]) {
    uint64_t v = U8BE(fee_be, 0);
    *has_fee_display = false;
    explicit_bzero(dst_str, dst_str_len);
    if (v == FEE_DISPLAY_VALUE_OMIT) {
        return;
    }
    amount_to_gtu_display(dst_str, dst_str_len, v);
    *has_fee_display = true;
}
