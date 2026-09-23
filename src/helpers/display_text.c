#include "globals.h"

#include <os.h>

#include "display_text.h"

bool is_displayable_text(const uint8_t *text, size_t length) {
    for (size_t i = 0; i < length; i++) {
        // 0x00-0x1F and 0x7F. NUL is the one that actually hides signed bytes by ending the
        // string early; the rest are refused because no screen can render them honestly.
        if (text[i] < 0x20 || text[i] == 0x7F) {
            PRINTF("Non-displayable byte 0x%02X in host-supplied text\n", text[i]);
            return false;
        }
    }
    return true;
}
