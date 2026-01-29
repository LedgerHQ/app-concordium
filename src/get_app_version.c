#include "get_app_version.h"
#include "globals.h"
#include <stdint.h>

int handler_get_version() {
    _Static_assert(APPVERSION_LEN == 3, "Length of (MAJOR || MINOR || PATCH) must be 3!");
    _Static_assert(MAJOR_VERSION >= 0 && MAJOR_VERSION <= UINT8_MAX,
                   "MAJOR version must be between 0 and 255!");
    _Static_assert(MINOR_VERSION >= 0 && MINOR_VERSION <= UINT8_MAX,
                   "MINOR version must be between 0 and 255!");
    _Static_assert(PATCH_VERSION >= 0 && PATCH_VERSION <= UINT8_MAX,
                   "PATCH version must be between 0 and 255!");

    return io_send_response_pointer(
        (const uint8_t *) &(uint8_t[APPVERSION_LEN]){(uint8_t) MAJOR_VERSION,
                                                     (uint8_t) MINOR_VERSION,
                                                     (uint8_t) PATCH_VERSION},
        APPVERSION_LEN,
        SWO_SUCCESS);
}
