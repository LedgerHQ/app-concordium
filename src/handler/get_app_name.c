#include <assert.h>  // _Static_assert

#include "get_app_name.h"
#include "globals.h"

#include <os.h>
#include <io.h>
#include <status_words.h>

/**
 * Length of APPNAME variable in the Makefile.
 */
#define APPNAME_LEN (sizeof(APPNAME) - 1)

/**
 * Maximum length of application name.
 */
#define MAX_APPNAME_LEN 64

int handle_get_app_name(void) {
    _Static_assert(APPNAME_LEN < MAX_APPNAME_LEN, "APPNAME must be at most 64 characters!");

    return io_send_response_pointer(PIC(APPNAME), APPNAME_LEN, SWO_SUCCESS);
}
