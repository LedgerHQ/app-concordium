#pragma once

#include <stddef.h>
#include <string.h>
#include "exceptions.h"
#include "status_words.h"
#include "os_utils.h"
#include "os_print.h"

/* os_longjmp is what THROW delegates to in the real SDK. */
static inline void __attribute__((noreturn)) os_longjmp(unsigned int exception) {
    longjmp(g_fuzzer_jmp_buf, (int)exception);
}
