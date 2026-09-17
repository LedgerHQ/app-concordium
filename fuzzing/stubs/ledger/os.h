#pragma once

#include <stddef.h>
#include <string.h>
#include "exceptions.h"
#include "status_words.h"
#include "os_utils.h"
#include "os_print.h"

/*
 * PIC() resolves a link-time address against the running code's load address on device. A
 * hosted fuzz binary is linked at its final address, so it is the identity here.
 */
#ifndef PIC
#define PIC(x) (x)
#endif

/* os_longjmp is what THROW delegates to in the real SDK. */
static inline void __attribute__((noreturn)) os_longjmp(unsigned int exception) {
    longjmp(g_fuzzer_jmp_buf, (int)exception);
}
