#pragma once

#include <setjmp.h>
#include "status_words.h"

typedef unsigned short exception_t;

/* Global jump buffer used by the fuzzer entry point to catch THROWs. */
extern jmp_buf g_fuzzer_jmp_buf;

/*
 * Where the last THROW came from.
 *
 * On device a THROW is os_longjmp, and nothing between the handler and the SDK top-level catch
 * stops it - so an input-validation THROW reached from an APDU exits the app to the dashboard
 * (finding V-006). Recording the site here lets a harness report *which* THROW an input
 * reached, which is how the set of paths that actually need converting was established rather
 * than guessed at.
 */
extern const char *g_fuzz_throw_file;
extern int g_fuzz_throw_line;
extern unsigned int g_fuzz_throw_sw;

/* THROW: record the site, then jump back to LLVMFuzzerTestOneInput. */
#define THROW(x)                              \
    do {                                      \
        g_fuzz_throw_file = __FILE__;         \
        g_fuzz_throw_line = __LINE__;         \
        g_fuzz_throw_sw = (unsigned int) (x); \
        longjmp(g_fuzzer_jmp_buf, (int) (x)); \
    } while (0)

/*
 * SDK TRY/CATCH/FINALLY macros — simplified for fuzzer use.
 * THROW inside TRY will skip FINALLY (acceptable: stubs never throw there).
 * Both TRY and FINALLY blocks execute sequentially on the normal path.
 */
#define BEGIN_TRY       {
#define TRY             /* try: */
#define CATCH(x)        } if (0) {
#define CATCH_OTHER(e)  } if (0) { exception_t e = 0; (void)e;
#define CATCH_ALL       } if (0) {
#define FINALLY         } {
#define CLOSE_TRY       /* nothing */
#define END_TRY         }
