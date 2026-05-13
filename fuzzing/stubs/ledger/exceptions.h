#pragma once

#include <setjmp.h>
#include "status_words.h"

typedef unsigned short exception_t;

/* Global jump buffer used by the fuzzer entry point to catch THROWs. */
extern jmp_buf g_fuzzer_jmp_buf;

/* THROW: jump back to LLVMFuzzerTestOneInput, discarding the exception. */
#define THROW(x) longjmp(g_fuzzer_jmp_buf, (int)(x))

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
