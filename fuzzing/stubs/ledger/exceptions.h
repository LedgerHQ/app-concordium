#pragma once

#include <setjmp.h>
#include "status_words.h"

typedef unsigned short exception_t;

/* Global jump buffer, the catch of last resort: where a THROW with no enclosing TRY lands. */
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

/*
 * TRY/CATCH/FINALLY, with the SDK's semantics rather than an approximation of them.
 *
 * These used to expand CATCH_OTHER to `if (0)` and FINALLY to a plain block: nothing was ever
 * caught on the host, and a THROW inside TRY jumped straight past FINALLY to the harness. Two
 * things followed from that, both wrong in the same direction - the host was more forgiving than
 * the device:
 *
 *   - the two guards that convert a thrown status word into a reply, dispatch_guarded()
 *     (app_main.c) and ux_run_guarded() (helpers/ux_guard.c), could not be exercised at all, so
 *     the V-006 property "a malformed APDU is answered, not fatal" was untestable off-device;
 *   - a FINALLY never ran on the throwing path, and FINALLY is where this app wipes key material
 *     (exportNewPathPrivateKeysForPurpose(), get_public_key(), sign()). A fuzzer could not have
 *     noticed a secret surviving a throw, because the wipe was skipped in the harness too.
 *
 * So the structure below mirrors $BOLOS_SDK/include/exceptions.h: a try_context_t per BEGIN_TRY,
 * chained through `previous`, with THROW landing in the innermost one. `ex` is cleared by a
 * CATCH clause, and END_TRY rethrows it when no clause consumed it - the rethrow that
 * export_private_key_new_path.c's comment is about. A throw with no enclosing TRY goes to
 * g_fuzzer_jmp_buf, which is the device's "unwinds past the app" case and what each harness
 * setjmps for.
 *
 * Two constraints come with that, both of which the SDK does not have to care about:
 *
 *   - the FINALLY label is a single fixed name, so one function can hold one TRY block. The SDK
 *     parameterises it (BEGIN_TRY_L(L) and friends) for exactly this reason; no function in this
 *     app has two, and a second one fails to compile rather than misbehaving.
 *   - a throw that reaches g_fuzzer_jmp_buf leaves g_try_context pointing into stack frames that
 *     are gone, so whoever owns that jump buffer has to clear it before running anything else -
 *     fuzz_reset_app_state() per input, the throw_harness.h macros per statement. On device the
 *     equivalent case ends the application, so the question never arises.
 */
typedef struct try_context_s try_context_t;

struct try_context_s {
    jmp_buf jmp_buf;
    try_context_t *previous;
    exception_t ex;
};

/* Innermost open TRY, or NULL. Defined in stubs.c. */
extern try_context_t *g_try_context;

static inline try_context_t *try_context_get(void) {
    return g_try_context;
}

static inline try_context_t *try_context_set(try_context_t *context) {
    try_context_t *previous = g_try_context;
    g_try_context = context;
    return previous;
}

/* THROW: record the site, then longjmp to the innermost TRY, or to the harness if there is none. */
#define THROW(x)                                               \
    do {                                                       \
        g_fuzz_throw_file = __FILE__;                          \
        g_fuzz_throw_line = __LINE__;                          \
        g_fuzz_throw_sw = (unsigned int) (x);                  \
        try_context_t *_ctx = try_context_get();               \
        if (_ctx != NULL) {                                    \
            longjmp(_ctx->jmp_buf, (int) (x));                 \
        }                                                      \
        longjmp(g_fuzzer_jmp_buf, (int) (x));                  \
    } while (0)

#define BEGIN_TRY \
    {             \
        try_context_t __try;

#define TRY                                     \
    __try.ex = (exception_t) setjmp(__try.jmp_buf); \
    if (__try.ex == 0) {                        \
        __try.previous = try_context_set(&__try);

#define CATCH(x)               \
    goto __FINALLY;            \
    }                          \
    else if (__try.ex == (x)) { \
        __try.ex = 0;          \
        CLOSE_TRY;

#define CATCH_OTHER(e)     \
    goto __FINALLY;        \
    }                      \
    else {                 \
        exception_t e;     \
        e = __try.ex;      \
        __try.ex = 0;      \
        CLOSE_TRY;

#define CATCH_ALL     \
    goto __FINALLY;   \
    }                 \
    else {            \
        __try.ex = 0; \
        CLOSE_TRY;

/* FINALLY runs on every path; it restores the context only if the TRY clause left it open. */
#define FINALLY                              \
    goto __FINALLY;                          \
    }                                        \
    __FINALLY : if (try_context_get() == &__try) { \
        CLOSE_TRY;                           \
    }

#define CLOSE_TRY try_context_set(__try.previous)

#define END_TRY                  \
    if (__try.ex != 0) {         \
        THROW(__try.ex);         \
    }                            \
    }                            \
    _Static_assert(true, "")
