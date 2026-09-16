#pragma once

/*
 * What the host stubs recorded about the last call they served.
 *
 * The stubbed key material is constant: get_public_key() and sign() zero their output whatever
 * path they are handed (stubs.c), deliberately, since an input-derived stub would make coverage
 * order-dependent (see fuzzing/src/fuzz_state.h). So a test cannot tell from the result which
 * key was derived, and "the approval derived from the path the review pinned, not from whatever
 * is in global_derivation_path by then" is not a property the output can express. These record
 * the argument instead, which is the thing actually under test.
 *
 * Nothing in src/ reads them and they are not app state - they are the host stub layer's
 * account of itself, for unit-tests/. stub_probes_reset() clears them between cases.
 */

#include <stdbool.h>
#include <stdint.h>

#include "derivation_path.h"

/** Path handed to the get_public_key() stub, and whether it was called at all. */
extern derivation_path_t g_stub_public_key_path;
extern bool g_stub_public_key_called;

/** Path handed to the sign() stub, and whether it was called at all. */
extern derivation_path_t g_stub_sign_path;
extern bool g_stub_sign_called;

/** Last status word io_send_sw() was handed, and whether it was called at all. */
extern uint16_t g_stub_last_sw;
extern bool g_stub_send_sw_called;

void stub_probes_reset(void);
