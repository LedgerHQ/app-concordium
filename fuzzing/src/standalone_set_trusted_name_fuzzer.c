/*
 * Fuzzer for SET_TRUSTED_NAME and the VERIFY_ADDRESS branch it unlocks (V-114, V-099).
 *
 * This target links the app's real src/handler/set_trusted_name.c and the SDK's real
 * lib_tlv/tlv_library.c, rather than the always-false _parse_tlv_internal() stub and the no-op
 * handle_set_trusted_name() the rest of the suite uses. That is what makes the following
 * reachable for the first time:
 *
 *   - the DER/TLV parser over the app's own tag schema, and each per-tag extraction callback
 *   - the duplicate-tag and required-tag rules, and every length check on a tag's value
 *   - the multi-hash processing that digests the descriptor under the algorithm it names
 *   - the challenge comparison against the value GET_CHALLENGE stored
 *   - the field validation that runs after PKI verification, and the error paths before it
 *   - handle_verify_address()'s trusted-descriptor branch: the key binding, the name copy,
 *     the mismatch handling and the single-use clearing, none of which any target could
 *     reach while nothing in the link was able to set g_trusted_name_valid
 *
 * Input: [control:1][pki_status:1][set_len:1][set descriptor bytes...][verify path bytes...]
 *   control bit 0  approve the verify-address review screen rather than reject it
 *   control bit 1  skip the SET step, so the VERIFY step runs with no binding in place -
 *                  the legacy BLS-derived-address path, and the state it must not inherit
 *   control bit 2  seed a stored challenge, so verify_challenge() can succeed
 *   pki_status     the verdict check_signature_with_pki() reports (see stubs/ledger_pki.h);
 *                  taken modulo the number of statuses so every branch stays reachable
 *
 * The PKI verdict is a fuzz-build control, not a weakening of the production invariant: the
 * descriptor still has to be PKI-signed on device. It exists so the code after verification
 * is reachable without holding a real certificate.
 */
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include "../stubs/ledger/exceptions.h"
#include "../stubs/ledger/parser.h"
#include "../stubs/ledger_pki.h"
#include "fuzz_state.h"
#include "fuzz_ui.h"
#include "handler/set_trusted_name.h"
#include "handler/verify_address.h"

/* Number of check_signature_with_pki_status_t values, so every verdict stays reachable. */
#define FUZZ_PKI_STATUS_COUNT 5

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) return 0;
    if (setjmp(g_fuzzer_jmp_buf) != 0) return 0;

    fuzz_reset_app_state();

    uint8_t control = data[0];
    g_fuzz_pki_status = (check_signature_with_pki_status_t) (data[1] % FUZZ_PKI_STATUS_COUNT);

    const uint8_t *body = data + 3;
    size_t body_len = size - 3;

    size_t set_len = data[2];
    if (set_len > body_len) {
        set_len = body_len;
    }

    /*
     * A descriptor is only accepted if its challenge matches the one GET_CHALLENGE issued.
     * Seeding it from the descriptor's own first bytes lets the fuzzer reach a match without
     * having to guess eight bytes, while leaving the mismatch path reachable too.
     */
    if ((control & 4) != 0) {
        g_stored_challenge = 0;
        for (size_t i = 0; i < 8 && i < set_len; i++) {
            g_stored_challenge = (g_stored_challenge << 8) | body[i];
        }
    }

    if ((control & 2) == 0) {
        command_t set_cmd = fuzz_make_command(INS_SET_TRUSTED_NAME, 0, 0, body, set_len);
        handle_set_trusted_name(&set_cmd);
    }

    /*
     * VERIFY_ADDRESS runs on whatever the SET step left behind - a valid binding, a partial
     * one from a rejected descriptor, or none at all. That transition is the integration the
     * suite had no coverage of.
     */
    const uint8_t *path = body + set_len;
    size_t path_len = body_len - set_len;

    command_t verify_cmd =
        fuzz_make_command(INS_VERIFY_ADDRESS, (uint8_t) (control >> 3), 0, path, path_len);
    handle_verify_address(&verify_cmd, &g_fuzz_flags);
    fuzz_answer_pending_ui((control & 1) != 0);

    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    return 0;
}
