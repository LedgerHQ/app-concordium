/*
 * Fuzzer for the real APDU boundary: apdu_parser() -> apdu_dispatcher() (finding V-096).
 *
 * Every other target hands a hand-built command_t straight to one handler, so the frame
 * boundary and the routing in between were never exercised. This one replays a sequence of
 * raw frames through the SDK's real parser and the app's real dispatcher, exactly as
 * app_main() does, which is what reaches:
 *
 *   - frames shorter than a header, and an Lc that disagrees with the physical length
 *     (apdu_parser rejects both; nothing else in the suite ever produced one)
 *   - the lc == 0 / data == NULL representation, and the per-instruction `!cmd->data` checks
 *   - a wrong CLA, an unknown INS, and the P1/P2 checks on the parameterless instructions
 *   - the instruction-switching guard: once a multi-packet flow is open, a host that changes
 *     the INS byte must be refused and the flow cleared
 *   - the isInitialCall bookkeeping across a sequence, rather than as an input bit
 *
 * Input: a stream of [len:1][raw apdu bytes...] frames.
 *   A frame whose declared length runs past the end of the input is truncated to what is
 *   left, so the parser sees genuinely short frames rather than only well-formed ones.
 *
 * The final byte of each frame's cdata is not special-cased: a frame is passed on verbatim,
 * including a declared length of zero, which is itself a parser input worth covering.
 */
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include "../stubs/ledger/exceptions.h"
#include "../stubs/ledger/parser.h"
#include "fuzz_state.h"
#include "fuzz_ui.h"
#include "apdu/dispatcher.h"

/* A BOLOS APDU is at most 5 header bytes plus 255 of cdata. */
#define FUZZ_MAX_FRAME 260

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    if (setjmp(g_fuzzer_jmp_buf) != 0) return 0;

    fuzz_reset_app_state();

    /*
     * Bit 0 of the leading control byte answers every review screen the sequence parks, so one
     * input covers both the approve and the reject continuation of whatever it reaches
     * (finding V-102). The rest of the byte is unused, and left to the mutator.
     */
    bool approve = (data[0] & 1) != 0;
    size_t offset = 1;

    while (offset < size) {
        size_t declared = data[offset++];
        size_t available = size - offset;
        size_t frame_len = (declared < available) ? declared : available;
        if (frame_len > FUZZ_MAX_FRAME) {
            frame_len = FUZZ_MAX_FRAME;
        }

        /*
         * apdu_parser() takes a mutable buffer and points cmd.data into it, so the frame is
         * copied out of the (const) fuzzer input rather than cast.
         */
        uint8_t frame[FUZZ_MAX_FRAME];
        for (size_t i = 0; i < frame_len; i++) {
            frame[i] = data[offset + i];
        }
        offset += frame_len;

        command_t cmd;
        if (!apdu_parser(&cmd, frame, frame_len)) {
            continue;
        }

        /* app_main() drops any frame whose CLA is not the app's before dispatching. */
        if (cmd.cla != FUZZ_CLA) {
            continue;
        }

        /*
         * The state app_main() maintains: the first frame of an instruction clears the
         * context union, and only then is currentInstruction claimed. Continuation frames
         * keep both, which is exactly what the dispatcher's switching guard reads.
         */
        bool isInitialCall = (global_tx_state.currentInstruction == INSTRUCTION_NONE);
        if (isInitialCall) {
            fuzz_reset_instruction_context(cmd.ins);
        }

        apdu_dispatcher(&cmd, &g_fuzz_flags, isInitialCall);

        /* Answer whatever the handler parked, the way the device's UI would. */
        fuzz_answer_pending_ui(approve);
    }

    return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    return 0;
}
