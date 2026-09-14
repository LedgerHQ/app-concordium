#pragma once

/*
 * Pending-approval ledger for the fuzz harnesses.
 *
 * Every handler in this app stops at a UI entry point and hands the security-sensitive half of
 * the operation to the approve/reject callback that entry point registers: the transaction hash
 * is finalised and signed in `buildAndSignTransactionHash()`, private keys are released in
 * `exportPrivateKey()` / `sendPrivateKeysNewPath()`, the next scheduled pair is parsed in
 * `processNextScheduledAmount()`, and a staged rejection has to clear the flow so a later packet
 * cannot resume it.
 *
 * The fuzz build replaces `src/ui/display_{bagl,nbgl}.c` wholesale, so those entry points used
 * to be empty functions and no harness ever recorded, let alone answered, a pending approval
 * (finding V-102). Everything past the review screen was therefore unreachable: hash
 * finalisation, signing and response bounds, the rule that approval must precede signing,
 * rejection handling, secret wiping, and every scheduled pair after the first.
 *
 * So each UI stub now records which continuation production would run, choosing between them
 * with the same condition on the same globals that display_nbgl.c uses, and
 * `fuzz_answer_pending_ui()` runs it - approve or reject - exactly as the real callback does.
 * The continuations are declared weak because each lives in a handler translation unit that
 * only some targets link; a target that does not link one simply cannot have parked it.
 */

#include <stdbool.h>

typedef enum {
    FUZZ_UI_NONE = 0,
    /* review_choice_sign: the final signing screen of an account transaction. */
    FUZZ_UI_SIGN_TRANSACTION,
    /* confirm_initial_scheduled_transfer_callback */
    FUZZ_UI_INITIAL_SCHEDULED_TRANSFER,
    /* processNextScheduledAmountWrapper: one more release-time/amount pair. */
    FUZZ_UI_NEXT_SCHEDULED_PAIR,
    /* sendSuccessNoIdleCallback: an intermediate screen that only asks for the next packet. */
    FUZZ_UI_SUCCESS_NO_IDLE,
    /* confirmConfigureBakerStageCallback: release a parked configure-baker stage. */
    FUZZ_UI_CONFIGURE_BAKER_STAGE,
    /* processNextVerificationKeyNoIdleCallback */
    FUZZ_UI_NEXT_VERIFICATION_KEY,
    /* review_added_credential */
    FUZZ_UI_ADDED_CREDENTIAL,
    /* review_credential_attribute */
    FUZZ_UI_CREDENTIAL_ATTRIBUTE,
    /* review_export_private_key: legacy export sink. */
    FUZZ_UI_EXPORT_PRIVATE_KEY,
    /* review_export_private_key_new_path */
    FUZZ_UI_EXPORT_PRIVATE_KEYS_NEW_PATH,
    /* review_public_key_choice / review_choice / review_verify_address: reply only. */
    FUZZ_UI_CONFIRM_ONLY,
} fuzz_ui_action_t;

/** Set by the UI stubs; read and cleared by fuzz_answer_pending_ui(). */
extern fuzz_ui_action_t g_fuzz_pending_ui_action;

/**
 * Answer whatever review screen the handler just parked, the way the user would.
 *
 * A no-op when no screen is pending, which is itself worth exercising: a handler that returns
 * without parking anything must not have signed or released a key. Clears the pending action
 * first, so a continuation that parks a further screen (the scheduled-pair loop does) is
 * recorded rather than lost, and one answer can never run two continuations.
 */
void fuzz_answer_pending_ui(bool approve);
