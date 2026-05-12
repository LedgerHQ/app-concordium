#include "globals.h"

#include "apdu/dispatcher.h"

#include <os.h>
#include <cx.h>
#include <io.h>
#include <parser.h>
#include <status_words.h>

#include "deploy_module.h"
#include "export_private_key_legacy_path.h"
#include "export_private_key_new_path.h"
#include "get_app_name.h"
#include "get_app_version.h"
#include "get_challenge.h"
#include "get_public_key.h"
#include "init_contract.h"
#include "set_trusted_name.h"
#include "sign_configure_baker.h"
#include "sign_configure_delegation.h"
#include "sign_credential_deployment.h"
#include "sign_public_information_for_ip.h"
#include "sign_register_data.h"
#include "sign_transfer.h"
#include "sign_transfer_to_public.h"
#include "sign_transfer_with_memo.h"
#include "sign_transfer_with_schedule.h"
#include "sign_transfer_with_schedule_and_memo.h"
#include "sign_plt.h"
#include "sign_update_credential.h"
#include "update_contract.h"
#include "verify_address.h"

/**
 * Central APDU dispatcher for the Concordium app (CLA is checked in app_main).
 *
 * This function is the single entry point for all supported APDU instructions. It:
 *   - Inspects `cmd->ins` and routes the request to the corresponding handler.
 *   - Performs basic validation that command data (`cmd->data`) is present whenever the
 *     instruction expects a non-empty cdata buffer.
 *   - Returns an appropriate status word via `io_send_sw(...)` in case of validation or
 *     consistency failures, before any handler is invoked.
 *   - Delegates any further argument parsing, semantic validation and user interaction to
 *     the instruction-specific handler functions included above.
 *
 * Multi-step signing flows (for example, large transactions that need to be streamed in
 * several APDU chunks) use the `isInitialCall` flag to distinguish the first chunk from
 * subsequent ones. Handlers that support such flows are responsible for maintaining any
 * required state across calls and for updating `flags` to request asynchronous UI steps.
 *
 * The dispatcher itself does not modify global state or `flags` directly; it only forwards
 * the pointer so that handlers can set UI / I/O flags as necessary for the BOLOS runtime.
 * If an unsupported or unknown instruction code is received, the relevant default branch
 * (not shown in this excerpt) is expected to signal `SWO_INVALID_INS`.
 *
 * @param cmd            Parsed APDU (`command_t`: ins, p1, p2, lc, data).
 * @param flags          BOLOS/UI flags for asynchronous signing and navigation.
 * @param isInitialCall  True on the first invocation of this instruction for the current
 *                       transaction (false for continuation chunks in a multi-step flow).
 *
 * @return 0 after a handler runs to completion and any response has been queued for
 *         transmission; validation failures return the value from `io_send_sw(...)`.
 */
int apdu_dispatcher(const command_t *cmd, volatile unsigned int *flags, bool isInitialCall) {
    /* Dispatch on the instruction byte. Each case performs minimal precondition checks
     * (in particular, that `cmd->data` is non-NULL when required) before delegating to
     * the specialized handler. Handlers are responsible for detailed parsing and for
     * populating the response buffer / status words.
     */
    /* Prevent instruction-switching attacks: once a multi-step flow is started the
     * host must not change the instruction byte mid-transaction. */
    if (global_tx_state.currentInstruction != INSTRUCTION_NONE &&
        global_tx_state.currentInstruction != (int) cmd->ins) {
        PRINTF("CMD GUARD TRIGGERED");
        global_tx_state.currentInstruction = INSTRUCTION_NONE;
        return io_send_sw(ERROR_INVALID_STATE);
    }

    switch (cmd->ins) {
        /* Key and address-related queries: return public information, do not modify state. */
        case INS_GET_PUBLIC_KEY:
            /* All instructions that consume APDU cdata must verify that `cmd->data` is set.
             * The length (`cmd->lc`) and content of the buffer is validated within the
             * called handler.
             */
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_get_public_key(cmd, flags);
            break;
        case INS_VERIFY_ADDRESS:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_verify_address(cmd, flags);
            break;

        /* Simple, single-step transfer signing. */
        case INS_SIGN_TRANSFER:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_sign_transfer(cmd, flags);
            break;

        /* Transfer signing variants that may span multiple APDU chunks.
         * For these, `isInitialCall` is true for the first APDU of the flow and false for
         * subsequent APDUs, allowing the handler to reset or resume internal parsing state.
         */
        case INS_SIGN_TRANSFER_WITH_MEMO:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_sign_transfer_with_memo(cmd, flags, isInitialCall);
            break;
        case INS_SIGN_TRANSFER_WITH_SCHEDULE:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_sign_transfer_with_schedule(cmd, flags, isInitialCall);
            break;
        case INS_SIGN_TRANSFER_WITH_SCHEDULE_AND_MEMO:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_sign_transfer_with_schedule_and_memo(cmd, flags, isInitialCall);
            break;
        case INS_CREDENTIAL_DEPLOYMENT:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_sign_credential_deployment(cmd, flags, isInitialCall);
            break;
        case INS_EXPORT_PRIVATE_KEY_LEGACY:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_export_private_key_legacy_path(cmd, flags);
            break;
        case INS_EXPORT_PRIVATE_KEY_NEW:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_export_private_key_new_path(cmd, flags);
            break;
        case INS_TRANSFER_TO_PUBLIC:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_sign_transfer_to_public(cmd, flags, isInitialCall);
            break;
        case INS_REGISTER_DATA:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_sign_register_data(cmd, flags, isInitialCall);
            break;
        case INS_PUBLIC_INFO_FOR_IP:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_sign_public_information_for_ip(cmd, flags, isInitialCall);
            break;
        case INS_CONFIGURE_BAKER:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_sign_configure_baker(cmd, flags, isInitialCall);
            break;
        case INS_CONFIGURE_DELEGATION:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_sign_configure_delegation(cmd, isInitialCall, flags);
            break;
        case INS_SIGN_UPDATE_CREDENTIAL:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_sign_update_credential(cmd, flags, isInitialCall);
            break;
        case INS_GET_APP_NAME:
            if (cmd->data != NULL) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            if (cmd->p1 != P1_DEFAULT || cmd->p2 != P2_DEFAULT) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }
            handle_get_app_name();
            global_tx_state.currentInstruction = INSTRUCTION_NONE;
            break;
        case INS_SET_TRUSTED_NAME:
            handle_set_trusted_name(cmd);
            break;
        case INS_GET_CHALLENGE:
            if (cmd->data != NULL) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            if (cmd->p1 != P1_DEFAULT || cmd->p2 != P2_DEFAULT) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }
            handle_get_challenge();
            break;
        case INS_DEPLOY_MODULE:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_deploy_module(cmd, isInitialCall);
            break;
        case INS_INIT_CONTRACT:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_init_contract(cmd, isInitialCall);
            break;
        case INS_UPDATE_CONTRACT:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_update_contract(cmd, isInitialCall);
            break;
        /* PLT (Protocol Level Token) blind-signing flow: INIT then one or more CONT chunks. */
        case INS_SIGN_PLT:
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            handle_sign_plt(cmd, flags, isInitialCall);
            break;
        case INS_APP_VERSION:
            if (cmd->data != NULL) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            if (cmd->p1 != P1_DEFAULT || cmd->p2 != P2_DEFAULT) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }

            handle_get_app_version();
            global_tx_state.currentInstruction = INSTRUCTION_NONE;
            break;
        default:
            THROW(SWO_INVALID_INS);
            break;
    }
    return 0;
}
