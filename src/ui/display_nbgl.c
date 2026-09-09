#ifdef HAVE_NBGL
#include "display.h"
#include "globals.h"

#include <io.h>
#include <os.h>
#include <status_words.h>
#include <nbgl_use_case.h>

#include "apdu/apdu_response.h"
#include "get_public_key.h"
#include "cbor_data_blob.h"
#include "sign_configure_baker.h"
#include "sign_credential_deployment.h"
#include "sign_transfer_schedule.h"
#include "tx_hash.h"

#include "menu_nbgl.h"

#define MAX_REVIEW_PAIRS 10

accountSender_t global_account_sender;
comparePublicKey_t global_compare_public_key;
static nbgl_contentTagValue_t pairs[MAX_REVIEW_PAIRS];
static signTransferWithScheduleContext_t *ctx_sign_transfer_with_schedule =
    &global.withDataBlob.signTransferWithScheduleContext;

/**
 * Writes the account header pairs that open every account-transaction review: the paying sender,
 * the signed energy ceiling and the network the signing path selects. Any "Max fees" line is a
 * host estimate outside the transaction hash, so the energy figure is the only cost bound the
 * signature commits to. The network comes from the host-supplied path and cannot be inferred from
 * the addresses on screen, which are encoded identically on mainnet and testnet.
 * @param pairIndex next free slot in `pairs`
 * @param senderItem tag name for the sender row, which differs per flow ("Sender", "From")
 * @return next free slot in `pairs`
 */
static uint8_t addAccountHeaderPairs(uint8_t pairIndex, const char *senderItem) {
    pairs[pairIndex].item = senderItem;
    pairs[pairIndex].value = (char *) global_account_sender.sender;
    pairIndex++;
    pairs[pairIndex].item = "Max energy";
    pairs[pairIndex].value = (char *) global_account_sender.energyDisplay;
    pairIndex++;
    pairs[pairIndex].item = "Network";
    pairs[pairIndex].value = (char *) global_account_sender.network;
    pairIndex++;
    return pairIndex;
}

static void review_choice(bool confirm) {
    // Answer, display a status page and go back to main
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
    }
}

static void review_public_key_choice(bool confirm) {
    // Answer, display a status page and go back to main
    if (confirm) {
        send_public_key(true);
    } else {
        send_user_rejection();
    }
}

static void review_verify_address(bool confirm) {
    if (confirm) {
        send_success_result_no_idle(0);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
    } else {
        send_user_rejection_no_idle();
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
    }
}

static void review_export_private_key(bool confirm) {
    // Answer, display a status page and go back to main
    if (confirm) {
        exportPrivateKey();
    } else {
        send_user_rejection();
    }
}

static void review_export_private_key_new_path(bool confirm) {
    // Answer, display a status page and go back to main
    if (confirm) {
        sendPrivateKeysNewPath();
    } else {
        rejectPrivateKeysNewPath();
    }
}

static void review_choice_sign(bool confirm) {
    // Answer, display a status page and go back to main
    if (confirm) {
        buildAndSignTransactionHash();
    } else {
        send_user_rejection();
    }
}

static void confirm_initial_scheduled_transfer_callback(bool confirm) {
    if (confirm) {
        confirmInitialScheduledTransfer();
    } else {
        send_user_rejection();
    }
}
/**
 * End the whole operation because the user rejected one of its staged screens.
 *
 * nbgl_useCaseReviewLight reports a rejection as `confirm == false`. Answering it with success
 * would leave the transaction active and simply ask the host for the next packet, so a "reject"
 * on an intermediate screen would be silently downgraded to "continue" and the user could still
 * be walked to the final signing screen. Clear the flow so no later packet can resume it.
 */
static void rejectStagedReview(void) {
    global_tx_state.currentInstruction = INSTRUCTION_NONE;
    send_user_rejection();
}

static void sendSuccessNoIdleCallback(bool confirm) {
    if (!confirm) {
        rejectStagedReview();
        return;
    }
    send_success_no_idle();
}

// Baker reviews must release the stage parked while the screen was up, rather than just
// replying; see confirmConfigureBakerStage.
static void confirmConfigureBakerStageCallback(bool confirm) {
    if (!confirm) {
        rejectStagedReview();
        return;
    }
    confirmConfigureBakerStage();
}

static void processNextVerificationKeyNoIdleCallback(bool confirm) {
    if (!confirm) {
        rejectStagedReview();
        return;
    }
    processNextVerificationKey();
}

static void review_added_credential(bool confirm) {
    if (confirm) {
        confirmAddedCredential();
    } else {
        send_user_rejection();
    }
}

static void review_credential_attribute(bool confirm) {
    if (confirm) {
        confirmAttribute();
    } else {
        send_user_rejection();
    }
}

void uiComparePubkey(void) {
    // Drawn from the snapshot, not the instruction union: this screen outlives its instruction.
    pairs[0].item = "Identity";
    pairs[0].value = (char *) global_compare_public_key.display;
    pairs[1].item = "Public key";
    pairs[1].value = global_compare_public_key.publicKey;

    static nbgl_contentTagValueList_t content;
    content.nbPairs = 2;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    content.wrapping = false;

    nbgl_useCaseReview(TYPE_OPERATION,
                       &content,
                       &ICON_APP_HOME,
                       "Public Key",
                       NULL,
                       "Export public key",
                       review_choice);
}

void uiGeneratePubkey(volatile unsigned int *flags) {
    pairs[0].item = "Identity";
    pairs[0].value = (char *) global.exportPublicKeyContext.display;

    static nbgl_contentTagValueList_t content;
    content.nbPairs = 1;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    content.wrapping = false;

    nbgl_useCaseReview(TYPE_OPERATION,
                       &content,
                       &ICON_APP_HOME,
                       "Public Key",
                       NULL,
                       "Export public key",
                       review_public_key_choice);
    *flags |= IO_ASYNCH_REPLY;
}

/**
 * Compose the export review title as "<operation> <verb>" and the finish title as
 * "<action>\n<verb>", in place.
 *
 * The offsets are derived from the strings themselves: keying them to fixed length macros
 * silently corrupted the text whenever the wording changed length.
 */
static void compose_export_private_key_titles(void) {
    exportPrivateKeyContext_t *exportCtx = &global.exportPrivateKeyContext;

    size_t operationLength = strlen((char *) exportCtx->display_review_operation);
    size_t reviewVerbLength = strlen((char *) exportCtx->display_review_verb);
    if (operationLength + 1 + reviewVerbLength + 1 > sizeof(exportCtx->display_review_operation)) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    exportCtx->display_review_operation[operationLength] = ' ';
    memmove(exportCtx->display_review_operation + operationLength + 1,
            exportCtx->display_review_verb,
            reviewVerbLength + 1);

    size_t actionLength = strlen((char *) exportCtx->display_sign);
    size_t signVerbLength = strlen((char *) exportCtx->display_sign_verb);
    if (actionLength + 1 + signVerbLength + 1 > sizeof(exportCtx->display_sign)) {
        THROW(ERROR_BUFFER_OVERFLOW);
    }
    exportCtx->display_sign[actionLength] = '\n';
    memmove(exportCtx->display_sign + actionLength + 1,
            exportCtx->display_sign_verb,
            signVerbLength + 1);
}

void uiExportPrivateKey(volatile unsigned int *flags) {
    // Create tag-value pairs for the content
    uint8_t pairIndex = 0;

    compose_export_private_key_titles();

    pairs[pairIndex].item = (char *) global.exportPrivateKeyContext.display_credid_title;
    pairs[pairIndex].value = (char *) global.exportPrivateKeyContext.display_credid;
    pairIndex++;

    // The P2-selected detail and the key types released: without these the user cannot tell
    // which network or which reusable secrets they are approving.
    pairs[pairIndex].item = (char *) global.exportPrivateKeyContext.display_detail_title;
    pairs[pairIndex].value = (char *) global.exportPrivateKeyContext.display_detail;
    pairIndex++;
    pairs[pairIndex].item = "Keys released";
    pairs[pairIndex].value = (char *) global.exportPrivateKeyContext.display_key_types;
    pairIndex++;
    pairs[pairIndex].item = "Warning";
    pairs[pairIndex].value = "These secrets leave this Ledger and can be reused";
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    content.wrapping = true;

    nbgl_useCaseReview(TYPE_OPERATION,
                       &content,
                       &ICON_APP_HOME,
                       (char *) global.exportPrivateKeyContext.display_review_operation,
                       NULL,
                       (char *) global.exportPrivateKeyContext.display_sign,
                       review_export_private_key);
    *flags |= IO_ASYNCH_REPLY;
}

void uiExportPrivateKeysNewPath(volatile unsigned int *flags) {
    // Create tag-value pairs for the content
    uint8_t pairIndex = 0;

    compose_export_private_key_titles();

    pairs[pairIndex].item = (char *) global.exportPrivateKeyContext.display_credid_title;
    pairs[pairIndex].value = (char *) global.exportPrivateKeyContext.display_credid;
    pairIndex++;

    // The P2-selected detail and the key types released: without these the user cannot tell
    // which network or which reusable secrets they are approving.
    pairs[pairIndex].item = (char *) global.exportPrivateKeyContext.display_detail_title;
    pairs[pairIndex].value = (char *) global.exportPrivateKeyContext.display_detail;
    pairIndex++;
    pairs[pairIndex].item = "Keys released";
    pairs[pairIndex].value = (char *) global.exportPrivateKeyContext.display_key_types;
    pairIndex++;
    pairs[pairIndex].item = "Warning";
    pairs[pairIndex].value = "These secrets leave this Ledger and can be reused";
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    content.wrapping = true;

    nbgl_useCaseReview(TYPE_OPERATION,
                       &content,
                       &ICON_APP_HOME,
                       (char *) global.exportPrivateKeyContext.display_review_operation,
                       NULL,
                       (char *) global.exportPrivateKeyContext.display_sign,
                       review_export_private_key_new_path);
    *flags |= IO_ASYNCH_REPLY;
}

void startConfigureBakerCommissionDisplay(void) {
    // Get context from global state
    signConfigureBaker_t *ctx = &global.signConfigureBaker;
    // Create tag-value pairs for the content
    uint8_t pairIndex = 0;

    if (ctx->firstDisplay) {
        // Add sender address
        pairIndex = addAccountHeaderPairs(pairIndex, "Sender");
        ctx->firstDisplay = false;
    }

    if (ctx->hasTransactionFeeCommission || ctx->hasBakingRewardCommission ||
        ctx->hasFinalizationRewardCommission) {
        pairs[pairIndex].item = "Commission";
        pairs[pairIndex].value = "rates";
        pairIndex++;
    }

    if (ctx->hasTransactionFeeCommission) {
        pairs[pairIndex].item = "Transaction fee";
        pairs[pairIndex].value =
            (char *) global.signConfigureBaker.commissionRates.transactionFeeCommissionRate;
        pairIndex++;
    }

    if (ctx->hasBakingRewardCommission) {
        pairs[pairIndex].item = "Baking reward";
        pairs[pairIndex].value =
            (char *) global.signConfigureBaker.commissionRates.bakingRewardCommissionRate;
        pairIndex++;
    }

    if (ctx->hasFinalizationRewardCommission) {
        pairs[pairIndex].item = "Finalization reward";
        pairs[pairIndex].value =
            (char *) global.signConfigureBaker.commissionRates.finalizationRewardCommissionRate;
        pairIndex++;
    }

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;

    // to signing screens.
    if (ctx->hasSuspended) {
        // Setup the review screen
        nbgl_useCaseReviewLight(TYPE_OPERATION,
                                &content,
                                &ICON_APP_HOME,
                                "Review Transaction",
                                NULL,  // No subtitle
                                "Continue with transaction",
                                confirmConfigureBakerStageCallback);
    } else {
        // Setup the review screen
        nbgl_useCaseReview(TYPE_TRANSACTION,
                           &content,
                           &ICON_APP_HOME,
                           "Review Transaction",
                           NULL,  // No subtitle
                           "Sign transaction",
                           review_choice_sign);
    }
}

void startConfigureBakerSuspendedDisplay(void) {
    // Get context from global state
    signConfigureBaker_t *ctx = &global.signConfigureBaker;
    // Create tag-value pairs for the content
    uint8_t pairIndex = 0;

    if (ctx->firstDisplay) {
        // Add sender address
        pairIndex = addAccountHeaderPairs(pairIndex, "Sender");
        ctx->firstDisplay = false;
    }

    pairs[pairIndex].item = "Validator status";
    pairs[pairIndex].value = (char *) global.signConfigureBaker.suspended;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;

    // to signing screens.
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review Transaction",
                       NULL,  // No subtitle
                       "Sign transaction",
                       review_choice_sign);
}

void startConfigureBakerDisplay(void) {
    // Get context from global state
    signConfigureBaker_t *ctx = &global.signConfigureBaker;

    // Create tag-value pairs for the content
    uint8_t pairIndex = 0;
    // Add sender address
    pairIndex = addAccountHeaderPairs(pairIndex, "Sender");

    ctx->firstDisplay = false;

    if (ctx->hasCapital) {
        if (ctx->capitalRestakeDelegation.stopBaking) {
            pairs[pairIndex].item = "Stop";
            pairs[pairIndex].value = "Baking";
        } else {
            pairs[pairIndex].item = "Amount to stake";
            pairs[pairIndex].value =
                (char *) global.signConfigureBaker.capitalRestakeDelegation.displayCapital;
        }
        pairIndex++;
    }

    if (ctx->hasRestakeEarnings) {
        pairs[pairIndex].item = "Restake earnings";
        pairs[pairIndex].value =
            (char *) global.signConfigureBaker.capitalRestakeDelegation.displayRestake;
        pairIndex++;
    }

    if (ctx->hasOpenForDelegation) {
        pairs[pairIndex].item = "Pool status";
        pairs[pairIndex].value =
            (char *) global.signConfigureBaker.capitalRestakeDelegation.displayOpenForDelegation;
        pairIndex++;
    }

    if (ctx->hasKeys) {
        pairs[pairIndex].item = "Update baker";
        pairs[pairIndex].value = "keys";
        pairIndex++;
        // Digest of the three validator verification keys being installed. The keys themselves
        // are signed but far too long to compare on screen, so without this the rotation is
        // blind.
        pairs[pairIndex].item = "Baker keys hash";
        pairs[pairIndex].value = (char *) global.signConfigureBaker.keysHashDisplay;
        pairIndex++;
    }

    // If there are additional steps, then show continue screen. If this is the
    // last step, then show signing screens.
    if (ctx->hasMetadataUrl || hasCommissionRate() || ctx->hasSuspended) {
        // Create the page content
        nbgl_contentTagValueList_t content;
        content.nbPairs = pairIndex;
        content.pairs = pairs;
        content.smallCaseForValue = false;
        content.nbMaxLinesForValue = 0;
        content.startIndex = 0;
        // Setup the review screen
        nbgl_useCaseReviewLight(TYPE_OPERATION,
                                &content,
                                &ICON_APP_HOME,
                                "Review Transaction",
                                NULL,  // No subtitle
                                "Continue with transaction",
                                confirmConfigureBakerStageCallback);
    } else {
        // Create the page content
        nbgl_contentTagValueList_t content;
        content.nbPairs = pairIndex;
        content.pairs = pairs;
        content.smallCaseForValue = false;
        content.nbMaxLinesForValue = 0;
        content.startIndex = 0;

        // Setup the review screen
        nbgl_useCaseReview(TYPE_TRANSACTION,
                           &content,
                           &ICON_APP_HOME,
                           "Review Transaction",
                           NULL,  // No subtitle
                           "Sign transaction",
                           review_choice_sign);
    }
}

void startConfigureBakerUrlDisplay(bool lastUrlPage) {
    // Get context from global state
    signConfigureBaker_t *ctx = &global.signConfigureBaker;

    // Create tag-value pairs for the content
    uint8_t pairIndex = 0;

    if (ctx->firstDisplay) {
        // Add sender address
        pairIndex = addAccountHeaderPairs(pairIndex, "Sender");
        ctx->firstDisplay = false;
    }

    if (!lastUrlPage) {
        pairs[pairIndex].item = "URL";
        pairs[pairIndex].value = (char *) global.signConfigureBaker.url.urlDisplay;
        pairIndex++;
    } else {
        if (ctx->url.urlLength == 0) {
            pairs[pairIndex].item = "Empty URL";
            pairs[pairIndex].value = "";
        } else {
            pairs[pairIndex].item = "URL";
            pairs[pairIndex].value = (char *) global.signConfigureBaker.url.urlDisplay;
        }
        pairIndex++;
    }

    // Offer signing only once every declared URL byte has been received AND no further stage
    // follows. `lastUrlPage` was previously used only to pick the displayed pair, so a
    // URL-only transaction whose URL spans several packets reached a terminal "Sign
    // transaction" on its first chunk and signed a hash covering just that prefix.
    if (!lastUrlPage || hasCommissionRate() || ctx->hasSuspended) {
        // Create the page content
        nbgl_contentTagValueList_t content;
        content.nbPairs = pairIndex;
        content.pairs = pairs;
        content.smallCaseForValue = false;
        content.nbMaxLinesForValue = 0;
        content.startIndex = 0;
        // Setup the review screen
        nbgl_useCaseReviewLight(TYPE_OPERATION,
                                &content,
                                &ICON_APP_HOME,
                                "Review Transaction",
                                NULL,  // No subtitle
                                "Continue with transaction",
                                confirmConfigureBakerStageCallback);
    } else {
        // Create the page content
        nbgl_contentTagValueList_t content;
        content.nbPairs = pairIndex;
        content.pairs = pairs;
        content.smallCaseForValue = false;
        content.nbMaxLinesForValue = 0;
        content.startIndex = 0;

        // Setup the review screen
        nbgl_useCaseReview(TYPE_TRANSACTION,
                           &content,
                           &ICON_APP_HOME,
                           "Review Transaction",
                           NULL,  // No subtitle
                           "Sign transaction",
                           review_choice_sign);
    }
}

void startConfigureDelegationDisplay(void) {
    // Get context from global state
    signConfigureDelegationContext_t *ctx = &global.signConfigureDelegation;

    // Create tag-value pairs for the content
    uint8_t pairIndex = 0;
    // Add sender address
    pairIndex = addAccountHeaderPairs(pairIndex, "Sender");

    // Add capital amount if present
    if (ctx->hasCapital) {
        if (ctx->stopDelegation) {
            pairs[pairIndex].item = "Action";
            pairs[pairIndex].value = "Stop delegation";
        } else {
            pairs[pairIndex].item = "Amount to delegate";
            pairs[pairIndex].value = (char *) ctx->displayCapital;
        }
        pairIndex++;
    }

    // Add restake earnings if present
    if (ctx->hasRestakeEarnings) {
        pairs[pairIndex].item = "Restake earnings";
        pairs[pairIndex].value = (char *) ctx->displayRestake;
        pairIndex++;
    }

    // Add delegation target if present
    if (ctx->hasDelegationTarget) {
        pairs[pairIndex].item = "Delegation target";
        pairs[pairIndex].value = (char *) ctx->displayDelegationTarget;
        pairIndex++;
    }

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;

    // Setup the review screen
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review Transaction",
                       NULL,  // No subtitle
                       "Sign transaction",
                       review_choice_sign);
}

void uiSignUpdateCredentialThresholdDisplay(volatile unsigned int *flags) {
    // Create tag-value pairs for the content
    uint8_t pairIndex = 0;

    // Add threshold information
    pairs[pairIndex].item = "Threshold";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.threshold;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;

    // Setup the review screen - this is the final step so use
    // nbgl_useCaseReview
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review Transaction",
                       NULL,  // No subtitle
                       "Sign transaction",
                       review_choice_sign);

    *flags |= IO_ASYNCH_REPLY;
}

void uiSignCredentialDeploymentAttributeDisplay(volatile unsigned int *flags) {
    signCredentialDeploymentContext_t *cred = &global.signCredentialDeploymentContext;

    pairs[0].item = (char *) cred->attributeName;
    pairs[0].value = (char *) cred->attributeValue;

    nbgl_contentTagValueList_t content;
    content.nbPairs = 1;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;

    // Mid-flow confirmation: further attributes and the signature come on later screens.
    nbgl_useCaseReviewLight(TYPE_TRANSACTION,
                            &content,
                            &ICON_APP_HOME,
                            "Review revealed attribute",
                            NULL,  // No subtitle
                            "Continue with transaction",
                            review_credential_attribute);

    *flags |= IO_ASYNCH_REPLY;
}

void uiSignUpdateCredentialAddedCredentialDisplay(volatile unsigned int *flags) {
    signCredentialDeploymentContext_t *cred = &global.signCredentialDeploymentContext;
    uint8_t pairIndex = 0;

    pairs[pairIndex].item = "Public key";
    pairs[pairIndex].value = (char *) cred->accountVerificationKey;
    pairIndex++;
    pairs[pairIndex].item = "Signature threshold";
    pairs[pairIndex].value = (char *) cred->signatureThreshold;
    pairIndex++;
    pairs[pairIndex].item = "AR threshold";
    pairs[pairIndex].value = (char *) cred->anonymityRevocationThreshold;
    pairIndex++;
    pairs[pairIndex].item = "RegIdCred";
    pairs[pairIndex].value = (char *) cred->regIdCred;
    pairIndex++;
    pairs[pairIndex].item = "Identity provider";
    pairs[pairIndex].value = (char *) cred->identityProviderIndex;
    pairIndex++;
    // One digest over the whole ordered AR list: the per-entry buffers hold only the last pair.
    pairs[pairIndex].item = "AR list hash";
    pairs[pairIndex].value = (char *) cred->arListHashDisplay;
    pairIndex++;

    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;

    // Mid-flow confirmation: the transaction is signed on a later screen, so this is a
    // continuation review rather than the final signing review.
    nbgl_useCaseReviewLight(TYPE_TRANSACTION,
                            &content,
                            &ICON_APP_HOME,
                            "Review added credential",
                            NULL,  // No subtitle
                            "Confirm added credential",
                            review_added_credential);

    *flags |= IO_ASYNCH_REPLY;
}

void uiSignUpdateCredentialInitialDisplay(volatile unsigned int *flags) {
    // Create tag-value pairs for the content
    uint8_t pairIndex = 0;

    // Add sender address
    pairIndex = addAccountHeaderPairs(pairIndex, "Sender");

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;

    // Setup the review screen
    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            &content,
                            &ICON_APP_HOME,
                            "Review",
                            "details",
                            "Continue with transaction",
                            sendSuccessNoIdleCallback);

    *flags |= IO_ASYNCH_REPLY;
}

void uiSignUpdateCredentialIdDisplay(volatile unsigned int *flags) {
    // Create tag-value pairs for the content
    uint8_t pairIndex = 0;

    // Add credential ID information
    pairs[pairIndex].item = "Credential ID";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.credentialId;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;

    // Setup the review screen
    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            &content,
                            &ICON_APP_HOME,
                            "Review",
                            "details",
                            "Continue with transaction",
                            sendSuccessNoIdleCallback);

    *flags |= IO_ASYNCH_REPLY;
}

void uiSignCredentialDeploymentVerificationKeyDisplay(volatile unsigned int *flags) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairs[pairIndex].item = "Public key";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.accountVerificationKey;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            &content,
                            &ICON_APP_HOME,
                            "Review",
                            "details",
                            "Continue with transaction",
                            processNextVerificationKeyNoIdleCallback);
    *flags |= IO_ASYNCH_REPLY;
}

void uiSignCredentialDeploymentNewIntroDisplay(void) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairs[pairIndex].item = "Public key";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.accountVerificationKey;
    pairIndex++;
    pairs[pairIndex].item = "Signature threshold";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.signatureThreshold;
    pairIndex++;
    pairs[pairIndex].item = "RegIdCred";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.regIdCred;
    pairIndex++;
    pairs[pairIndex].item = "Identity provider";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.identityProviderIndex;
    pairIndex++;
    pairs[pairIndex].item = "AR threshold";
    pairs[pairIndex].value =
        (char *) global.signCredentialDeploymentContext.anonymityRevocationThreshold;
    pairIndex++;
    // One digest over the whole ordered AR list: the per-entry buffers hold only the last pair.
    pairs[pairIndex].item = "AR list hash";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.arListHashDisplay;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review Transaction",
                       NULL,
                       "Sign details",
                       review_choice_sign);
}

void uiSignCredentialDeploymentExistingIntroDisplay(void) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairs[pairIndex].item = "Public key";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.accountVerificationKey;
    pairIndex++;
    pairs[pairIndex].item = "Signature threshold";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.signatureThreshold;
    pairIndex++;
    pairs[pairIndex].item = "RegIdCred";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.regIdCred;
    pairIndex++;
    pairs[pairIndex].item = "Identity provider";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.identityProviderIndex;
    pairIndex++;
    pairs[pairIndex].item = "AR threshold";
    pairs[pairIndex].value =
        (char *) global.signCredentialDeploymentContext.anonymityRevocationThreshold;
    pairIndex++;
    // One digest over the whole ordered AR list: the per-entry buffers hold only the last pair.
    pairs[pairIndex].item = "AR list hash";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.arListHashDisplay;
    pairIndex++;
    pairs[pairIndex].item = "Address";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.accountAddress;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review Transaction",
                       NULL,
                       "Sign details",
                       review_choice_sign);
}

void uiSignCredentialDeploymentNewDisplay(void) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairs[pairIndex].item = "Public key";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.accountVerificationKey;
    pairIndex++;
    pairs[pairIndex].item = "Signature threshold";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.signatureThreshold;
    pairIndex++;
    pairs[pairIndex].item = "RegIdCred";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.regIdCred;
    pairIndex++;
    pairs[pairIndex].item = "Identity provider";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.identityProviderIndex;
    pairIndex++;
    pairs[pairIndex].item = "AR threshold";
    pairs[pairIndex].value =
        (char *) global.signCredentialDeploymentContext.anonymityRevocationThreshold;
    pairIndex++;
    // One digest over the whole ordered AR list: the per-entry buffers hold only the last pair.
    pairs[pairIndex].item = "AR list hash";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.arListHashDisplay;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review Transaction",
                       NULL,
                       "Sign details",
                       review_choice_sign);
}

void uiSignCredentialDeploymentExistingDisplay(void) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairs[pairIndex].item = "Public key";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.accountVerificationKey;
    pairIndex++;
    pairs[pairIndex].item = "Signature threshold";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.signatureThreshold;
    pairIndex++;
    pairs[pairIndex].item = "RegIdCred";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.regIdCred;
    pairIndex++;
    pairs[pairIndex].item = "Identity provider";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.identityProviderIndex;
    pairIndex++;
    pairs[pairIndex].item = "AR threshold";
    pairs[pairIndex].value =
        (char *) global.signCredentialDeploymentContext.anonymityRevocationThreshold;
    pairIndex++;
    // One digest over the whole ordered AR list: the per-entry buffers hold only the last pair.
    pairs[pairIndex].item = "AR list hash";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.arListHashDisplay;
    pairIndex++;
    pairs[pairIndex].item = "Address";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.accountAddress;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review Transaction",
                       NULL,
                       "Sign details",
                       review_choice_sign);
}

void uiSignCredentialDeploymentVerificationKeyFlowDisplay(volatile unsigned int *flags) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairs[pairIndex].item = "Public key";
    pairs[pairIndex].value = (char *) global.signCredentialDeploymentContext.accountVerificationKey;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            &content,
                            &ICON_APP_HOME,
                            "Review",
                            "details",
                            "Continue with transaction",
                            processNextVerificationKeyNoIdleCallback);
    *flags |= IO_ASYNCH_REPLY;
}

void uiSignPublicInformationForIpCompleteDisplay(void) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairs[pairIndex].item = "Public key";
    pairs[pairIndex].value = (char *) global.signPublicInformationForIp.publicKey;
    pairIndex++;
    pairs[pairIndex].item = "Key type";
    pairs[pairIndex].value = global.signPublicInformationForIp.keyType;
    pairIndex++;
    pairs[pairIndex].item = "Signature threshold";
    pairs[pairIndex].value = (char *) global.signPublicInformationForIp.threshold;
    pairIndex++;
    pairs[pairIndex].item = "Id Cred Pub";
    pairs[pairIndex].value = (char *) global.signPublicInformationForIp.idCredPub;
    pairIndex++;
    pairs[pairIndex].item = "Credential ID";
    pairs[pairIndex].value = (char *) global.signPublicInformationForIp.credId;
    pairIndex++;
    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review identity",
                       "provider info",
                       "Sign identity",
                       review_choice_sign);
}
void uiReviewPublicInformationForIpDisplay(void) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairs[pairIndex].item = "Public key";
    pairs[pairIndex].value = global.signPublicInformationForIp.publicKey;
    pairIndex++;
    pairs[pairIndex].item = "Key type";
    pairs[pairIndex].value = global.signPublicInformationForIp.keyType;
    pairIndex++;
    pairs[pairIndex].item = "Id Cred Pub";
    pairs[pairIndex].value = (char *) global.signPublicInformationForIp.idCredPub;
    pairIndex++;
    pairs[pairIndex].item = "Credential ID";
    pairs[pairIndex].value = (char *) global.signPublicInformationForIp.credId;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            &content,
                            &ICON_APP_HOME,
                            "Review identity",
                            "provider info",
                            "Continue reviewing info",
                            sendSuccessNoIdleCallback);
}

void uiSignPublicInformationForIpFinalDisplay(void) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairs[pairIndex].item = "Public key";
    pairs[pairIndex].value = (char *) global.signPublicInformationForIp.publicKey;
    pairIndex++;
    pairs[pairIndex].item = "Key type";
    pairs[pairIndex].value = global.signPublicInformationForIp.keyType;
    pairIndex++;
    pairs[pairIndex].item = "Signature threshold";
    pairs[pairIndex].value = (char *) global.signPublicInformationForIp.threshold;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review identity",
                       NULL,  // No subtitle
                       "Sign identity",
                       review_choice_sign);
}

void uiSignPublicInformationForIpPublicKeyDisplay(void) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairs[pairIndex].item = "Public key";
    pairs[pairIndex].value = global.signPublicInformationForIp.publicKey;
    pairIndex++;
    pairs[pairIndex].item = "Key type";
    pairs[pairIndex].value = global.signPublicInformationForIp.keyType;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            &content,
                            &ICON_APP_HOME,
                            "Review identity",
                            NULL,  // No subtitle
                            "Continue reviewing info",
                            sendSuccessNoIdleCallback);
}

void uiRegisterDataInitialDisplay(volatile unsigned int *flags) {
    uint8_t pairIndex = 0;
    pairIndex = addAccountHeaderPairs(pairIndex, "Sender");
    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReviewLight(TYPE_OPERATION,
                            &content,
                            &ICON_APP_HOME,
                            "Review transaction",
                            NULL,  // No subtitle
                            "Continue with transaction",
                            sendSuccessNoIdleCallback);
    *flags |= IO_ASYNCH_REPLY;
}

void uiRegisterDataPayloadDisplay(volatile unsigned int *flags) {
    // Get context from global state
    signRegisterData_t *ctx = &global.withDataBlob.signRegisterData;

    uint8_t index = 0;
    pairs[index].item = "Data";
    pairs[index].value = (char *) global.withDataBlob.cborContext.display;
    index++;
    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = index;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;

    if (ctx->dataLength > 0) {
        // Setup the review screen
        nbgl_useCaseReviewLight(TYPE_OPERATION,
                                &content,
                                &ICON_APP_HOME,
                                "Review Data",
                                NULL,  // No subtitle
                                "Continue with transaction",
                                sendSuccessNoIdleCallback);
    } else {
        nbgl_useCaseReview(TYPE_TRANSACTION,
                           &content,
                           &ICON_APP_HOME,
                           "Review Data",
                           NULL,  // No subtitle
                           "Sign transaction",
                           review_choice_sign);
    }

    *flags |= IO_ASYNCH_REPLY;
}

void startTransferDisplay(bool displayMemo, volatile unsigned int *flags) {
    uint8_t index = 0;
    index = addAccountHeaderPairs(index, "From");
    pairs[index].item = "Amount";
    pairs[index].value = (char *) global.withDataBlob.signTransferContext.displayAmount;
    index++;
    pairs[index].item = "To";
    pairs[index].value = (char *) global.withDataBlob.signTransferContext.displayStr;
    index++;
    if (displayMemo) {
        pairs[index].item = "Memo";
        pairs[index].value = (char *) global.withDataBlob.cborContext.display;
        index++;
    }
    if (global.withDataBlob.signTransferContext.has_fee_display) {
        // Host-supplied and outside the transaction hash, so it is labelled an estimate; the
        // signed bound is the "Max energy" row above.
        pairs[index].item = "Max fees (est.)";
        pairs[index].value = (char *) global.withDataBlob.signTransferContext.fee_display_str;
        index++;
    }

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = index;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review transaction to send CCD",
                       NULL,  // No subtitle
                       "Sign transaction to send CCD",
                       review_choice_sign);

    *flags |= IO_ASYNCH_REPLY;
}

void uiSignTransferToPublicDisplay(volatile unsigned int *flags) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairIndex = addAccountHeaderPairs(pairIndex, "Sender");
    pairs[pairIndex].item = "Unshield amount";
    pairs[pairIndex].value = (char *) global.signTransferToPublic.amount;
    pairIndex++;
    pairs[pairIndex].item = "Recipient";
    pairs[pairIndex].value = (char *) global.signTransferToPublic.recipientAddress;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review Transaction",
                       NULL,  // No subtitle
                       "Sign transaction",
                       review_choice_sign);
    *flags |= IO_ASYNCH_REPLY;
}

// Add this wrapper function before uiSignScheduledTransferPairFlowDisplay
static void processNextScheduledAmountWrapper(bool choice) {
    if (choice) {
        processNextScheduledAmount(ctx_sign_transfer_with_schedule->buffer);
    } else {
        send_user_rejection();
    }
}

void uiSignScheduledTransferPairFlowDisplay(void) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairs[pairIndex].item = "Release time (UTC)";
    pairs[pairIndex].value =
        (char *) global.withDataBlob.signTransferWithScheduleContext.displayTimestamp;
    pairIndex++;
    pairs[pairIndex].item = "Amount";
    pairs[pairIndex].value =
        (char *) global.withDataBlob.signTransferWithScheduleContext.displayAmount;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReviewLight(TYPE_TRANSACTION,
                            &content,
                            &ICON_APP_HOME,
                            "Review Scheduled release",
                            NULL,  // No subtitle
                            "Show next release",
                            processNextScheduledAmountWrapper);
}

void uiSignScheduledTransferPairFlowSignDisplay(void) {
    // Setup data to display
    uint8_t pairIndex = 0;
    pairs[pairIndex].item = "Release time (UTC)";
    pairs[pairIndex].value =
        (char *) global.withDataBlob.signTransferWithScheduleContext.displayTimestamp;
    pairIndex++;
    pairs[pairIndex].item = "Amount";
    pairs[pairIndex].value =
        (char *) global.withDataBlob.signTransferWithScheduleContext.displayAmount;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review Scheduled release",
                       NULL,  // No subtitle
                       "Sign transaction",
                       review_choice_sign);
}

void uiVerifyAddress(volatile unsigned int *flags) {
    uint8_t index = 0;
    // "Identity" for the compact P1 formats, "Derivation path" for the full-path one.
    pairs[index].item = (char *) global.verifyAddressContext.display_label;
    pairs[index].value = (char *) global.verifyAddressContext.display;
    index++;
    // The host picks the network, and mainnet and testnet addresses are encoded identically, so
    // the address on screen does not reveal which one was derived.
    pairs[index].item = "Network";
    pairs[index].value = (char *) global.verifyAddressContext.network;
    index++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = index;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseAddressReview((char *) global.verifyAddressContext.address,
                              &content,
                              &ICON_APP_HOME,
                              "Verify Address",
                              NULL,  // No subtitle
                              review_verify_address);
    *flags |= IO_ASYNCH_REPLY;
}

void startInitialScheduledTransferDisplay(bool displayMemo) {
    uint8_t index = 0;
    index = addAccountHeaderPairs(index, "Sender");
    pairs[index].item = "Recipient";
    pairs[index].value = (char *) global.withDataBlob.signTransferWithScheduleContext.displayStr;
    index++;
    if (displayMemo) {
        pairs[index].item = "Memo";
        pairs[index].value = (char *) global.withDataBlob.cborContext.display;
        index++;
    }
    if (global.withDataBlob.signTransferWithScheduleContext.has_fee_display) {
        // Host-supplied and outside the transaction hash, so it is labelled an estimate; the
        // signed bound is the "Max energy" row above.
        pairs[index].item = "Max fees (est.)";
        pairs[index].value =
            (char *) global.withDataBlob.signTransferWithScheduleContext.fee_display_str;
        index++;
    }
    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = index;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReviewLight(TYPE_TRANSACTION,
                            &content,
                            &ICON_APP_HOME,
                            "Review Transfer with schedule",
                            NULL,  // No subtitle
                            "Continue with transfer",
                            confirm_initial_scheduled_transfer_callback);
}

void uiDeployModuleDisplay(void) {
    uint8_t pairIndex = addAccountHeaderPairs(0, "Sender");
    pairs[pairIndex].item = "Version";
    pairs[pairIndex].value = (char *) global.deployModule.versionDisplay;
    pairIndex++;
    // Digest of the module source: without it the screen shows nothing about the code deployed.
    pairs[pairIndex].item = "Module hash";
    pairs[pairIndex].value = (char *) global.deployModule.sourceHashDisplay;
    pairIndex++;

    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review Transaction \nto deploy module",
                       NULL,  // No subtitle
                       "Sign transaction\nto deploy module",
                       review_choice_sign);
}

void uiUpdateContractDisplay(void) {
    uint8_t pairIndex = 0;
    pairIndex = addAccountHeaderPairs(pairIndex, "Sender");
    pairs[pairIndex].item = "Amount";
    pairs[pairIndex].value = (char *) global.updateContract.amountDisplay;
    pairIndex++;
    pairs[pairIndex].item = "Index";
    pairs[pairIndex].value = (char *) global.updateContract.indexDisplay;
    pairIndex++;
    pairs[pairIndex].item = "Sub index";
    pairs[pairIndex].value = (char *) global.updateContract.subIndexDisplay;
    pairIndex++;
    // Receive name and parameter digest are both hashed into the signed transaction.
    pairs[pairIndex].item = "Receive name";
    pairs[pairIndex].value = (char *) global.updateContract.nameDisplay;
    pairIndex++;
    pairs[pairIndex].item = "Payload hash";
    pairs[pairIndex].value = (char *) global.updateContract.paramsHashDisplay;
    pairIndex++;
    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review Transaction \nto update contract",
                       NULL,  // No subtitle
                       "Sign transaction\nto update contract",
                       review_choice_sign);
}

void uiInitContractDisplay(void) {
    uint8_t pairIndex = 0;
    pairIndex = addAccountHeaderPairs(pairIndex, "Sender");
    pairs[pairIndex].item = "Amount";
    pairs[pairIndex].value = (char *) global.initContract.amountDisplay;
    pairIndex++;
    pairs[pairIndex].item = "Module ref";
    pairs[pairIndex].value = (char *) global.initContract.moduleRefDisplay;
    pairIndex++;
    // Contract name and parameter digest are both hashed into the signed transaction.
    pairs[pairIndex].item = "Contract name";
    pairs[pairIndex].value = (char *) global.initContract.nameDisplay;
    pairIndex++;
    pairs[pairIndex].item = "Payload hash";
    pairs[pairIndex].value = (char *) global.initContract.paramsHashDisplay;
    pairIndex++;
    // Create the page content
    nbgl_contentTagValueList_t content;
    content.nbPairs = pairIndex;
    content.pairs = pairs;
    content.smallCaseForValue = false;
    content.nbMaxLinesForValue = 0;
    content.startIndex = 0;
    // Setup the review screen. INS 0x07 creates a new contract instance; the titles used to be
    // copies of the INS 0x08 update-contract wording, which named the wrong operation.
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &content,
                       &ICON_APP_HOME,
                       "Review Transaction \nto initialize contract",
                       NULL,  // No subtitle
                       "Sign transaction\nto initialize contract",
                       review_choice_sign);
}

#endif
