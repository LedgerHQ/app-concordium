#pragma once

/**
 * Instruction-scoped state: one union (`global`) shared by all APDU flows.
 * All member struct/enum types are defined here so the layout lives in one place.
 */

#include <stdbool.h>
#include <stdint.h>

#include <cx.h>
#include <parser.h>

#include "app_sizes.h"
#include "buffer.h"
#include "derivation_path.h"
#include "set_trusted_name.h"
#include "helpers/time.h"
#include "tlv_library.h"

/* ----- Sizes for exportPrivateKeyContext_t (INS export-private-key; handlers in
 * export_private_key_*.c) ----- */

#define MAX_KEYS_TO_EXPORT 3

#define LENGTH_AND_PRIVATE_KEY_SIZE 33  // 1 byte for length, 32 bytes for private key

#define ACCOUNT_SUBTREE 0
#define NORMAL_ACCOUNTS 0

#define P1_LEGACY_PRF_KEY                 0x00
#define P1_LEGACY_PRF_KEY_RECOVERY        0x01
#define P1_LEGACY_PRF_KEY_AND_ID_CRED_SEC 0x02
#define P2_LEGACY_SEED                    0x01
#define P2_LEGACY_KEY                     0x02

#define P1_IDENTITY_CREDENTIAL_CREATION 0x00
#define P1_ACCOUNT_CREATION             0x01
#define P1_ID_RECOVERY                  0x02
#define P1_ACCOUNT_CREDENTIAL_DISCOVERY 0x03
#define P1_CREATION_OF_ZK_PROOF         0x04

#define P2_MAINNET 0x00
#define P2_TESTNET 0x01

#define EXPORT_PRIVATE_KEY_TITLE_BUFF_LEN       40
#define EXPORT_PRIVATE_KEY_REVIEW_OPERATION_LEN 17
#define EXPORT_PRIVATE_KEY_SIGN_OPERATION_LEN   15
#define EXPORT_PRIVATE_KEY_CREDID_TITLE_LEN     15
#define EXPORT_PRIVATE_KEY_CREDID_LEN           22
#define EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN      24
#define EXPORT_PRIVATE_KEY_SIGN_VERB_LEN        (EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN + 1)

/* ----- Nested types for transactionWithDataBlob_t ----- */

typedef enum {
    TX_TRANSFER_INITIAL = 49,
    TX_TRANSFER_MEMO_INITIAL = 50,
    TX_TRANSFER_MEMO = 51,
    TX_TRANSFER_AMOUNT = 52
} simpleTransferState_t;

typedef struct {
    unsigned char displayStr[57];
    uint8_t displayAmount[30];
    uint8_t fee_display_str[30];
    bool has_fee_display;
    simpleTransferState_t state;
} signTransferContext_t;

typedef enum {
    TX_REGISTER_DATA_INITIAL = 57,
    TX_REGISTER_DATA_PAYLOAD_START = 58,
    TX_REGISTER_DATA_PAYLOAD = 59,
} registerDataState_t;

typedef struct {
    uint8_t display[255];
    uint16_t dataLength;
    registerDataState_t state;
} signRegisterData_t;

typedef struct {
    uint32_t cborLength;
    uint32_t displayUsed;
    uint8_t display[COMMON_DISPLAY_SIZE];
    uint8_t majorType;
} cborContext_t;

typedef enum {
    TX_TRANSFER_WITH_SCHEDULE_INITIAL = 28,
    TX_TRANSFER_WITH_SCHEDULE_TRANSFER_PAIRS = 29,
    TX_TRANSFER_WITH_SCHEDULE_MEMO_START = 55,
    TX_TRANSFER_WITH_SCHEDULE_MEMO = 56,
} transferWithScheduleState_t;

typedef struct {
    uint8_t transactionType;
    transferWithScheduleState_t state;

    unsigned char displayStr[57];
    uint8_t remainingNumberOfScheduledAmounts;
    uint8_t scheduledAmountsInCurrentPacket;

    uint8_t displayAmount[30];
    uint8_t fee_display_str[30];
    bool has_fee_display;
    uint8_t displayTimestamp[25];

    tm time;

    uint8_t buffer[255];
    uint8_t pos;
} signTransferWithScheduleContext_t;

typedef struct {
    union {
        signTransferContext_t signTransferContext;
        signTransferWithScheduleContext_t signTransferWithScheduleContext;
        signRegisterData_t signRegisterData;
    };
    cborContext_t cborContext;
} transactionWithDataBlob_t;

/* ----- Remaining instruction context structs ----- */

typedef struct {
    uint32_t version;
    uint32_t sourceLength;
    uint32_t remainingSourceLength;
    uint8_t sourceHash[COMMON_HASH_SIZE];
    char sourceHashDisplay[COMMON_HASH_SIZE * 2 + 1];
    char versionDisplay[11];
} deployModule_t;

typedef enum {
    INIT_CONTRACT_INITIAL = 60,
    INIT_CONTRACT_NAME_FIRST = 61,
    INIT_CONTRACT_NAME_NEXT = 62,
    INIT_CONTRACT_PARAMS_FIRST = 63,
    INIT_CONTRACT_PARAMS_NEXT = 64,
    INIT_CONTRACT_END = 65
} initContractState_t;

typedef struct {
    uint64_t amount;
    uint8_t moduleRef[COMMON_MODULE_REF_SIZE];
    char amountDisplay[COMMON_AMOUNT_DISPLAY_SIZE];
    char moduleRefDisplay[COMMON_MODULE_REF_SIZE * 2 + 1];
    uint32_t nameLength;
    uint32_t remainingNameLength;
    uint32_t paramsLength;
    uint32_t remainingParamsLength;
    initContractState_t state;
} initContract_t;

typedef enum {
    UPDATE_CONTRACT_INITIAL = 60,
    UPDATE_CONTRACT_NAME_FIRST = 61,
    UPDATE_CONTRACT_NAME_NEXT = 62,
    UPDATE_CONTRACT_PARAMS_FIRST = 63,
    UPDATE_CONTRACT_PARAMS_NEXT = 64,
    UPDATE_CONTRACT_END = 65
} updateContractState_t;

typedef struct {
    uint64_t amount;
    uint8_t moduleRef[COMMON_MODULE_REF_SIZE];
    char amountDisplay[30];
    char indexDisplay[30];
    char subIndexDisplay[30];
    uint32_t nameLength;
    uint32_t remainingNameLength;
    uint32_t paramsLength;
    uint32_t remainingParamsLength;
    updateContractState_t state;
} updateContract_t;

typedef struct {
    uint8_t display[21];
    char publicKey[68];
    bool signPublicKey;
} exportPublicKeyContext_t;

typedef struct {
    uint8_t display_review_operation[EXPORT_PRIVATE_KEY_TITLE_BUFF_LEN];
    uint8_t display_review_verb[EXPORT_PRIVATE_KEY_REVIEW_VERB_LEN];
    uint8_t display_sign_verb[EXPORT_PRIVATE_KEY_SIGN_VERB_LEN + 1];
    uint8_t display_credid_title[EXPORT_PRIVATE_KEY_CREDID_TITLE_LEN];
    uint8_t display_credid[EXPORT_PRIVATE_KEY_CREDID_LEN];
    uint8_t display_sign[EXPORT_PRIVATE_KEY_TITLE_BUFF_LEN];
    bool exportBoth;
    bool exportSeed;
    bool isNewPath;
    uint8_t outputPrivateKeys[MAX_KEYS_TO_EXPORT * LENGTH_AND_PRIVATE_KEY_SIZE];
    uint8_t privateKeysLength;
} exportPrivateKeyContext_t;

typedef struct {
    uint8_t display[21];
    /** Without trusted descriptor: path-derived base58. With PKI descriptor: tag 0x20 UTF-8 (cert).
     */
    char address[TRUSTED_NAME_MAX_LEN + 1];
} verifyAddressContext_t;

typedef enum {
    TX_PUBLIC_INFO_FOR_IP_INITIAL = 22,
    TX_PUBLIC_INFO_FOR_IP_VERIFICATION_KEY = 23,
    TX_PUBLIC_INFO_FOR_IP_THRESHOLD = 24
} publicInfoForIpState_t;

typedef struct {
    bool showIntro;
    uint8_t publicKeysLength;
    char publicKey[68];
    uint8_t threshold[COMMON_THRESHOLD_SIZE];
    char idCredPub[48 * 2 + 1];
    char credId[48 * 2 + 1];

    char keyType[2 + 1];
    publicInfoForIpState_t state;
} signPublicInformationForIp_t;

typedef enum {
    TX_CREDENTIAL_DEPLOYMENT_INITIAL = 4,
    TX_CREDENTIAL_DEPLOYMENT_VERIFICATION_KEYS_LENGTH = 5,
    TX_CREDENTIAL_DEPLOYMENT_VERIFICATION_KEY = 6,
    TX_CREDENTIAL_DEPLOYMENT_SIGNATURE_THRESHOLD = 7,
    TX_CREDENTIAL_DEPLOYMENT_AR_IDENTITY = 8,
    TX_CREDENTIAL_DEPLOYMENT_CREDENTIAL_DATES = 9,
    TX_CREDENTIAL_DEPLOYMENT_ATTRIBUTE_TAG = 10,
    TX_CREDENTIAL_DEPLOYMENT_ATTRIBUTE_VALUE = 11,
    TX_CREDENTIAL_DEPLOYMENT_LENGTH_OF_PROOFS = 12,
    TX_CREDENTIAL_DEPLOYMENT_PROOFS = 13,
    TX_CREDENTIAL_DEPLOYMENT_NEW_OR_EXISTING = 14
} protocolState_t;

typedef enum {
    TX_UPDATE_CREDENTIAL_INITIAL = 0,
    TX_UPDATE_CREDENTIAL_CREDENTIAL_INDEX = 21,
    TX_UPDATE_CREDENTIAL_CREDENTIAL = 22,
    TX_UPDATE_CREDENTIAL_ID_COUNT = 23,
    TX_UPDATE_CREDENTIAL_ID = 24,
    TX_UPDATE_CREDENTIAL_THRESHOLD = 25
} updateCredentialState_t;

typedef struct {
    uint8_t type;
    uint8_t numberOfVerificationKeys;

    uint8_t credentialDeploymentCount;
    uint8_t credentialIdCount;
    char credentialId[102];
    uint8_t threshold[COMMON_THRESHOLD_SIZE];
    updateCredentialState_t updateCredentialState;

    char accountVerificationKey[68];
    uint8_t signatureThreshold[COMMON_THRESHOLD_SIZE];

    uint8_t anonymityRevocationThreshold[13];
    uint16_t anonymityRevocationListLength;

    char regIdCred[48 * 2 + 1];
    char identityProviderIndex[4 * 2 + 1];
    char arIdentity[4 * 2 + 1];
    char encIdCredPubShare[96 * 2 + 1];

    uint8_t validTo[COMMON_TIMESTAMP_SIZE];
    uint8_t createdAt[COMMON_TIMESTAMP_SIZE];

    uint16_t attributeListLength;

    cx_sha256_t attributeHash;
    uint8_t attributeValueLength;

    uint32_t proofLength;
    uint8_t accountAddress[57];

    protocolState_t state;
    bool showIntro;
} signCredentialDeploymentContext_t;

typedef enum {
    TX_TRANSFER_TO_PUBLIC_INITIAL = 25,
    TX_TRANSFER_TO_PUBLIC_REMAINING_AMOUNT = 26,
    TX_TRANSFER_TO_PUBLIC_PROOF = 27
} transferToPublicState_t;

typedef struct {
    uint8_t amount[30];
    uint8_t recipientAddress[57];
    uint16_t proofSize;
    transferToPublicState_t state;
} signTransferToPublic_t;

typedef enum {
    CONFIGURE_BAKER_INITIAL = 60,
    CONFIGURE_BAKER_FIRST = 61,
    CONFIGURE_BAKER_AGGREGATION_KEY = 62,
    CONFIGURE_BAKER_URL_LENGTH = 63,
    CONFIGURE_BAKER_URL = 64,
    CONFIGURE_BAKER_COMMISSION_RATES = 65,
    CONFIGURE_BAKER_SUSPENDED = 66,
    CONFIGURE_BAKER_END = 67
} configureBakerState_t;

typedef struct {
    bool stopBaking;
    uint8_t displayCapital[30];
    uint8_t displayRestake[4];
    uint8_t displayOpenForDelegation[15];
} configureBakerCapitalRestakeOpenForDelegationBlob_t;

typedef struct {
    uint16_t urlLength;
    uint8_t urlDisplay[COMMON_URL_DISPLAY_SIZE];
} configureBakerUrl_t;

typedef struct {
    uint8_t transactionFeeCommissionRate[COMMON_COMMISSION_SIZE];
    uint8_t bakingRewardCommissionRate[COMMON_COMMISSION_SIZE];
    uint8_t finalizationRewardCommissionRate[COMMON_COMMISSION_SIZE];
} configureBakerCommisionRates_t;

typedef struct {
    bool hasCapital;
    bool hasRestakeEarnings;
    bool hasOpenForDelegation;
    bool hasKeys;
    bool hasMetadataUrl;
    bool hasTransactionFeeCommission;
    bool hasBakingRewardCommission;
    bool hasFinalizationRewardCommission;
    bool hasSuspended;
    bool firstDisplay;

    union {
        configureBakerCapitalRestakeOpenForDelegationBlob_t capitalRestakeDelegation;
        configureBakerUrl_t url;
        configureBakerCommisionRates_t commissionRates;
        uint8_t suspended[18];
    };

    configureBakerState_t state;
} signConfigureBaker_t;

typedef struct {
    bool stopDelegation;
    uint8_t displayCapital[30];
    uint8_t displayRestake[4];
    uint8_t displayDelegationTarget[30];
    bool hasCapital;
    bool hasRestakeEarnings;
    bool hasDelegationTarget;
} signConfigureDelegationContext_t;

typedef struct trustedNameMultiHashCtx_s {
    cx_sha256_t sha256;
    cx_sha3_t sha3_256;
    cx_sha3_t keccak_256;
    cx_ripemd160_t ripemd160;
    cx_sha512_t sha512;
} trustedNameMultiHashCtx_t;

typedef struct trustedNameTlvExtracted_s {
    TLV_reception_t received_tags;

    uint8_t structure_type;
    uint8_t version;
    uint8_t trusted_name_type;
    uint8_t trusted_name_source;
    char name[TRUSTED_NAME_MAX_LEN + 1];
    buffer_t address;
    uint64_t chain_id;
    uint64_t challenge;
    uint16_t signer_key_id;
    uint8_t signer_algo;
    buffer_t signature;
} trustedNameTlvExtracted_t;

typedef struct trustedNamePkiContext_s {
    uint64_t stored_challenge;
    trustedNameMultiHashCtx_t hash_ctx;
    trustedNameTlvExtracted_t tlv;
} trustedNamePkiContext_t;

/* ----- Union ----- */

typedef union {
    exportPrivateKeyContext_t exportPrivateKeyContext;
    exportPublicKeyContext_t exportPublicKeyContext;
    verifyAddressContext_t verifyAddressContext;

    signPublicInformationForIp_t signPublicInformationForIp;
    signCredentialDeploymentContext_t signCredentialDeploymentContext;

    signTransferToPublic_t signTransferToPublic;
    signConfigureBaker_t signConfigureBaker;
    signConfigureDelegationContext_t signConfigureDelegation;
    deployModule_t deployModule;
    initContract_t initContract;
    updateContract_t updateContract;
    transactionWithDataBlob_t withDataBlob;
    trustedNamePkiContext_t trustedNamePki;
} instructionContext;

/** Instruction-scoped union; storage in `globals.c`. */
extern instructionContext global;
