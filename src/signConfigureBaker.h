#pragma once

#include <parser.h>

/**
 * Handles the signing flow for a 'Configure Baker' transaction. It validates
 * that the correct UpdateType is supplied and will fail otherwise.
 * Command data: see /doc/ins_configure_delegation.md.
 */
void handleSignConfigureBaker(const command_t *cmd,
                              volatile unsigned int *flags,
                              bool isInitialCall);

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

bool hasCommissionRate();
