#pragma once

/* ISO 7816 / Ledger status words (mirrors ledger-secure-sdk/include/status_words.h) */

#define SWO_NO_RESPONSE                   0x0000
#define SWO_INCORRECT_DATA                0x6A80
#define SWO_FUNCTION_NOT_SUPPORTED        0x6A81
#define SWO_WRONG_DATA_LENGTH             0x6A87
#define SWO_WRONG_P1_P2                   0x6B00
#define SWO_CONDITIONS_NOT_SATISFIED      0x6985
#define SWO_WRONG_LENGTH                  0x6700
#define SWO_INVALID_INS                   0x6D00
#define SWO_INVALID_CLA                   0x6E00
#define SWO_UNKNOWN                       0x6F00
#define SWO_SUCCESS                       0x9000
#define SWO_SECURITY_CONDITION_NOT_SATISFIED 0x6982
#define SWO_INCONSISTENT_TLV_STRUCT       0x6A85
#define SWO_INCORRECT_P1_P2               0x6A86
