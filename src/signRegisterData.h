#pragma once

#include <parser.h>

/**
 * Handles the signing flow, including updating the display, for the 'register data'
 * account transaction. Command data: see /doc/ins_register_data.md.
 */
void handleSignRegisterData(const command_t *cmd, volatile unsigned int *flags, bool isInitialCall);

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

void handleData(void);
