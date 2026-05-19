#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* APDU command structure (mirrors ledger-secure-sdk/lib_standard_app/parser.h) */
typedef struct {
    uint8_t  cla;
    uint8_t  ins;
    uint8_t  p1;
    uint8_t  p2;
    uint8_t  lc;
    uint8_t *data;
} command_t;

bool apdu_parser(command_t *cmd, uint8_t *buf, size_t buf_len);
