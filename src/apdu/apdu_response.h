#pragma once

#include <stdint.h>

/**
 * Send a user rejection back to the caller (SWO_CONDITIONS_NOT_SATISFIED), then return to main
 * menu.
 */
void send_user_rejection(void);

/**
 * Same as send_user_rejection but does not return to the menu.
 */
void send_user_rejection_no_idle(void);

/**
 * Send success with empty payload, no idle menu.
 */
void send_success_no_idle(void);

/**
 * Send success with tx bytes already in G_io_apdu_buffer, no idle menu.
 */
void send_success_result_no_idle(uint8_t tx);

/**
 * Send success and return to main menu; tx is length of response body (status words appended).
 */
void send_success(uint8_t tx);
