#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Reports whether host-supplied bytes can be shown verbatim on a review screen.
 *
 * Text arriving from the host is hashed into the transaction in full but rendered as a C string,
 * so an embedded NUL ends the display while the signature still covers everything after it: the
 * user approves bytes that were never shown. The remaining C0 controls and DEL have no faithful
 * rendering either, so they are refused rather than drawn as something they are not.
 *
 * Returns a verdict rather than throwing: a rejected transaction has to answer the host with a
 * status word, and an uncaught THROW would take the whole app down instead.
 *
 * Call this before the bytes reach a display buffer, for every chunk of a multi-packet field.
 *
 * @param text bytes about to be shown to the user
 * @param length number of bytes to check
 * @return true if every byte is displayable
 */
bool is_displayable_text(const uint8_t *text, size_t length);
