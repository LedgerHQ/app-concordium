#pragma once

#include <stddef.h>
#include <stdint.h>

#include "cx.h"

/*
 * GET_CHALLENGE draws its challenge here. The fuzz stub returns a fixed value: a random
 * challenge would make the trusted-name challenge comparison unreachable, since no input
 * could ever match it.
 */
cx_err_t cx_rng_no_throw(uint8_t *buffer, size_t len);
