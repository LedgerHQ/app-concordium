#pragma once

/*
 * The SDK's TLV library includes this for PIC() and for PRINTF().
 *
 * PIC() resolves a link-time address against the running code's load address on device; a
 * hosted fuzz binary is linked at its final address, so it is the identity here.
 */
#include "os_print.h"

#ifndef PIC
#define PIC(x) (x)
#endif
