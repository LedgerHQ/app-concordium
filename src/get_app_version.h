#pragma once

/**
 * Maximum length of MAJOR_VERSION || MINOR_VERSION || PATCH_VERSION.
 */
#define APPVERSION_LEN 3

#ifndef MAJOR_VERSION
#error "Major version not set"
#endif  // MAJOR_VERSION

#ifndef MINOR_VERSION
#error "Minor version not set"

#endif  // MINOR_VERSION

#ifndef PATCH_VERSION
#error "Patch version not set"
#endif  // PATCH_VERSION
/**
 * Handler gor GET_VERSION command. Send APDU response with version
 * of the application.
 *
 * @see MAJOR_VERSION, MINOR_VERSION and PATCH_VERSION in Makefile.
 *
 * @return zero or positive integer if success, negative integer otherwise.
 *
 */
int handler_get_version(void);