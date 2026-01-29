#ifndef GET_APP_VERSION_H
#define GET_APP_VERSION_H

/**
 * Maximum length of MAJOR_VERSION || MINOR_VERSION || PATCH_VERSION.
 */
#define APPVERSION_LEN 3
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

#endif  // GET_APP_VERSION_H