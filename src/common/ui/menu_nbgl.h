#pragma once

// Stub. APPNAME is defined in makefile
#ifndef APPNAME
#error "APPNAME is not set"
#endif  // APPNAME

#include "nbgl_types.h"
// Stub. APPVERSION is defined in makefile
#ifndef APPVERSION
#error "APPVERSION is not set"
#endif  // APPVERSION

extern const nbgl_icon_details_t C_app_concordium_64px;

void ui_menu_main(void);
