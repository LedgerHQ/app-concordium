// Thin wrapper so we can suppress third-party warnings without touching the submodule.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#include "../tinycbor/src/cborparser.c"
#pragma GCC diagnostic pop
