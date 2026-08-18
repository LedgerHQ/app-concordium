# ****************************************************************************
#    Ledger App Concordium
#    (c) 2023 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

########################################
#        Mandatory configuration       #
########################################
# Application name
APPNAME = "Concordium"

# Application version
APPVERSION_M = 5
APPVERSION_N = 6
APPVERSION_P = 3
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

DEFINES += APPVERSION=\"$(APPVERSION)\"
# Make the version parameters accessible from the app.
DEFINES += APPVERSION_M=$(APPVERSION_M)
DEFINES += APPVERSION_N=$(APPVERSION_N)
DEFINES += APPVERSION_P=$(APPVERSION_P)


# Application source files
APP_SOURCE_PATH += src

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOS = icons/app_concordium_16px.gif
ICON_NANOX = icons/app_concordium_14px.gif
ICON_NANOSP = icons/app_concordium_14px.gif
ICON_STAX = icons/app_concordium_32px.gif
ICON_FLEX = icons/app_concordium_40px.gif
ICON_APEX_P = icons/app_concordium_32px.png

# Application allowed derivation curves.
# Possibles curves are: secp256k1, secp256r1, ed25519 and bls12381g1
# If your app needs it, you can specify multiple curves by using:
# `CURVE_APP_LOAD_PARAMS = <curve1> <curve2>`
CURVE_APP_LOAD_PARAMS = ed25519

# Application allowed derivation paths.
# You should request a specific path for your app.
# This serve as an isolation mechanism.
# Most application will have to request a path according to the BIP-0044
# and SLIP-0044 standards.
# If your app needs it, you can specify multiple path by using:
# `PATH_APP_LOAD_PARAMS = "44'/1'" "45'/1'"`
# purpose=coin(44) / coin_type=Testnet(1)
PATH_APP_LOAD_PARAMS = "44'/919'" "44'/1'" "1105'/0'"

# Setting to allow building variant applications
# - <VARIANT_PARAM> is the name of the parameter which should be set
#   to specify the variant that should be build.
# - <VARIANT_VALUES> a list of variant that can be build using this app code.
#   * It must at least contains one value.
#   * Values can be the app ticker or anything else but should be unique.
VARIANT_PARAM = COIN
VARIANT_VALUES = CCD

# Enabling DEBUG flag will enable PRINTF and disable optimizations
#DEBUG = 1

########################################
#     Application custom permissions   #
########################################
# See SDK `include/appflags.h` for the purpose of each permission
#HAVE_APPLICATION_FLAG_DERIVE_MASTER = 1
#HAVE_APPLICATION_FLAG_GLOBAL_PIN = 1
#HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1
#HAVE_APPLICATION_FLAG_LIBRARY = 1

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1
#ENABLE_NFC = 1

########################################
#    Nano PKI + TLV (lib_pki/lib_tlv)  #
########################################
# Required for trusted-name verification (TLV descriptor format + PKI signature).
ENABLE_PKI_LIBRARY = 1
ENABLE_TLV_LIBRARY = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1
#ENABLE_NBGL_KEYBOARD = 1
#ENABLE_NBGL_KEYPAD = 1

########################################
#          Features disablers          #
########################################
# These advanced settings allow to disable some feature that are by
# default enabled in the SDK `Makefile.standard_app`.
#DISABLE_STANDARD_APP_FILES = 1
#DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1 # To allow custom size declaration
#DISABLE_STANDARD_APP_DEFINES = 1 # Will set all the following disablers
#DISABLE_STANDARD_SNPRINTF = 1
#DISABLE_STANDARD_USB = 1
#DISABLE_STANDARD_WEBUSB = 1
#DISABLE_STANDARD_BAGL_UX_FLOW = 1
#DISABLE_DEBUG_LEDGER_ASSERT = 1
#DISABLE_DEBUG_THROW = 1


# Accept test signer key ID (0x00) for trusted name TLV (Speculos / PKI tests).
# - DEBUG=1: enabled for local dev (pytest skips PKI tests on release builds automatically).
# - ENABLE_TRUSTED_NAME_TEST_KEY=1: optional (e.g. CI without DEBUG).
# Production: plain `make` (no DEBUG, no ENABLE).
ifeq ($(DEBUG),1)
DEFINES += TRUSTED_NAME_TEST_KEY
endif
ifeq ($(ENABLE_TRUSTED_NAME_TEST_KEY),1)
DEFINES += TRUSTED_NAME_TEST_KEY
endif

# HKDF API is implemented in the SDK but declared only under lib_cxng/src (not in the public cx.h umbrella).
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src

# tinycbor (CBOR parser, v0.6.0) — parser only, encoder excluded
DEFINES          += CBOR_NO_ENCODER_API
APP_SOURCE_FILES += deps/tinycbor/src/cborparser.c
INCLUDES_PATH    += deps/tinycbor/src

include $(BOLOS_SDK)/Makefile.standard_app

# Suppress -Wimplicit-fallthrough only for the tinycbor submodule source.
# OBJ_DIR is defined by the SDK (Makefile.target) so must come after the include above.
$(OBJ_DIR)/app/deps/tinycbor/src/cborparser.o: CFLAGS += -Wno-implicit-fallthrough

# arm-none-eabi-size always reports bss == total SRAM on Ledger targets: the
# linker script extends .bss to END_STACK to reserve stack space, so the bss
# column is the whole SRAM budget, not just BSS variables.  Use nm to extract
# the linker-defined _bss/_ebss/_stack/_estack labels and compute the real split.
.PHONY: app-size-report
app-size-report: $(BIN_TARGETS) $(DBG_TARGETS)
	@echo ""
	@echo "Finished Concordium Ledger app ($(TARGET_NAME)) → $(BIN_DIR)/app.elf"
	@$(GCCPATH)arm-none-eabi-size $(BIN_DIR)/app.elf | \
	  awk 'NR==2 { printf "  flash  %6d B\n", $$1 }'
	@$(GCCPATH)arm-none-eabi-nm $(BIN_DIR)/app.elf 2>/dev/null | \
	  python3 -c "import sys; s={p[2]:int(p[0],16) for l in sys.stdin for p in [l.split()] if len(p)==3}; bss=s.get('_bss'); ebss=s.get('_ebss'); stk=s.get('_stack'); estk=s.get('_estack'); print(f'  SRAM   {(ebss-bss)+(estk-stk):6d} B total: {ebss-bss} B BSS variables, {estk-stk} B stack headroom') if all(v is not None for v in [bss,ebss,stk,estk]) else print('  SRAM   (nm symbols _bss/_ebss/_stack/_estack not found; SDK linker script may have changed)')"

default: app-size-report
