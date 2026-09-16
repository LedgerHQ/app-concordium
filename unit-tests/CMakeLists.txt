cmake_minimum_required(VERSION 3.10)
project(concordium_unit_tests LANGUAGES C)

# ---------------------------------------------------------------------------
# Host unit tests for the parsing and display helpers.
#
# The workflow that runs these was disabled and pointed at a directory that did not exist on
# this branch, so nothing gated a change to security-sensitive parsing code (finding V-116).
#
# The host-stub layer is fuzzing/stubs/, not a second copy of its own. Those stubs already
# shadow every SDK header the helpers include and already define the app globals, and they are
# exercised on every CI fuzz build, so a divergence between them and the app is caught quickly.
# A private set of stubs here would be a second thing to keep in step with the SDK, and the one
# that is only built by a workflow nobody looks at is the one that rots.
# ---------------------------------------------------------------------------

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

include(CTest)
enable_testing()

set(APP_SRC    ${CMAKE_CURRENT_SOURCE_DIR}/../src)
set(FUZZ_STUBS ${CMAKE_CURRENT_SOURCE_DIR}/../fuzzing/stubs)

if(DEFINED BOLOS_SDK)
    set(LEDGER_SDK_RAW ${BOLOS_SDK})
elseif(DEFINED ENV{BOLOS_SDK})
    set(LEDGER_SDK_RAW $ENV{BOLOS_SDK})
else()
    set(LEDGER_SDK_RAW ${CMAKE_CURRENT_SOURCE_DIR}/../../ledger-secure-sdk)
endif()

# The workflow sets BOLOS_SDK=../sdk, and if(EXISTS) with a relative path is undefined in CMake.
# Resolve against this directory, which is what "../sdk" means to the caller that cd'd here.
get_filename_component(LEDGER_SDK "${LEDGER_SDK_RAW}" ABSOLUTE BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

if(NOT EXISTS ${LEDGER_SDK}/lib_standard_app/format.c)
    message(FATAL_ERROR
        "ledger-secure-sdk not found at '${LEDGER_SDK}' (from '${LEDGER_SDK_RAW}'). "
        "Set BOLOS_SDK to a checkout of it.")
endif()

# ---------------------------------------------------------------------------
# Device ABI. The SDK builds the app with -funsigned-char -fshort-enums
# (Makefile.defines), so a state enum is one byte on device. Without these the structs under
# test have a different layout here than the ones the device runs, and the _Static_asserts in
# src/instruction_context.h (finding V-103) fail the build outright rather than silently
# testing a different struct.
# ---------------------------------------------------------------------------
add_compile_options(-funsigned-char -fshort-enums -Wall -Wextra -g -O0)

# Coverage, for the lcov/Codecov steps in .github/workflows/unit_tests.yml.
add_compile_options(--coverage)
add_link_options(--coverage)

set(APP_INCLUDE_DIRS
    ${FUZZ_STUBS}/ledger
    ${FUZZ_STUBS}
    ${APP_SRC}
    ${APP_SRC}/helpers
    ${APP_SRC}/handler
    ${APP_SRC}/apdu
    ${APP_SRC}/ui
    ${LEDGER_SDK}/lib_standard_app
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# The same source set the fuzz targets share, so a test links exactly what CI already builds.
add_library(app_host STATIC
    ${FUZZ_STUBS}/stubs.c
    ${LEDGER_SDK}/lib_standard_app/format.c
    ${APP_SRC}/helpers/base58check.c
    ${APP_SRC}/helpers/cbor_data_blob.c
    ${APP_SRC}/helpers/derivation_path.c
    ${APP_SRC}/helpers/display_text.c
    ${APP_SRC}/helpers/fee_display.c
    ${APP_SRC}/helpers/numberHelpers.c
    ${APP_SRC}/helpers/sign_transfer_schedule.c
    ${APP_SRC}/helpers/time.c
    ${APP_SRC}/helpers/tx_hash.c
)
target_include_directories(app_host PUBLIC ${APP_INCLUDE_DIRS})

# ---------------------------------------------------------------------------
# One executable per test file, registered with CTest.
# Usage: add_unit_test(<name> [extra_source ...]) - pass a handler .c to test it, the way
# fuzzing/CMakeLists.txt does. app_host carries only what every test needs.
# ---------------------------------------------------------------------------
function(add_unit_test NAME)
    add_executable(${NAME} ${NAME}.c ${ARGN})
    target_include_directories(${NAME} PRIVATE ${APP_INCLUDE_DIRS})
    target_link_libraries(${NAME} PRIVATE app_host cmocka gcov)
    add_test(NAME ${NAME} COMMAND ${NAME})
endfunction()

add_unit_test(test_display_text)
add_unit_test(test_cbor_data_blob)
add_unit_test(test_time)
add_unit_test(test_derivation_path)
add_unit_test(test_get_public_key ${APP_SRC}/handler/get_public_key.c)
