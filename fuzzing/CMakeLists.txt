cmake_minimum_required(VERSION 3.10)
project(StandaloneFuzzer
    VERSION 1.2.0
    DESCRIPTION "Concordium Ledger App Fuzzers"
    LANGUAGES C
)

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
  find_program(CLANG_EXECUTABLE clang)
  if(CLANG_EXECUTABLE)
    set(CMAKE_C_COMPILER ${CLANG_EXECUTABLE} CACHE STRING "C compiler" FORCE)
    set(CMAKE_CXX_COMPILER clang++ CACHE STRING "C++ compiler" FORCE)
  else()
    message(FATAL_ERROR "Fuzzer needs to be built with Clang")
  endif()
endif()

# Favor ClusterFuzzLite-provided flags if present; otherwise use safe defaults.
set(FALLBACK_CFLAGS "-O1 -g -fno-omit-frame-pointer -fsanitize-coverage=trace-cmp,indirect-calls,8bit-counters")
if(DEFINED ENV{SANITIZER})
  if("$ENV{SANITIZER}" STREQUAL "address")
    string(APPEND FALLBACK_CFLAGS " -fsanitize=address -fsanitize-address-use-after-scope")
  elseif("$ENV{SANITIZER}" STREQUAL "undefined")
    string(APPEND FALLBACK_CFLAGS " -fsanitize=undefined -fno-sanitize-recover=undefined")
  elseif("$ENV{SANITIZER}" STREQUAL "memory")
    string(APPEND FALLBACK_CFLAGS " -fsanitize=memory -fsanitize-memory-track-origins=2")
  endif()
endif()

# Compatible with ClusterFuzzLite.
if(NOT DEFINED ENV{LIB_FUZZING_ENGINE})
    set(COMPILATION_FLAGS_ "-g -Wall -fsanitize=fuzzer,address,undefined")
else()
    set(COMPILATION_FLAGS_ "$ENV{LIB_FUZZING_ENGINE} $ENV{CFLAGS}")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

string(REPLACE " " ";" COMPILATION_FLAGS ${COMPILATION_FLAGS_})

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
set(APP_SRC    ${CMAKE_CURRENT_SOURCE_DIR}/../src)
if(DEFINED BOLOS_SDK)
    set(LEDGER_SDK ${BOLOS_SDK})
else()
    set(LEDGER_SDK ${CMAKE_CURRENT_SOURCE_DIR}/../../ledger-secure-sdk)
endif()

# ---------------------------------------------------------------------------
# Sources compiled into every fuzz target.
# Excludes: globals.c (defined in stubs.c), concordium_crypto.c (stubbed),
#           set_trusted_name.c (stubbed), apdu_response.c (stubbed),
#           display_bagl.c / display_nbgl.c (stubbed).
# ---------------------------------------------------------------------------
set(TINYCBOR_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../deps/tinycbor/src/cborparser.c)
# cborparser.c uses intentional fall-throughs; suppress only for this file.
set_source_files_properties(${TINYCBOR_SRC} PROPERTIES COMPILE_FLAGS "-Wno-implicit-fallthrough")

set(SHARED_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/stubs/stubs.c
    ${LEDGER_SDK}/lib_standard_app/format.c
    ${APP_SRC}/helpers/base58check.c
    ${APP_SRC}/helpers/cbor_data_blob.c
    ${TINYCBOR_SRC}
    ${APP_SRC}/helpers/derivation_path.c
    ${APP_SRC}/helpers/fee_display.c
    ${APP_SRC}/helpers/numberHelpers.c
    ${APP_SRC}/helpers/sign_transfer_schedule.c
    ${APP_SRC}/helpers/time.c
    ${APP_SRC}/helpers/tx_hash.c
)

# ---------------------------------------------------------------------------
# Include directories (same for all targets).
# stubs/ledger shadows the Ledger SDK headers (os.h, cx.h, io.h, …).
# stubs/ provides buffer.h, tlv_library.h, glyphs.h.
# ---------------------------------------------------------------------------
set(FUZZ_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/stubs/ledger
    ${CMAKE_CURRENT_SOURCE_DIR}/stubs
    ${APP_SRC}
    ${APP_SRC}/helpers
    ${APP_SRC}/handler
    ${APP_SRC}/apdu
    ${APP_SRC}/ui
    ${LEDGER_SDK}/lib_standard_app
    ${CMAKE_CURRENT_SOURCE_DIR}/../deps/tinycbor/src
)

# ---------------------------------------------------------------------------
# Helper: build one fuzz target.
# Usage: add_fuzz_target(<name> [extra_source ...])
# The fuzzer harness is always src/<name>.c; pass the handler .c as extra.
# ---------------------------------------------------------------------------
function(add_fuzz_target TARGET)
    set(EXTRA_SOURCES ${ARGN})
    add_executable(${TARGET}
        src/${TARGET}.c
        ${EXTRA_SOURCES}
        ${SHARED_SOURCES}
    )
    target_include_directories(${TARGET} PRIVATE ${FUZZ_INCLUDE_DIRS})
    target_compile_options(${TARGET} PUBLIC ${COMPILATION_FLAGS})
    target_link_options(${TARGET} PUBLIC ${COMPILATION_FLAGS})
endfunction()

# ---------------------------------------------------------------------------
# Fuzz targets
# cbor_data_blob_fuzzer has no dedicated handler; cbor_data_blob.c is shared.
# ---------------------------------------------------------------------------
add_fuzz_target(standalone_cbor_data_blob_fuzzer)

add_fuzz_target(standalone_export_pk_legacy_path_fuzzer
    ${APP_SRC}/handler/export_private_key_legacy_path.c)

add_fuzz_target(standalone_export_pk_new_path_fuzzer
    ${APP_SRC}/handler/export_private_key_new_path.c)

add_fuzz_target(standalone_get_public_key_fuzzer
    ${APP_SRC}/handler/get_public_key.c)

add_fuzz_target(standalone_verify_address_fuzzer
    ${APP_SRC}/handler/verify_address.c)

add_fuzz_target(standalone_sign_transfer_fuzzer
    ${APP_SRC}/handler/sign_transfer.c)

add_fuzz_target(standalone_sign_transfer_to_public_fuzzer
    ${APP_SRC}/handler/sign_transfer_to_public.c)

add_fuzz_target(standalone_sign_transfer_with_memo_fuzzer
    ${APP_SRC}/handler/sign_transfer_with_memo.c)

add_fuzz_target(standalone_sign_transfer_with_schedule_fuzzer
    ${APP_SRC}/handler/sign_transfer_with_schedule.c)

add_fuzz_target(standalone_sign_transfer_with_schedule_and_memo_fuzzer
    ${APP_SRC}/handler/sign_transfer_with_schedule_and_memo.c)

add_fuzz_target(standalone_sign_configure_baker_fuzzer
    ${APP_SRC}/handler/sign_configure_baker.c)

add_fuzz_target(standalone_sign_configure_delegation_fuzzer
    ${APP_SRC}/handler/sign_configure_delegation.c)

add_fuzz_target(standalone_sign_update_credential_fuzzer
    ${APP_SRC}/handler/sign_update_credential.c
    ${APP_SRC}/handler/sign_credential_deployment.c)

add_fuzz_target(standalone_sign_credential_deployment_fuzzer
    ${APP_SRC}/handler/sign_credential_deployment.c)

add_fuzz_target(standalone_sign_public_information_for_ip_fuzzer
    ${APP_SRC}/handler/sign_public_information_for_ip.c)

add_fuzz_target(standalone_sign_register_data_fuzzer
    ${APP_SRC}/handler/sign_register_data.c)

add_fuzz_target(standalone_deploy_module_fuzzer
    ${APP_SRC}/handler/deploy_module.c)

add_fuzz_target(standalone_init_contract_fuzzer
    ${APP_SRC}/handler/init_contract.c)

add_fuzz_target(standalone_update_contract_fuzzer
    ${APP_SRC}/handler/update_contract.c)
