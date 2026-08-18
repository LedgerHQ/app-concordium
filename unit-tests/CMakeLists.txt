cmake_minimum_required(VERSION 3.10)
project(ConcordiumUnitTests LANGUAGES C)

find_package(cmocka REQUIRED)

set(APP_SRC       ${CMAKE_CURRENT_SOURCE_DIR}/../src)
set(FUZZ_STUBS    ${CMAKE_CURRENT_SOURCE_DIR}/../fuzzing/stubs)
set(TINYCBOR_SRC  ${CMAKE_CURRENT_SOURCE_DIR}/../deps/tinycbor/src)

if(DEFINED BOLOS_SDK)
    set(LEDGER_SDK ${BOLOS_SDK})
else()
    set(LEDGER_SDK ${CMAKE_CURRENT_SOURCE_DIR}/../../ledger-secure-sdk)
endif()

# FUZZ_STUBS/ledger shadows the real SDK headers with host-compatible stubs.
# FUZZ_STUBS provides buffer.h, tlv_library.h, glyphs.h pulled in by instruction_context.h.
set(UNIT_INCLUDES
    ${FUZZ_STUBS}/ledger
    ${FUZZ_STUBS}
    ${APP_SRC}
    ${APP_SRC}/helpers
    ${APP_SRC}/handler
    ${LEDGER_SDK}/lib_standard_app
    ${TINYCBOR_SRC}
)

set(COMPILE_FLAGS -std=gnu11 --coverage -O0 -g -Wall -Wextra)

# ---------------------------------------------------------------------------
# test_cbor_data_blob
# ---------------------------------------------------------------------------
add_executable(test_cbor_data_blob
    test_cbor_data_blob.c
    stubs.c
    ${APP_SRC}/helpers/cbor_data_blob.c
    ${APP_SRC}/helpers/numberHelpers.c
    ${LEDGER_SDK}/lib_standard_app/format.c
    ${TINYCBOR_SRC}/cborparser.c
)
target_include_directories(test_cbor_data_blob PRIVATE ${UNIT_INCLUDES})
target_compile_options(test_cbor_data_blob PRIVATE ${COMPILE_FLAGS})
target_link_libraries(test_cbor_data_blob PRIVATE cmocka)
target_link_options(test_cbor_data_blob PRIVATE --coverage)

include(CTest)
add_test(NAME test_cbor_data_blob COMMAND test_cbor_data_blob)
