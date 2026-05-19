#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "buffer.h"

/* ── TLV types (mirrors ledger-secure-sdk/lib_tlv/) ──────────────────── */

typedef uint32_t TLV_tag_t;
typedef uint64_t TLV_flag_t;
typedef TLV_flag_t(tag_to_flag_function_t)(TLV_tag_t tag);

typedef struct {
    TLV_flag_t              flags;
    tag_to_flag_function_t *tag_to_flag_function;
} TLV_reception_internal_t;
typedef TLV_reception_internal_t TLV_reception_t;

typedef enum { ENFORCE_UNIQUE_TAG, ALLOW_MULTIPLE_TAG } tag_unicity_t;

typedef struct {
    TLV_tag_t tag;
    buffer_t  value;
    buffer_t  raw;
} tlv_data_t;

typedef bool(tlv_handler_cb_t)(const tlv_data_t *data, void *tlv_extracted);

typedef struct {
    TLV_tag_t         tag;
    tlv_handler_cb_t *func;
    bool              is_unique;
} _internal_tlv_handler_t;

bool _parse_tlv_internal(const _internal_tlv_handler_t *handlers,
                         uint8_t                        handlers_count,
                         tlv_handler_cb_t              *common_handler,
                         tag_to_flag_function_t        *tag_to_flag_function,
                         const buffer_t                *payload,
                         void                          *tlv_out,
                         TLV_reception_t               *received_tags_flags);

bool tlv_check_received_tags(TLV_reception_t received, const TLV_tag_t *tags, size_t tag_count);
bool tlv_enforce_u8_value(const tlv_data_t *data, uint8_t expected_value);
bool get_uint64_t_from_tlv_data(const tlv_data_t *data, uint64_t *value);
bool get_uint32_t_from_tlv_data(const tlv_data_t *data, uint32_t *value);
bool get_uint16_t_from_tlv_data(const tlv_data_t *data, uint16_t *value);
bool get_uint8_t_from_tlv_data(const tlv_data_t *data, uint8_t *value);
bool get_bool_from_tlv_data(const tlv_data_t *data, bool *value);
bool get_buffer_from_tlv_data(const tlv_data_t *data, buffer_t *out,
                               uint16_t min_size, uint16_t max_size);
bool get_string_from_tlv_data(const tlv_data_t *data, char *out,
                               uint16_t min_length, uint16_t out_size);

/* CHECK_RECEIVED_TAGS variadic wrapper */
#define TLV_CHECK_RECEIVED_TAGS(received, ...)          \
    tlv_check_received_tags(received,                   \
                            (TLV_tag_t[]){__VA_ARGS__}, \
                            sizeof((TLV_tag_t[]){__VA_ARGS__}) / sizeof(TLV_tag_t))

/* ── X-macro helpers used by DEFINE_TLV_PARSER ───────────────────────── */
#define __X_DEFINE_TLV__TAG_ASSIGN(value, name, callback, unicity) name = value,
#define __X_DEFINE_TLV__TAG_INDEX(value, name, callback, unicity)  name##_INDEX,
#define __X_DEFINE_TLV__TAG_FLAG(value, name, callback, unicity) \
    name##_FLAG = ((TLV_flag_t)1 << name##_INDEX),
#define __X_DEFINE_TLV__TAG_TO_FLAG_CASE(value, name, callback, unicity) \
    case name: return name##_FLAG;
#define __X_DEFINE_TLV__TAG_CALLBACKS(value, name, callback, unicity) \
    {.tag = name, .func = (tlv_handler_cb_t *)(callback), .is_unique = ((unicity) == ENFORCE_UNIQUE_TAG)},

/* DEFINE_TLV_PARSER: expands to enums + inline parser function */
#define DEFINE_TLV_PARSER(TAG_LIST, COMMON_HANDLER, PARSE_FUNCTION_NAME)    \
    enum { TAG_LIST(__X_DEFINE_TLV__TAG_ASSIGN) };                           \
    enum { TAG_LIST(__X_DEFINE_TLV__TAG_INDEX) PARSE_FUNCTION_NAME##_TAG_COUNT, }; \
    _Static_assert(PARSE_FUNCTION_NAME##_TAG_COUNT <= sizeof(TLV_flag_t) * 8, \
                   "Too many tags");                                         \
    enum { TAG_LIST(__X_DEFINE_TLV__TAG_FLAG) };                             \
    static inline TLV_flag_t PARSE_FUNCTION_NAME##_tag_to_flag(TLV_tag_t tag) { \
        switch (tag) { TAG_LIST(__X_DEFINE_TLV__TAG_TO_FLAG_CASE) default: return 0; } \
    }                                                                        \
    static inline bool PARSE_FUNCTION_NAME(const buffer_t *payload,         \
                                           void *tlv_out,                   \
                                           TLV_reception_t *received_tags_flags) { \
        _internal_tlv_handler_t handlers[PARSE_FUNCTION_NAME##_TAG_COUNT] = { \
            TAG_LIST(__X_DEFINE_TLV__TAG_CALLBACKS) };                      \
        return _parse_tlv_internal(handlers, PARSE_FUNCTION_NAME##_TAG_COUNT, \
                                   (tlv_handler_cb_t *)COMMON_HANDLER,       \
                                   PARSE_FUNCTION_NAME##_tag_to_flag,        \
                                   payload, tlv_out, received_tags_flags);   \
    }
