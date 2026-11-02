// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#ifndef CHAT_UTIL_H
#define CHAT_UTIL_H

#include <stddef.h>
#include <stdint.h>

#define COUNT_OF(a) (sizeof (a) / sizeof (a)[0])

// A printf-like function, its format string the fmt-th argument and what it formats from the args-th,
// so the compiler checks each call.
#if defined(__GNUC__) || defined(__clang__)
#define PRINTF_LIKE(fmt, args) __attribute__((format(printf, fmt, args)))
#else
#define PRINTF_LIKE(fmt, args)
#endif

// " · ", between the parts of a line.
#define DOT_SEP " \xc2\xb7 "

#define HEX_DIGITS "0123456789abcdef"
void hex_encode(const uint8_t *in, size_t len, char *out);
// Lowercase only, as hex_encode writes it, so a value has one spelling.
int hex_decode(const char *in, size_t hexlen, uint8_t *out);
// A hex digit's value, in either case, or -1.
int hex_value(char c);
// Hex in groups of four digits, "a1b2 c3d4 ...", for codes people read out to each other.
#define HEX_GROUPS_LEN(n) ((n) * 2 + (n) / 2 + 1)
void hex_groups(const uint8_t *in, size_t len, char *out);

size_t clean_text(const char *in, char *out, size_t max_len);

// True if the text holds any character clean_text strips: control, C1 or bidi controls.
int has_control_chars(const char *in);

// Links in a message: http:// and https:// addresses, and domain names, with a path or without.
// LINK_URL_MAX holds the address one opens, with its NUL; a longer one isn't a link.
#define LINK_URL_MAX 1024
// The first link in s (n bytes) from *from on: where it starts (*at) and its length. *from goes
// past it. 0 once there are no more.
int link_next(const char *s, size_t n, size_t *from, size_t *at, size_t *len);
// The address a link opens: as written with http:// or https://, otherwise https:// before it, with
// each byte past ASCII, '$' and '\'' %-encoded. 0, or -1 (and "") if it doesn't fit in cap.
int link_target(const char *link, size_t n, char *out, size_t cap);

// The length of the @nick at s if it names nick (any case, and not run on into a longer name, so
// "@ann," names ann but "@anna" and "@ann-2" don't), or 0.
size_t mention_len(const char *s, const char *nick);

void random_session_id(char *out, size_t len);
// A session id in the same letters from n, for one worked out rather than made up.
void session_id_from(uint64_t n, char *out, size_t len);

#define BASE64_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
// The characters base64_encode writes for n bytes, without its NUL.
#define BASE64_LEN(n) (((n) + 2) / 3 * 4)
size_t base64_encode(const uint8_t *in, size_t n, char *out);
// A character's value in the standard base64 alphabet, or -1.
int base64_value(char c);

// Strict: padded standard alphabet only. Returns the decoded length, or -1.
long base64_decode_strict(const char *in, size_t inlen, uint8_t *out, size_t cap);

// RFC 4648's base32, unpadded, as authenticator apps take a secret. out needs BASE32_LEN(n).
#define BASE32_LEN(n) (((n) * 8 + 4) / 5 + 1)
size_t base32_encode(const uint8_t *in, size_t n, char *out);

// A code point UTF-8 can hold: not past U+10FFFF, and not a UTF-16 surrogate.
#define UNICODE_MAX 0x10ffffu
int is_unicode_scalar(uint32_t cp);
// Code point at s[i] (n = length of s). *adv gets its length in bytes. A malformed byte is returned as is.
uint32_t utf8_decode(const char *s, size_t n, size_t i, size_t *adv);
#define UTF8_CHAR_MAX 4
// Writes cp as UTF-8 (1 to UTF8_CHAR_MAX bytes) and returns the length.
size_t utf8_put(uint32_t cp, char *out);
// A byte that carries on a character, not one that starts it.
static inline int utf8_is_cont(unsigned char c) { return (c & 0xc0) == 0x80; }
// The length of the character a byte starts, or 0 if it can't start one.
static inline size_t utf8_lead_len(unsigned char c) {
    return c < 0x80 ? 1 : (c & 0xe0) == 0xc0 ? 2 : (c & 0xf0) == 0xe0 ? 3 : (c & 0xf8) == 0xf0 ? 4 : 0;
}
// C0 and C1 control characters, and DEL.
static inline int is_control_cp(uint32_t cp) { return cp < 0x20 || cp == 0x7f || (cp >= 0x80 && cp <= 0x9f); }

// Terminal columns the character at s[i] takes (0 for combining marks and zero-width characters,
// 2 for East Asian wide ones and emoji). *adv gets its length in bytes. A locale free version of
// wcwidth. A malformed byte or a control character counts as one column, since the UI shows a
// replacement character in its place.
int utf8_char_cols(const char *s, size_t n, size_t i, size_t *adv);
// The same for a character already decoded from more than one byte.
int utf8_cp_cols(uint32_t cp);
// How many bytes of s (at most len) fit in max_cols columns, stopping on a character boundary.
// *cols (if not NULL) gets the number of columns they take.
size_t utf8_fit_cols(const char *s, size_t len, int max_cols, int *cols);
int utf8_str_cols(const char *s);

void random_nickname(char *out, size_t out_cap);

double now_seconds(void);

void copy_str(char *dst, const char *src, size_t dstsize);
int starts_with(const char *s, const char *prefix);

// A retry delay: base, doubled for each try up to max_shift times, and never more than cap.
double backoff(int tries, double base, int max_shift, double cap);

// "HH:MM" and "YYYY-MM-DD HH:MM", local time. The lengths include the NUL. A stamp's date is
// DATE_LEN long, then a space and the time.
#define HHMM_LEN 6
#define STAMP_LEN 17
#define DATE_LEN 10
void current_hhmm(char out[HHMM_LEN]);
void current_stamp(char out[STAMP_LEN]);
// The stamp for a time (seconds since 1970).
void stamp_at(long long t, char out[STAMP_LEN]);

static inline uint16_t load_be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline uint32_t load_be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static inline uint64_t load_be64(const uint8_t *p) { return (uint64_t)load_be32(p) << 32 | load_be32(p + 4); }
static inline void store_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}
static inline void store_be64(uint8_t *p, uint64_t v) {
    store_be32(p, (uint32_t)(v >> 32));
    store_be32(p + 4, (uint32_t)v);
}

#endif
