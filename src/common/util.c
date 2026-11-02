// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "common/util.h"
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

#define BASE64_GROUP 3   // bytes in each four characters
#define BASE64_QUAD 4
#define BASE32_BITS 5

static const char B64CH[] = BASE64_CHARS;

size_t base64_encode(const uint8_t *in, size_t n, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < n; i += BASE64_GROUP) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = B64CH[(v >> 18) & 0x3f];
        out[o++] = B64CH[(v >> 12) & 0x3f];
        out[o++] = (i + 1 < n) ? B64CH[(v >> 6) & 0x3f] : '=';
        out[o++] = (i + 2 < n) ? B64CH[v & 0x3f] : '=';
    }
    out[o] = '\0';
    return o;
}

int base64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    return c == '+' ? 62 : c == '/' ? 63 : -1;
}

size_t base32_encode(const uint8_t *in, size_t n, char *out) {
    static const char B32CH[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const uint32_t mask = (1u << BASE32_BITS) - 1;
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        acc = acc << 8 | in[i];
        bits += 8;
        while (bits >= BASE32_BITS) { out[o++] = B32CH[(acc >> (bits - BASE32_BITS)) & mask]; bits -= BASE32_BITS; }
    }
    if (bits > 0) out[o++] = B32CH[(acc << (BASE32_BITS - bits)) & mask];
    out[o] = '\0';
    return o;
}

long base64_decode_strict(const char *in, size_t inlen, uint8_t *out, size_t cap) {
    if (inlen % BASE64_QUAD != 0) return -1;
    size_t o = 0;
    for (size_t i = 0; i < inlen; i += BASE64_QUAD) {
        uint32_t v = 0;
        int pad = 0;
        for (int k = 0; k < BASE64_QUAD; k++) {
            char ch = in[i + k];
            int six = base64_value(ch);
            if (ch == '=' && i + BASE64_QUAD == inlen && k >= 2 && (k == 3 || in[i + 3] == '=')) { pad++; v <<= 6; continue; }
            if (six < 0 || pad) return -1;
            v = (v << 6) | (uint32_t)six;
        }
        for (int k = 0; k < BASE64_GROUP - pad; k++) {
            if (o >= cap) return -1;
            out[o++] = (uint8_t)(v >> (16 - 8 * k));
        }
    }
    return (long)o;
}

void hex_encode(const uint8_t *in, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = HEX_DIGITS[in[i] >> 4];
        out[i * 2 + 1] = HEX_DIGITS[in[i] & 0xf];
    }
    out[len * 2] = '\0';
}

void hex_groups(const uint8_t *in, size_t len, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        if (i > 0 && i % 2 == 0) out[o++] = ' ';
        out[o++] = HEX_DIGITS[in[i] >> 4];
        out[o++] = HEX_DIGITS[in[i] & 0xf];
    }
    out[o] = '\0';
}

static int hex_lower(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

int hex_value(char c) {
    int v = hex_lower(c);
    return v >= 0 ? v : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

int hex_decode(const char *in, size_t hexlen, uint8_t *out) {
    if (strlen(in) != hexlen || hexlen % 2 != 0) return -1;
    for (size_t i = 0; i < hexlen / 2; i++) {
        int hi = hex_lower(in[i * 2]), lo = hex_lower(in[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int is_unicode_scalar(uint32_t cp) { return cp <= UNICODE_MAX && !(cp >= 0xd800 && cp <= 0xdfff); }

// Strict: overlong forms, surrogates and anything past U+10FFFF are malformed. Decoding those
// leniently would let e.g. C1 9B through as '[' while an 8-bit terminal reads the 9B as CSI.
static uint32_t utf8_next(const unsigned char *s, size_t n, size_t i, size_t *adv) {
    static const uint32_t MIN_CP[UTF8_CHAR_MAX + 1] = { 0, 0, 0x80, 0x800, 0x10000 };
    unsigned char c = s[i];
    size_t len = utf8_lead_len(c);
    if (len <= 1 || i + len > n) { *adv = 1; return c; }
    // The lead byte's own bits: those after its len ones and a zero.
    uint32_t cp = c & (0x7fu >> len);
    for (size_t k = 1; k < len; k++) {
        unsigned char cc = s[i + k];
        if (!utf8_is_cont(cc)) { *adv = 1; return c; }
        cp = (cp << 6) | (cc & 0x3f);
    }
    if (cp < MIN_CP[len] || !is_unicode_scalar(cp)) { *adv = 1; return c; }
    *adv = len;
    return cp;
}

uint32_t utf8_decode(const char *s, size_t n, size_t i, size_t *adv) {
    return utf8_next((const unsigned char *)s, n, i, adv);
}

size_t utf8_put(uint32_t cp, char *out) {
    if (cp < 0x80) { out[0] = (char)cp; return 1; }
    if (cp < 0x800) { out[0] = (char)(0xc0 | (cp >> 6)); out[1] = (char)(0x80 | (cp & 0x3f)); return 2; }
    if (cp < 0x10000) {
        out[0] = (char)(0xe0 | (cp >> 12)); out[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
        out[2] = (char)(0x80 | (cp & 0x3f)); return 3;
    }
    out[0] = (char)(0xf0 | (cp >> 18)); out[1] = (char)(0x80 | ((cp >> 12) & 0x3f));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3f)); out[3] = (char)(0x80 | (cp & 0x3f));
    return 4;
}

typedef struct { uint32_t lo, hi; } cp_range_t;

static int in_ranges(uint32_t cp, const cp_range_t *r, size_t n) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (cp < r[mid].lo) hi = mid;
        else if (cp > r[mid].hi) lo = mid + 1;
        else return 1;
    }
    return 0;
}

// Sorted. Combining marks and characters that take no column.
static const cp_range_t ZERO_WIDTH[] = {
    { 0x0300, 0x036f }, { 0x0483, 0x0489 }, { 0x0591, 0x05bd }, { 0x05bf, 0x05bf }, { 0x05c1, 0x05c2 },
    { 0x05c4, 0x05c5 }, { 0x05c7, 0x05c7 }, { 0x0610, 0x061a }, { 0x064b, 0x065f }, { 0x0670, 0x0670 },
    { 0x06d6, 0x06dc }, { 0x06df, 0x06e4 }, { 0x06e7, 0x06e8 }, { 0x06ea, 0x06ed }, { 0x0e31, 0x0e31 },
    { 0x0e34, 0x0e3a }, { 0x0e47, 0x0e4e }, { 0x1ab0, 0x1aff }, { 0x1dc0, 0x1dff }, { 0x200b, 0x200f },
    { 0x202a, 0x202e }, { 0x2060, 0x2064 }, { 0x20d0, 0x20ff }, { 0xfe00, 0xfe0f }, { 0xfe20, 0xfe2f },
    { 0xfeff, 0xfeff }, { 0xe0000, 0xe007f }, { 0xe0100, 0xe01ef },
};

// Sorted. East Asian wide and fullwidth ranges, and emoji that terminals draw two columns wide.
static const cp_range_t WIDE[] = {
    { 0x1100, 0x115f }, { 0x231a, 0x231b }, { 0x2329, 0x232a }, { 0x23e9, 0x23ec }, { 0x23f0, 0x23f0 },
    { 0x23f3, 0x23f3 }, { 0x25fd, 0x25fe }, { 0x2614, 0x2615 }, { 0x2648, 0x2653 }, { 0x267f, 0x267f },
    { 0x2693, 0x2693 }, { 0x26a1, 0x26a1 }, { 0x26aa, 0x26ab }, { 0x26bd, 0x26be }, { 0x26c4, 0x26c5 },
    { 0x26ce, 0x26ce }, { 0x26d4, 0x26d4 }, { 0x26ea, 0x26ea }, { 0x26f2, 0x26f3 }, { 0x26f5, 0x26f5 },
    { 0x26fa, 0x26fa }, { 0x26fd, 0x26fd }, { 0x2705, 0x2705 }, { 0x270a, 0x270b }, { 0x2728, 0x2728 },
    { 0x274c, 0x274c }, { 0x274e, 0x274e }, { 0x2753, 0x2755 }, { 0x2757, 0x2757 }, { 0x2795, 0x2797 },
    { 0x27b0, 0x27b0 }, { 0x27bf, 0x27bf }, { 0x2b1b, 0x2b1c }, { 0x2b50, 0x2b50 }, { 0x2b55, 0x2b55 },
    { 0x2e80, 0x303e }, { 0x3041, 0x33ff }, { 0x3400, 0x4dbf }, { 0x4e00, 0x9fff }, { 0xa000, 0xa4cf },
    { 0xa960, 0xa97f }, { 0xac00, 0xd7a3 }, { 0xf900, 0xfaff }, { 0xfe10, 0xfe19 }, { 0xfe30, 0xfe6f },
    { 0xff00, 0xff60 }, { 0xffe0, 0xffe6 }, { 0x16fe0, 0x18cff }, { 0x1b000, 0x1b2ff }, { 0x1f004, 0x1f004 },
    { 0x1f0cf, 0x1f0cf }, { 0x1f18e, 0x1f18e }, { 0x1f191, 0x1f19a }, { 0x1f200, 0x1f251 }, { 0x1f300, 0x1f64f },
    { 0x1f680, 0x1f6ff }, { 0x1f7e0, 0x1f7eb }, { 0x1f90c, 0x1f9ff }, { 0x1fa70, 0x1faff }, { 0x20000, 0x3fffd },
};

int utf8_cp_cols(uint32_t cp) {
    if (cp < 0x80) return 1;
    if (in_ranges(cp, ZERO_WIDTH, COUNT_OF(ZERO_WIDTH))) return 0;
    return in_ranges(cp, WIDE, COUNT_OF(WIDE)) ? 2 : 1;
}

int utf8_char_cols(const char *s, size_t n, size_t i, size_t *adv) {
    uint32_t cp = utf8_next((const unsigned char *)s, n, i, adv);
    return *adv == 1 ? 1 : utf8_cp_cols(cp);
}

size_t utf8_fit_cols(const char *s, size_t len, int max_cols, int *cols) {
    size_t i = 0;
    int used = 0;
    while (i < len && s[i]) {
        size_t adv;
        int w = utf8_char_cols(s, len, i, &adv);
        if (used + w > max_cols) break;
        used += w;
        i += adv;
    }
    if (cols) *cols = used;
    return i;
}

int utf8_str_cols(const char *s) {
    int cols;
    utf8_fit_cols(s, strlen(s), INT_MAX, &cols);
    return cols;
}

static int is_stripped(uint32_t cp) {
    if (is_control_cp(cp)) return 1;
    if (cp == 0x61c || cp == 0x200e || cp == 0x200f) return 1;
    if (cp >= 0x202a && cp <= 0x202e) return 1;
    if (cp >= 0x2066 && cp <= 0x2069) return 1;
    return 0;
}

int has_control_chars(const char *in) {
    size_t n = strlen(in), i = 0;
    const unsigned char *s = (const unsigned char *)in;
    while (i < n) {
        size_t adv;
        if (is_stripped(utf8_next(s, n, i, &adv))) return 1;
        i += adv;
    }
    return 0;
}

static int is_space(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

size_t clean_text(const char *in, char *out, size_t max_len) {
    size_t n = strlen(in), i = 0, o = 0;
    const unsigned char *s = (const unsigned char *)in;
    while (i < n) {
        size_t adv;
        uint32_t cp = utf8_next(s, n, i, &adv);
        // A lone byte of 0x80 or more is malformed and dropped, so the result is always valid UTF-8.
        if (!is_stripped(cp) && !(adv == 1 && cp >= 0x80)) {
            if (o + adv > max_len) break;
            memcpy(out + o, s + i, adv);
            o += adv;
        }
        i += adv;
    }

    while (o > 0 && is_space(out[o - 1])) o--;
    size_t lead = 0;
    while (lead < o && is_space(out[lead])) lead++;
    if (lead > 0) { memmove(out, out + lead, o - lead); o -= lead; }
    out[o] = '\0';
    return o;
}

static int ascii_alnum(char c) { return (c >= '0' && c <= '9') || ((c | 0x20) >= 'a' && (c | 0x20) <= 'z'); }

// What a link holds past its host: anything printable but a space and what RFC 3986 never leaves
// unencoded, and the bytes of characters past ASCII, which clean_text has rid of controls and bidi marks.
static int link_byte(unsigned char c) { return c >= 0x80 || (c > ' ' && c < 0x7f && !strchr("\"<>\\^`{|}", c)); }

static size_t scheme_len(const char *s, size_t n) {
    static const char *const SCHEMES[] = { "https://", "http://" };
    for (size_t k = 0; k < COUNT_OF(SCHEMES); k++) {
        const char *p = SCHEMES[k];
        size_t i = 0;
        while (p[i] && i < n && (s[i] == p[i] || (p[i] >= 'a' && s[i] == p[i] - 'a' + 'A'))) i++;
        if (!p[i]) return i;
    }
    return 0;
}

// Two or more labels of letters, digits and '-' (not first or last), the last of them two or more
// letters in one case, so "e.g", "v0.5.3" and "end.Next" aren't names. Its length, or 0.
static size_t domain_len(const char *s, size_t n) {
    size_t i = 0, last = 0, end = 0;
    int labels = 0;
    for (;;) {
        size_t st = i;
        while (i < n && (ascii_alnum(s[i]) || s[i] == '-')) i++;
        if (i == st || s[st] == '-' || s[i - 1] == '-') break;
        labels++;
        last = st;
        end = i;
        if (i + 1 < n && s[i] == '.' && ascii_alnum(s[i + 1])) i++;
        else break;
    }
    if (labels < 2 || end - last < 2) return 0;
    int lower = 0, upper = 0;
    for (size_t k = last; k < end; k++) {
        if (s[k] >= 'a' && s[k] <= 'z') lower = 1;
        else if (s[k] >= 'A' && s[k] <= 'Z') upper = 1;
        else return 0;
    }
    return lower && upper ? 0 : end;
}

// A name starts a link only where it isn't the rest of a word, a path, an address or another link
// ("ida@ieji.de", "~/notes.md"). Past ASCII, the character before could be a letter.
static int name_starts(const char *s, size_t i) {
    if (i == 0) return 1;
    unsigned char c = (unsigned char)s[i - 1];
    return c < 0x80 && !ascii_alnum((char)c) && !strchr("-_.@/\\:~#$%&+=", c);
}

static int name_ends(const char *s, size_t n, size_t e) {
    if (e >= n) return 1;
    if (strchr("@_-", s[e])) return 0;
    return !(s[e] == '.' && e + 1 < n && (ascii_alnum(s[e + 1]) || strchr("_-", s[e + 1])));
}

// Leaves off what's around a link rather than in it: a sentence's punctuation after it, and a bracket
// it didn't open, as in "(see example.com)". Never before min.
static size_t link_trim(const char *s, size_t start, size_t end, size_t min) {
    // ” ’ » … 。 ）
    static const char *const CLOSERS[] = { "\xe2\x80\x9d", "\xe2\x80\x99", "\xc2\xbb", "\xe2\x80\xa6", "\xe3\x80\x82",
                                           "\xef\xbc\x89" };
    for (;;) {
        if (end <= min) return end;
        char c = s[end - 1];
        if (strchr(".,;:!?'*", c)) { end--; continue; }
        if (c == ')' || c == ']') {
            char open = c == ')' ? '(' : '[';
            int depth = 0;
            for (size_t k = start; k < end; k++) depth += s[k] == open ? 1 : s[k] == c ? -1 : 0;
            if (depth < 0) { end--; continue; }
        }
        size_t cut = 0;
        for (size_t k = 0; k < COUNT_OF(CLOSERS) && !cut; k++) {
            size_t l = strlen(CLOSERS[k]);
            if (end - min >= l && memcmp(s + end - l, CLOSERS[k], l) == 0) cut = l;
        }
        if (!cut) return end;
        end -= cut;
    }
}

// What the address a link opens %-encodes: bytes past ASCII, and what a shell reads inside quotes,
// since xdg-open can pass it through eval.
static int target_encodes(unsigned char c) { return c >= 0x80 || c == '$' || c == '\''; }

static size_t target_len(const char *link, size_t n) {
    size_t len = scheme_len(link, n) ? 0 : sizeof "https://" - 1;
    for (size_t i = 0; i < n; i++) len += target_encodes((unsigned char)link[i]) ? 3 : 1;
    return len;
}

int link_next(const char *s, size_t n, size_t *from, size_t *at, size_t *len) {
    for (size_t i = *from; i < n; i++) {
        size_t e, sl = scheme_len(s + i, n - i);
        if (sl && (i == 0 || !ascii_alnum(s[i - 1])) && i + sl < n && (ascii_alnum(s[i + sl]) || s[i + sl] == '[')) {
            for (e = i + sl; e < n && link_byte((unsigned char)s[e]); e++) {}
            e = link_trim(s, i, e, i + sl + 1);
        } else if (ascii_alnum(s[i]) && name_starts(s, i)) {
            size_t d = domain_len(s + i, n - i);
            if (!d || !name_ends(s, n, i + d)) continue;
            e = i + d;
            if (e < n && strchr("/?#", s[e])) {
                size_t p = e;
                while (p < n && link_byte((unsigned char)s[p])) p++;
                e = link_trim(s, i, p, e);
            }
        } else {
            continue;
        }
        if (target_len(s + i, e - i) >= LINK_URL_MAX) { i = e - 1; continue; }
        *at = i;
        *len = e - i;
        *from = e;
        return 1;
    }
    *from = n;
    return 0;
}

int link_target(const char *link, size_t n, char *out, size_t cap) {
    static const char HEX_UPPER[] = "0123456789ABCDEF";
    if (target_len(link, n) >= cap) {
        if (cap) out[0] = '\0';
        return -1;
    }
    size_t o = 0;
    if (!scheme_len(link, n)) for (const char *p = "https://"; *p; p++) out[o++] = *p;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)link[i];
        if (!target_encodes(c)) { out[o++] = (char)c; continue; }
        out[o++] = '%';
        out[o++] = HEX_UPPER[c >> 4];
        out[o++] = HEX_UPPER[c & 15];
    }
    out[o] = '\0';
    return 0;
}

size_t mention_len(const char *s, const char *nick) {
    size_t n = strlen(nick);
    if (s[0] != '@' || n == 0) return 0;
    for (size_t i = 0; i < n; i++)
        if (tolower((unsigned char)s[1 + i]) != tolower((unsigned char)nick[i])) return 0;
    const char *rest = s + 1 + n;
    size_t adv;
    uint32_t cp = utf8_decode(rest, strlen(rest), 0, &adv);
    // Accented Latin letters go on a name too; other scripts, symbols and emoji end it, so a mention
    // can run into the next word where there are no spaces.
    int name = cp < 0x80 ? isalnum((int)cp) || cp == '-' || cp == '_'
                         : cp >= 0xc0 && cp <= 0x24f && cp != 0xd7 && cp != 0xf7;
    return name ? 0 : 1 + n;
}

#define SESSION_ID_MAX 64

static const char SID_ALPHABET[] = "23456789ABCDEFGHJKMNPQRSTVWXYZ";

void random_session_id(char *out, size_t len) {
    if (len > SESSION_ID_MAX) len = SESSION_ID_MAX;
    // randombytes_uniform has no modulo bias, so every character carries the full log2(30) bits.
    for (size_t i = 0; i < len; i++)
        out[i] = SID_ALPHABET[randombytes_uniform((uint32_t)(sizeof(SID_ALPHABET) - 1))];
    out[len] = '\0';
}

void session_id_from(uint64_t n, char *out, size_t len) {
    if (len > SESSION_ID_MAX) len = SESSION_ID_MAX;
    for (size_t i = 0; i < len; i++) {
        out[i] = SID_ALPHABET[n % (sizeof SID_ALPHABET - 1)];
        n /= sizeof SID_ALPHABET - 1;
    }
    out[len] = '\0';
}

static const char *NICK_ADJ[] = {
    "swift", "quiet", "brave", "lucky", "quick", "calm", "bright", "bold",
    "gentle", "sharp", "steady", "sunny", "clever", "mellow", "sly", "eager",
    "plucky", "spry", "vivid", "wry", "keen", "amber", "cosmic", "rustic",
};
static const char *NICK_NOUN[] = {
    "otter", "falcon", "maple", "comet", "heron", "lynx", "willow", "badger",
    "raven", "cedar", "ember", "sparrow", "harbor", "meadow", "gecko", "juniper",
    "pixel", "quartz", "tundra", "wren", "yonder", "zephyr", "canyon", "delta",
};
#define NICK_NUMBERS 100   // the number after the noun, 0 to 99

void random_nickname(char *out, size_t out_cap) {
    const char *adj = NICK_ADJ[randombytes_uniform((uint32_t)COUNT_OF(NICK_ADJ))];
    const char *noun = NICK_NOUN[randombytes_uniform((uint32_t)COUNT_OF(NICK_NOUN))];
    snprintf(out, out_cap, "%s-%s%u", adj, noun, (unsigned)randombytes_uniform(NICK_NUMBERS));
}

void copy_str(char *dst, const char *src, size_t dstsize) {
    if (dstsize == 0) return;
    size_t n = strlen(src);
    if (n > dstsize - 1) n = dstsize - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

int starts_with(const char *s, const char *prefix) { return strncmp(s, prefix, strlen(prefix)) == 0; }

double backoff(int tries, double base, int max_shift, double cap) {
    int shift = tries < max_shift ? tries : max_shift;
    double d = base * (double)(1u << shift);
    return d > cap ? cap : d;
}
