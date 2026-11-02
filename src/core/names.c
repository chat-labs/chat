// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// Names and other text: nicks and how a peer's name is shown, colours, labels, timers, invites,
// and the room a call goes to.
#include "core/engine.h"

const named_color_t COLOR_PALETTE[] = {
    { "red",     0xE5, 0x48, 0x4D }, { "orange",  0xF7, 0x6B, 0x15 },
    { "yellow",  0xF5, 0xD9, 0x0A }, { "green",   0x30, 0xA4, 0x6C },
    { "teal",    0x12, 0xA5, 0x94 }, { "cyan",    0x00, 0xA2, 0xC7 },
    { "blue",    0x00, 0x90, 0xFF }, { "indigo",  0x3E, 0x63, 0xDD },
    { "purple",  0x8E, 0x4E, 0xC6 }, { "pink",    0xD6, 0x40, 0x9F },
    { "brown",   0xAD, 0x7F, 0x58 }, { "gray",    0x8B, 0x8D, 0x98 },
};
const int COLOR_PALETTE_N = (int)COUNT_OF(COLOR_PALETTE);

void chat_random_colour(uint8_t rgb[3]) {
    const named_color_t *pick = &COLOR_PALETTE[gen_uniform((uint32_t)COLOR_PALETTE_N)];
    rgb[0] = pick->r; rgb[1] = pick->g; rgb[2] = pick->b;
}

int nick_ieq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

int parse_color(const char *text, uint8_t rgb[3]) {
    const char *h = text;
    if (h[0] == '#') h++;
    size_t len = strlen(h);
    if (len == COLOR_HEX_LEN) {
        int ok = 1;
        uint8_t tmp[3];
        for (int i = 0; i < 3; i++) {
            int hi = hex_value(h[i * 2]), lo = hex_value(h[i * 2 + 1]);
            if (hi < 0 || lo < 0) { ok = 0; break; }
            tmp[i] = (uint8_t)((hi << 4) | lo);
        }
        if (ok) { memcpy(rgb, tmp, 3); return 0; }
    }
    // The palette's names are lower case.
    for (int i = 0; i < COLOR_PALETTE_N; i++)
        if (nick_ieq(text, COLOR_PALETTE[i].name)) {
            rgb[0] = COLOR_PALETTE[i].r; rgb[1] = COLOR_PALETTE[i].g; rgb[2] = COLOR_PALETTE[i].b;
            return 0;
        }
    return -1;
}

void color_to_hex(const uint8_t rgb[3], char out[COLOR_HEX_LEN + 1]) { hex_encode(rgb, 3, out); }

void short_id(const uint8_t id[ID_LEN], char out[SHORT_ID_HEX + 1]) { hex_encode(id, SHORT_ID_LEN, out); }

void where_str(addr_t a, const uint8_t *id, char out[WHERE_LEN]) {
    char sid[SHORT_ID_HEX + 1] = "";
    if (a.kind == ADDR_NOSTR && !id) id = a.ip;
    if (id) short_id(id, sid);
    if (a.kind == ADDR_NOSTR) {
        snprintf(out, WHERE_LEN, "%s over the relays", sid);
    } else if (a.kind == ADDR_TOR) {
        if (!id) short_id(a.ip, sid);
        snprintf(out, WHERE_LEN, id ? "%s over Tor" : "Tor stream %s", sid);
    } else {
        char as[ADDR_STR_LEN];
        addr_to_string(a, as);
        if (id) snprintf(out, WHERE_LEN, "%s at %s", sid, as);
        else copy_str(out, as, WHERE_LEN);
    }
}

// Characters that render as nothing, or next to nothing.
static int is_invisible(uint32_t cp) {
    return cp == 0xad || cp == 0x34f || cp == 0x61c || cp == 0x115f || cp == 0x1160 || cp == 0x17b4
        || cp == 0x17b5 || cp == 0x180e || (cp >= 0x200b && cp <= 0x200d) || (cp >= 0x2060 && cp <= 0x2064)
        || cp == 0x3164 || cp == 0xfeff || cp == 0xffa0 || (cp >= 0xfe00 && cp <= 0xfe0f)
        || (cp >= 0xe0000 && cp <= 0xe007f);
}

// Fullwidth ASCII, and other brackets and marks that look like the ones the UI uses, mapped to plain ASCII.
static uint32_t fold_punct(uint32_t cp) {
    if (cp >= 0xff01 && cp <= 0xff5e) return cp - 0xff01 + 0x21;
    switch (cp) {
        case 0x207d: case 0x208d: case 0x2768: case 0x276a: case 0x27ee: case 0x2985: case 0xfe59: case 0xff5f:
            return '(';
        case 0x207e: case 0x208e: case 0x2769: case 0x276b: case 0x27ef: case 0x2986: case 0xfe5a: case 0xff60:
            return ')';
        case 0xfe5f: return '#';
        case 0x2d0: case 0x2236: case 0xa789: case 0xfe13: case 0xfe55: return ':';
        case 0xfe6b: return '@';
        default: return cp;
    }
}

// Letters from other scripts that look like Latin ones.
static const struct { uint16_t cp; char ascii; } LOOKALIKES[] = {
    { 0x0131, 'i' }, { 0x0261, 'g' }, { 0x0391, 'A' }, { 0x0392, 'B' }, { 0x0395, 'E' }, { 0x0396, 'Z' },
    { 0x0397, 'H' }, { 0x0399, 'I' }, { 0x039a, 'K' }, { 0x039c, 'M' }, { 0x039d, 'N' }, { 0x039f, 'O' },
    { 0x03a1, 'P' }, { 0x03a4, 'T' }, { 0x03a5, 'Y' }, { 0x03a7, 'X' }, { 0x03b1, 'a' }, { 0x03b9, 'i' },
    { 0x03ba, 'k' }, { 0x03bd, 'v' }, { 0x03bf, 'o' }, { 0x03c1, 'p' }, { 0x03c5, 'u' }, { 0x0405, 'S' },
    { 0x0406, 'I' }, { 0x0408, 'J' }, { 0x0410, 'A' }, { 0x0412, 'B' }, { 0x0415, 'E' }, { 0x041a, 'K' },
    { 0x041c, 'M' }, { 0x041d, 'H' }, { 0x041e, 'O' }, { 0x0420, 'P' }, { 0x0421, 'C' }, { 0x0422, 'T' },
    { 0x0425, 'X' }, { 0x0430, 'a' }, { 0x0435, 'e' }, { 0x043a, 'k' }, { 0x043e, 'o' }, { 0x0440, 'p' },
    { 0x0441, 'c' }, { 0x0443, 'y' }, { 0x0445, 'x' }, { 0x0455, 's' }, { 0x0456, 'i' }, { 0x0458, 'j' },
    { 0x04ae, 'Y' }, { 0x04bb, 'h' }, { 0x04c0, 'I' }, { 0x0501, 'd' }, { 0x051b, 'q' }, { 0x051d, 'w' },
    { 0x217c, 'l' },
};

// A nick normalised for comparing: lookalikes mapped to Latin, i/I/1/| to l, 0 to o, with case
// and invisible characters ignored.
void nick_skeleton(const char *nick, char *out, size_t cap) {
    size_t n = strlen(nick), i = 0, o = 0;
    while (i < n) {
        size_t adv;
        uint32_t cp = fold_punct(utf8_decode(nick, n, i, &adv));
        i += adv;
        if (is_invisible(cp)) continue;
        for (size_t k = 0; k < COUNT_OF(LOOKALIKES); k++)
            if (LOOKALIKES[k].cp == cp) { cp = (uint32_t)LOOKALIKES[k].ascii; break; }
        if (cp < 0x80) cp = (uint32_t)tolower((int)cp);
        if (cp == 'i' || cp == '|' || cp == '1') cp = 'l';
        else if (cp == '0') cp = 'o';
        char enc[UTF8_CHAR_MAX];
        size_t len = utf8_put(cp, enc);
        if (o + len >= cap) break;
        memcpy(out + o, enc, len);
        o += len;
    }
    out[o] = '\0';
}

void chat_nick_skeleton(const char *nick, char *out, size_t cap) { nick_skeleton(nick, out, cap); }

void chat_clean_nick(const char *in, char out[MAX_NICK + 1]) {
    char tmp[MAX_NICK + 1], kept[MAX_NICK + 1];
    clean_text(in, tmp, MAX_NICK);
    size_t n = strlen(tmp), i = 0, o = 0;
    while (i < n) {
        size_t adv;
        uint32_t cp = utf8_decode(tmp, n, i, &adv);
        uint32_t f = fold_punct(cp);
        if (!is_invisible(cp) && !(f < 0x80 && strchr("()#:@", (int)f))) {
            if (f != cp) kept[o++] = (char)f;
            else { memcpy(kept + o, tmp + i, adv); o += adv; }
        }
        i += adv;
    }
    kept[o] = '\0';
    clean_text(kept, out, MAX_NICK);
    if (!out[0]) copy_str(out, "anon", MAX_NICK + 1);
}

void set_peer_nick(peer_t *p, const char *nick) {
    chat_clean_nick(nick, p->nick);
    nick_skeleton(p->nick, p->nick_skel, sizeof p->nick_skel);
}

void set_own_nick(chat_t *c, const char *nick) {
    chat_clean_nick(nick, c->nick);
    nick_skeleton(c->nick, c->nick_skel, sizeof c->nick_skel);
}

void chat_peer_name(const chat_t *c, const peer_t *p, char out[CHAT_NAME_LEN]) {
    int clash = strcmp(p->nick_skel, c->nick_skel) == 0;
    for (int i = 0; i < c->peer_hi && !clash; i++) {
        const peer_t *q = &c->peers[i];
        if (q == p || !q->used || !q->ok) continue;
        clash = strcmp(p->nick_skel, q->nick_skel) == 0;
    }
    if (!clash) { copy_str(out, p->nick, CHAT_NAME_LEN); return; }
    char idhex[SHORT_ID_HEX + 1]; short_id(p->id, idhex);
    snprintf(out, CHAT_NAME_LEN, "%s#%s", p->nick, idhex);
}

int has_mention(const char *text, const char *nick) {
    for (const char *at = strchr(text, '@'); at; at = strchr(at + 1, '@'))
        if (mention_len(at, nick)) return 1;
    return 0;
}

// What's added to p's name on a line from it: whether its code was compared, or that it wasn't when
// that holds messages back. The full-screen UI shows it as a symbol (tui.c's MARKS).
const char *code_mark(const chat_t *c, const peer_t *p) {
    if (p->code_ok == CODE_DIFFERENT) return " (codes differ)";
    if (p->code_ok == CODE_SAME) return " (code compared)";
    return c->verify_required ? " (code not compared)" : "";
}

int chat_code_state(const chat_t *c, const peer_t *p) {
    if (p->code_ok == CODE_DIFFERENT) return CODE_DIFFERS;
    if (p->code_ok == CODE_SAME) return CODE_COMPARED;
    if (p->trust == TRUST_OTHER_KEY) return CODE_KEY_CHANGED;
    return c->verify_required ? CODE_TO_COMPARE : CODE_NOTHING;
}

const char *chat_verify_label(verify_state_t s) {
    switch (s) {
        case VERIFY_VERIFIED: return "verified";
        case VERIFY_FAILED:   return "\xe2\x9a\xa0 signature invalid";
        case VERIFY_UNVERIFIED:
        default:               return "unverified";
    }
}

void chat_build_label(const peer_t *p, char *out, size_t cap) {
    switch (p->build_state) {
        // Only its claim. A client modified to lie can send an official build's hash.
        case BUILD_OFFICIAL:  snprintf(out, cap, "says official v%s", p->build_version); break;
        case BUILD_MODIFIED:  snprintf(out, cap, "modified client (says v%s)", p->build_version); break;
        case BUILD_UNCHECKED: snprintf(out, cap, "v%s, build not checked", p->build_version); break;
        case BUILD_UNKNOWN:
        default:              snprintf(out, cap, "build unknown"); break;
    }
}

void chat_format_timer(unsigned seconds, char *out, size_t cap) {
    if (!seconds) snprintf(out, cap, "off");
    else if (seconds % 86400 == 0) snprintf(out, cap, "%ud", seconds / 86400);
    else if (seconds % 3600 == 0) snprintf(out, cap, "%uh", seconds / 3600);
    else if (seconds % 60 == 0) snprintf(out, cap, "%um", seconds / 60);
    else snprintf(out, cap, "%us", seconds);
}

int chat_parse_timer(const char *s, unsigned *seconds) {
    if (strcmp(s, "off") == 0 || strcmp(s, "0") == 0) { *seconds = 0; return 0; }
    char *end;
    unsigned long n = strtoul(s, &end, 10);
    unsigned long unit = *end == 's' ? 1 : *end == 'm' ? 60 : *end == 'h' ? 3600 : *end == 'd' ? 86400 : 0;
    if (end == s || !isdigit((unsigned char)s[0]) || !unit || end[1] || n > TIMER_MAX / unit || n * unit < TIMER_MIN)
        return -1;
    *seconds = (unsigned)(n * unit);
    return 0;
}

int chat_contact_room(const identity_keypair_t *mine, const uint8_t their_pub[ID_SIGN_PUB_LEN], uint64_t day,
                      char id[SESSION_ID_LEN + 1], char password[CONTACT_PASSWORD_LEN + 1]) {
    uint8_t k[CONTACT_SECRET_LEN];
    if (contact_secret(mine, their_pub, day, k) != 0) return -1;
    session_id_from(load_be64(k), id, SESSION_ID_LEN);
    hex_encode(k + CONTACT_SECRET_LEN - CONTACT_PASSWORD_LEN / 2, CONTACT_PASSWORD_LEN / 2, password);
    crypto_wipe(k, sizeof k);
    return 0;
}

uint64_t chat_contact_day(void) { return (uint64_t)time(NULL) / DAY_SECONDS; }

int chat_invite(const char *id, const char *password, char *out, size_t cap) {
    if (!id[0] || strchr(id, ':') || strlen(id) > MAX_SESSION_NAME || strlen(password) > MAX_PASSWORD) return -1;
    uint8_t check[INVITE_CHECK_LEN];
    char hex[INVITE_CHECK_LEN * 2 + 1];
    invite_check(id, password, check);
    hex_encode(check, sizeof check, hex);
    int n = snprintf(out, cap, INVITE_PREFIX "%s:%s:%s", id, password, hex);
    if (n < 0 || (size_t)n >= cap) { crypto_wipe(out, cap); return -1; }
    return 0;
}

// Pasted from somewhere, so spaces round it don't count, and nor does the prefix's case.
int chat_is_invite(const char *text) {
    static const char prefix[] = INVITE_PREFIX;
    while (*text == ' ') text++;
    for (size_t i = 0; i < sizeof prefix - 1; i++)
        if (tolower((unsigned char)text[i]) != prefix[i]) return 0;
    return 1;
}

int chat_invite_parse(const char *text, char id[MAX_SESSION_NAME + 1], char password[MAX_PASSWORD + 1]) {
    if (!chat_is_invite(text)) return 0;
    while (*text == ' ') text++;
    const char *body = text + sizeof INVITE_PREFIX - 1, *end = body + strlen(body);
    while (end > body && end[-1] == ' ') end--;
    const char *first = memchr(body, ':', (size_t)(end - body)), *last = end;
    while (last > body && last[-1] != ':') last--;
    size_t id_len = first ? (size_t)(first - body) : 0;
    if (!first || last - 1 <= first || end - last != INVITE_CHECK_LEN * 2 || id_len == 0 || id_len > MAX_SESSION_NAME
        || (size_t)(last - 1 - (first + 1)) > MAX_PASSWORD)
        return -1;
    uint8_t check[INVITE_CHECK_LEN], want[INVITE_CHECK_LEN];
    char hex[INVITE_CHECK_LEN * 2 + 1];
    for (int i = 0; i < INVITE_CHECK_LEN * 2; i++) hex[i] = (char)tolower((unsigned char)last[i]);
    hex[INVITE_CHECK_LEN * 2] = '\0';
    if (hex_decode(hex, INVITE_CHECK_LEN * 2, check) != 0) return -1;
    memcpy(id, body, id_len);
    id[id_len] = '\0';
    size_t pw_len = (size_t)(last - 1 - (first + 1));
    memcpy(password, first + 1, pw_len);
    password[pw_len] = '\0';
    invite_check(id, password, want);
    if (memcmp(check, want, sizeof check) != 0) {
        crypto_wipe(password, MAX_PASSWORD + 1);
        return -1;
    }
    return 1;
}
