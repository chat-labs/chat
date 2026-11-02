// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What comes from relays, routers and Tor, TOML, Bytewords, QR codes and links in messages, all
// without a network.
#include "harness.h"
#include "tui/tui.h"

typedef struct { int n; char seen[10][160]; } toml_log_t;

static void toml_got(void *ctx, const char *table, const char *key, const toml_value *v) {
    toml_log_t *l = ctx;
    if (l->n >= 10) return;
    char *o = l->seen[l->n++];
    int p = snprintf(o, 160, "%s.%s=", table, key);
    switch (v->type) {
        case TOML_STRING: snprintf(o + p, 160 - (size_t)p, "s:%s", v->s); break;
        case TOML_BOOL:   snprintf(o + p, 160 - (size_t)p, "b:%d", v->b); break;
        case TOML_INT:    snprintf(o + p, 160 - (size_t)p, "i:%lld", v->i); break;
        case TOML_ARRAY:
            p += snprintf(o + p, 160 - (size_t)p, "a:");
            for (int k = 0; k < v->n; k++) p += snprintf(o + p, 160 - (size_t)p, "%s%s", k ? "|" : "", v->items[k]);
            break;
    }
}

void test_toml(double *t) {
    (void)t;
    static const char text[] =
        "# a comment\n"
        "top = 1\n"
        "[network]  # after a header\n"
        "routing = \"tor\"\n"
        "lan = false\n"
        "relays = [\n  \"wss://a\", # first\n  'wss://b',\n]\n"
        "port = 4_000\n"
        "ratio = 1.5\n"
        "a.b = true\n"
        "\n[ profile ]\r\n"
        "nick = \"al\\\"i\\u00e9\\\\\"\r\n"
        "\"colour\" = 'pur\\ple'\n"
        "open = \"no end\n"
        "[[x]]\n"
        "lost = 1\n";
    static const char *const want[] = {
        ".top=i:1", "network.routing=s:tor", "network.lan=b:0", "network.relays=a:wss://a|wss://b",
        "network.port=i:4000", "profile.nick=s:al\"i\xc3\xa9\\", "profile.colour=s:pur\\ple",
    };
    toml_log_t l = { 0 };
    int bad_line = 0, bad = toml_parse(text, toml_got, &l, &bad_line);
    CHECK(l.n == 7, "read %d keys, want 7", l.n);
    for (int i = 0; i < l.n && i < 7; i++) CHECK(strcmp(l.seen[i], want[i]) == 0, "read %s, want %s", l.seen[i], want[i]);
    // A float, a dotted key, an unended string, an array of tables, and a key under it.
    CHECK(bad == 5 && bad_line == 11, "%d lines left out from line %d, want 5 from line 11", bad, bad_line);

    char line[256] = "k = ";
    size_t n = toml_put_str(line, 4, sizeof line, "a\"b\\c\n\x01\xc3\xa9");
    toml_log_t back = { 0 };
    CHECK(n < sizeof line && toml_parse(line, toml_got, &back, NULL) == 0 && back.n == 1
          && strcmp(back.seen[0], ".k=s:a\"b\\c\n\x01\xc3\xa9") == 0, "a string didn't come back the same: %s", line);
    CHECK(toml_put_str(line, 0, 4, "abcdef") == 4, "a string that didn't fit wasn't refused");
}

// What comes from relays, routers and Tor, taken apart without a network.
void test_parsers(double *t) {
    (void)t;
    // An address Tor itself handed out, and the same with one character changed.
    CHECK(onion_valid("loz66ml5itetz4mg7lor2nzfceeawpenvab57hrkcqcbldkebzkszpyd"), "a real onion address fails its checksum");
    CHECK(!onion_valid("loz66ml5itetz4mg7lor2nzfceeawpenvab57hrkcqcbldkebzkszpye"), "a mistyped onion address passes");
    CHECK(!onion_valid("loz66ml5itetz4mg7lor2nzfceeawpenvab57hrkcqcbldkebzkszpy"), "a short onion address passes");

    static js_arena arena;
    const char *msg = "[\"EVENT\",\"ab\",{\"kind\":21000,\"tags\":[[\"e\",\"x\\u00e9\\n\"]],\"content\":\"a\\\"b\"}]";
    const js_value *v = js_parse(msg, strlen(msg), &arena);
    CHECK(v && v->type == JS_ARR && v->n == 3, "a relay message didn't parse");
    if (v && v->n == 3) {
        const js_value *ev = &v->items[2];
        const js_value *kind = js_obj_get(ev, "kind");
        CHECK(kind && kind->is_int && kind->i == 21000, "event kind came out wrong");
        const char *content = js_str(js_obj_get(ev, "content"));
        CHECK(content && strcmp(content, "a\"b") == 0, "escaped content came out as '%s'", content ? content : "");
        const js_value *tags = js_obj_get(ev, "tags");
        const char *tag = tags && tags->n == 1 ? js_str(&tags->items[0].items[1]) : NULL;
        CHECK(tag && strcmp(tag, "x\xc3\xa9\n") == 0, "a \\u escape didn't decode to UTF-8");
        char out[64];
        size_t n = tag ? js_put_str(out, 0, sizeof out, tag, strlen(tag)) : 0;
        CHECK(n > 0 && strcmp(out, "\"x\xc3\xa9\\n\"") == 0, "NIP-01 escaping gave %s", n ? out : "nothing");
    }
    CHECK(js_parse("[1,]", 4, &arena) == NULL, "a trailing comma parsed");
    CHECK(js_parse("[\"\\ud800\"]", 10, &arena) == NULL, "a lone surrogate parsed");

    const char *xml = "<root><service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>"
                      "<controlURL>/ppp</controlURL></service><service><serviceType>"
                      "urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL> /ctl/ip </controlURL>"
                      "</service></root>";
    char service[96], url[256];
    CHECK(portmap_parse_control_url(xml, strlen(xml), service, sizeof service, url, sizeof url) == 0
          && strcmp(url, "/ctl/ip") == 0 && strstr(service, "WANIPConnection:1"),
          "UPnP control URL came out wrong");
    const char *resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    char body[64];
    int status = 0;
    CHECK(portmap_http_body(resp, strlen(resp), &status, body, sizeof body) == 0 && status == 200
          && strcmp(body, "hello world") == 0, "a chunked reply came out as '%s'", body);

    uint8_t key[NOSTR_KEY_LEN], plain[NOSTR_WRAP_PLAIN], back[NOSTR_WRAP_PLAIN], sealed[NOSTR_WRAP_LEN], sealed2[NOSTR_WRAP_LEN];
    gen_random(key, sizeof key);
    gen_random(plain, sizeof plain);
    nostr_wrap(key, plain, sealed);
    nostr_wrap(key, plain, sealed2);
    CHECK(nostr_unwrap(key, sealed, sizeof sealed, back) == 0 && memcmp(back, plain, sizeof plain) == 0, "a wrapped event didn't open");
    CHECK(memcmp(sealed, sealed2, sizeof sealed) != 0, "the same datagram wrapped twice came out the same");
    sealed[100] ^= 1;
    CHECK(nostr_unwrap(key, sealed, sizeof sealed, back) != 0, "a tampered event opened");
}

// Bytewords' own example, a word for each byte of a 16-byte seed in groups of four, and every word.
void test_bytewords(double *t) {
    (void)t;
    static const uint8_t seed[16] = { 0xc7, 0x09, 0x85, 0x80, 0x12, 0x5e, 0x2a, 0xb0,
                                      0x98, 0x12, 0x53, 0x46, 0x8b, 0x2d, 0xbc, 0x52 };
    char out[BYTEWORDS_LEN(16)];
    bytewords(seed, sizeof seed, out);
    CHECK(strcmp(out, "slot axis limp lava \xc2\xb7 brag holy door puff \xc2\xb7 monk brag guru frog \xc2\xb7 luau drop roof grim") == 0,
          "Bytewords' example came out as %s", out);
    static uint8_t all[256];
    static char every[BYTEWORDS_LEN(256)];
    for (int i = 0; i < 256; i++) all[i] = (uint8_t)i;
    bytewords(all, sizeof all, every);
    size_t n = strlen(every);
    CHECK(n == 256 * 4 + 192 + 63 * 4 && strncmp(every, "able acid also apex", 19) == 0 && strcmp(every + n - 4, "zoom") == 0,
          "the 256 words came out wrong (%zu bytes)", n);
}

// Where a link in a message starts and ends, what isn't one, the address it opens, and the chat's
// links newest first.
void test_links(double *t) {
    (void)t;
    static const struct { const char *text, *link; } CASES[] = {
        { "@Jay finlay's ieji ID is @ida@ieji.de (ieji.de/@ida)", "ieji.de/@ida" },
        { "see https://en.wikipedia.org/wiki/C_(language).", "https://en.wikipedia.org/wiki/C_(language)" },
        { "<HTTP://Example.com/a?b=1&c=2>", "HTTP://Example.com/a?b=1&c=2" },
        { "chat.vin.moe, then", "chat.vin.moe" },
        { "is it www.example.com?", "www.example.com" },
        { "main.go:42", "main.go" },
        { "\xe2\x80\x9chttps://x.org/\xc3\xa9\xe2\x80\x9d", "https://x.org/\xc3\xa9" },
        { "mail finlay@tuta.com, e.g. v0.5.3 or end.Next or ~/notes.md", NULL },
        { "http:// https://", NULL },
    };
    for (size_t i = 0; i < COUNT_OF(CASES); i++) {
        size_t from = 0, at = 0, len = 0, n = strlen(CASES[i].text);
        int got = link_next(CASES[i].text, n, &from, &at, &len);
        if (!CASES[i].link) {
            CHECK(!got, "found a link in '%s': %.*s", CASES[i].text, (int)len, CASES[i].text + at);
            continue;
        }
        CHECK(got && len == strlen(CASES[i].link) && memcmp(CASES[i].text + at, CASES[i].link, len) == 0,
              "'%s' gave '%.*s', want '%s'", CASES[i].text, (int)len, CASES[i].text + at, CASES[i].link);
    }
    char out[LINK_URL_MAX];
    CHECK(link_target("ieji.de/@ida", 12, out, sizeof out) == 0 && strcmp(out, "https://ieji.de/@ida") == 0,
          "a link without its https:// opens as %s", out);
    static const char shell[] = "http://x.org/$(id)'\xc3\xa9";
    CHECK(link_target(shell, sizeof shell - 1, out, sizeof out) == 0 && strcmp(out, "http://x.org/%24(id)%27%C3%A9") == 0,
          "a link with what a shell reads opens as %s", out);
    CHECK(link_target("x.org", 5, out, 8) == -1 && out[0] == '\0', "an address too long for its buffer wasn't refused");

    static tui_scrollback_t sb;
    tui_scrollback_clear(&sb);
    tui_scrollback_push(&sb, "12:00", "ida: see x.org and https://y.org/z", NULL, 0, 4);
    tui_scrollback_push(&sb, "12:01", "* bob.example joined", NULL, 0, 0);
    tui_scrollback_push(&sb, "12:02", "bob: a.io", NULL, 0, 4);
    unsigned upto = sb.total;
    tui_scrollback_push(&sb, "12:03", "ida: later.org", NULL, 0, 4);
    tui_link_t l = { .own = 0 };
    static const char *const want[] = { "a.io", "https://y.org/z", "x.org" };
    for (int i = 0; i < 3; i++)
        CHECK(tui_chat_link(&sb, upto, i, &l) == 3 && strcmp(l.text, want[i]) == 0
              && strcmp(l.from, i == 0 ? "bob" : "ida") == 0 && strcmp(l.hhmm, i == 0 ? "12:02" : "12:00") == 0,
              "the chat's link %d came out as %s from %s at %s, want %s", i, l.text, l.from, l.hhmm, want[i]);
}

void test_mentions(double *t) {
    (void)t;
    static const struct { const char *text; int names; } CASES[] = {
        { "@Finlay-android-test Test", 0 },
        { "@finlay2 @finlay_ @finlay\xc3\xa9", 0 },
        { "@fin finlay", 0 },
        { "hi @FINLAY, you there?", 1 },
        { "@finlay's", 1 },
        { "@finlay", 1 },
        { "@finlay\xe3\x81\x95\xe3\x82\x93", 1 },
        { "@Finlay-android-test and @finlay", 1 },
    };
    for (size_t i = 0; i < COUNT_OF(CASES); i++)
        CHECK(has_mention(CASES[i].text, "finlay") == CASES[i].names, "'%s' %s finlay", CASES[i].text,
              CASES[i].names ? "doesn't name" : "names");
    CHECK(mention_len("@Finlay. hi", "finlay") == 7, "a mention's length doesn't stop at the nick");
    CHECK(!has_mention("@", "") && !mention_len("@finlay", ""), "an empty nick is mentioned");
}

static int qr_at(const uint8_t *m, int size, int x, int y) { return m[y * size + x]; }

// A QR code, by its structure: the version a length needs, the finders and their separators, the
// timing patterns, and format information that's the same in both copies and a valid BCH code.
void test_qr(double *t) {
    (void)t;
    static uint8_t m[QR_MAX_SIZE * QR_MAX_SIZE];
    char text[256];
    // Byte mode at level M holds 14 bytes in version 1, 106 in version 6, 213 in version 10.
    static const struct { size_t len; int size; } SIZES[] = { { 14, 21 }, { 15, 25 }, { 106, 41 }, { 107, 45 }, { 213, 57 } };
    for (size_t i = 0; i < sizeof SIZES / sizeof SIZES[0]; i++) {
        memset(text, 'a', SIZES[i].len);
        text[SIZES[i].len] = '\0';
        int s = qr_encode(text, m);
        CHECK(s == SIZES[i].size, "%zu bytes made a QR code of %d modules, want %d", SIZES[i].len, s, SIZES[i].size);
    }
    memset(text, 'a', 214);
    text[214] = '\0';
    CHECK(qr_encode(text, m) == -1, "214 bytes didn't fail");
    int s = qr_encode("otpauth://totp/chat:default?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=chat", m);
    CHECK(s == 37, "an otpauth link made a QR code of %d modules, want 37", s);
    if (s != 37) return;
    const int corner[3][2] = { { 3, 3 }, { s - 4, 3 }, { 3, s - 4 } };
    int finders = 1;
    for (int f = 0; f < 3; f++)
        for (int dy = -4; dy <= 4; dy++)
            for (int dx = -4; dx <= 4; dx++) {
                int x = corner[f][0] + dx, y = corner[f][1] + dy, d = abs(dx) > abs(dy) ? abs(dx) : abs(dy);
                if (x >= 0 && x < s && y >= 0 && y < s && qr_at(m, s, x, y) != (d != 2 && d != 4)) finders = 0;
            }
    CHECK(finders, "a finder or its separator is wrong");
    int timing = 1;
    for (int i = 8; i < s - 8; i++)
        if (qr_at(m, s, i, 6) != (i % 2 == 0) || qr_at(m, s, 6, i) != (i % 2 == 0)) timing = 0;
    CHECK(timing && qr_at(m, s, 8, s - 8), "the timing patterns or the dark module are wrong");
    int a = 0, b = 0;
    for (int i = 0; i <= 5; i++) a |= qr_at(m, s, 8, i) << i;
    a |= qr_at(m, s, 8, 7) << 6 | qr_at(m, s, 8, 8) << 7 | qr_at(m, s, 7, 8) << 8;
    for (int i = 9; i < 15; i++) a |= qr_at(m, s, 14 - i, 8) << i;
    for (int i = 0; i < 8; i++) b |= qr_at(m, s, s - 1 - i, 8) << i;
    for (int i = 8; i < 15; i++) b |= qr_at(m, s, 8, s - 15 + i) << i;
    int bits = a ^ 0x5412, data = bits >> 10, rem = data;
    for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    CHECK(a == b && (rem & 0x3ff) == (bits & 0x3ff) && (data >> 3) == 0,
          "the format information is wrong (%04x and %04x)", (unsigned)a, (unsigned)b);
}
