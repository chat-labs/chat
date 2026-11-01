// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// --json: one session, for another program to drive. What happens comes out on stdout as one JSON
// object per line, its type in "t", and commands come in on stdin the same way, named by "cmd".
// docs/json.md has every object.
#include "app/app.h"
#include "common/bytewords.h"
#include "common/json.h"
#include "common/qr.h"

#define JSON_VERSION 1
// Shorter than WAIT_MS, since the program on the other end waits on each answer.
#define JSON_WAIT_MS 50
// How often the peers, the network and the rest are looked at for changes, and the files' list,
// which transfers move on all the time.
#define STATE_EVERY 0.2
#define FILES_EVERY 0.5
// Pictures are scaled to fit a square this size, unless "start" asks for a smaller one.
#define PICTURE_MAX 1024
#define PICTURE_MIN 16
#define COMMAND_MAX 16384

int g_json;

// What was sent last of each kind, so only what changed goes out, and what "start" set up.
static struct {
    char *peers, *net, *files;
    double state_at, files_at;
    int timer_sent;
    unsigned timer;
    char timer_who[CHAT_NAME_LEN + 8];
    unsigned move_seq;
    int picture_max;
    uint8_t picture_bg[3];
    char dir[FILE_DIR_MAX];
    char password[MAX_PASSWORD + 1];
    int kept;
} g_js;

static js_arena g_arena;

static const char *const IDENTITY_NAMES[] = { "none", "native", "age", "pgp" };
static const char *const SIGNED_NAMES[] = { "unverified", "verified", "failed" };
static const char *const CODE_NAMES[] = { "nothing", "compare", "compared", "differs", "key-changed" };
static const char *const BUILD_NAMES[] = { "unknown", "unchecked", "official", "modified" };
static const char *const DL_NAMES[] = { "offered", "fetching", "done", "failed", "queued" };
static const char *const LAUNCH_NAMES[] = { "auto", "always", "never" };
static const char *const NOTIFY_NAMES[] = { "none", "mentions", "all" };
static const char *const PREVIEW_NAMES[] = { "off", "nick", "message" };
static const char *const VERIFY_NAMES[] = { "required", "optional" };
static const char *const NET_LOG_NAMES[] = { "normal", "verbose", "off" };

static int pick(const char *v, const char *const *names, int n) {
    for (int i = 0; v && i < n; i++) if (strcmp(v, names[i]) == 0) return i;
    return -1;
}

// ---- writing ----

// One object, built up and written as one line.
typedef struct { char *buf; size_t n, cap; int failed; } jout_t;

// Grows by copying, so no copy of a message is left behind unwiped.
static int jo_room(jout_t *o, size_t more) {
    if (o->failed) return -1;
    if (o->n + more < o->cap) return 0;
    size_t cap = o->cap ? o->cap : 512;
    while (o->n + more >= cap) cap *= 2;
    char *b = malloc(cap);
    if (!b) { o->failed = 1; return -1; }
    if (o->buf) { memcpy(b, o->buf, o->n); crypto_wipe(o->buf, o->cap); free(o->buf); }
    o->buf = b;
    o->cap = cap;
    return 0;
}

static void jo_raw(jout_t *o, const char *s) {
    size_t n = strlen(s);
    if (jo_room(o, n + 1) != 0) return;
    memcpy(o->buf + o->n, s, n + 1);
    o->n += n;
}

static void jo_esc(jout_t *o, const char *s) {
    size_t len = strlen(s);
    if (jo_room(o, len * 6 + 3) != 0) return;
    o->n = js_put_str(o->buf, o->n, o->cap, s, len);
}

// The comma before a value, unless it's the first in its object or array, then its key.
static void jo_key(jout_t *o, const char *key) {
    if (o->n && o->buf[o->n - 1] != '{' && o->buf[o->n - 1] != '[') jo_raw(o, ",");
    if (key) { jo_esc(o, key); jo_raw(o, ":"); }
}

static void jo_str(jout_t *o, const char *key, const char *s) {
    jo_key(o, key);
    jo_esc(o, s);
}

static void jo_int(jout_t *o, const char *key, long long v) {
    char num[24];
    snprintf(num, sizeof num, "%lld", v);
    jo_key(o, key);
    jo_raw(o, num);
}

static void jo_bool(jout_t *o, const char *key, int v) {
    jo_key(o, key);
    jo_raw(o, v ? "true" : "false");
}

static void jo_hex(jout_t *o, const char *key, const uint8_t *b, size_t n) {
    char hex[2 * ID_LEN + 1];
    if (n > ID_LEN) n = ID_LEN;
    hex_encode(b, n, hex);
    jo_str(o, key, hex);
}

static void jo_colour(jout_t *o, const char *key, const uint8_t rgb[3]) {
    char s[8];
    snprintf(s, sizeof s, "#%02x%02x%02x", rgb[0], rgb[1], rgb[2]);
    jo_str(o, key, s);
}

static void jo_open(jout_t *o, const char *key, const char *bracket) {
    jo_key(o, key);
    jo_raw(o, bracket);
}

static void jo_begin(jout_t *o, const char *type) {
    memset(o, 0, sizeof *o);
    jo_raw(o, "{");
    jo_str(o, "t", type);
}

static void jo_free(jout_t *o) {
    if (o->buf) { crypto_wipe(o->buf, o->cap); free(o->buf); }
    memset(o, 0, sizeof *o);
}

// A program that stopped reading ends the session, as a closed stdin does.
static void jo_write(const jout_t *o) {
    if (fwrite(o->buf, 1, o->n, stdout) != o->n || fflush(stdout) != 0) g_interrupted = 1;
}

// Ends the object and writes it as one line.
static void jo_send(jout_t *o) {
    jo_raw(o, "}\n");
    if (!o->failed) jo_write(o);
    jo_free(o);
}

// The same, unless it's what was sent last of its kind (*last), which it then replaces.
static void jo_send_changed(jout_t *o, char **last) {
    jo_raw(o, "}\n");
    if (o->failed || (*last && strcmp(*last, o->buf) == 0)) { jo_free(o); return; }
    jo_write(o);
    if (*last) { crypto_wipe(*last, strlen(*last)); free(*last); }
    *last = o->buf;
    o->buf = NULL;
    jo_free(o);
}

static void forget(char **last) {
    if (*last) { crypto_wipe(*last, strlen(*last)); free(*last); *last = NULL; }
}

// The state objects go out again in full, as for a new room.
static void forget_state(void) {
    forget(&g_js.peers);
    forget(&g_js.net);
    forget(&g_js.files);
    g_js.state_at = g_js.files_at = 0;
    g_js.timer_sent = 0;
    g_js.move_seq = 0;
}

PRINTF_LIKE(1, 2) static void say_error(const char *fmt, ...) {
    char msg[320];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    jout_t o;
    jo_begin(&o, "error");
    jo_str(&o, "text", msg);
    jo_send(&o);
}

void json_log(const char *hhmm, const char *text) {
    jout_t o;
    jo_begin(&o, "log");
    jo_str(&o, "at", hhmm);
    jo_str(&o, "text", text);
    jo_send(&o);
}

static void say_hello(void) {
    jout_t o;
    jo_begin(&o, "hello");
    jo_int(&o, "v", JSON_VERSION);
    jo_str(&o, "version", TEST_BUILD ? CHAT_VERSION " (" TEST_LABEL ")" : CHAT_VERSION);
    jo_str(&o, "built", CHAT_BUILD_STAMP);
    jo_send(&o);
}

// The room's invite, and its QR code as rows of 0 and 1 (1 dark), for the other program to show.
static void put_invite(jout_t *o, const char *room, const char *password) {
    char invite[INVITE_MAX];
    if (chat_invite(room, password, invite, sizeof invite) != 0) return;
    jo_str(o, "invite", invite);
    uint8_t qr[QR_MAX_SIZE * QR_MAX_SIZE];
    int size = qr_encode(invite, qr);
    if (size > 0) {
        char row[QR_MAX_SIZE + 1];
        jo_open(o, "qr", "[");
        for (int y = 0; y < size; y++) {
            for (int x = 0; x < size; x++) row[x] = qr[y * size + x] ? '1' : '0';
            row[size] = '\0';
            jo_str(o, NULL, row);
        }
        jo_raw(o, "]");
    }
    crypto_wipe(invite, sizeof invite);
    crypto_wipe(qr, sizeof qr);
}

// "ready" for the room "start" opened, "moved" for the one :move went to.
static void say_room(chat_t *c, const char *type, const char *password, int created, const char *from) {
    jout_t o;
    jo_begin(&o, type);
    jo_str(&o, "room", chat_session_name(c));
    jo_str(&o, "password", password);
    jo_bool(&o, "created", created);
    if (from) jo_str(&o, "from", from);
    put_invite(&o, chat_session_name(c), password);
    jo_open(&o, "me", "{");
    jo_hex(&o, "id", chat_my_id(c), ID_LEN);
    jo_str(&o, "nick", chat_nick(c));
    jo_colour(&o, "colour", chat_colour(c));
    jo_raw(&o, "}");
    jo_str(&o, "route", routing_mode_name(chat_route_mode(c)));
    if (chat_route_mode(c) == ROUTE_UDP) jo_int(&o, "port", chat_port(c));
    jo_bool(&o, "history", chat_history(c));
    jo_send(&o);
}

// "identity": the key in use. made: one made here, so its secret goes out too, for the program to keep.
static void say_identity(const identity_keypair_t *kp, int pgp, uint32_t created, int made) {
    jout_t o;
    jo_begin(&o, "identity");
    jo_str(&o, "kind", pgp ? "pgp" : "age");
    uint8_t fp[ID_FP_LEN];
    char fphex[HEX_GROUPS_LEN(ID_FP_LEN)];
    identity_fingerprint(kp->pub, fp);
    hex_groups(fp, ID_FP_LEN, fphex);
    jo_str(&o, "fingerprint", fphex);
    if (pgp && made) {
        static char armor[PGP_ARMOR_MAX];
        uint8_t pfp[PGP_FP_LEN];
        if (pgp_export_secret_key(kp, g_app.nick, created, armor, sizeof armor, pfp) == 0) jo_str(&o, "secret", armor);
        pgp_export_public_key(kp, g_app.nick, created, armor, sizeof armor, pfp);
        jo_str(&o, "public", armor);
        crypto_wipe(armor, sizeof armor);
    } else if (!pgp) {
        char recipient[AGE_RECIPIENT_STRLEN + 1];
        age_export_recipient(kp, recipient);
        jo_str(&o, "public", recipient);
        if (made) {
            char secret[AGE_SECRET_KEY_STRLEN + 1];
            age_export_secret_key(kp, secret);
            jo_str(&o, "secret", secret);
            crypto_wipe(secret, sizeof secret);
        }
    }
    jo_send(&o);
}

// ---- what the session says ----

static void json_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags,
                       int color_len, int file) {
    chat_t *c = ui;
    jout_t o;
    jo_begin(&o, "line");
    jo_str(&o, "at", hhmm);
    if (flags & LINE_CHAT) {
        const chat_line_t *l = chat_line(c);
        const char *body = color_len > 0 && (size_t)color_len <= strlen(text) ? text + color_len : text;
        if (*body == ' ') body++;
        jo_str(&o, "kind", "message");
        jo_str(&o, "text", body);
        if (l->mid) jo_str(&o, "mid", l->mid);
        if (l->origin) {
            jo_hex(&o, "from", l->origin, ID_LEN);
            jo_bool(&o, "mine", memcmp(l->origin, chat_my_id(c), ID_LEN) == 0);
        }
        if (l->nick) jo_str(&o, "nick", l->nick);
        if (l->peer) jo_hex(&o, "peer", chat_peer_id(l->peer), ID_LEN);
        if (flags & LINE_OWN) jo_int(&o, "own", chat_own_seq(c));
        if (flags & LINE_DIRECT) jo_bool(&o, "direct", 1);
        if (flags & LINE_MENTION) jo_bool(&o, "mention", 1);
        if (chat_line_quote(c) > 0) jo_int(&o, "quote", chat_line_quote(c));
        if (file > 0) jo_int(&o, "file", file);
    } else {
        jo_str(&o, "kind", flags & LINE_WARN ? "warn" : "note");
        jo_str(&o, "text", text);
    }
    if (rgb) jo_colour(&o, "colour", rgb);
    jo_send(&o);
}

// A room :move left says nothing more while it closes.
static void json_quiet(void *ui, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len,
                       int file) {
    (void)ui; (void)hhmm; (void)text; (void)rgb; (void)flags; (void)color_len; (void)file;
}

static void json_notify(void *ui, const char *nick, const char *text, int mentioned) {
    (void)ui;
    jout_t o;
    jo_begin(&o, "notify");
    if (nick) jo_str(&o, "nick", nick);
    if (text) jo_str(&o, "text", text);
    jo_bool(&o, "mention", mentioned);
    jo_send(&o);
}

static void json_delivery(void *ui, unsigned own, chat_delivery_t what, const char *name) {
    (void)ui;
    jout_t o;
    jo_begin(&o, "delivery");
    jo_int(&o, "own", own);
    if (what == CHAT_MISSED) jo_str(&o, "missed", name);
    else jo_bool(&o, "settled", 1);
    jo_send(&o);
}

// A picture fetched to be shown, decoded by chat's own readers in their sandbox and sent as pixels,
// so the program showing it never parses what a peer sent.
static void json_file_view(void *ui, int num, const char *name, const uint8_t *data, size_t len) {
    (void)ui;
    image_thumb_t th;
    char why[160];
    jout_t o;
    jo_begin(&o, "picture");
    jo_int(&o, "num", num);
    jo_str(&o, "name", name);
    if (thumb_decode(data, len, g_js.picture_max, g_js.picture_max, g_js.picture_bg, &th, why, sizeof why) != 0) {
        jo_str(&o, "error", why);
        jo_send(&o);
        return;
    }
    size_t raw = (size_t)th.w * (size_t)th.h * 3;
    char *b64 = malloc(BASE64_LEN(raw) + 1);
    if (b64) {
        base64_encode(th.rgb, raw, b64);
        jo_int(&o, "w", th.w);
        jo_int(&o, "h", th.h);
        jo_int(&o, "src_w", th.src_w);
        jo_int(&o, "src_h", th.src_h);
        jo_str(&o, "rgb", b64);
        crypto_wipe(b64, BASE64_LEN(raw) + 1);
        free(b64);
    } else {
        jo_str(&o, "error", "not enough memory");
    }
    thumb_free(&th);
    jo_send(&o);
}

static void send_peers(chat_t *c) {
    jout_t o;
    jo_begin(&o, "peers");
    jo_open(&o, "list", "[");
    for (int i = 0; i < CHAT_PEER_SLOTS; i++) {
        const peer_t *p = chat_peer_at(c, i);
        if (!p) continue;
        char name[CHAT_NAME_LEN], label[96];
        chat_peer_name(c, p, name);
        jo_open(&o, NULL, "{");
        jo_hex(&o, "id", chat_peer_id(p), ID_LEN);
        jo_str(&o, "name", name);
        jo_str(&o, "nick", chat_peer_nick(p));
        jo_colour(&o, "colour", chat_peer_colour(p));
        jo_str(&o, "identity", IDENTITY_NAMES[chat_peer_identity_source(p)]);
        const uint8_t *fp = chat_peer_fingerprint(p);
        if (fp) {
            char fphex[HEX_GROUPS_LEN(ID_FP_LEN)];
            hex_groups(fp, ID_FP_LEN, fphex);
            jo_str(&o, "signed", SIGNED_NAMES[chat_peer_verify_state(p)]);
            jo_str(&o, "fingerprint", fphex);
        }
        jo_open(&o, "code", "{");
        jo_str(&o, "state", CODE_NAMES[chat_code_state(c, p)]);
        const uint8_t *vfy = chat_peer_verify_code(p);
        if (vfy) {
            char words[BYTEWORDS_LEN(VERIFY_LEN)], hex[HEX_GROUPS_LEN(VERIFY_LEN)];
            bytewords(vfy, VERIFY_LEN, words);
            hex_groups(vfy, VERIFY_LEN, hex);
            jo_str(&o, "words", words);
            jo_str(&o, "hex", hex);
        }
        jo_raw(&o, "}");
        chat_build_label(p, label, sizeof label);
        jo_open(&o, "build", "{");
        jo_str(&o, "state", BUILD_NAMES[chat_peer_build_state(p)]);
        jo_str(&o, "label", label);
        jo_raw(&o, "}");
        jo_bool(&o, "history", chat_peer_keeps_history(p));
        jo_bool(&o, "ignored", chat_ignored(c, chat_peer_id(p)));
        jo_bool(&o, "dm", chat_peer_can_dm(p));
        jo_raw(&o, "}");
    }
    jo_raw(&o, "]");
    jo_send_changed(&o, &g_js.peers);
}

static void send_net(chat_t *c) {
    chat_net_t n;
    chat_net(c, &n);
    jout_t o;
    jo_begin(&o, "net");
    jo_bool(&o, "ready", chat_ready(c));
    jo_int(&o, "online", chat_online_count(c));
    jo_int(&o, "pending", chat_pending_count(c));
    if (chat_route_mode(c) == ROUTE_TOR) {
        char tor[96];
        tor_link_status(tor, sizeof tor);
        jo_str(&o, "tor", tor);
        if (n.onion != CHAT_NET_OFF) jo_bool(&o, "onion", n.onion);
    } else {
        if (n.dht != CHAT_NET_OFF) { jo_bool(&o, "dht", n.dht); jo_int(&o, "dht_found", n.dht_found); }
        if (n.portmap != CHAT_NET_OFF) jo_bool(&o, "portmap", n.portmap);
    }
    if (n.relays != CHAT_NET_OFF) {
        jo_open(&o, "relays", "{");
        jo_bool(&o, "used", n.relays);
        jo_int(&o, "up", n.relays_up);
        jo_int(&o, "total", n.relays_total);
        jo_raw(&o, "}");
    }
    jo_send_changed(&o, &g_js.net);
}

static void send_files(chat_t *c, double now) {
    if (now - g_js.files_at < FILES_EVERY) return;
    g_js.files_at = now;
    jout_t o;
    jo_begin(&o, "files");
    jo_open(&o, "list", "[");
    for (int i = 0; i < FILE_OFFERS_MAX; i++) {
        const file_entry_t *e = chat_file_at(c, i);
        if (!e) continue;
        jo_open(&o, NULL, "{");
        jo_int(&o, "num", e->num);
        jo_str(&o, "name", e->name);
        jo_int(&o, "size", (long long)e->size);
        jo_bool(&o, "mine", e->mine);
        jo_hex(&o, "from", e->owner, ID_LEN);
        jo_bool(&o, "image", e->image);
        jo_str(&o, "at", e->at);
        jo_str(&o, "state", DL_NAMES[e->dl]);
        if (e->dl == DL_ACTIVE || e->dl == DL_QUEUED) jo_bool(&o, "show", e->view);
        if (e->dl == DL_ACTIVE) {
            jo_int(&o, "got", (long long)chat_file_got(e));
            double eta = chat_file_eta(c, e, now);
            if (eta <= ETA_UNVERIFIED) jo_str(&o, "waiting", "verify");
            else if (eta < 0) jo_str(&o, "waiting", "sender");
            else jo_int(&o, "eta", (long long)(eta + 0.5));
        }
        if (e->dl == DL_QUEUED) jo_int(&o, "after", chat_file_queued_after(c, e));
        if (e->dl == DL_FAILED && e->why[0]) jo_str(&o, "why", e->why);
        if (e->saved[0]) jo_str(&o, "saved", e->saved);
        if (e->mine) {
            char name[CHAT_NAME_LEN], to[3 * CHAT_NAME_LEN];
            int permille = 0, n = chat_file_sending(c, e, now, name, &permille);
            if (n > 0) {
                jo_open(&o, "sending", "{");
                jo_int(&o, "count", n);
                jo_str(&o, "name", name);
                jo_int(&o, "permille", permille);
                jo_raw(&o, "}");
            }
            chat_file_sent_to(e, to, sizeof to);
            if (to[0]) jo_str(&o, "sent_to", to);
        }
        jo_raw(&o, "}");
    }
    jo_raw(&o, "]");
    jo_send_changed(&o, &g_js.files);
}

static void send_timer(chat_t *c) {
    char who[CHAT_NAME_LEN + 8] = "";
    unsigned s = chat_timer(c, who, sizeof who);
    if (g_js.timer_sent && s == g_js.timer && strcmp(who, g_js.timer_who) == 0) return;
    g_js.timer_sent = 1;
    g_js.timer = s;
    copy_str(g_js.timer_who, who, sizeof g_js.timer_who);
    jout_t o;
    jo_begin(&o, "timer");
    jo_int(&o, "seconds", s);
    if (s) jo_str(&o, "who", who);
    jo_send(&o);
}

// A request to move, once when it comes and once (seq 0) when it's answered or gone.
static void send_move(chat_t *c) {
    const chat_move_ask_t *a = chat_move_asked(c);
    unsigned seq = a ? a->seq : 0;
    if (seq == g_js.move_seq) return;
    g_js.move_seq = seq;
    jout_t o;
    jo_begin(&o, "move");
    jo_int(&o, "seq", seq);
    if (a) {
        jo_str(&o, "from", a->from);
        jo_int(&o, "coming", a->coming);
        jo_str(&o, "names", a->coming_names);
        jo_str(&o, "at", a->at);
    }
    jo_send(&o);
}

static void send_state(chat_t *c, double now) {
    if (now - g_js.state_at >= STATE_EVERY) {
        g_js.state_at = now;
        send_peers(c);
        send_net(c);
        send_timer(c);
        send_move(c);
    }
    send_files(c, now);
}

// ---- reading commands ----

static const char *jstr(const js_value *v, const char *key) { return js_str(js_obj_get(v, key)); }

static int jbool(const js_value *v, const char *key, int dflt) {
    const js_value *b = js_obj_get(v, key);
    return b && b->type == JS_BOOL ? b->b : dflt;
}

static long long jint(const js_value *v, const char *key, long long dflt) {
    const js_value *n = js_obj_get(v, key);
    return n && n->type == JS_NUM && n->is_int ? n->i : dflt;
}

static const peer_t *peer_arg(chat_t *c, const js_value *v) {
    const char *hex = jstr(v, "peer");
    uint8_t id[ID_LEN];
    const peer_t *p = hex && strlen(hex) == 2 * ID_LEN && hex_decode(hex, 2 * ID_LEN, id) == 0 ? chat_peer_by_id(c, id) : NULL;
    if (!p) say_error("no peer here with that \"peer\" id");
    return p;
}

// One of chat's commands for peer p, by the name chat shows it with: "verify NAME ok", "msg NAME TEXT".
static void run_on(chat_t *c, const char *cmd, const peer_t *p, const char *rest) {
    char name[CHAT_NAME_LEN], line[MAX_TEXT + CHAT_NAME_LEN + 16];
    chat_peer_name(c, p, name);
    snprintf(line, sizeof line, "%s %s%s%s", cmd, name, rest ? " " : "", rest ? rest : "");
    chat_run_command(c, line);
    crypto_wipe(line, sizeof line);
}

// "identity", or "start"'s: a new key, or one given as text, made the one in use. answer: say which.
static int read_identity(const js_value *v, int answer) {
    const char *kind = jstr(v, "kind"), *key = jstr(v, "key");
    int pgp = pick(kind, IDENTITY_NAMES, 4) == IDENT_PGP;
    if (!pgp && pick(kind, IDENTITY_NAMES, 4) != IDENT_AGE) { say_error("identity needs \"kind\": age or pgp"); return -1; }
    identity_keypair_t kp;
    int made = jbool(v, "new", 0);
    uint32_t created = (uint32_t)time(NULL);
    if (made) {
        gen_identity_keypair(&kp);
    } else if (!key || (pgp ? pgp_import_secret_key_text(key, &kp) : age_import_secret_key_text(key, &kp)) != 0) {
        say_error(pgp ? "\"key\" isn't an unencrypted PGP EdDSA secret key" : "\"key\" isn't an AGE secret key");
        return -1;
    }
    g_app.identity_source = pgp ? IDENT_PGP : IDENT_AGE;
    g_app.identity = kp;
    if (answer) say_identity(&kp, pgp, created, made);
    crypto_wipe(&kp, sizeof kp);
    return 0;
}

static int read_route(const js_value *r) {
    if (!r) {
        if (!g_app.route_chosen) choose_route(ROUTE_UDP);
        return 0;
    }
    const char *mode = jstr(r, "mode");
    int m = mode ? pick(mode, ROUTE_NAMES, 2) : (int)g_app.route.mode;
    if (m < 0) { say_error("route \"mode\" is udp or tor"); return -1; }
    choose_route((route_mode_t)m);
    routing_t *rt = &g_app.route;
    if (!jbool(r, "dht", 1)) rt->dht4 = rt->dht6 = 0;
    if (!jbool(r, "ipv6", 1)) rt->dht6 = 0;
    if (!jbool(r, "lan", 1)) rt->lan = 0;
    if (!jbool(r, "portmap", 1)) rt->portmap = 0;
    const char *nostr = jstr(r, "nostr");
    if (nostr) {
        int k = pick(nostr, NOSTR_NAMES, 3);
        if (k < 0) { say_error("route \"nostr\" is off, fallback or always"); return -1; }
        rt->nostr = k;
    }
    const js_value *relays = js_obj_get(r, "relays");
    if (relays && relays->type == JS_ARR) {
        rt->n_relays = 0;
        for (size_t i = 0; i < relays->n; i++) {
            const char *u = js_str(&relays->items[i]);
            if (!u || nostr_url_ok(u) != 0) { say_error("bad relay %s (want wss://host[:port][/path])", u ? u : "(not text)"); return -1; }
            if (rt->n_relays >= NOSTR_MAX_RELAYS) { say_error("at most %d relays", NOSTR_MAX_RELAYS); return -1; }
            copy_str(rt->relays[rt->n_relays++], u, NOSTR_URL_MAX);
        }
    }
    const js_value *t = js_obj_get(r, "tor");
    if (!t) return 0;
    const char *socks = jstr(t, "socks"), *control = jstr(t, "control"), *password = jstr(t, "password");
    const char *launch = jstr(t, "launch"), *path = jstr(t, "path");
    if ((socks && !valid_host_port(socks)) || (control && !valid_host_port(control))) {
        say_error("tor \"socks\" and \"control\" are host:port");
        return -1;
    }
    if (socks) copy_str(rt->tor.socks, socks, sizeof rt->tor.socks);
    if (control) copy_str(rt->tor.control, control, sizeof rt->tor.control);
    if (password) copy_str(rt->tor.password, password, sizeof rt->tor.password);
    if (launch) {
        int k = pick(launch, LAUNCH_NAMES, 3);
        if (k < 0) { say_error("tor \"launch\" is auto, always or never"); return -1; }
        g_app.tor.launch = k;
    }
    if (path) {
        char found[TOR_PATH_MAX];
        if (platform_find_program("tor", path, found, sizeof found) != 0) {
            say_error("can't use %s as tor - it has to be a full path to a program only root or you can change", path);
            return -1;
        }
        copy_str(g_app.tor.path, found, sizeof g_app.tor.path);
    }
    return 0;
}

// What "start" sets besides the room: everyone's settings, as the settings page has them.
static int read_settings(const js_value *v) {
    const char *nick = jstr(v, "nick"), *colour = jstr(v, "colour"), *verify = jstr(v, "verify");
    const char *net_log = jstr(v, "net_log");
    if (nick) chat_clean_nick(nick, g_app.nick);
    if (!g_app.nick[0]) random_nickname(g_app.nick, sizeof g_app.nick);
    if (colour && parse_color(colour, g_app.color) != 0) { say_error("unknown colour %s", colour); return -1; }
    if (read_route(js_obj_get(v, "route")) != 0) return -1;
    if (verify) {
        int k = pick(verify, VERIFY_NAMES, 2);
        if (k < 0) { say_error("\"verify\" is optional or required"); return -1; }
        g_app.verify_optional = k;
    }
    if (net_log) {
        int k = pick(net_log, NET_LOG_NAMES, 3);
        if (k < 0) { say_error("\"net_log\" is normal, verbose or off"); return -1; }
        g_app.net_log = k;
    }
    const js_value *notify = js_obj_get(v, "notify");
    if (notify) {
        const char *mode = jstr(notify, "mode"), *preview = jstr(notify, "preview");
        int m = mode ? pick(mode, NOTIFY_NAMES, 3) : (int)g_app.notify_mode;
        int p = preview ? pick(preview, PREVIEW_NAMES, 3) : (int)g_app.notify_preview;
        if (m < 0 || p < 0) { say_error("notify \"mode\" is none, mentions or all, and \"preview\" off, nick or message"); return -1; }
        g_app.notify_mode = (notify_mode_t)m;
        g_app.notify_preview = (notify_preview_t)p;
    }
    const js_value *files = js_obj_get(v, "files");
    if (files) {
        long long limit = jint(files, "limit", 0);
        if (limit < 0 || (uint64_t)limit > FILE_HARD_MAX) { say_error("files \"limit\" is 1 byte to 1 GB"); return -1; }
        if (limit) g_app.file_cap = (uint64_t)limit;
        g_app.fast_files = jbool(files, "fast", g_app.fast_files);
        g_app.picture_noise = jbool(files, "noise", g_app.picture_noise);
        const char *dir = jstr(files, "dir");
        if (dir) copy_str(g_js.dir, dir, sizeof g_js.dir);
    }
    const js_value *picture = js_obj_get(v, "picture");
    long long max = picture ? jint(picture, "max", PICTURE_MAX) : PICTURE_MAX;
    g_js.picture_max = max < PICTURE_MIN ? PICTURE_MIN : max > PICTURE_MAX ? PICTURE_MAX : (int)max;
    const char *bg = picture ? jstr(picture, "background") : NULL;
    if (bg && parse_color(bg, g_js.picture_bg) != 0) { say_error("unknown picture background %s", bg); return -1; }
    const js_value *identity = js_obj_get(v, "identity");
    return identity ? read_identity(identity, 0) : 0;
}

// The session "start" asks for, or NULL after saying why there's none.
static chat_t *json_start(const js_value *v, const options_t *opts) {
    if (read_settings(v) != 0) return NULL;
    chat_opts_t o;
    memset(&o, 0, sizeof o);
    copy_str(o.nick, g_app.nick, sizeof o.nick);
    const char *room = jstr(v, "room"), *password = jstr(v, "password"), *invite = jstr(v, "invite");
    if (invite) {
        // Its check catches a mistyped or cut off invite, instead of joining some other room.
        int r = chat_invite_parse(invite, o.session_name, o.password);
        if (r != 1) {
            crypto_wipe(&o, sizeof o);
            say_error(r == 0 ? "\"invite\" isn't an invite (chat:ID:PASSWORD:CHECK)" : "\"invite\" is mistyped or cut off");
            return NULL;
        }
        o.created = jbool(v, "create", 0);
    } else {
        if (!room && opts->session[0]) room = opts->session;
        o.created = jbool(v, "create", !room);
        if (room) copy_str(o.session_name, room, sizeof o.session_name);
        else random_session_id(o.session_name, SESSION_ID_LEN);
        if (password) {
            copy_str(o.password, password, sizeof o.password);
        } else if (platform_env_take("CHAT_PASSWORD", o.password, sizeof o.password) != 0 && o.created) {
            // As the NEW box suggests one: the id is often passed around in the open.
            uint8_t pw[MOVE_PASSWORD_BYTES];
            gen_random(pw, sizeof pw);
            bytewords_plain(pw, sizeof pw, o.password);
            crypto_wipe(pw, sizeof pw);
        }
    }
    long long port = jint(v, "port", opts->port);
    const js_value *peers = js_obj_get(v, "peers");
    int n_peers = peers && peers->type == JS_ARR ? (int)peers->n : opts->n_peers;
    const char *why = port < 0 || port > UINT16_MAX ? "\"port\" is 0 to 65535"
                      : n_peers > 0 && g_app.route.mode == ROUTE_TOR ? "\"peers\" can't be used with Tor routing" : NULL;
    if (why) { crypto_wipe(&o, sizeof o); say_error("%s", why); return NULL; }
    o.port = (uint16_t)port;
    sandbox_up();
    for (int i = 0; i < n_peers && o.n_peers < (int)COUNT_OF(o.peers); i++) {
        const char *hp = peers && peers->type == JS_ARR ? js_str(&peers->items[i]) : opts->peers[i];
        if (!hp || addr_parse_hostport(hp, &o.peers[o.n_peers]) != 0) {
            crypto_wipe(&o, sizeof o);
            say_error("can't use peer %s", hp ? hp : "(not text)");
            return NULL;
        }
        o.n_peers++;
    }
    o.route = g_app.route;
    if (o.route.mode == ROUTE_TOR) {
        tor_link_ensure(now_seconds());
        o.route.tor.socks[0] = o.route.tor.control[0] = '\0';
    }
    app_session_opts(&o);
    o.persist = jbool(v, "history", 0);
    o.file_view = json_file_view;
    o.delivery = json_delivery;
    chat_t *c = chat_new();
    if (!c) { crypto_wipe(&o, sizeof o); say_error("not enough memory for a session"); return NULL; }
    chat_init(c, &o, json_print, json_notify, c, now_seconds());
    copy_str(g_js.password, o.password, sizeof g_js.password);
    int created = o.created;
    crypto_wipe(&o, sizeof o);
    if (!chat_started(c)) {
        say_error("%s", chat_start_error(c));
        chat_shutdown(c);
        chat_free(c);
        return NULL;
    }
    g_plain_engine = c;
    chat_set_net_log(c, g_app.net_log);
    long long timer = jint(v, "timer", 0);
    if (timer >= TIMER_MIN && timer <= TIMER_MAX) chat_set_timer(c, (unsigned)timer);
    g_js.kept = jbool(v, "kept", 0);
    say_room(c, "ready", g_js.password, created, NULL);
    return c;
}

// --json's :move opens the new room in the same process, as --simple's does, and says where it is.
static chat_t *json_move(chat_t *c, chat_t **left, const chat_move_to_t *to) {
    if (*left) { chat_shutdown(*left); chat_free(*left); *left = NULL; }
    chat_t *n = chat_new();
    if (!n) { say_error("couldn't open the new room: not enough memory"); return NULL; }
    chat_opts_t o;
    memset(&o, 0, sizeof o);
    copy_str(o.nick, chat_nick(c), sizeof o.nick);
    copy_str(o.session_name, to->session_name, sizeof o.session_name);
    copy_str(o.password, to->password, sizeof o.password);
    o.created = to->created;
    o.route = g_app.route;
    if (o.route.mode == ROUTE_TOR) {
        copy_str(o.route.tor.socks, g_tor.state == TL_READY ? g_tor.socks : "", sizeof o.route.tor.socks);
        copy_str(o.route.tor.control, g_tor.state == TL_READY ? g_tor.control : "", sizeof o.route.tor.control);
    }
    app_session_opts(&o);
    memcpy(o.color, chat_colour(c), 3);
    o.persist = chat_history(c);
    o.moved = 1;
    o.moved_key = to->key;
    o.file_view = json_file_view;
    o.delivery = json_delivery;
    chat_init(n, &o, json_print, json_notify, n, now_seconds());
    crypto_wipe(&o, sizeof o);
    if (!chat_started(n)) {
        say_error("couldn't open the new room: %s", chat_start_error(n));
        chat_shutdown(n);
        chat_free(n);
        return NULL;
    }
    if (chat_route_mode(n) == ROUTE_TOR && g_tor.state == TL_READY && g_tor.proc)
        chat_tor_set_ports(n, g_tor.socks, g_tor.control, torproc_password(g_tor.proc));
    chat_set_net_log(n, chat_net_log(c));
    chat_move_go(c, to, n, now_seconds());
    chat_set_print(c, json_quiet);
    copy_str(g_js.password, to->password, sizeof g_js.password);
    forget_state();
    say_room(n, "moved", to->password, to->created, to->from);
    return n;
}

// ---- commands on a session; each returns 0 once it's time to stop ----

typedef int (*json_cmd_fn)(chat_t *c, const js_value *v, double now);

static int js_send(chat_t *c, const js_value *v, double now) {
    const char *text = jstr(v, "text");
    if (!text) say_error("send needs \"text\"");
    else chat_send_text(c, text, now);
    return 1;
}

static int js_reply(chat_t *c, const js_value *v, double now) {
    const char *mid = jstr(v, "mid"), *text = jstr(v, "text");
    if (!mid || !text) say_error("reply needs \"mid\" and \"text\"");
    else if (chat_send_reply(c, mid, text, now) != 0) say_error("that message is too old to answer");
    return 1;
}

static int js_dm(chat_t *c, const js_value *v, double now) {
    (void)now;
    const char *text = jstr(v, "text");
    const peer_t *p = peer_arg(c, v);
    if (p && !text) say_error("dm needs \"text\"");
    else if (p) run_on(c, "msg", p, text);
    return 1;
}

static int js_verify(chat_t *c, const js_value *v, double now) {
    (void)now;
    int same = jbool(v, "same", -1);
    const peer_t *p = peer_arg(c, v);
    if (p && same < 0) say_error("verify needs \"same\": true once the codes match, false if they don't");
    else if (p) run_on(c, "verify", p, same ? "ok" : "no");
    return 1;
}

static int js_ignore(chat_t *c, const js_value *v, double now) {
    (void)now;
    const peer_t *p = peer_arg(c, v);
    if (p) run_on(c, "ignore", p, jbool(v, "on", 1) ? NULL : "off");
    return 1;
}

static int js_fetch(chat_t *c, const js_value *v, double now) {
    (void)now;
    long long num = jint(v, "num", 0);
    int show = jbool(v, "show", 0);
    if (num < 1 || num > FILE_NUM_MAX) say_error("fetch needs a file's \"num\"");
    else chat_file_fetch(c, (int)num, show, jbool(v, "anyway", 0), show ? NULL : g_js.dir);
    return 1;
}

static int js_offer(chat_t *c, const js_value *v, double now) {
    (void)now;
    const char *path = jstr(v, "path");
    if (!path) say_error("offer needs \"path\"");
    else chat_send_file(c, path, jbool(v, "asis", 0));
    return 1;
}

static int js_cancel(chat_t *c, const js_value *v, double now) {
    (void)now;
    long long num = jint(v, "num", 0);
    char line[32];
    if (num < 1 || num > FILE_NUM_MAX) { say_error("cancel needs a file's \"num\""); return 1; }
    snprintf(line, sizeof line, "cancel %lld", num);
    chat_run_command(c, line);
    return 1;
}

static int js_timer(chat_t *c, const js_value *v, double now) {
    (void)now;
    long long s = jint(v, "seconds", -1);
    if (s != 0 && (s < TIMER_MIN || s > TIMER_MAX)) say_error("timer \"seconds\" is 0 (none) or %u to %u", TIMER_MIN, TIMER_MAX);
    else chat_set_timer(c, (unsigned)s);
    return 1;
}

static int js_history(chat_t *c, const js_value *v, double now) {
    (void)now;
    chat_set_history(c, jbool(v, "on", 1));
    return 1;
}

static int js_settings(chat_t *c, const js_value *v, double now) {
    (void)now;
    const char *nick = jstr(v, "nick"), *colour = jstr(v, "colour"), *verify = jstr(v, "verify");
    const js_value *notify = js_obj_get(v, "notify");
    uint8_t rgb[3];
    if (colour && parse_color(colour, rgb) != 0) { say_error("unknown colour %s", colour); return 1; }
    if (colour) { memcpy(g_app.color, rgb, 3); chat_set_colour(c, rgb); }
    if (nick) { chat_clean_nick(nick, g_app.nick); chat_set_nick(c, g_app.nick); }
    if (verify) {
        int k = pick(verify, VERIFY_NAMES, 2);
        if (k < 0) say_error("\"verify\" is optional or required");
        else chat_set_verify_required(c, !k);
    }
    if (notify) {
        int m = pick(jstr(notify, "mode"), NOTIFY_NAMES, 3), p = pick(jstr(notify, "preview"), PREVIEW_NAMES, 3);
        if (m >= 0) chat_set_notify_mode(c, (notify_mode_t)m);
        if (p >= 0) chat_set_notify_preview(c, (notify_preview_t)p);
    }
    return 1;
}

static int js_identity(chat_t *c, const js_value *v, double now) {
    (void)now;
    if (read_identity(v, 1) == 0) chat_set_identity(c, g_app.identity_source, &g_app.identity);
    return 1;
}

static int js_move(chat_t *c, const js_value *v, double now) {
    (void)now;
    int answer = jbool(v, "answer", -1);
    if (answer >= 0) { chat_run_command(c, answer ? "move yes" : "move no"); return 1; }
    chat_move_plan_t plan;
    chat_move_plan(c, &plan);
    jout_t o;
    jo_begin(&o, "move_plan");
    jo_int(&o, "coming", plan.coming);
    jo_str(&o, "coming_names", plan.coming_names);
    jo_int(&o, "left", plan.left);
    jo_str(&o, "left_names", plan.left_names);
    jo_send(&o);
    return 1;
}

static int js_newtor(chat_t *c, const js_value *v, double now) {
    (void)c; (void)v; (void)now;
    app_newtor(NULL, NULL);
    push_log("* %s", g_app.message);
    g_app.message[0] = '\0';
    return 1;
}

static int js_command(chat_t *c, const js_value *v, double now) {
    (void)now;
    const char *line = jstr(v, "line");
    if (!line) { say_error("command needs \"line\", as typed after :"); return 1; }
    // What it says, an unknown command too, comes as lines.
    return chat_run_command(c, line[0] == ':' ? line + 1 : line) != CMD_QUIT;
}

static int js_state(chat_t *c, const js_value *v, double now) {
    (void)c; (void)v; (void)now;
    forget_state();
    return 1;
}

static int js_quit(chat_t *c, const js_value *v, double now) {
    (void)c; (void)now;
    g_js.kept = jbool(v, "kept", g_js.kept);
    return 0;
}

static const struct { const char *name; json_cmd_fn fn; } COMMANDS[] = {
    { "send", js_send },         { "reply", js_reply },       { "dm", js_dm },
    { "verify", js_verify },     { "ignore", js_ignore },     { "fetch", js_fetch },
    { "offer", js_offer },       { "cancel", js_cancel },     { "timer", js_timer },
    { "history", js_history },   { "settings", js_settings }, { "identity", js_identity },
    { "move", js_move },         { "newtor", js_newtor },     { "command", js_command },
    { "state", js_state },       { "quit", js_quit },
};

// One line from stdin. 0 once it's time to stop.
static int json_command(chat_t *c, const char *line, double now) {
    const js_value *v = js_parse(line, strlen(line), &g_arena);
    const char *cmd = v && v->type == JS_OBJ ? jstr(v, "cmd") : NULL;
    int go = 1;
    size_t i = 0;
    while (cmd && i < COUNT_OF(COMMANDS) && strcmp(cmd, COMMANDS[i].name) != 0) i++;
    if (!cmd) say_error("not a command: each line is one JSON object with \"cmd\"");
    else if (i == COUNT_OF(COMMANDS)) say_error("no command %s", cmd);
    else go = COMMANDS[i].fn(c, v, now);
    crypto_wipe(&g_arena, sizeof g_arena);
    return go;
}

// The commands waiting on stdin, in order. 0 once it's time to stop, at "quit" or EOF.
static int json_input(chat_t *c, stdin_reader_t *reader, double now) {
    static char line[COMMAND_MAX];
    int rc;
    while ((rc = stdin_reader_poll(reader, line, sizeof line)) == 1) {
        int go = json_command(c, line, now);
        crypto_wipe(line, sizeof line);
        if (!go) return 0;
    }
    return rc != -1;
}

// Until "start": only "identity", to make or read a key before any room, and "quit". NULL to stop.
static chat_t *wait_for_start(stdin_reader_t *reader, const options_t *opts) {
    static char line[COMMAND_MAX];
    chat_t *c = NULL;
    int stop = 0;
    while (!c && !stop && !g_interrupted) {
        int rc = stdin_reader_poll(reader, line, sizeof line);
        if (rc == -1) break;
        if (rc == 0) { platform_sleep_ms(JSON_WAIT_MS); continue; }
        const js_value *v = js_parse(line, strlen(line), &g_arena);
        const char *cmd = v && v->type == JS_OBJ ? jstr(v, "cmd") : NULL;
        if (!cmd) say_error("not a command: each line is one JSON object with \"cmd\"");
        else if (strcmp(cmd, "start") == 0) stop = !(c = json_start(v, opts));
        else if (strcmp(cmd, "identity") == 0) read_identity(v, 1);
        else if (strcmp(cmd, "quit") == 0) stop = 1;
        else say_error("no session yet: \"start\" one first");
        crypto_wipe(line, sizeof line);
        crypto_wipe(&g_arena, sizeof g_arena);
    }
    return c;
}

static _Noreturn void json_quit(chat_t *c, chat_t *left, stdin_reader_t *reader, int code) {
    if (g_panic) panic_saves();
    if (left) { chat_shutdown(left); chat_free(left); }
    if (c) {
        chat_set_coming_back(c, g_js.kept);
        chat_shutdown(c);
        chat_free(c);
    }
    g_plain_engine = NULL;
    tor_link_stop();
    if (reader) stdin_reader_stop(reader);
    jout_t o;
    jo_begin(&o, "bye");
    jo_send(&o);
    forget_state();
    crypto_wipe(g_js.password, sizeof g_js.password);
    net_shutdown();
    platform_notify_shutdown();
    fflush(stdout);
    _exit(code);
}

int run_json(const options_t *opts) {
    g_json = g_plain = 1;
    g_js.picture_max = PICTURE_MAX;
    say_hello();
    catch_quit_signals();
    stdin_reader_t *reader = stdin_reader_start();
    if (!reader) { say_error("can't read stdin"); json_quit(NULL, NULL, NULL, 1); }
    chat_t *c = wait_for_start(reader, opts), *left = NULL;
    if (!c) json_quit(NULL, NULL, reader, g_interrupted ? 0 : 1);

    int alive = 1;
    while (alive && !g_interrupted && !g_ctrl_c) {
        sock_t socks[2 * CHAT_MAX_SOCKS];
        int nc = chat_sockets(c, socks), ns = nc + (left ? chat_sockets(left, socks + nc) : 0);
        int ready[2 * CHAT_MAX_SOCKS] = {0};
        net_wait(socks, ready, ns, JSON_WAIT_MS);
        double now = now_seconds();
        if (g_sigquit) {
            g_sigquit = 0;
            if (g_app.panic.key) panic(PANIC_KEY);
            break;
        }
        for (int i = 0; i < ns; i++) if (ready[i]) chat_on_socket_readable(i < nc ? c : left, socks[i], now);
        alive = json_input(c, reader, now);
        chat_move_to_t to;
        if (alive && chat_move_staged(c, &to)) {
            chat_t *n = json_move(c, &left, &to);
            if (n) { left = c; c = n; g_plain_engine = c; }
            crypto_wipe(&to, sizeof to);
        }
        tor_link_ensure(now);
        tor_link_step(now);
        chat_tick(c, now_seconds());
        if (left) {
            chat_tick(left, now_seconds());
            if (chat_move_finished(left, now_seconds())) { chat_shutdown(left); chat_free(left); left = NULL; }
        }
        send_state(c, now_seconds());
    }
    json_quit(c, left, reader, 0);
}
