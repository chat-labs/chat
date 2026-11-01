// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
#include "app/update.h"
#include "core/chat.h"
#include "core/files.h"
#include "platform/platform.h"
#include "common/util.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stdarg.h>

#ifndef CHAT_VERSION
#define CHAT_VERSION "0.0.0"
#endif

#define UPDATE_REPO "chat-labs/chat"
// The most a download may be (64 MiB), and how long curl gets for one.
#define UPDATE_MAX_BYTES 67108864
#define FETCH_TIMEOUT_S 300
#define STR_(x) #x
#define STR(x) STR_(x)
// What the release's JSON, its SHA256SUMS and the signature of that are read up to.
#define RELEASE_JSON_MAX (1 << 20)
#define SUMS_MAX (1 << 16)
#define SIG_MAX 4096
// The running executable's path, and with a suffix for the files an update writes next to it.
#define EXE_PATH_MAX 1024
#define EXE_TMP_MAX 1100
#define SHA256_HEX (2 * crypto_hash_sha256_BYTES)
#define HELPER_STOP_MS 1000

#if defined(__x86_64__) || defined(_M_X64)
#define UPDATE_ARCH "x86_64"
#elif defined(__aarch64__) || defined(_M_ARM64)
#define UPDATE_ARCH "aarch64"
#endif

#ifdef UPDATE_ARCH
#ifdef _WIN32
#define UPDATE_ASSET "chat-windows-" UPDATE_ARCH ".exe"
#elif defined(__APPLE__)
#define UPDATE_ASSET "chat-macos-" UPDATE_ARCH
#else
#define UPDATE_ASSET "chat-linux-" UPDATE_ARCH
#endif
#endif

enum { UPD_IDLE = 0, UPD_RUNNING = 1, UPD_DONE = 2 };
static int g_state = UPD_IDLE;
static char g_msg[UPDATE_MSG_MAX];
static int g_ok;
static int g_betas;

static char g_proxy[64];

void update_set_proxy(const char *socks) { copy_str(g_proxy, socks ? socks : "", sizeof g_proxy); }

// ---- progress, for the box ----

// The update runs on its own thread and the screen reads this while drawing. A spinlock is
// enough for copies this small.
static char g_lock;
static update_view_t g_view;
static char g_dl_path[EXE_TMP_MAX];   // the download on its way, else ""
static long g_dl_total;               // its size as GitHub gives it, else 0

// Where each step puts the bar, in thousandths. The download moves it from AT_DOWNLOAD to AT_DOWNLOADED.
enum {
    AT_CHECKING = 0, AT_FOUND = 100, AT_SIGNATURE = 130, AT_DOWNLOAD = 200, AT_DOWNLOADED = 900,
    AT_VERIFYING = 920, AT_INSTALLING = 960, AT_DONE = 1000
};

static void view_lock(void) { while (__atomic_test_and_set(&g_lock, __ATOMIC_ACQUIRE)) {} }
static void view_unlock(void) { __atomic_clear(&g_lock, __ATOMIC_RELEASE); }

// What chat asks the updater for, and what the updater sends back after each step.
typedef struct { uint8_t betas; char proxy[sizeof g_proxy]; } helper_ask_t;
typedef struct {
    update_view_t view;
    char dl_path[EXE_TMP_MAX];
    long dl_total;
    int done, ok;
    char msg[UPDATE_MSG_MAX];
} helper_report_t;

static platform_proc_t *g_helper;
static int g_helper_link = -1;
static int g_helper_off;         // turned off during an update, so it stops once that's done
static int g_report_link = -1;   // in the updater

static void report(int done) {
    if (g_report_link < 0) return;
    helper_report_t r;
    memset(&r, 0, sizeof r);
    view_lock();
    r.view = g_view;
    copy_str(r.dl_path, g_dl_path, sizeof r.dl_path);
    r.dl_total = g_dl_total;
    view_unlock();
    r.done = done;
    r.ok = g_ok;
    copy_str(r.msg, g_msg, sizeof r.msg);
    platform_link_send(g_report_link, &r, sizeof r);
}

static void view_reset(void) {
    view_lock();
    memset(&g_view, 0, sizeof g_view);
    g_view.started = g_view.running = 1;
    g_dl_path[0] = '\0';
    g_dl_total = 0;
    view_unlock();
}

// A line in the console. The oldest is dropped once it's full.
PRINTF_LIKE(2, 3) static void say(update_line_kind_t kind, const char *fmt, ...) {
    char line[UPDATE_LINE_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    view_lock();
    if (g_view.n_log == UPDATE_LOG_MAX) {
        memmove(g_view.log[0], g_view.log[1], sizeof g_view.log[0] * (UPDATE_LOG_MAX - 1));
        memmove(g_view.kind, g_view.kind + 1, UPDATE_LOG_MAX - 1);
        g_view.n_log--;
    }
    copy_str(g_view.log[g_view.n_log], line, sizeof g_view.log[0]);
    g_view.kind[g_view.n_log++] = (unsigned char)kind;
    view_unlock();
    report(0);
}

// A short description of the current step, and how far along it is.
PRINTF_LIKE(2, 3) static void stage(int permille, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    view_lock();
    g_view.permille = permille;
    vsnprintf(g_view.step, sizeof g_view.step, fmt, ap);
    view_unlock();
    va_end(ap);
    report(0);
}

static void downloading(const char *path, long total) {
    view_lock();
    copy_str(g_dl_path, path ? path : "", sizeof g_dl_path);
    g_dl_total = total;
    view_unlock();
    report(0);
}

void update_view(update_view_t *v) {
    char path[sizeof g_dl_path];
    view_lock();
    *v = g_view;
    copy_str(path, g_dl_path, sizeof path);
    long total = g_dl_total;
    view_unlock();
    if (!v->running || !path[0]) return;
    // curl writes the download straight to the file, so the file's size is the progress.
    long got = 0;
    FILE *f = platform_fopen(path, "rb");
    if (f) {
        if (fseek(f, 0, SEEK_END) == 0) got = ftell(f);
        fclose(f);
    }
    if (got < 0) got = 0;
    char gs[24], ts[24];
    file_format_size((uint64_t)got, gs, sizeof gs);
    if (total > 0) {
        if (got > total) got = total;
        v->permille = AT_DOWNLOAD + (int)((int64_t)(AT_DOWNLOADED - AT_DOWNLOAD) * got / total);
        file_format_size((uint64_t)total, ts, sizeof ts);
        snprintf(v->amount, sizeof v->amount, "%s of %s", gs, ts);
    } else {
        snprintf(v->amount, sizeof v->amount, "%s so far", gs);
    }
}

static int fetch(const char *url, const char *out_path, int api) {
    // -q must come first: it stops curl reading a .curlrc that could turn off TLS checks or add a proxy.
    // --socks5-hostname leaves name lookups to the proxy, so Tor resolves GitHub, not local DNS.
    const char *argv[24] = {
        "curl", "-q", "-fsL", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
        "--max-time", STR(FETCH_TIMEOUT_S), "--max-filesize", STR(UPDATE_MAX_BYTES),
        "-H", api ? "Accept: application/vnd.github+json" : "Accept: application/octet-stream",
        "-o", out_path, url,
    };
    int n = 0;
    while (argv[n]) n++;
    uint8_t r[8];
    char user[sizeof r * 2 + sizeof ":x"];
    if (g_proxy[0]) {
        // Made-up SOCKS credentials give each download circuits of its own (Tor isolates by them),
        // so the exit can't tie one download to another, or to chat's own streams.
        randombytes_buf(r, sizeof r);
        hex_encode(r, sizeof r, user);
        copy_str(user + sizeof r * 2, ":x", sizeof user - sizeof r * 2);
        argv[n++] = "--socks5-hostname"; argv[n++] = g_proxy;
        argv[n++] = "--proxy-user"; argv[n++] = user;
    }
    return platform_run_quiet(argv);
}

static char *slurp(const char *path, size_t max, size_t *len_out) {
    FILE *f = platform_fopen(path, "rb");
    if (!f) return NULL;
    char *buf = malloc(max + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, max, f);
    fclose(f);
    buf[n] = '\0';
    if (len_out) *len_out = n;
    return buf;
}

static int parse_tag(const char *json, char *tag, size_t cap) {
    const char *p = strstr(json, "\"tag_name\"");
    if (!p) return -1;
    p += strlen("\"tag_name\"");
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p++ != ':') return -1;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p++ != '"') return -1;
    size_t n = 0;
    for (; *p && *p != '"'; p++) {
        if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-' && *p != '_') return -1;
        if (n + 1 >= cap) return -1;
        tag[n++] = *p;
    }
    if (*p != '"' || n == 0) return -1;
    tag[n] = '\0';
    return 0;
}

// Returns a beta's number ("0.5.0-beta.2" is 2), or LONG_MAX for a release, which comes after
// its betas.
static long parse_version(const char *s, long v[3]) {
    v[0] = v[1] = v[2] = 0;
    if (*s == 'v' || *s == 'V') s++;
    for (int i = 0; i < 3 && isdigit((unsigned char)*s); i++) {
        v[i] = strtol(s, (char **)&s, 10);
        if (*s != '.') break;
        s++;
    }
    if (*s != '-') return LONG_MAX;
    const char *dot = strrchr(s, '.');
    long n = dot ? strtol(dot + 1, NULL, 10) : 0;
    return n > 0 && n < LONG_MAX ? n : 1;
}

static int version_newer(const char *remote, const char *local) {
    long r[3], l[3];
    long remote_beta = parse_version(remote, r);
    long local_beta = parse_version(local, l);
    for (int i = 0; i < 3; i++)
        if (r[i] != l[i]) return r[i] > l[i];
    return remote_beta > local_beta;
}

static int sums_lookup(const char *sums, const char *name, uint8_t hash[crypto_hash_sha256_BYTES]) {
    size_t nlen = strlen(name);
    const char *line = sums;
    while (*line) {
        const char *end = strchr(line, '\n');
        size_t llen = end ? (size_t)(end - line) : strlen(line);
        if (llen > 0 && line[llen - 1] == '\r') llen--;
        if (llen >= SHA256_HEX + 2 && (line[SHA256_HEX] == ' ' || line[SHA256_HEX] == '\t')) {
            const char *fname = line + SHA256_HEX + 1;
            if (*fname == ' ' || *fname == '*') fname++;
            size_t flen = llen - (size_t)(fname - line);
            if (flen == nlen && memcmp(fname, name, nlen) == 0) {
                char hex[SHA256_HEX + 1];
                memcpy(hex, line, SHA256_HEX); hex[SHA256_HEX] = '\0';
                return hex_decode(hex, SHA256_HEX, hash);
            }
        }
        if (!end) break;
        line = end + 1;
    }
    return -1;
}

// The size GitHub gives for the release file called name, or 0 if it isn't there. It's only used
// for the progress bar. The file is verified by the signed SHA-256.
static long asset_size(const char *json, const char *name) {
    char want[80];
    snprintf(want, sizeof want, "\"%s\"", name);
    size_t wlen = strlen(want);
    for (const char *p = json; (p = strstr(p, want)) != NULL; p += wlen) {
        // As the value of a "name": a download URL ends in the name too, and a label may be it.
        const char *k = p;
        while (k > json && isspace((unsigned char)k[-1])) k--;
        if (k == json || k[-1] != ':') continue;
        k--;
        while (k > json && isspace((unsigned char)k[-1])) k--;
        if (k - json < 6 || memcmp(k - 6, "\"name\"", 6) != 0) continue;
        const char *s = strstr(p, "\"size\"");
        if (!s) return 0;
        s += 6;
        while (isspace((unsigned char)*s)) s++;
        if (*s++ != ':') return 0;
        while (isspace((unsigned char)*s)) s++;
        long v = strtol(s, NULL, 10);
        return v > 0 && v <= UPDATE_MAX_BYTES ? v : 0;
    }
    return 0;
}

#ifdef CHAT_RELEASE_PUBKEY
static const char RELEASE_PUBKEY[] = CHAT_RELEASE_PUBKEY;
#else
static const char RELEASE_PUBKEY[] = "";
#endif
#ifdef CHAT_RELEASE_BACKUP_PUBKEY
static const char RELEASE_BACKUP_PUBKEY[] = CHAT_RELEASE_BACKUP_PUBKEY;
#else
static const char RELEASE_BACKUP_PUBKEY[] = "";
#endif

// Checks a minisign signature (the SHA256SUMS.minisig next to SHA256SUMS) against one release key.
// The trusted comment must be "chat <tag>", so a signed SHA256SUMS from an older release can't be
// passed off as a newer one.
static int signed_by(const char *key, const char *msg, size_t msg_len, const char *sig_text, const char *tag) {
    uint8_t pk[MINISIGN_KEY_LEN];
    if (minisign_pubkey(key, pk) != 0) return -1;

    enum { L_UNTRUSTED, L_SIGNATURE, L_TRUSTED, L_GLOBAL, LINES };
    const char *lines[LINES]; size_t lens[LINES];
    const char *p = sig_text;
    for (int i = 0; i < LINES; i++) {
        const char *end = strchr(p, '\n');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (n > 0 && p[n - 1] == '\r') n--;
        lines[i] = p; lens[i] = n;
        if (!end) { if (i < L_GLOBAL) return -1; } else p = end + 1;
    }
    static const char TC[] = "trusted comment: ";
    if (lens[L_TRUSTED] < sizeof TC - 1 || memcmp(lines[L_TRUSTED], TC, sizeof TC - 1) != 0) return -1;
    const char *comment = lines[L_TRUSTED] + sizeof TC - 1;
    size_t comment_len = lens[L_TRUSTED] - (sizeof TC - 1);

    char want[64];
    int want_len = snprintf(want, sizeof want, "chat %s", tag);
    if (want_len < 0 || (size_t)want_len != comment_len || memcmp(comment, want, comment_len) != 0) return -1;

    uint8_t s[crypto_sign_BYTES], global[crypto_sign_BYTES];
    if (base64_decode_strict(lines[L_GLOBAL], lens[L_GLOBAL], global, sizeof global) != (long)sizeof global) return -1;
    if (minisign_verify(pk, msg, msg_len, lines[L_SIGNATURE], lens[L_SIGNATURE], s) != 0) return -1;

    uint8_t signed_comment[crypto_sign_BYTES + sizeof want];
    memcpy(signed_comment, s, crypto_sign_BYTES);
    memcpy(signed_comment + crypto_sign_BYTES, comment, comment_len);
    return crypto_sign_verify_detached(global, signed_comment, crypto_sign_BYTES + comment_len, pk + MINISIGN_BODY) == 0
         ? 0 : -1;
}

// The key built in from keys/minisign.pub, or its backup from keys/minisign-backup.pub.
static int minisign_ok(const char *msg, size_t msg_len, const char *sig_text, const char *tag) {
    if (signed_by(RELEASE_PUBKEY, msg, msg_len, sig_text, tag) == 0) return 0;
    return RELEASE_BACKUP_PUBKEY[0] ? signed_by(RELEASE_BACKUP_PUBKEY, msg, msg_len, sig_text, tag) : -1;
}

// SHA-256 of the next len bytes of f, or of all the rest if len is negative. Returns how many
// bytes that was, or -1 if reading failed.
static long hash_stream(FILE *f, long len, uint8_t out[crypto_hash_sha256_BYTES]) {
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    uint8_t buf[16384];
    long total = 0;
    for (;;) {
        size_t want = len < 0 || len - total > (long)sizeof buf ? sizeof buf : (size_t)(len - total), n;
        if (want == 0 || (n = fread(buf, 1, want, f)) == 0) break;
        crypto_hash_sha256_update(&st, buf, n);
        total += (long)n;
    }
    crypto_hash_sha256_final(&st, out);
    return ferror(f) ? -1 : total;
}

static int hash_file(const char *path, uint8_t out[crypto_hash_sha256_BYTES], long *size_out) {
    FILE *f = platform_fopen(path, "rb");
    if (!f) return -1;
    long total = hash_stream(f, -1, out);
    fclose(f);
    if (total < 0) return -1;
    if (size_out) *size_out = total;
    return 0;
}

// A URL without its "https://", as the console shows it.
static const char *shown_url(const char *url) { return url + sizeof "https://" - 1; }

// The message goes to the console log and into the box. A failure replaces the step it failed
// at, and leaves the bar where it stopped.
PRINTF_LIKE(1, 0) static void finish_v(const char *fmt, va_list ap) {
    vsnprintf(g_msg, sizeof g_msg, fmt, ap);
    const char *text = starts_with(g_msg, UPDATE_PREFIX) ? g_msg + sizeof UPDATE_PREFIX - 1 : g_msg;
    say(g_ok ? UPDATE_LINE_GOOD : UPDATE_LINE_BAD, "%s", text);
    downloading(NULL, 0);
    view_lock();
    if (g_ok) g_view.permille = AT_DONE;
    else copy_str(g_view.step, "Update failed", sizeof g_view.step);
    g_view.ok = g_ok;
    g_view.running = 0;
    view_unlock();
    report(1);
    __atomic_store_n(&g_state, UPD_DONE, __ATOMIC_RELEASE);
}

PRINTF_LIKE(1, 2) static void finish(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    finish_v(fmt, ap);
    va_end(ap);
}

PRINTF_LIKE(1, 2) static void succeed(const char *fmt, ...) {
    g_ok = 1;
    va_list ap;
    va_start(ap, fmt);
    finish_v(fmt, ap);
    va_end(ap);
}

static void update_thread(void *unused) {
    (void)unused;
    stage(AT_CHECKING, "Checking GitHub for a newer release%s", g_betas ? " or beta" : "");
#if !defined(UPDATE_ASSET)
    finish(UPDATE_PREFIX "no release builds exist for this CPU architecture");
#else
    if (!RELEASE_PUBKEY[0]) {
        finish(UPDATE_PREFIX "this build has no release signing key (keys/minisign.pub), so it can't check a release");
        return;
    }
    char exe[EXE_PATH_MAX], tmp_json[EXE_TMP_MAX], tmp_sums[EXE_TMP_MAX], tmp_sig[EXE_TMP_MAX], tmp_bin[EXE_TMP_MAX];
    char url[512];
    if (platform_exe_path(exe, sizeof exe) != 0) { finish(UPDATE_PREFIX "could not locate the running executable"); return; }
    snprintf(tmp_json, sizeof tmp_json, "%s.release", exe);
    snprintf(tmp_sums, sizeof tmp_sums, "%s.sums", exe);
    snprintf(tmp_sig, sizeof tmp_sig, "%s.sums.minisig", exe);
    snprintf(tmp_bin, sizeof tmp_bin, "%s.download", exe);

    say(UPDATE_LINE_INFO, "this is v" CHAT_VERSION ", " UPDATE_ASSET);
    if (g_proxy[0]) say(UPDATE_LINE_DETAIL, "downloads go through Tor (%s)", g_proxy);
    // GitHub's latest release is never a pre-release, so betas come from the list, newest first.
    snprintf(url, sizeof url, "https://api.github.com/repos/" UPDATE_REPO "/releases%s",
             g_betas ? "?per_page=1" : "/latest");
    say(UPDATE_LINE_DETAIL, "GET %s", shown_url(url));
    if (fetch(url, tmp_json, 1) != 0) {
        platform_remove(tmp_json);
        finish(UPDATE_PREFIX "could not reach GitHub (is curl installed, and is %s's folder writable?)", exe);
        return;
    }
    char *json = slurp(tmp_json, RELEASE_JSON_MAX, NULL);
    platform_remove(tmp_json);
    char tag[40];
    int ok = json && parse_tag(json, tag, sizeof tag) == 0;
    long total = ok ? asset_size(json, UPDATE_ASSET) : 0;
    free(json);
    if (!ok) { finish(UPDATE_PREFIX "GitHub's reply had no usable release tag"); return; }
    say(UPDATE_LINE_INFO, g_betas ? "newest release, betas included, is %s" : "latest release is %s", tag);
    if (!version_newer(tag, CHAT_VERSION)) {
        stage(AT_DONE, "Already up to date");
        if (g_betas) succeed(UPDATE_PREFIX "already up to date (v" CHAT_VERSION ", newest with betas is %s)", tag);
        else succeed(UPDATE_PREFIX "already up to date (v" CHAT_VERSION ", latest is %s)", tag);
        return;
    }
    stage(AT_FOUND, "Release %s found", tag);

    snprintf(url, sizeof url, "https://github.com/" UPDATE_REPO "/releases/download/%s/SHA256SUMS", tag);
    say(UPDATE_LINE_DETAIL, "GET %s", shown_url(url));
    if (fetch(url, tmp_sums, 0) != 0) {
        platform_remove(tmp_sums);
        finish(UPDATE_PREFIX "release %s has no SHA256SUMS - refusing to install it", tag);
        return;
    }
    size_t sums_len = 0;
    char *sums = slurp(tmp_sums, SUMS_MAX, &sums_len);
    platform_remove(tmp_sums);

    // SHA256SUMS comes from the same place as the binary, so on its own it only catches corruption.
    // The signature, made offline with the release key, is what verifies it.
    stage(AT_SIGNATURE, "Checking %s's signature", tag);
    snprintf(url, sizeof url, "https://github.com/" UPDATE_REPO "/releases/download/%s/SHA256SUMS.minisig", tag);
    say(UPDATE_LINE_DETAIL, "GET %s", shown_url(url));
    char *sig = NULL;
    if (fetch(url, tmp_sig, 0) == 0) sig = slurp(tmp_sig, SIG_MAX, NULL);
    platform_remove(tmp_sig);
    int signed_ok = sums && sig && minisign_ok(sums, sums_len, sig, tag) == 0;
    free(sig);
    if (!signed_ok) {
        free(sums);
        finish(UPDATE_PREFIX "release %s has no valid release-key signature - refusing to install it", tag);
        return;
    }
    say(UPDATE_LINE_GOOD, "SHA256SUMS is signed by the release key, for %s", tag);

    uint8_t want[crypto_hash_sha256_BYTES];
    ok = sums_lookup(sums, UPDATE_ASSET, want) == 0;
    free(sums);
    if (!ok) { finish(UPDATE_PREFIX "SHA256SUMS lists no " UPDATE_ASSET " for %s - nothing installed", tag); return; }
    char want_hex[2 * sizeof want + 1];
    hex_encode(want, sizeof want, want_hex);
    say(UPDATE_LINE_DETAIL, "expecting SHA-256 %.16s...", want_hex);

    stage(AT_DOWNLOAD, "Downloading %s", tag);
    snprintf(url, sizeof url, "https://github.com/" UPDATE_REPO "/releases/download/%s/" UPDATE_ASSET, tag);
    if (total > 0) {
        char ts[24];
        file_format_size((uint64_t)total, ts, sizeof ts);
        say(UPDATE_LINE_DETAIL, "GET %s (%s)", shown_url(url), ts);
    } else {
        say(UPDATE_LINE_DETAIL, "GET %s", shown_url(url));
    }
    downloading(tmp_bin, total);
    int got_ok = fetch(url, tmp_bin, 0) == 0;
    downloading(NULL, 0);
    if (!got_ok) {
        platform_remove(tmp_bin);
        finish(UPDATE_PREFIX "downloading " UPDATE_ASSET " from %s failed - nothing installed", tag);
        return;
    }
    stage(AT_VERIFYING, "Verifying the download");
    uint8_t got[crypto_hash_sha256_BYTES];
    long size = 0;
    if (hash_file(tmp_bin, got, &size) != 0 || size == 0 || memcmp(got, want, sizeof got) != 0) {
        platform_remove(tmp_bin);
        finish(UPDATE_PREFIX "SHA-256 of the %s download does NOT match SHA256SUMS - discarded, nothing installed", tag);
        return;
    }
    char size_s[24];
    file_format_size((uint64_t)size, size_s, sizeof size_s);
    say(UPDATE_LINE_GOOD, "downloaded %s; its SHA-256 matches SHA256SUMS", size_s);

    stage(AT_INSTALLING, "Installing %s", tag);
    say(UPDATE_LINE_DETAIL, "replacing %s", exe);
    if (platform_replace_exe(tmp_bin, exe) != 0) {
        platform_remove(tmp_bin);
        finish(UPDATE_PREFIX "verified %s but could not replace the executable (permissions?)", tag);
        return;
    }
    stage(AT_DONE, "Installed %s - restart chat to run it", tag);
    succeed(UPDATE_PREFIX "installed %s (signature and SHA-256 verified) - restart chat to run it", tag);
#endif
}

// The update runs in the updater, and its progress shows here as if it ran in chat.
static void relay_thread(void *unused) {
    (void)unused;
    helper_ask_t ask;
    memset(&ask, 0, sizeof ask);
    ask.betas = (uint8_t)(g_betas != 0);
    copy_str(ask.proxy, g_proxy, sizeof ask.proxy);
    helper_report_t r;
    if (platform_link_send(g_helper_link, &ask, sizeof ask) == 0) {
        while (platform_link_recv(g_helper_link, &r, sizeof r) == 0) {
            view_lock();
            g_view = r.view;
            copy_str(g_dl_path, r.dl_path, sizeof g_dl_path);
            g_dl_total = r.dl_total;
            view_unlock();
            if (r.done) {
                g_ok = r.ok;
                copy_str(g_msg, r.msg, sizeof g_msg);
                __atomic_store_n(&g_state, UPD_DONE, __ATOMIC_RELEASE);
                return;
            }
        }
    }
    update_helper_stop();
    finish(UPDATE_PREFIX "the updater has stopped - quit chat and run chat --update");
}

int update_start(int betas) {
    int idle = UPD_IDLE;
    if (!__atomic_compare_exchange_n(&g_state, &idle, UPD_RUNNING, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -1;
    g_ok = 0;
    g_betas = betas;
    view_reset();
    if (platform_spawn_thread(update_helper_running() ? relay_thread : update_thread, NULL) != 0) {
        view_lock();
        g_view.running = 0;
        view_unlock();
        __atomic_store_n(&g_state, UPD_IDLE, __ATOMIC_RELEASE);
        return -1;
    }
    return 0;
}

int update_poll(char *msg, size_t cap) {
    if (__atomic_load_n(&g_state, __ATOMIC_ACQUIRE) != UPD_DONE) return 0;
    copy_str(msg, g_msg, cap);
    __atomic_store_n(&g_state, UPD_IDLE, __ATOMIC_RELEASE);
    if (g_helper_off) update_helper_stop();
    return 1;
}

int update_run(int betas, char *msg, size_t cap) {
    g_ok = 0;
    g_betas = betas;
    view_reset();
    update_thread(NULL);
    update_poll(msg, cap);
    return g_ok ? 0 : -1;
}

// ---- the updater, outside chat's sandbox (Linux) ----

void update_helper_start(void) {
    int link;
    platform_proc_t *p = platform_spawn_self(UPDATE_HELPER_NAME, UPDATE_HELPER_ARG, &link);
    if (!p) return;
    g_helper_link = link;
    __atomic_store_n(&g_helper, p, __ATOMIC_RELEASE);
}

void update_helper_stop(void) {
    platform_proc_t *p = __atomic_exchange_n(&g_helper, NULL, __ATOMIC_ACQ_REL);
    if (!p) return;
    platform_link_close(g_helper_link);
    g_helper_link = -1;
    platform_proc_stop(p, HELPER_STOP_MS);
}

int update_helper_running(void) { return __atomic_load_n(&g_helper, __ATOMIC_ACQUIRE) != NULL; }

// The relay thread uses the link until the update is done, so it can't be closed under it.
void update_helper_enable(int on) {
    g_helper_off = !on;
    if (!on && __atomic_load_n(&g_state, __ATOMIC_ACQUIRE) != UPD_RUNNING) update_helper_stop();
}

// A bug in chat could be what's asking, so the proxy can only be a host and port.
static int ask_ok(const helper_ask_t *a) {
    static const char HOST_PORT[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:[]";
    return a->betas <= 1 && memchr(a->proxy, '\0', sizeof a->proxy) && strspn(a->proxy, HOST_PORT) == strlen(a->proxy);
}

int update_helper(int link) {
    char exe[EXE_PATH_MAX], curl[EXE_PATH_MAX], why[160];
    platform_set_name(UPDATE_HELPER_NAME);
    if (platform_exe_path(exe, sizeof exe) != 0) return 1;
    char *slash = strrchr(exe, '/');
    if (!slash) return 1;
    if (slash == exe) slash[1] = '\0'; else *slash = '\0';
    const char *run[] = { curl };
    platform_sandbox(run, platform_find_program("curl", NULL, curl, sizeof curl) == 0, exe, why, sizeof why);
    g_report_link = link;
    helper_ask_t ask;
    char msg[UPDATE_MSG_MAX];
    while (platform_link_recv(link, &ask, sizeof ask) == 0 && ask_ok(&ask)) {
        update_set_proxy(ask.proxy);
        update_run(ask.betas, msg, sizeof msg);
    }
    return 0;
}

// ---- this build, as reported to peers ----

const char *update_release_key(void) { return RELEASE_PUBKEY; }
const char *update_release_backup_key(void) { return RELEASE_BACKUP_PUBKEY; }

// What `just release` appends to each binary: the signed list ("chat vVERSION", each binary's
// hash, then the signature line), and a footer of the list's length in LIST_LEN_DIGITS digits and this.
#define LIST_MAGIC "CHATBLD1"
#define LIST_LEN_DIGITS 8
#define LIST_FOOTER (LIST_LEN_DIGITS + (int)sizeof LIST_MAGIC - 1)
#define LIST_MAX 1024

// Takes the list apart into b: only one for this version, with hashes as sha256sum writes them.
static void parse_list(char *text, chat_build_t *b) {
    char *lines[BUILD_LIST_MAX + 3];
    int n = 0;
    for (char *p = text; *p; ) {
        char *end = strchr(p, '\n');
        if (!end || n == (int)COUNT_OF(lines)) return;
        *end = '\0';
        lines[n++] = p;
        p = end + 1;
    }
    if (n < 3 || strcmp(lines[0], "chat v" CHAT_VERSION) != 0 || strlen(lines[n - 1]) != MINISIGN_SIG_B64_LEN) return;
    char list[BUILD_LIST_LEN + 1] = "";
    size_t pos = 0;
    for (int i = 1; i < n - 1; i++) {
        if (strlen(lines[i]) != BUILD_HASH_LEN * 2 || strspn(lines[i], HEX_DIGITS) != BUILD_HASH_LEN * 2) return;
        pos += (size_t)snprintf(list + pos, sizeof list - pos, "%s%s", i > 1 ? "," : "", lines[i]);
    }
    copy_str(b->list, list, sizeof b->list);
    copy_str(b->list_sig, lines[n - 1], sizeof b->list_sig);
}

int update_self_build(chat_build_t *b) {
    memset(b, 0, sizeof *b);
    copy_str(b->version, CHAT_VERSION, sizeof b->version);
#ifdef __linux__
    // The file this process was started from, even if an update has replaced it since.
    FILE *f = platform_fopen("/proc/self/exe", "rb");
#else
    char exe[EXE_PATH_MAX];
    FILE *f = platform_exe_path(exe, sizeof exe) == 0 ? platform_fopen(exe, "rb") : NULL;
#endif
    if (!f) return -1;
    long size = fseek(f, 0, SEEK_END) == 0 ? ftell(f) : -1;
    long core = size;
    char foot[LIST_FOOTER], text[LIST_MAX + 1];
    if (size > LIST_FOOTER && fseek(f, size - LIST_FOOTER, SEEK_SET) == 0 && fread(foot, 1, LIST_FOOTER, f) == LIST_FOOTER
        && memcmp(foot + LIST_LEN_DIGITS, LIST_MAGIC, sizeof LIST_MAGIC - 1) == 0) {
        long len = 0;
        for (int i = 0; i < LIST_LEN_DIGITS && len >= 0; i++) len = isdigit((unsigned char)foot[i]) ? len * 10 + (foot[i] - '0') : -1;
        if (len > 0 && len <= LIST_MAX && len <= size - LIST_FOOTER) {
            // The hash doesn't include the list, since the list can't contain its own hash.
            core = size - LIST_FOOTER - len;
            if (fseek(f, core, SEEK_SET) == 0 && fread(text, 1, (size_t)len, f) == (size_t)len) {
                text[len] = '\0';
                parse_list(text, b);
            }
        }
    }
    uint8_t hash[crypto_hash_sha256_BYTES];
    long hashed = size >= 0 && fseek(f, 0, SEEK_SET) == 0 ? hash_stream(f, core, hash) : -1;
    fclose(f);
    if (hashed < 0 || hashed != core) return -1;
    memcpy(b->hash, hash, sizeof b->hash);
    b->ok = 1;
    return 0;
}

void update_cleanup_stale(void) {
    char exe[EXE_PATH_MAX], old[EXE_TMP_MAX];
    if (platform_exe_path(exe, sizeof exe) != 0) return;
    snprintf(old, sizeof old, "%s.old", exe);
    platform_remove(old);
}
