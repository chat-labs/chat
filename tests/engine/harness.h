// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What the engine test's files share: alice, bob and carol's sessions (and alice's and bob's in the
// room :move takes them to), what each prints, the clock they keep to, checks, and the network's
// faults. engine_test.c runs the tests in order, each on the state the one before leaves.
#ifndef CHAT_HARNESS_H
#define CHAT_HARNESS_H

#include "core/chat.h"
#include "core/engine.h"
#include "core/trust.h"
#include "fake_net.h"
#include "common/json.h"
#include "common/toml.h"
#include "transport/portmap.h"
#include "common/image/image.h"
#include "common/image/clean.h"
#include "common/util.h"
#include "crypto/age.h"
#include "crypto/pgp.h"
#include "platform/platform.h"
#include "common/qr.h"
#include "common/bytewords.h"
#include "app/saves/saves.h"
#include "app/sessions/rooms.h"
#include "test_os.h"
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#ifdef __linux__
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#endif

#define LOG_LINES 512

typedef struct {
    const char *who;
    char lines[LOG_LINES][1024];
    int n;
    int modified_warnings;
    int anon_joins;   // "* anon ... joined": a peer announced before its nick came
    int joining, unheralded_joins;   // "joining" lines not yet followed by "joined", and "joined" without one
    int compare_prompts;   // "compare this code with ..."
    int held;              // "not sent to ...: compare verify codes first"
    int mismatched;        // "file N ... didn't match what was offered"
    int withdrawn;         // "NICK no longer offers file N"
    int key_warnings;      // a peer with a verified nick signs with another key
    int known_keys;        // a peer signs with a key verified before
    int histories;         // "* NICK keeps a history of this chat"
    int move_asks;         // "* NICK wants to move this room ..."
    int came_along;        // "* NICK came along from the room you moved from ..."
    int dm_old;            // "* NICK's chat is too old for direct messages"
    int timer_asks, timer_stops;   // "* NICK asks for messages here to go after ...", "... stopped asking ..."
    int offline, lefts;    // "* NICK went offline (...)", "* NICK left (...)"
} log_t;

extern chat_t A, B, C, A2, B2;
extern log_t log_a, log_b, log_c, log_a2, log_b2;
extern int checks, failures;
extern int verbose;

#define CHECK(cond, ...) do { \
    checks++; \
    if (cond) { if (verbose) printf("  pass  %s\n", #cond); } \
    else { failures++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); \
           if (verbose) printf("  fail  %s\n", #cond); } \
} while (0)

extern const uint8_t BUILD_ALICE[BUILD_HASH_LEN], BUILD_BOB[BUILD_HASH_LEN], BUILD_CAROL[BUILD_HASH_LEN];
extern char release_list[BUILD_LIST_LEN + 1], release_sig[MINISIGN_SIG_B64_LEN + 1];
extern double g_now;
extern chat_t *const ALL[5];
extern const log_t *const ALL_LOGS[3];
#define N_ALL ((int)(sizeof ALL / sizeof ALL[0]))
extern int n_live;
extern int live_mask;

// Runs the sessions until cond holds or seconds of simulated time pass, a tenth of a second at a time.
#define RUN_UNTIL(t, seconds, cond) do { \
    double end_ = *(t) + (seconds); \
    while (!(cond) && *(t) < end_) { *(t) += 0.1; pump(2, *(t)); } \
} while (0)
#define RUN_FOR(t, seconds) RUN_UNTIL(t, seconds, 0)

// Drops the next session frame from one port to another.
typedef struct { int armed; uint16_t from, to; int dropped; } drop_t;
// Drops every fifth session frame from one port to another.
typedef struct { uint16_t from, to; int seen, dropped; } lossy_t;

// harness.c
void on_print(void *ui, const char *hhmm, const char *text, const uint8_t *rgb, unsigned flags, int color_len, int file);
int log_count(const log_t *l, const char *needle);
void make_release(void);
void base_opts(chat_opts_t *o, const char *nick, uint16_t port, const uint16_t *peer_ports, int n, int created);
void start(chat_t *c, log_t *l, const char *nick, uint16_t port, const uint16_t *peer_ports, int n, int created,
           const uint8_t build[BUILD_HASH_LEN], int released);
void pump(int rounds, double t);
int rehandshaking_any(void);
peer_t *peer_named(chat_t *c, const char *nick);
int pending_msgs(const chat_t *c);
void confirm(chat_t *x, const char *x_calls_y, chat_t *y, const char *y_calls_x);
int is_session_frame(const void *data, size_t len);
int drop_one(void *ctx, addr_t from, addr_t to, const void *data, size_t len);
int drop_fifth(void *ctx, addr_t from, addr_t to, const void *data, size_t len);
int queues_empty(const chat_t *x, const peer_t *p);
void send_and_lose(chat_t *x, chat_t *y, const char *y_nick, const char *text, double *t);
int rekeyed(chat_t *x, const char *y_nick);
const uint8_t *find_bytes(const uint8_t *h, size_t hl, const char *needle);
int write_file(const char *path, const uint8_t *data, size_t len);

// sessions_test.c
void test_connect(double *t);
void test_verify_gate(double *t);
void test_message(double *t);
void test_long_message(double *t);
void test_constant_rate(double *t);
void test_lost_message(double *t);
void test_delivered(double *t);
void test_rekey(double *t);
void test_message_across_rekey(double *t);
void test_cookie_rate(double *t);
void test_udp_masked(double *t);
void test_dht_keys(double *t);
void test_dht(double *t);
void test_junk(double *t);
void test_lookalike_nick(double *t);
void test_third_peer(double *t);
void test_direct_message(double *t);
void test_reply(double *t);
void test_ignore(double *t);
void test_timer(double *t);
void test_candidates_settle(double *t);
void test_builds(double *t);

// parsers_test.c
void test_bytewords(double *t);
void test_links(double *t);
void test_mentions(double *t);
void test_qr(double *t);
void test_toml(double *t);
void test_parsers(double *t);

// platform_test.c
void test_read_file(double *t);
void test_sandbox(double *t);

// identity_test.c
void test_contact_room(double *t);
void test_invite(double *t);
void test_identity_keys(double *t);

// saves_test.c
void test_passphrase_seal(double *t);
void test_device_lock(double *t);
void test_factor_locks(double *t);
void test_totp(double *t);
void test_save_factors(double *t);
void test_duress(double *t);
void test_lock_screen(double *t);
void test_history(double *t);
void test_rooms(double *t);
void test_tor_state(double *t);

// pictures_test.c
extern const uint8_t PNG_4X2[92];
void test_images(double *t);
void test_clean(double *t);
void test_clean_offer(double *t);

// files_test.c
void test_files(double *t);
void test_file_names(double *t);

// move_test.c
void test_trust(double *t);
void test_move(double *t);
void test_offline(double *t);

#endif
