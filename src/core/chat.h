// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// The engine: a session in a room (chat_t), which the app starts, gives the time and its sockets,
// and asks and tells things through these functions. What a session holds is the engine's own
// (core/state.h).
#ifndef CHAT_CHAT_H
#define CHAT_CHAT_H

#include "platform/net.h"
#include "crypto/crypto.h"
#include "core/cmd.h"
#include "transport/nostr.h"
#include "transport/tor.h"
#include "core/files.h"
#include "common/util.h"
#include <stdint.h>
#include <stdio.h>

#define MAX_PEERS 50
#define MAX_PENDING_PEERS 64

#define MAX_NICK 24
#define MAX_TEXT 880

#define MAX_SESSION_NAME 64
// A new session's id: this many characters from random_session_id.
#define SESSION_ID_LEN 10
#define MAX_PASSWORD 255
#define MAX_STATIC_PEERS 16

// ---- files ----
//
// A file is offered to the connected peers ("fo"). Nothing else is sent until someone decides to
// fetch it. They then ask for a window of chunks at a time ("fg") and the sender sends them in
// the slots that would otherwise carry a nop ("fd"), so a transfer looks the same as normal
// traffic. Through the relays it's two per slot. With fast transfers on, a peer's slots come much
// closer together during a transfer: faster, but visible as a burst (through the relays, only as
// close as they allow). Each chunk goes in its place in the window, and a run of missing chunks is
// requested again. A complete window is written in order and hashed, and the file is only kept if
// the hash matches the offer.
#define FILE_HARD_MAX (1024ull * 1024 * 1024)
#define FILE_CAP_DEFAULT (8ull * 1024 * 1024)
#define FILE_OFFERS_MAX 64
#define FILE_ID_LEN 8

// A file fetched to be shown rather than saved is held in memory, up to this size.
#define FILE_VIEW_MAX (64u * 1024 * 1024)
// Pictures that were shown stay in memory, up to this much in all (the oldest are dropped first), so
// :show and :download use them instead of fetching them again.
#define FILE_CACHE_MAX (128u * 1024 * 1024)

// The peers one of ours went to in full that are named, beyond those it's only counted.
#define FILE_SENT_MAX 4
// A folder a file is saved in, where it was saved, and the hidden file it's written to until then.
#define FILE_DIR_MAX 600
#define FILE_SAVED_MAX 800
#define FILE_PART_MAX 640
// The highest file number a command takes.
#define FILE_NUM_MAX 1000000

// A peer's nick as shown (chat_peer_name), with "#" and the start of its id if another looks the same.
#define SHORT_ID_LEN 4
#define SHORT_ID_HEX (2 * SHORT_ID_LEN)
#define CHAT_NAME_LEN (MAX_NICK + 2 + SHORT_ID_HEX)

typedef enum { ROUTE_UDP = 0, ROUTE_TOR = 1 } route_mode_t;

// The relays, the same in both routes: off, only while something needs them, or always.
enum { NOSTR_OFF = 0, NOSTR_FALLBACK = 1, NOSTR_ALWAYS = 2 };

// How a session reaches peers. UDP: straight between peers, found through the DHT (IPv4, IPv6),
// LAN broadcast and relays, with a router port mapping so more of them can connect. Tor: onion
// services. Either way, Nostr relays carry traffic when the route can't, through Tor in Tor
// routing. Nothing else goes on the network.
typedef struct {
    route_mode_t mode;
    int dht4, dht6, lan, portmap, nostr;
    char relays[NOSTR_MAX_RELAYS][NOSTR_URL_MAX];
    int n_relays;
    tor_opts_t tor;
} routing_t;

void routing_defaults(routing_t *r);
const char *routing_mode_name(route_mode_t m);

typedef enum { NOTIFY_NONE = 0, NOTIFY_MENTIONS = 1, NOTIFY_ALL = 2 } notify_mode_t;
// What a desktop notification shows: only that a message came in (the default), who it's from, or
// who and what it says. Never the session, since its id is all someone needs to join one with a
// blank password, and desktops keep notifications.
typedef enum { PREVIEW_OFF = 0, PREVIEW_NICK = 1, PREVIEW_MESSAGE = 2 } notify_preview_t;
typedef enum { IDENT_NONE = 0, IDENT_NATIVE = 1, IDENT_AGE = 2, IDENT_PGP = 3 } identity_source_t;

typedef enum { VERIFY_UNVERIFIED = 0, VERIFY_VERIFIED = 1, VERIFY_FAILED = 2 } verify_state_t;

// A peer's verify code as the sidebar shows it (chat_code_state).
enum { CODE_NOTHING = 0, CODE_TO_COMPARE = 1, CODE_COMPARED = 2, CODE_DIFFERS = 3, CODE_KEY_CHANGED = 4 };

// What a peer's "v" says about the build it runs. A peer can lie about its hash, so OFFICIAL is
// only its claim. MODIFIED is a build that doesn't claim to be from a release.
typedef enum {
    BUILD_UNKNOWN = 0,   // it sent none: a build from before "v"
    BUILD_UNCHECKED,     // this build has no release key to check it with
    BUILD_OFFICIAL,
    BUILD_MODIFIED       // not a binary of the release it names, or with no signed list of it
} build_state_t;

#define MAX_VERSION 15

// A release binary ends with a list of that release's binaries (the SHA-256 of each, without the
// list), signed with the release key. `just release` appends it. A build sends peers its own list
// in "v", so they can check it without asking anyone else. Three hashes keep "v" inside one
// normal sized session frame.
#define BUILD_LIST_MAX 3
#define BUILD_LIST_LEN (BUILD_LIST_MAX * (BUILD_HASH_LEN * 2 + 1))

// This program's build, as reported to peers.
typedef struct {
    int ok;   // 0 if the executable couldn't be read: nothing is sent
    char version[MAX_VERSION + 1];
    uint8_t hash[BUILD_HASH_LEN];
    char list[BUILD_LIST_LEN + 1];              // the list's hashes, hex, comma-separated; "" if none
    char list_sig[MINISIGN_SIG_B64_LEN + 1];    // the list's signature line
} chat_build_t;

// A nick with lookalike characters, case and invisible characters normalised away.
#define NICK_SKEL_LEN (4 * MAX_NICK + 1)

// DL_QUEUED: asked for while another file from the same sender is coming. It starts after that one.
typedef enum { DL_NONE = 0, DL_ACTIVE, DL_DONE, DL_FAILED, DL_QUEUED } dl_state_t;

typedef struct {
    int used;
    int num;                     // what it's called in commands: :download NUM
    int mine;
    uint8_t owner[ID_LEN];       // who offered it
    uint8_t fid[FILE_ID_LEN];
    uint64_t size;
    uint8_t sha[SHA256_LEN];
    char name[FILE_NAME_MAX + 1];
    int image;                   // offered as a PNG, JPEG or GIF (only decoding it says it is one)
    FILE *fp;                    // ours: open for its chunks, so the file offered is the one sent
    uint8_t *clean;              // ours, cleaned (common/image/clean.h): the bytes offered, from memory in fp's place

    dl_state_t dl;
    int view;                    // fetched to show (into mem), not to save (to out)
    int also_show, also_save;    // asked for the other way while on its way: shown or saved too once it's here
    char save_dir[FILE_DIR_MAX]; // the folder to save it in, "" for Downloads
    char saved[FILE_SAVED_MAX];  // where it was last saved, "" if it wasn't
    uint8_t *cache;              // a picture shown here: its bytes, checked against sha, for :show and :download
    FILE *out;
    char part_path[FILE_PART_MAX];
    uint8_t *mem;
    uint64_t done;               // bytes in order, written and hashed
    sha256_ctx_t hash;
    uint64_t win_off;            // the window asked for: win_n chunks from win_off
    int win_n;
    uint64_t win_got;            // which of them have come
    int req_end;                 // the chunk after the run of the window last asked for
    uint8_t *win;
    double retry_at;
    int retries;
    double since;                // when the fetch started
    double gone_since;           // when its sender left, while it's away
    char at[HHMM_LEN];           // when it was offered, HH:MM
    char why[64];                // why the last fetch failed
    // Ours: who it went to in full.
    int n_sent;
    uint8_t sent_id[FILE_SENT_MAX][ID_LEN];
    char sent_name[FILE_SENT_MAX][CHAT_NAME_LEN];
} file_entry_t;

// file: the number of the file a line offers (an image can be shown under it), else 0.
typedef void (*chat_print_fn)(void *ui, const char *hhmm, const char *text, const uint8_t *rgb,
                              unsigned flags, int color_len, int file);

#define LINE_CHAT 1u
#define LINE_MENTION 2u
// A warning the user must see, such as a verified peer's key changing: shown in the chat as well
// as the console.
#define LINE_WARN 4u
// A message of ours, numbered as chat_own_seq says while it's printed, for chat_delivery_fn.
#define LINE_OWN 8u
// A direct message, to one peer or from one (chat_line says which).
#define LINE_DIRECT 16u

// What became of a message of ours: a peer it went to never acked it (name says who), or there's
// nothing left to hear about it. Settled with nobody missed, every peer it went to has it. Copies
// passed on by others aren't acked back, so that's the peers we're connected to.
typedef enum { CHAT_MISSED, CHAT_SETTLED } chat_delivery_t;
typedef void (*chat_delivery_fn)(void *ui, unsigned own, chat_delivery_t what, const char *name);

// A file fetched to be shown has arrived, complete and matching the offer. Its bytes are only
// valid during the call.
typedef void (*chat_file_fn)(void *ui, int num, const char *name, const uint8_t *data, size_t len);

// A message that should get a notification. nick and text are NULL unless the session's
// notify_preview allows the notification to show them.
typedef void (*chat_notify_fn)(void *ui, const char *nick, const char *text, int mentioned);

// ---- moving the room (:move) ----
//
// With no server, nobody can be put out of a room, and a password that leaked can't be changed. :move
// instead takes the peers whose verify codes were compared, and whose builds can move, to a new room
// with an id and password made up on the spot, and leaves everyone else in this one. Each of them is
// sent the new room over its session ("mv"), and asked whether to go. Everyone moving shows the others
// a key of its own for the move, over the sessions here ("mk", or in "mv"), and signs its sessions in
// the new room with it ("mp"), so codes compared here count there.

// The longest the room being left stays open, waiting for the keys of those moving with us.
#define MOVE_LINGER 90.0
// The new room's password: this many random bytes, as words.
#define MOVE_PASSWORD_BYTES 8
// How many names a list of peers spells out before it counts the rest.
#define MOVE_NAMED 6
#define MOVE_NAME_LEN (CHAT_NAME_LEN + 32)
#define MOVE_NAMES_LEN (MOVE_NAMED * (MOVE_NAME_LEN + 5) + 32)

// Who :move would take along, and who it would leave behind (with why).
typedef struct {
    int coming, left;
    char coming_names[MOVE_NAMES_LEN], left_names[MOVE_NAMES_LEN];
} chat_move_plan_t;

// Where a move goes, to open the new session with: its id and password, the room it's from, and the
// key shown there, which signs our sessions in the new one. created: we're the one moving the room.
typedef struct {
    char session_name[MAX_SESSION_NAME + 1];
    char password[MAX_PASSWORD + 1];
    char from[MAX_SESSION_NAME + 1];
    identity_keypair_t key;
    int created;
} chat_move_to_t;

// A request to move, as it's shown: who asks (with their code's mark), who else is asked along, and
// when it came. seq is new for each request.
typedef struct {
    unsigned seq;
    char from[MOVE_NAME_LEN];
    char coming_names[MOVE_NAMES_LEN];
    int coming;
    char at[HHMM_LEN];
} chat_move_ask_t;

// A session, and a peer in it: core/state.h has what they hold.
typedef struct chat_s chat_t;
typedef struct peer_s peer_t;

typedef struct {
    char nick[MAX_NICK + 1];
    char session_name[MAX_SESSION_NAME + 1];
    char password[MAX_PASSWORD + 1];
    uint16_t port;
    addr_t peers[MAX_STATIC_PEERS];
    int n_peers;
    routing_t route;
    int created;
    int once;
    notify_mode_t notify_mode;
    notify_preview_t notify_preview;
    // Send to peers whose verify code wasn't compared (the default is not to).
    int verify_optional;
    int persist;   // keeps a history (chat_set_history)

    identity_source_t identity_source;
    identity_keypair_t identity;
    int has_color;
    uint8_t color[3];

    uint64_t file_cap;      // 0: FILE_CAP_DEFAULT
    int fast_files, picture_noise;

    // What peers are told about this build, and the release key (minisign, base64) used to check
    // their builds' lists, and its backup. "" leaves them unchecked.
    chat_build_t build;
    char release_key[64];
    char release_backup_key[64];

    // The session moved here from another room (:move), and moved_key signs our sessions here.
    int moved;
    identity_keypair_t moved_key;

    // Called when a file fetched to be shown has come (chat_file_fetch), and when a message of ours is
    // settled. Either can be NULL.
    chat_file_fn file_view;
    chat_delivery_fn delivery;
} chat_opts_t;

// A session's memory, zeroed, for chat_init (NULL if there's none), and back once chat_shutdown is
// done with it.
chat_t *chat_new(void);
void chat_free(chat_t *c);

void chat_init(chat_t *c, const chat_opts_t *o, chat_print_fn print, chat_notify_fn notify, void *ui, double now);
void chat_shutdown(chat_t *c);

void chat_tick(chat_t *c, double now);
void chat_on_socket_readable(chat_t *c, sock_t which, double now);

// Plain-mode entry point: ":name args" runs a command, anything else is sent. Returns 0 on :quit.
int chat_submit_line(chat_t *c, const char *line, double now);

// Runs "name args" (no leading ':') from CHAT_COMMANDS against this session.
cmd_result_t chat_run_command(chat_t *c, const char *line);
void chat_send_text(chat_t *c, const char *text, double now);
// Sends text as an answer to the message with id mid (chat_line's), quoting the start of it. -1 if
// that message is no longer among the recent ones a reply can answer.
int chat_send_reply(chat_t *c, const char *mid, const char *text, double now);
// Offers the file at path (used as is: ~ and quotes aren't expanded) to everyone here, like :send.
// A picture offered is cleaned first (common/image/clean.h), unless asis.
void chat_send_file(chat_t *c, const char *path, int asis);

extern const command_t CHAT_COMMANDS[];

void chat_set_nick(chat_t *c, const char *nick);

// Files. chat_file_fetch gets file num, either to show (view, passed to the session's file_view
// once it's here) or to save in dir (NULL or "" for Downloads). A picture already shown, or a file
// already saved, is used instead of fetching it again if it still matches the offer. While another
// file from the same sender is coming, it's queued and starts after that one. anyway: fetch even if
// over the size limit. Returns 0, or -1 after saying why.
int chat_file_fetch(chat_t *c, int num, int view, int anyway, const char *dir);
const file_entry_t *chat_file(const chat_t *c, int num);
// A queued file: the number of the file from the same sender it waits for, or 0.
int chat_file_queued_after(const chat_t *c, const file_entry_t *e);
// A file being fetched: the bytes received, including any in the window not written yet, and
// roughly how many seconds the rest will take, at the rate so far or, before there is one, at the
// rate its path allows. ETA_AWAY while its sender is away, ETA_UNVERIFIED while their verify code
// needs comparing again (they came back with a new one).
#define ETA_AWAY (-1.0)
#define ETA_UNVERIFIED (-2.0)
uint64_t chat_file_got(const file_entry_t *e);
double chat_file_eta(const chat_t *c, const file_entry_t *e, double now);
// A picture's bytes, checked against its offer: kept from when it was shown, a saved copy, or ours.
// NULL if there's none here. Only valid until the next call into the session.
const uint8_t *chat_file_bytes(chat_t *c, int num);
// One of ours: how many peers are fetching it now, the one furthest along (into name) and how far
// they've got, in thousandths.
int chat_file_sending(const chat_t *c, const file_entry_t *e, double now, char name[CHAT_NAME_LEN], int *permille);
// Who one of ours went to in full: "bob", "bob and carol", "bob and 2 others", or "".
void chat_file_sent_to(const file_entry_t *e, char *out, size_t cap);
void chat_set_file_options(chat_t *c, uint64_t cap, int fast);
// The size over which a file needs "anyway" to be fetched.
uint64_t chat_file_cap(const chat_t *c);
void chat_set_colour(chat_t *c, const uint8_t rgb[3]);

// Cleans a nick and removes the characters the UI puts around nicks ("(verified)", "#id", "name:"),
// including lookalikes such as fullwidth brackets, and invisible characters, so no nick can fake
// them. Never empty: uses "anon" if nothing is left.
void chat_clean_nick(const char *in, char out[MAX_NICK + 1]);
// A nick normalised for comparing (lookalikes, case and invisible characters ignored), as used to
// tell nicks apart. out holds NICK_SKEL_LEN.
void chat_nick_skeleton(const char *nick, char *out, size_t cap);

// A peer's nick as shown, with "#" and its id prefix added when another peer's nick, or ours,
// looks the same (case and common lookalike letters ignored).
void chat_peer_name(const chat_t *c, const peer_t *p, char out[CHAT_NAME_LEN]);

void chat_set_identity(chat_t *c, identity_source_t source, const identity_keypair_t *idkp);

// Whether we keep a history of the session: peers' "k" is sent again so they're told straight away.
void chat_set_history(chat_t *c, int on);

// How much of the network the console shows, as :set net names it: its news, every handshake packet
// too, or only its problems.
enum { NET_LOG_NORMAL = 0, NET_LOG_VERBOSE, NET_LOG_OFF };
void chat_set_net_log(chat_t *c, int level);

// The message timer (:timer): messages older than this go from the screen and from memory, and a
// history keeps no longer. Ours goes to peers in "k", like history, and every chat that keeps to
// timers ("t") keeps to the shortest anyone in the session asks for. It's a request: a modified chat,
// or a screenshot, can keep anything. In seconds, 0 for none.
#define TIMER_MIN 60u
#define TIMER_MAX (7u * 24 * 3600)
void chat_set_timer(chat_t *c, unsigned seconds);
// The one kept to, and who asked for it ("you", or a peer's name) in who if it's given.
unsigned chat_timer(const chat_t *c, char *who, size_t cap);
// "10m", "2h", "1d" or "90s" for seconds, and back (0, or -1 for something else).
void chat_format_timer(unsigned seconds, char *out, size_t cap);
int chat_parse_timer(const char *s, unsigned *seconds);
// What names the session's history: from its key, the same each time it's joined with the same id
// and password, and nothing anyone else can work out.
#define CHAT_HISTORY_ID_LEN 16
void chat_history_id(const chat_t *c, uint8_t out[CHAT_HISTORY_ID_LEN]);

// A call (:call): the room only this identity and a verified key can work out, for a day (UTC days
// since 1970, chat_contact_day), as its id and password. 0, or -1 if that key can't make one.
#define CONTACT_PASSWORD_LEN 64
#define DAY_SECONDS 86400
int chat_contact_room(const identity_keypair_t *mine, const uint8_t their_pub[ID_SIGN_PUB_LEN], uint64_t day,
                      char id[SESSION_ID_LEN + 1], char password[CONTACT_PASSWORD_LEN + 1]);
uint64_t chat_contact_day(void);

// Whether the member with this id is ignored here (:ignore): what it says, sends directly and offers
// isn't shown, though what it says is still passed on to others.
int chat_ignored(const chat_t *c, const uint8_t id[ID_LEN]);
// Checks connected peers against the verified and ignored signing keys after either list changed
// outside this session, and un-ignores any peer signing with a key removed from the ignored list.
void chat_recheck_trust(chat_t *c);
void chat_unignore_key(chat_t *c, const uint8_t pub[ID_SIGN_PUB_LEN]);

// An invite (:invite): a room's id and password as one string, "chat:ID:PASSWORD:CHECK", CHECK being
// invite_check in hex. The password can hold ':', since the id ends at the first and the check
// starts after the last, but an id with ':' in it can't have one. chat_invite: 0, or -1 if the id
// can't go in one or it doesn't fit in cap (INVITE_MAX does).
#define INVITE_PREFIX "chat:"
#define INVITE_MAX (sizeof INVITE_PREFIX + MAX_SESSION_NAME + MAX_PASSWORD + INVITE_CHECK_LEN * 2 + 2)
int chat_invite(const char *id, const char *password, char *out, size_t cap);
// Whether text starts as an invite does, and chat_invite_parse takes it apart: 1 for an invite, with
// its id and password; 0 if text isn't one; -1 if it is, but it's mistyped or cut off, so its check
// doesn't match.
int chat_is_invite(const char *text);
int chat_invite_parse(const char *text, char id[MAX_SESSION_NAME + 1], char password[MAX_PASSWORD + 1]);

// :move. Who it would take along: peers whose code was compared, whose builds can move.
void chat_move_plan(chat_t *c, chat_move_plan_t *plan);
// The one moving the room: a new id and password into to. 0, or -1 after saying why (nobody can come).
int chat_move_begin(chat_t *c, chat_move_to_t *to);
// The request to move that's waiting for an answer, or NULL. One from a peer whose code wasn't compared
// waits for that first.
const chat_move_ask_t *chat_move_asked(const chat_t *c);
// The answer to it: yes fills to (0, or -1 if there's no request), no forgets it.
int chat_move_accept(chat_t *c, chat_move_to_t *to);
void chat_move_decline(chat_t *c);
// Where --simple's ":move yes" goes, once: 1, with to filled.
int chat_move_staged(chat_t *c, chat_move_to_t *to);
// The new session opened (moved_to): the one moving the room now asks those coming. This session gives
// moved_to the keys it's shown, now and as they come, and stays open only until chat_move_finished.
// moved_to has to outlive it, or be unlinked first.
void chat_move_go(chat_t *c, const chat_move_to_t *to, chat_t *moved_to, double now);
void chat_move_unlink(chat_t *c, const chat_t *moved_to);
// A session that moved out has done its part: those moving with us have our key and we theirs, or
// MOVE_LINGER has passed. It can be closed.
int chat_move_finished(const chat_t *c, double now);

#define CHAT_MAX_SOCKS 12
int chat_sockets(chat_t *c, sock_t out[CHAT_MAX_SOCKS]);
// Whether the session started: its keys were made, and its UDP socket (DHT) or its Tor link (Tor)
// opened. If not, chat_start_error says why.
int chat_started(const chat_t *c);
const char *chat_start_error(const chat_t *c);
// Applies changed routing toggles to a running session. The mode and the Tor settings only apply
// to sessions opened afterwards. Returns 1 if those differ from this session's.
int chat_apply_routing(chat_t *c, const routing_t *r);
// Moves a Tor session to the tor at these ports (the one chat started, or found running). password
// is what chat's own tor takes; NULL for a running tor, which takes the session's torpassword.
void chat_tor_set_ports(chat_t *c, const char *socks, const char *control, const char *password);
// That tor has connected to the Tor network, so relays that failed while it was connecting are retried.
void chat_tor_connected(chat_t *c);
// New Tor circuits for the session, its relay connections' too, and a new onion address for its
// peers (tor_refresh).
void chat_tor_refresh(chat_t *c);
int chat_online_count(const chat_t *c);
int chat_pending_count(const chat_t *c);
int chat_candidate_count(const chat_t *c);

int chat_ready(const chat_t *c);

// ---- what a session is, for the app to show ----

const char *chat_nick(const chat_t *c);
const char *chat_session_name(const chat_t *c);
// Our id here (ID_LEN bytes) and our colour (3).
const uint8_t *chat_my_id(const chat_t *c);
const uint8_t *chat_colour(const chat_t *c);
route_mode_t chat_route_mode(const chat_t *c);
// The UDP port it listens on.
uint16_t chat_port(const chat_t *c);
// Whether we keep a history of it (chat_set_history).
int chat_history(const chat_t *c);
// Whether nothing goes to a peer until its verify code was compared.
int chat_verify_required(const chat_t *c);
// The level chat_set_net_log last set.
int chat_net_log(const chat_t *c);
// The newest file's number (0 before any), and the file in slot i of FILE_OFFERS_MAX, or NULL.
int chat_newest_file(const chat_t *c);
const file_entry_t *chat_file_at(const chat_t *c, int i);
// While a line is printed: the number of our message it is (LINE_OWN), and how much of a reply's
// text, from the start, is the quote (0 for any other line).
unsigned chat_own_seq(const chat_t *c);
int chat_line_quote(const chat_t *c);
// While a message's line is printed: its id (hex), who wrote it (their id and nick: ours for our
// own, and for a relayed one what the peer passing it on says), and the peer it came from, or a
// direct one is to or from (NULL for ours to everyone). A file's offer has no id, and any other
// line has none of them.
typedef struct {
    const char *mid;
    const uint8_t *origin;
    const char *nick;
    const peer_t *peer;
} chat_line_t;
const chat_line_t *chat_line(const chat_t *c);
// The session this one moved to (:move), or NULL.
const chat_t *chat_moved_to(const chat_t *c);

// How the session reaches its peers, as the sidebar shows it. CHAT_NET_OFF where that part is off.
#define CHAT_NET_OFF (-1)
typedef struct {
    int onion;                     // Tor: its onion address is published
    int portmap;                   // UDP: 1 once the router has mapped its port, 0 before
    int relays;                    // 1 in use (relays_up of relays_total connected), 0 on but not needed
    int relays_up, relays_total;
    int dht;                       // UDP: 1 once it knows other nodes, 0 before
    int dht_found;                 // the peers found through it
    unsigned rx;                   // packets received
} chat_net_t;
void chat_net(const chat_t *c, chat_net_t *out);

// The peers, in slots 0 to CHAT_PEER_SLOTS - 1. chat_peer_at: the one in slot i once its handshake is
// done, or NULL. chat_peer_by_id: the one with this id, done or not, or NULL.
#define CHAT_PEER_SLOTS (MAX_PEERS + MAX_PENDING_PEERS)
const peer_t *chat_peer_at(const chat_t *c, int i);
const peer_t *chat_peer_by_id(const chat_t *c, const uint8_t id[ID_LEN]);
const char *chat_peer_nick(const peer_t *p);
const uint8_t *chat_peer_id(const peer_t *p);
const uint8_t *chat_peer_colour(const peer_t *p);
identity_source_t chat_peer_identity_source(const peer_t *p);
verify_state_t chat_peer_verify_state(const peer_t *p);
build_state_t chat_peer_build_state(const peer_t *p);
// Whether its "k" says it keeps a history of the session.
int chat_peer_keeps_history(const peer_t *p);
// Its verify code (VERIFY_LEN bytes), or NULL until the handshake has made one, and its signing
// identity's fingerprint (ID_FP_LEN bytes), or NULL if it signs with none.
const uint8_t *chat_peer_verify_code(const peer_t *p);
const uint8_t *chat_peer_fingerprint(const peer_t *p);
// Whether its build reads direct messages (:msg).
int chat_peer_can_dm(const peer_t *p);

// ---- what the app sets ----

void chat_set_verify_required(chat_t *c, int on);
void chat_set_notify_mode(chat_t *c, notify_mode_t mode);
void chat_set_notify_preview(chat_t *c, notify_preview_t preview);
void chat_set_picture_noise(chat_t *c, int on);
void chat_set_print(chat_t *c, chat_print_fn print);
// Kept to come back to (Reopen sessions): chat_shutdown then tells the peers that read "off" that we
// went offline, not that we left.
void chat_set_coming_back(chat_t *c, int on);
const char *chat_verify_label(verify_state_t s);
// A peer's verify code as the sidebar shows it: 0 nothing to do, 1 to be compared, 2 compared,
// 3 different, 4 to be compared because it signs with another key than the one verified for its nick.
int chat_code_state(const chat_t *c, const peer_t *p);
// What p runs, for :peers: "says official v0.3.1", "modified client (says v0.3.1)" and so on.
void chat_build_label(const peer_t *p, char *out, size_t cap);

typedef struct { const char *name; uint8_t r, g, b; } named_color_t;
extern const named_color_t COLOR_PALETTE[];
extern const int COLOR_PALETTE_N;
// One of the palette's, at random.
void chat_random_colour(uint8_t rgb[3]);

int parse_color(const char *text, uint8_t rgb[3]);

#endif
