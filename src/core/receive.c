// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
// What comes in: datagrams and relayed frames, opened, and the records a session carries.
#include "core/engine.h"

static int check_trust(chat_t *c, peer_t *p);

// Checks p against the verified keys again, and offers it our files if that makes its code compared.
static int recheck_trust(chat_t *c, peer_t *p) {
    int was_ok = p->code_ok, warned = check_trust(c, p);
    if (was_ok != CODE_SAME && p->code_ok == CODE_SAME) file_offer_all(c, p);
    return warned;
}

#define PX_READ_MAX 12

// "k": who p is, and what its build can do, sent again with each handshake.
static void on_k(chat_t *c, peer_t *p, char **f) {
    p->k_seen = 1;
    set_peer_nick(p, f[1]);
    identity_source_t had_source = p->identity_source;
    verify_state_t had_state = p->identity_state;
    uint8_t had_pub[ID_SIGN_PUB_LEN];
    memcpy(had_pub, p->identity_pub, ID_SIGN_PUB_LEN);
    uint8_t rgb[3];
    if (parse_color(f[2], rgb) == 0) memcpy(p->color, rgb, 3);
    // f[3] is the history flag, then capability letters older builds ignore: "r" = sends rk,
    // "b" = reads records joined by newlines, "l" = reads messages up to MAX_TEXT, "m" = moves rooms,
    // "p" = reads direct messages, "q" = reads replies ("mr"), "o" = reads "off", "t" = keeps to message
    // timers, then the seconds of the one it asks for.
    int had_history = p->persists;
    p->persists = (f[3][0] == '1');
    if (p->announced && had_history != p->persists) {
        char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
        if (p->persists) ui_warn(c, "* %s keeps a history of this chat now", name);
        else ui_print(c, "* %s stopped keeping a history of this chat", name);
    }
    p->announces_rekey = strchr(f[3], 'r') != NULL;
    p->batches = strchr(f[3], 'b') != NULL;
    p->long_text = strchr(f[3], 'l') != NULL;
    p->can_move = strchr(f[3], 'm') != NULL;
    p->can_pm = strchr(f[3], 'p') != NULL;
    p->can_reply = strchr(f[3], 'q') != NULL;
    p->can_offline = strchr(f[3], 'o') != NULL;
    const char *tp = strchr(f[3], 't');
    unsigned long asked = tp ? strtoul(tp + 1, NULL, 10) : 0;
    unsigned had_timer = p->timer;
    p->can_timer = tp != NULL;
    p->timer = asked >= TIMER_MIN && asked <= TIMER_MAX ? (unsigned)asked : 0;
    if (had_timer != p->timer) {
        char name[CHAT_NAME_LEN], d[16];
        chat_peer_name(c, p, name);
        chat_format_timer(p->timer, d, sizeof d);
        if (p->timer && !peer_trusted(c, p))
            ui_print(c, "* %s asks for messages here to go after %s - kept to once you've compared codes", name, d);
        else if (p->timer)
            ui_print(c, "* %s asks for messages here to go after %s: chat takes them off the screen and out of "
                        "memory then (a modified chat, or a screenshot, can keep anything)", name, d);
        else ui_print(c, "* %s stopped asking for messages here to go", name);
    }
    int idtype = atoi(f[4]);
    size_t idpub_len = strlen(f[5]), sig_len = strlen(f[6]);
    if (idtype > IDENT_NONE && idtype <= IDENT_PGP && idpub_len == ID_SIGN_PUB_LEN * 2 && sig_len == ID_SIGN_LEN * 2) {
        uint8_t idpub[ID_SIGN_PUB_LEN], sig[ID_SIGN_LEN];
        if (hex_decode(f[5], idpub_len, idpub) == 0 && hex_decode(f[6], sig_len, sig) == 0) {
            p->identity_source = (identity_source_t)idtype;
            memcpy(p->identity_pub, idpub, ID_SIGN_PUB_LEN);
            identity_fingerprint(idpub, p->identity_fp);
            p->identity_state = check_session_sig(c, p, identity_verify, idpub, sig) == 0
                                 ? VERIFY_VERIFIED : VERIFY_FAILED;
        } else {
            p->identity_source = IDENT_NONE; p->identity_state = VERIFY_UNVERIFIED;
        }
    } else {
        p->identity_source = IDENT_NONE; p->identity_state = VERIFY_UNVERIFIED;
    }
    // A peer that joined before its k came is checked now, and one whose nick or key changed again.
    int warned = p->announced ? recheck_trust(c, p) : 0;
    // A re-handshake (rekey, rejoin) sends k again. Say so if the identity behind it changes.
    if (had_source != IDENT_NONE && !warned) {
        char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
        if (p->identity_source == IDENT_NONE) {
            ui_print(c, "* warning: %s no longer presents a signing identity", name);
        } else if (memcmp(had_pub, p->identity_pub, ID_SIGN_PUB_LEN) != 0) {
            char fphex[HEX_GROUPS_LEN(ID_FP_LEN)]; hex_groups(p->identity_fp, ID_FP_LEN, fphex);
            ui_print(c, "* warning: %s now presents a different signing identity (fingerprint %s) - :verify it again",
                     name, fphex);
        } else if (p->identity_state == VERIFY_FAILED && had_state != VERIFY_FAILED) {
            ui_print(c, "* warning: %s's identity signature is now invalid", name);
        }
    }
}

// "rk": the key this peer will re-handshake with next, sent over the session we already trust.
static void on_rk(peer_t *p, char **f) {
    uint8_t next[PUB_LEN];
    if (hex_decode(f[1], PUB_LEN * 2, next) == 0) {
        memcpy(p->next_pub, next, PUB_LEN);
        p->next_pub_set = 1;
        p->rk_refused_since = 0.0;
    }
}

static void on_nick(chat_t *c, peer_t *p, char **f) {
    set_peer_nick(p, f[1]);
    if (p->announced) {
        if (p->trust == TRUST_OTHER_KEY) p->trust = TRUST_UNKNOWN;
        recheck_trust(c, p);
    }
}

// "px": other members' addresses to try.
static void on_px(chat_t *c, char **f) {
    char *item = f[1];
    for (int cnt = 0; item && *item && cnt < PX_READ_MAX; cnt++) {
        char *comma = strchr(item, ',');
        if (comma) *comma = '\0';
        addr_t a;
        size_t il = strlen(item);
        if (il == TOR_ADDR_LEN + sizeof ".onion" - 1 && strcmp(item + TOR_ADDR_LEN, ".onion") == 0) {
            // Only Tor mode uses onion addresses. Nothing else may ever look them up.
            item[TOR_ADDR_LEN] = '\0';
            if (c->tor && tor_target(c->tor, item, &a) == 0) add_candidate(c, a);
        } else if (c->route.mode == ROUTE_UDP && addr_parse_ip_port(item, &a) == 0) {
            // Numeric only. A hostname here would make us resolve any name a peer sends.
            add_candidate(c, a);
        }
        item = comma ? comma + 1 : NULL;
    }
}

static void on_build(chat_t *c, peer_t *p, char **f, int n) {
    uint8_t proof[BUILD_HASH_LEN];
    if (!version_ok(f[1]) || strlen(f[2]) != BUILD_HASH_LEN * 2
        || hex_decode(f[2], BUILD_HASH_LEN * 2, proof) != 0) return;
    check_build(c, p, f[1], proof, n == 5 ? f[3] : NULL, n == 5 ? f[4] : NULL);
}

// "m", and "mr", a reply: the id of the message it answers comes after its own. Only p itself is
// authenticated here. The origin id and nick are whatever p says.
static void on_message(chat_t *c, peer_t *p, char **f, int n, double now) {
    uint8_t mid_raw[MID_LEN], origin[ID_LEN], reply_raw[MID_LEN];
    const char *reply = n == 6 ? f[2] : NULL;
    if (reply) { f[2] = f[3]; f[3] = f[4]; f[4] = f[5]; }
    if (hex_decode(f[1], MID_HEX, mid_raw) != 0 || hex_decode(f[2], ID_LEN * 2, origin) != 0
        || (reply && (strlen(reply) != MID_HEX || hex_decode(reply, MID_HEX, reply_raw) != 0)))
        return;
    char ack[16]; snprintf(ack, sizeof ack, "a\t%s", f[1]);
    send_peer(c, p, ack);
    int direct = memcmp(origin, p->id, ID_LEN) == 0;
    if (!direct) {
        if (memcmp(origin, c->my_id, ID_LEN) == 0) return;
        // The origin is connected to us, so its own copy will arrive. A relayed one could be forged.
        peer_t *op = find_peer_by_id(c, origin);
        if (op && op->ok) return;
    }
    if (seen_has(c, f[1])) return;
    seen_add(c, f[1]);
    // Its parts, should a peer that only takes short messages pass them on from the origin later.
    if (strlen(f[4]) > OLD_MAX_TEXT)
        for (int i = 0; i < MAX_TEXT_PARTS; i++) {
            char pmid[MID_HEX + 1];
            part_mid(f[1], i, pmid);
            seen_add(c, pmid);
        }
    char nick[MAX_NICK + 1], text[MAX_TEXT + 1], via[CHAT_NAME_LEN], prefix[REPLY_PREFIX_MAX] = "";
    char line[REPLY_PREFIX_MAX + MAX_TEXT + 1];
    if (direct) copy_str(nick, p->nick, sizeof nick);
    else chat_clean_nick(f[3], nick);
    clean_text(f[4], text, MAX_TEXT);
    if (reply) reply_prefix(c, reply, prefix, sizeof prefix);
    // An ignored member's message is still passed on, so ignoring it changes nothing for anyone else.
    if (!chat_ignored(c, origin)) {
        // A reply to us counts as a mention.
        const recent_msg_t *answered = reply ? recent_find(c, reply) : NULL;
        int mentioned = has_mention(text, c->nick) || (answered && memcmp(answered->origin, c->my_id, ID_LEN) == 0);
        char shown[MAX_NICK + CHAT_NAME_LEN + 48];
        chat_peer_name(c, p, via);
        // A relayed nick is only the relayer's claim, so it always includes the origin's id. Nicks can't
        // contain brackets, so what's added in brackets can't be faked.
        const char *mark = code_mark(c, p);
        if (direct) snprintf(shown, sizeof shown, "%s%s", via, mark);
        else snprintf(shown, sizeof shown, "%s#%.*s (via %s%s)", nick, SHORT_ID_HEX, f[2], via, mark);
        snprintf(line, sizeof line, "%s%s", prefix, text);
        c->line_quote = (int)strlen(prefix);
        c->line = (chat_line_t){ f[1], origin, nick, p };
        ui_chat(c, direct ? p->color : NULL, mentioned, shown, line);
        c->line = (chat_line_t){ 0 };
        c->line_quote = 0;
        recent_add(c, f[1], origin, nick, text, now);
        // Only as much as the preview setting allows, since desktops keep what a notification shows.
        if (c->notify && (c->notify_mode == NOTIFY_ALL || (c->notify_mode == NOTIFY_MENTIONS && mentioned)))
            c->notify(c->ui, c->notify_preview >= PREVIEW_NICK ? shown : NULL,
                      c->notify_preview == PREVIEW_MESSAGE ? text : NULL, mentioned);
    }
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *q = &c->peers[i];
        if (!q->used || !q->ok || q == p || memcmp(q->id, origin, ID_LEN) == 0) continue;
        // Only passed on to peers our own messages would go to.
        if (!peer_trusted(c, q)) continue;
        if (reply) send_reply(c, q, f[1], reply, f[2], nick, text, prefix, 0, now);
        else send_message(c, q, f[1], f[2], nick, text, 0, now);
    }
}

// "pm": meant for us alone, so never passed on. Only p itself sends one.
static void on_direct(chat_t *c, peer_t *p, char **f) {
    if (!ack_record(c, p, f[1]) || seen_has(c, f[1])) return;
    seen_add(c, f[1]);
    if (chat_ignored(c, p->id)) return;
    char text[MAX_TEXT + 1], via[CHAT_NAME_LEN], shown[CHAT_NAME_LEN + 48];
    clean_text(f[2], text, MAX_TEXT);
    chat_peer_name(c, p, via);
    snprintf(shown, sizeof shown, "%s (" DM_ARROW " you)%s", via, code_mark(c, p));
    c->line = (chat_line_t){ f[1], p->id, p->nick, p };
    ui_direct(c, p->color, 1, shown, text);
    c->line = (chat_line_t){ 0 };
    // It's for us, so it counts as a mention.
    if (c->notify && c->notify_mode != NOTIFY_NONE)
        c->notify(c->ui, c->notify_preview >= PREVIEW_NICK ? shown : NULL,
                  c->notify_preview == PREVIEW_MESSAGE ? text : NULL, 1);
}

static void on_ack(chat_t *c, peer_t *p, char **f) {
    for (int i = 0; i < MAX_PENDING_MSGS; i++) {
        pending_msg_t *pm = &c->pending[i];
        if (!pm->used || pm->peer_slot != peer_slot(c, p) || strcmp(pm->mid, f[1]) != 0) continue;
        unsigned own = pm->own;
        pending_clear(pm);
        own_settled(c, own);
    }
}

// "mk": its key for the move, which the room we moved to checks its "mp" against.
static void on_move_key(chat_t *c, peer_t *p, char **f) {
    uint8_t key[ID_SIGN_PUB_LEN];
    if (!ack_record(c, p, f[1]) || strlen(f[2]) != ID_SIGN_PUB_LEN * 2 || hex_decode(f[2], ID_SIGN_PUB_LEN * 2, key) != 0) return;
    if (!p->move_pub_set || memcmp(p->move_pub, key, ID_SIGN_PUB_LEN) != 0) {
        memcpy(p->move_pub, key, ID_SIGN_PUB_LEN);
        p->move_pub_set = 1;
        p->move_passed = 0;
    }
}

static void on_move_proof(chat_t *c, peer_t *p, char **f) {
    uint8_t sig[ID_SIGN_LEN];
    if (strlen(f[1]) != ID_SIGN_LEN * 2 || hex_decode(f[1], ID_SIGN_LEN * 2, sig) != 0) return;
    memcpy(p->move_sig, sig, ID_SIGN_LEN);
    p->move_sig_set = 1;
    check_came_with(c, p);
}

// A record over p's session, by its kind and how many fields it has. Anything else is ignored, so
// a record a newer build sends does no harm.
static void on_session(chat_t *c, peer_t *p, char *plain, double now) {
    char *f[MAX_FIELDS];
    int n = split_tabs(plain, f, MAX_FIELDS);
    uint8_t rgb[3];
    if (n == 7 && strcmp(f[0], "k") == 0) on_k(c, p, f);
    else if (n == 2 && strcmp(f[0], "rk") == 0) on_rk(p, f);
    else if (n == 2 && strcmp(f[0], "c") == 0) { if (parse_color(f[1], rgb) == 0) memcpy(p->color, rgb, 3); }
    else if (n == 2 && strcmp(f[0], "n") == 0) on_nick(c, p, f);
    else if (n == 2 && strcmp(f[0], "px") == 0) on_px(c, f);
    else if (n == 2 && strcmp(f[0], "ta") == 0) { if (onion_valid(f[1])) copy_str(p->onion, f[1], sizeof p->onion); }
    else if ((n == 3 || n == 5) && strcmp(f[0], "v") == 0) on_build(c, p, f, n);
    else if ((n == 5 && strcmp(f[0], "m") == 0) || (n == 6 && strcmp(f[0], "mr") == 0)) on_message(c, p, f, n, now);
    else if (n == 3 && strcmp(f[0], "pm") == 0) on_direct(c, p, f);
    else if (n == 2 && strcmp(f[0], "a") == 0) on_ack(c, p, f);
    else if (n == 6 && strcmp(f[0], "mv") == 0) on_move(c, p, f, now);
    else if (n == 3 && strcmp(f[0], "mk") == 0) on_move_key(c, p, f);
    else if (n == 2 && strcmp(f[0], "mp") == 0) on_move_proof(c, p, f);
    else if (f[0][0] == 'f' && f[0][1] && !f[0][2]) file_on_record(c, p, f, n, now);
    else if (n == 1 && strcmp(f[0], "bye") == 0) drop_peer(c, p, "left");
    else if (n == 1 && strcmp(f[0], "off") == 0) drop_peer(c, p, "went offline");
}

static void note_source(chat_t *c, addr_t a) {
    net_stats_t *st = &c->st;
    for (int i = 0; i < st->n_src; i++) if (addr_equal(st->src[i], a)) { st->src_n[i]++; return; }
    int slot = st->n_src < NET_SOURCES ? st->n_src++ : NET_SOURCES - 1;
    st->src[slot] = a; st->src_n[slot] = 1;
}

// A datagram from a UDP socket, unmasked: a piece of a room frame, or a frame. Anything else is
// passed to the DHT unchanged, since DHT messages are never masked.
static void on_udp(chat_t *c, const uint8_t *raw, size_t len, addr_t addr, double now) {
    c->st.rx++;
    uint8_t d[FRAME_BUF_LEN];
    if (len <= sizeof d) {
        memcpy(d, raw, len);
        if (udp_mask(c->udp_key, d, len) == 0 && (on_chunk(c, d, len, addr, now) || on_frame(c, d, len, addr, now))) {
            note_source(c, addr);
            return;
        }
    }
    if (c->dht_on && addr.kind == ADDR_UDP && dht_on_packet(&c->dht, raw, len, addr, dht_candidate_cb, c)) {
        c->st.dht++;
        return;
    }
    note_source(c, addr);
    c->st.other++;
}

// A datagram through the relays or Tor, which carry whole frames, unmasked.
void on_relayed(chat_t *c, uint8_t *data, size_t len, addr_t addr, double now) {
    c->st.rx++;
    note_source(c, addr);
    if (!on_frame(c, data, len, addr, now)) c->st.other++;
}

static int in_window(const ratchet_t *r, uint32_t index, uint32_t max_skip) {
    return r->started && index >= r->index && index - r->index <= max_skip;
}

static int peer_try_unseal(peer_t *p, const uint8_t *data, size_t len, uint32_t index, uint32_t max_skip,
                            uint8_t *plain, size_t plain_cap, size_t *plain_len, int *on_old) {
    uint8_t mk[MSG_KEY_LEN];
    ratchet_t advanced;
    *on_old = 0;
    int got = in_window(&p->recv_chain, index, max_skip)
               && ratchet_peek(&p->recv_chain, index, mk, &advanced) == 0
               && session_unseal(mk, index, data, len, plain, plain_cap, plain_len) == 0;
    if (!got && p->old_until > 0.0 && in_window(&p->old_recv, index, max_skip)
        && ratchet_peek(&p->old_recv, index, mk, &advanced) == 0
        && session_unseal(mk, index, data, len, plain, plain_cap, plain_len) == 0) {
        got = 1;
        *on_old = 1;
    }
    crypto_wipe(mk, sizeof mk);
    if (!got) return 0;
    if (*on_old) p->old_recv = advanced;
    else p->recv_chain = advanced;
    return 1;
}

// Compares p's nick and signing key with the verified keys (core/trust.h), once "k" has brought
// them. A key verified before, in this run or one before it, signed this handshake's keys, so
// nobody in the middle could have made it: the code doesn't need comparing again. A peer with the
// nick of a verified key that signs with another key, or none, is warned about once. Returns 1 if
// it warned.
static int check_trust(chat_t *c, peer_t *p) {
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    // A peer that signs with a key you ignore is ignored wherever it turns up.
    if (p->identity_state == VERIFY_VERIFIED && ignore_by_key(p->identity_pub) && !chat_ignored(c, p->id)) {
        set_ignored(c, p->id, 1);
        ui_print(c, "* %s signs with a key you ignore - what they say isn't shown (:ignore %s off shows it)", name, name);
    }
    const trust_entry_t *t = p->identity_state == VERIFY_VERIFIED ? trust_by_key(p->identity_pub) : NULL;
    if (t) {
        char was[MAX_NICK + 1]; copy_str(was, t->nick, sizeof was);
        int renamed = strcmp(t->nick, p->nick) != 0;
        // The entry follows the nick, so the next peer with the old nick isn't taken for this one.
        if (renamed) trust_add(p->identity_source, p->identity_pub, p->nick);
        if (p->trust == TRUST_KEY) return 0;
        p->trust = TRUST_KEY;
        if (p->code_ok != CODE_NOT_COMPARED) return 0;
        p->code_ok = CODE_SAME;
        if (renamed) ui_print(c, "* %s signs with the key you verified for %s - no need to compare codes again", name, was);
        else ui_print(c, "* %s signs with the key you verified before - no need to compare codes again", name);
        return 0;
    }
    int i = trust_find_nick(p->nick_skel, 0);
    if (i < 0) { p->trust = TRUST_UNKNOWN; return 0; }
    if (p->trust == TRUST_OTHER_KEY) return 0;
    p->trust = TRUST_OTHER_KEY;
    t = trust_at(i);
    char was[HEX_GROUPS_LEN(ID_FP_LEN)], now_fp[HEX_GROUPS_LEN(ID_FP_LEN) + 16];
    uint8_t fp[ID_FP_LEN];
    identity_fingerprint(t->pub, fp);
    hex_groups(fp, ID_FP_LEN, was);
    if (p->identity_source == IDENT_NONE) copy_str(now_fp, "no signing key", sizeof now_fp);
    else if (p->identity_state == VERIFY_FAILED) copy_str(now_fp, "a key with an invalid signature", sizeof now_fp);
    else hex_groups(p->identity_fp, ID_FP_LEN, now_fp);
    ui_warn(c, "* warning: %s does not sign with the key you verified for %s (fingerprint %s); it signs with %s. "
               "Their key changed, or someone else uses this nick. Treat them as unverified until you compare "
               "verify codes again: :verify %s",
            name, t->nick, was, now_fp, name);
    return 1;
}

void chat_recheck_trust(chat_t *c) {
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (!p->used) continue;
        if (p->trust == TRUST_KEY && (p->identity_state != VERIFY_VERIFIED || !trust_by_key(p->identity_pub)))
            p->trust = TRUST_UNKNOWN;
        if (p->ok && p->announced) recheck_trust(c, p);
    }
}

void chat_unignore_key(chat_t *c, const uint8_t pub[ID_SIGN_PUB_LEN]) {
    for (int i = 0; i < c->peer_hi; i++) {
        peer_t *p = &c->peers[i];
        if (p->used && p->identity_state == VERIFY_VERIFIED && memcmp(p->identity_pub, pub, ID_SIGN_PUB_LEN) == 0)
            set_ignored(c, p->id, 0);
    }
}

// "* NICK (verified) joined": shown once p's nick and identity are known, which "k" carries. It's
// the first frame p sends, but it can be lost or overtaken, and another frame opening first would
// otherwise announce "anon (unverified)".
void announce_join(chat_t *c, peer_t *p) {
    p->announced = 1;
    const char *idlabel;
    switch (p->identity_state) {
        case VERIFY_VERIFIED: idlabel = " (verified)"; break;
        case VERIFY_FAILED:   idlabel = " (\xe2\x9a\xa0 signature invalid)"; break;
        case VERIFY_UNVERIFIED:
        default:               idlabel = " (unverified)"; break;
    }
    char name[CHAT_NAME_LEN]; chat_peer_name(c, p, name);
    ui_print_colored(c, p->color, "* %s%s%s joined (%d online)", name, idlabel,
                      p->persists ? " [keeps history]" : "", live_count(c) + 1);
    if (p->persists) ui_warn(c, "* %s keeps a history of this chat", name);
    // A peer that dropped and came back did a fresh handshake, with nothing linking it to the one
    // that may have been verified. Someone who forced the drop could be in the middle of it.
    for (size_t g = 0; g < GONE_MAX; g++) {
        if (!c->gone[g].used || memcmp(c->gone[g].id, p->id, ID_LEN) != 0) continue;
        c->gone[g].used = 0;
        if (memcmp(c->gone[g].vfy, p->vfy, VERIFY_LEN) == 0) continue;
        char was[HEX_GROUPS_LEN(VERIFY_LEN)], now_hex[HEX_GROUPS_LEN(VERIFY_LEN)];
        hex_groups(c->gone[g].vfy, VERIFY_LEN, was); hex_groups(p->vfy, VERIFY_LEN, now_hex);
        ui_print(c, "* %s reconnected with a new verify code (was %s, now %s) - if you had compared "
                    "codes with them, compare the new one", name, was, now_hex);
    }
    check_trust(c, p);
    if (p->came_with) tell_came_with(c, p);
    if (p->code_ok == CODE_NOT_COMPARED) {
        char code[HEX_GROUPS_LEN(VERIFY_LEN)]; hex_groups(p->vfy, VERIFY_LEN, code);
        char words[BYTEWORDS_LEN(VERIFY_LEN)]; bytewords(p->vfy, VERIFY_LEN, words);
        // The room's password only proves someone is a member, and any member could sit between two
        // others. The code only matches on both ends if nobody is in the middle. Older versions show
        // it in hex only.
        if (c->verify_required)
            ui_print(c, "* compare this code with %s over another channel (in person, a call): %s (in hex %s) - then "
                        ":verify %s ok, or :verify %s no if theirs differs. Until then nothing you send reaches them",
                     name, words, code, name, name);
        else
            ui_print(c, "* verify code with %s: %s (in hex %s) - compare it over another channel, then :verify %s ok", name,
                     words, code, name);
    }
    tell_build(c, p);
    file_offer_all(c, p);
}

// 1 if data was a frame: the room's, or a peer's session frame.
int on_frame(chat_t *c, uint8_t *data, size_t len, addr_t addr, double now) {
    uint8_t plain[FRAME_BUF_LEN];
    size_t plain_len;
    if (room_unseal(c->room_key, data, len, plain, sizeof plain - 1, &plain_len) == 0) {
        plain[plain_len] = '\0';
        c->st.room_ok++;
        on_room(c, (char *)plain, addr, now);
        return 1;
    }
    // Checked before the peer loop, so a frame no sealer could produce doesn't cost ratchet steps.
    if (sealed_len_ok(len, SESSION_HEADER_LEN, SESSION_MIN_BODY)) {
        uint32_t index = load_be32(data);
        int hit = -1, fast = -1, on_old = 0;
        for (int i = 0; i < c->peer_hi && fast < 0; i++)
            if (c->peers[i].used && addr_equal(c->peers[i].addr, addr)) fast = i;
        for (int i = 0; i < c->peer_hi && fast < 0; i++)
            if (c->peers[i].used && c->peers[i].prev_addr.port && addr_equal(c->peers[i].prev_addr, addr)) fast = i;
        if (fast >= 0 && peer_try_unseal(&c->peers[fast], data, len, index, RATCHET_MAX_SKIP, plain,
                                          sizeof plain - 1, &plain_len, &on_old))
            hit = fast;
        if (hit < 0 && take_token(&c->roam_tokens, &c->roam_at, now, ROAM_RATE, ROAM_BURST)) {
            for (int i = 0; i < c->peer_hi; i++) {
                if (i == fast || !c->peers[i].used) continue;
                if (peer_try_unseal(&c->peers[i], data, len, index, ROAM_MAX_SKIP, plain, sizeof plain - 1,
                                     &plain_len, &on_old)) { hit = i; break; }
            }
        }
        if (hit >= 0) {
            peer_t *p = &c->peers[hit];
            if (!on_old) {
                if (p->old_until > 0.0) rekey_drop_overlap(p);
                p->chain_confirmed = 1;
                p->vfy_set = 1;
            }
            c->st.session_ok++;
            plain[plain_len] = '\0';
            // The best path that works: direct UDP, then Tor (end to end, no relay in the middle), then the
            // relays. A worse path is only used once the better one goes quiet.
            if (!addr_equal(p->addr, addr)
                && (path_rank(addr) >= path_rank(p->addr) || now - p->path_seen[p->addr.kind] > UDP_STALE)) {
                p->prev_addr = p->addr;
                p->addr = addr;
            }
            p->path_seen[addr.kind] = now;
            p->seen = now;
            int was_pending = !p->ok;
            p->ok = 1;
            if (was_pending) p->ok_since = now;
            // Records, one per line. No record contains a newline.
            for (char *rec = (char *)plain; rec; ) {
                char *nl = strchr(rec, '\n');
                if (nl) *nl = '\0';
                on_session(c, p, rec, now);
                if (!p->used) return 1;
                rec = nl ? nl + 1 : NULL;
            }
            if (was_pending) {
                c->st.connects++;
                send_k_now(c, p);
                p->k_sent = 1;
                p->next_k = now + K_EVERY;
                if (!c->created && !c->ever_connected) ui_print(c, "* connected - chat is open");
                // "joined" follows once the nick and identity are in.
                char idhex[SHORT_ID_HEX + 1]; short_id(p->id, idhex);
                ui_print(c, "* joining: peer %s - connected, waiting for its nick and identity", idhex);
                c->ever_connected = 1;
                c->once_used = 1;
                send_onion(c, p);
                introduce(c, p);
            }
            // In a room we moved to, one who came along sends "mp" ahead of each k, but its first frame can
            // go before we could read it. The join waits for it (or JOIN_WAIT), so it doesn't ask to compare
            // codes compared already.
            if (!p->announced && p->k_seen && (!c->moved || p->move_sig_set)) announce_join(c, p);
            return 1;
        }
    }
    return 0;
}

void transports_step(chat_t *c, double now) {
    if (c->nostr) nostr_step(c->nostr, now);
    if (c->tor) tor_step(c->tor, now);
}

// The most datagrams read from a socket in one go, so one busy socket doesn't hold up the rest.
#define RECV_BATCH 64

void chat_on_socket_readable(chat_t *c, sock_t which, double now) {
    c->now = now;
    if (which == SOCK_INVALID) return;
    if (which != c->sock && which != c->lan_sock) { transports_step(c, now); return; }
    uint8_t buf[FRAME_BUF_LEN];
    addr_t from;
    for (int i = 0; i < RECV_BATCH; i++) {
        int n = net_recv(which, buf, sizeof buf, &from);
        if (n < 0) break;
        on_udp(c, buf, (size_t)n, from, now);
    }
}
