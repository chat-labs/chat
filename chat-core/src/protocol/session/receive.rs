// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! What comes in: datagrams and relayed frames, opened, and each record a session carries.

use super::peer::{Caps, CodeOk, PeerIdent, TrustMatch};
use super::*;
use crate::protocol::api::{LeaveReason, SignatureState};
use crate::protocol::crypto::identity::{self, IdentityKind};
use crate::protocol::crypto::{
    self, SESSION_HEADER_LEN, SESSION_MIN_BODY, room_open, sealed_len_ok, session_index, session_open, udp_mask,
};
use crate::protocol::names::{TIMER_MAX, TIMER_MIN, format_timer};
use crate::protocol::record::{self, fields, str_field};
use crate::protocol::wire::CellResult;
use crate::protocol::{hex, text};
use zeroize::Zeroizing;

/// A frame can skip at most this far ahead when it comes from an address that isn't its peer's:
/// it's tried against every peer, so junk mustn't cost many ratchet steps.
const ROAM_MAX_SKIP: u32 = 16;
pub(super) const K_EVERY: f64 = 2.0;

impl Session {
    /// A datagram from a UDP socket: unmasked, a piece of a room frame or a frame. Anything else
    /// may be the DHT's, which is never masked.
    pub(super) fn on_udp(&mut self, addr: Addr, raw: &[u8]) {
        self.st.rx += 1;
        if raw.len() <= 2828 {
            let mut d = raw.to_vec();
            if udp_mask(&self.keys.udp, &mut d) {
                match self.reasm.add(&d, addr, self.now) {
                    CellResult::Frame(frame) => {
                        self.st.rx_chunks += 1;
                        self.st.rx_chunk_done += 1;
                        if !self.on_frame(&frame, addr) {
                            self.st.other += 1;
                        }
                        return;
                    }
                    CellResult::Kept => {
                        self.st.rx_chunks += 1;
                        return;
                    }
                    CellResult::NotACell => {
                        if self.on_frame(&d, addr) {
                            return;
                        }
                    }
                }
            }
        }
        if let (Addr::Udp(sa), Some(dht)) = (addr, &mut self.dht)
            && dht.on_packet(raw, sa, self.now)
        {
            self.st.dht += 1;
            return;
        }
        self.st.other += 1;
    }

    fn try_unseal(&mut self, slot: usize, frame: &[u8], index: u32, max_skip: u32) -> Option<(Zeroizing<Vec<u8>>, bool)> {
        let p = self.peer_mut(slot);
        if p.recv.in_window(index, max_skip)
            && let Some((mk, next)) = p.recv.peek(index)
            && let Some(plain) = session_open(&mk, index, frame)
        {
            p.recv = next;
            return Some((plain, false));
        }
        if p.old_until > 0.0
            && p.old_recv.in_window(index, max_skip)
            && let Some((mk, next)) = p.old_recv.peek(index)
            && let Some(plain) = session_open(&mk, index, frame)
        {
            p.old_recv = next;
            return Some((plain, true));
        }
        None
    }

    /// Whether data was a frame: the room's, or a peer's session frame.
    pub(super) fn on_frame(&mut self, data: &[u8], addr: Addr) -> bool {
        if let Some(plain) = room_open(&self.keys.room, data) {
            self.st.room_ok += 1;
            self.on_room(&plain, addr);
            return true;
        }
        // Checked first, so a frame no sealer could make costs no ratchet steps.
        if !sealed_len_ok(data.len(), SESSION_HEADER_LEN, SESSION_MIN_BODY) {
            return false;
        }
        let Some(index) = session_index(data) else { return false };
        let fast = self
            .used()
            .find(|&i| self.peer(i).addr == addr)
            .or_else(|| self.used().find(|&i| self.peer(i).prev_addr == Some(addr)));
        let mut hit = fast.and_then(|s| self.try_unseal(s, data, index, crypto::RATCHET_MAX_SKIP).map(|r| (s, r)));
        if hit.is_none() && self.roam.take(self.now, ROAM_RATE, ROAM_BURST) {
            let others: Vec<usize> = self.used().filter(|&i| Some(i) != fast).collect();
            for s in others {
                if let Some(r) = self.try_unseal(s, data, index, ROAM_MAX_SKIP) {
                    hit = Some((s, r));
                    break;
                }
            }
        }
        let Some((slot, (plain, on_old))) = hit else { return false };
        let now = self.now;
        self.st.session_ok += 1;
        let p = self.peer_mut(slot);
        if !on_old {
            if p.old_until > 0.0 {
                p.drop_overlap();
            }
            // A re-handshake has just finished: whatever waits for an ack may have been lost while
            // it ran, so it goes again now rather than at its next retry.
            if !p.chain_confirmed {
                for pm in &mut p.pending {
                    pm.next_retry = pm.next_retry.min(now);
                }
            }
            p.chain_confirmed = true;
            p.vfy_set = true;
        }
        // The best path that works: direct UDP, then Tor, then the relays. A worse one is only
        // taken once the better one has gone quiet.
        if p.addr != addr && (addr.rank() >= p.addr.rank() || now - p.path_seen[p.addr.kind_index()] > tick::UDP_STALE) {
            p.prev_addr = Some(p.addr);
            p.addr = addr;
        }
        p.path_seen[addr.kind_index()] = now;
        p.seen = now;
        let was_pending = !p.ok;
        p.ok = true;
        if was_pending {
            p.ok_since = now;
        }
        let id = p.id;
        for rec in record::records(&plain) {
            self.on_session(slot, rec);
            if self.peers[slot].as_ref().is_none_or(|p| p.id != id) {
                return true;
            }
        }
        if was_pending {
            self.st.connects += 1;
            self.send_k_now(slot);
            let p = self.peer_mut(slot);
            p.k_sent = 1;
            p.next_k = now + K_EVERY;
            if !self.created && !self.ever_connected {
                self.note("connected - chat is open");
                self.events.push_back(Event::Opened);
            }
            self.net_news(format!(
                "joining: peer {} - connected, waiting for its nick and identity",
                hex::encode(&id[..4])
            ));
            self.ever_connected = true;
            self.send_onion(slot);
            self.introduce(slot);
        }
        let p = self.peer(slot);
        if !p.announced && p.k_seen && !self.join_waits_for_proof(p) {
            self.announce_join(slot);
        }
        true
    }

    /// A record over a peer's session, by its name and how many fields it has. Anything else is
    /// ignored, so a record a newer build sends does no harm.
    fn on_session(&mut self, slot: usize, rec: &[u8]) {
        let f = fields(rec);
        let n = f.len();
        match (f[0], n) {
            (b"k", 7) => self.on_k(slot, &f),
            (b"rk", 2) => {
                if let Some(next) = str_field(&f, 1).and_then(hex::decode_array::<32>) {
                    let p = self.peer_mut(slot);
                    p.next_pub = Some(next);
                    p.rk_refused_since = 0.0;
                }
            }
            (b"c", 2) => {
                if let Some(c) = str_field(&f, 1).and_then(Colour::parse) {
                    self.peer_mut(slot).colour = c;
                    self.peer_changed(slot);
                }
            }
            (b"n", 2) => {
                self.peer_mut(slot).set_nick(f[1]);
                if self.peer(slot).announced {
                    let p = self.peer_mut(slot);
                    if p.trust == TrustMatch::OtherKey {
                        p.trust = TrustMatch::Unknown;
                    }
                    self.check_trust(slot);
                    self.peer_changed(slot);
                }
            }
            (b"px", 2) => self.on_px(f[1]),
            (b"ta", 2) => {
                // The newest wins: a peer that took a new onion (new circuits) says so again.
                if let Some(onion) = str_field(&f, 1).filter(|o| crypto::onion_key(o).is_some()) {
                    self.peer_mut(slot).onion = Some(onion.to_string());
                }
            }
            (b"v", 3 | 5) => {
                let (Some(version), Some(proof)) = (str_field(&f, 1), str_field(&f, 2).and_then(hex::decode_array::<32>)) else {
                    return;
                };
                if !handshake::version_ok(version) {
                    return;
                }
                let list = if n == 5 { str_field(&f, 3).zip(str_field(&f, 4)) } else { None };
                if n == 5 && list.is_none() {
                    return;
                }
                let version = version.to_string();
                self.check_build(slot, &version, &proof, list);
            }
            (b"m", 5) | (b"mr", 6) => self.on_message(slot, &f),
            (b"pm", 3) => self.on_direct(slot, &f),
            (b"a", 2) => {
                if let Some(mid) = str_field(&f, 1) {
                    let mid = mid.to_string();
                    self.on_ack(slot, &mid);
                }
            }
            (b"mv", 6) => self.on_move(slot, &f),
            (b"mk", 3) => self.on_move_key(slot, &f),
            (b"mp", 2) => self.on_move_proof(slot, &f),
            (b"fo", 7) | (b"fg", 4) | (b"fd", 4) | (b"fx", 2) => self.on_file_record(slot, &f),
            (b"bye", 1) => self.drop_peer(slot, LeaveReason::Left),
            (b"off", 1) => self.drop_peer(slot, LeaveReason::Offline),
            _ => {}
        }
    }

    /// "k": who the peer is and what its build can do, sent again with each handshake.
    fn on_k(&mut self, slot: usize, f: &[&[u8]]) {
        let my_id = self.my_id;
        let p = self.peer_mut(slot);
        p.k_seen = true;
        p.set_nick(f[1]);
        let had = p.ident.clone();
        if let Some(c) = std::str::from_utf8(f[2]).ok().and_then(Colour::parse) {
            p.colour = c;
        }
        // The history flag, then capability letters older builds ignore.
        let flags = f[3];
        let had_history = p.persists;
        p.persists = flags.first() == Some(&b'1');
        let has = |c: u8| flags.contains(&c);
        let t_at = flags.iter().position(|&c| c == b't');
        let asked: u64 = t_at
            .map(|i| {
                String::from_utf8_lossy(&flags[i + 1..])
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
            })
            .and_then(|d| d.parse().ok())
            .unwrap_or(0);
        p.caps = Caps {
            announces_rekey: has(b'r'),
            batches: has(b'b'),
            long_text: has(b'l'),
            can_move: has(b'm'),
            can_pm: has(b'p'),
            can_reply: has(b'q'),
            can_offline: has(b'o'),
            can_timer: t_at.is_some(),
        };
        let had_timer = p.timer;
        p.timer = if (u64::from(TIMER_MIN)..=u64::from(TIMER_MAX)).contains(&asked) {
            asked as u32
        } else {
            0
        };
        let new_timer = p.timer;
        let persists = p.persists;
        let announced = p.announced;

        // The signing identity, and its signature over this session's keys.
        let idtype = std::str::from_utf8(f[4])
            .ok()
            .and_then(|s| s.parse::<u8>().ok())
            .and_then(IdentityKind::from_wire);
        let ident = match (
            idtype,
            str_field(f, 5).and_then(hex::decode_array::<32>),
            str_field(f, 6).and_then(hex::decode_array::<64>),
        ) {
            (Some(kind), Some(public), Some(sig)) => {
                let ok = identity::verify_session(&public, &sig, &p.public, &p.id, &p.my_pub, &my_id)
                    || p.prev_keys
                        .is_some_and(|(their_prev, my_prev)| identity::verify_session(&public, &sig, &their_prev, &p.id, &my_prev, &my_id));
                Some(PeerIdent {
                    kind,
                    public,
                    fingerprint: crypto::fingerprint(&public),
                    state: if ok { SignatureState::Verified } else { SignatureState::Failed },
                })
            }
            _ => None,
        };
        p.ident = ident.clone();

        let name = self.peer_name(slot);
        if announced && had_history != persists {
            if persists {
                self.warn(format!("{name} keeps a history of this chat now"));
            } else {
                self.note(format!("{name} stopped keeping a history of this chat"));
            }
        }
        if had_timer != new_timer {
            let d = format_timer(new_timer);
            let trusted = self.trusted(self.peer(slot));
            if new_timer > 0 && !trusted {
                self.note(format!(
                    "{name} asks for messages here to go after {d} - kept to once you've compared codes"
                ));
            } else if new_timer > 0 {
                self.note(format!(
                    "{name} asks for messages here to go after {d}: they come off the screen and out of memory then \
                     (a modified chat, or a screenshot, can keep anything)"
                ));
            } else {
                self.note(format!("{name} stopped asking for messages here to go"));
            }
        }
        // A peer that joined before its k came is checked now, and one whose nick or key changed again.
        let warned = announced && self.check_trust(slot);
        if let Some(had) = had
            && !warned
        {
            match &ident {
                None => self.note(format!("warning: {name} no longer presents a signing identity")),
                Some(i) if i.public != had.public => self.warn(format!(
                    "warning: {name} now presents a different signing identity (fingerprint {}) - compare verify codes again",
                    hex::groups(&i.fingerprint)
                )),
                Some(i) if i.state == SignatureState::Failed && had.state != SignatureState::Failed => {
                    self.warn(format!("warning: {name}'s identity signature is now invalid"));
                }
                _ => {}
            }
        }
        self.peer_changed(slot);
        self.emit_timer_if_changed();
    }

    /// "m" and "mr" (a reply: the id it answers comes after its own). Only the peer it came
    /// from is authenticated: the origin and nick are whatever it says.
    fn on_message(&mut self, slot: usize, f: &[&[u8]]) {
        let reply = f.len() == 6;
        let (mid_f, reply_f, origin_f, nick_f, text_f) = if reply {
            (f[1], Some(f[2]), f[3], f[4], f[5])
        } else {
            (f[1], None, f[2], f[3], f[4])
        };
        let Some(mid) = std::str::from_utf8(mid_f)
            .ok()
            .filter(|m| hex::decode_array::<4>(m).is_some())
            .map(str::to_string)
        else {
            return;
        };
        let Some(origin) = std::str::from_utf8(origin_f).ok().and_then(hex::decode_array::<16>) else {
            return;
        };
        let reply_mid = match reply_f {
            Some(r) => match std::str::from_utf8(r).ok().filter(|m| hex::decode_array::<4>(m).is_some()) {
                Some(r) => Some(r.to_string()),
                None => return,
            },
            None => None,
        };
        self.send_peer(slot, &format!("a\t{mid}"));
        let p = self.peer(slot);
        let direct = origin == p.id;
        if !direct {
            if origin == self.my_id {
                return;
            }
            // The origin is connected to us, so its own copy will come. A relayed one could be forged.
            if self.find_peer(&origin).is_some_and(|o| self.peer(o).ok) {
                return;
            }
        }
        if self.seen_has(&mid) {
            return;
        }
        self.seen_add(&mid);
        // Its parts too, should a peer that only reads short messages pass them on later.
        if text_f.len() > messages::OLD_MAX_TEXT {
            for i in 0..messages::MAX_TEXT_PARTS {
                let pm = messages::part_mid(&mid, i);
                self.seen_add(&pm);
            }
        }
        let p = self.peer(slot);
        let nick = if direct { p.nick.clone() } else { text::clean_nick(nick_f) };
        let body = text::clean(text_f, MAX_TEXT);
        let prefix = reply_mid.as_deref().map(|r| self.reply_prefix(r)).unwrap_or_default();
        let peer_id = p.peer_id();
        let colour = p.colour;
        if !self.is_ignored(&origin) {
            let answered_us = reply_mid
                .as_deref()
                .and_then(|r| self.recent_find(r))
                .is_some_and(|r| r.origin == self.my_id);
            let mention = text::has_mention(&body, &self.nick) || answered_us;
            let via = self.peer_name(slot);
            let name = if direct {
                via
            } else {
                format!("{nick}#{}", hex::encode(&origin[..4]))
            };
            let msg = Message {
                mid: mid.clone(),
                from: PeerId(origin),
                nick: nick.clone(),
                name,
                peer: Some(peer_id),
                colour: direct.then_some(colour),
                mine: false,
                own: None,
                direct: false,
                mention,
                relayed: !direct,
                text: format!("{prefix}{body}"),
                quote_len: prefix.len(),
                reply_to: reply_mid.clone(),
                file: None,
                at: self.unix,
            };
            self.events.push_back(Event::Message(msg));
            self.recent_add(&mid, origin, &nick, &body);
        }
        // Passed on to the peers our own messages would go to, never back to the origin.
        let origin_hex = hex::encode(&origin);
        for q in self.live() {
            let qp = self.peer(q);
            if q == slot || qp.id == origin || !self.trusted(qp) {
                continue;
            }
            match &reply_mid {
                Some(r) => {
                    self.send_reply(q, &mid, r, &origin_hex, &nick, &body, &prefix, None);
                }
                None => {
                    self.send_message(q, &mid, &origin_hex, &nick, &body, None);
                }
            }
        }
    }

    /// "pm": for us alone, never passed on. Only the peer itself sends one.
    fn on_direct(&mut self, slot: usize, f: &[&[u8]]) {
        if !self.ack_record(slot, f[1]) {
            return;
        }
        let mid = String::from_utf8_lossy(f[1]).into_owned();
        if self.seen_has(&mid) {
            return;
        }
        self.seen_add(&mid);
        let p = self.peer(slot);
        if self.is_ignored(&p.id) {
            return;
        }
        let msg = Message {
            mid,
            from: p.peer_id(),
            nick: p.nick.clone(),
            name: self.peer_name(slot),
            peer: Some(p.peer_id()),
            colour: Some(p.colour),
            mine: false,
            own: None,
            direct: true,
            mention: true,
            relayed: false,
            text: text::clean(f[2], MAX_TEXT),
            quote_len: 0,
            reply_to: None,
            file: None,
            at: self.unix,
        };
        self.events.push_back(Event::Message(msg));
    }

    /// Acks a record that carries a message id, if it's one. Returns whether it was.
    pub(super) fn ack_record(&mut self, slot: usize, mid: &[u8]) -> bool {
        let Some(mid) = std::str::from_utf8(mid).ok().filter(|m| hex::decode_array::<4>(m).is_some()) else {
            return false;
        };
        let ack = format!("a\t{mid}");
        self.send_peer(slot, &ack);
        true
    }

    /// Compares a peer's nick and signing key with the verified keys, once "k" brought them. A
    /// key verified before signed this handshake's keys, so nobody in the middle could have made
    /// it: the code needn't be compared again. A peer with the nick of a verified key that signs
    /// with another, or none, is warned about once. Returns whether it warned.
    pub(super) fn check_trust(&mut self, slot: usize) -> bool {
        let name = self.peer_name(slot);
        let p = self.peer(slot);
        let trusted_before = self.trusted(p);
        let id = p.id;
        let verified_key = p
            .ident
            .as_ref()
            .filter(|i| i.state == SignatureState::Verified)
            .map(|i| (i.kind, i.public));
        let (skel, nick) = (p.skel.clone(), p.nick.clone());
        let mut notes = Vec::new();
        let trust = self.trust.clone();
        let mut t = trust.lock().expect("trust lock");
        // A peer signing with an ignored key is ignored wherever it turns up.
        if let Some((_, public)) = verified_key
            && t.ignored_by_key(&public).is_some()
            && !self.is_ignored(&id)
        {
            self.set_ignored(&id, true);
            notes.push((
                Level::Note,
                format!("{name} signs with a key you ignore - what they say isn't shown"),
            ));
        }
        let mut warned = false;
        if let Some((kind, public)) = verified_key
            && let Some(entry) = t.verified_by_key(&public).cloned()
        {
            // The entry follows the nick, so the next peer with the old nick isn't taken for this one.
            if entry.nick != nick {
                t.verify(kind, &public, &nick);
            }
            let p = self.peer_mut(slot);
            if p.trust != TrustMatch::Key {
                p.trust = TrustMatch::Key;
                if p.code_ok == CodeOk::NotCompared {
                    p.code_ok = CodeOk::Same;
                    let was = if entry.nick != nick {
                        format!(" for {}", entry.nick)
                    } else {
                        " before".into()
                    };
                    notes.push((
                        Level::Note,
                        format!("{name} signs with the key you verified{was} - no need to compare codes again"),
                    ));
                }
            }
        } else if let Some(entry) = t.verified_by_nick(&skel).cloned() {
            let p = self.peer_mut(slot);
            if p.trust != TrustMatch::OtherKey {
                p.trust = TrustMatch::OtherKey;
                let now_fp = match &p.ident {
                    None => "no signing key".to_string(),
                    Some(i) if i.state == SignatureState::Failed => "a key with an invalid signature".into(),
                    Some(i) => hex::groups(&i.fingerprint),
                };
                notes.push((
                    Level::Warn,
                    format!(
                        "warning: {name} does not sign with the key you verified for {} (fingerprint {}); it signs with {now_fp}. \
                         Their key changed, or someone else uses this nick. Treat them as unverified until you compare \
                         verify codes again",
                        entry.nick,
                        hex::groups(&crypto::fingerprint(&entry.public))
                    ),
                ));
                warned = true;
            }
        } else {
            self.peer_mut(slot).trust = TrustMatch::Unknown;
        }
        drop(t);
        for (level, text) in notes {
            self.events.push_back(Event::Notice { level, text });
        }
        // A key verified before made it trusted: it gets our offers now.
        let p = self.peer(slot);
        if p.announced && !trusted_before && self.trusted(p) {
            self.file_offer_all(slot);
        }
        warned
    }

    /// "NICK (verified) joined": once "k" has brought the nick and identity.
    pub(super) fn announce_join(&mut self, slot: usize) {
        self.peer_mut(slot).announced = true;
        let name = self.peer_name(slot);
        let p = self.peer(slot);
        let label = match p.ident.as_ref().map(|i| i.state) {
            Some(SignatureState::Verified) => " (verified)",
            Some(SignatureState::Failed) => " (\u{26a0} signature invalid)",
            _ => " (unverified)",
        };
        let persists = p.persists;
        let (id, vfy) = (p.id, p.vfy);
        let online = self.live_count() + 1;
        self.note(format!(
            "{name}{label}{} joined ({online} online)",
            if persists { " [keeps history]" } else { "" }
        ));
        if persists {
            self.warn(format!("{name} keeps a history of this chat"));
        }
        // A peer that dropped and came back did a fresh handshake: someone who forced the drop
        // could be in the middle of it.
        if let Some(pos) = self.gone.iter().position(|(gid, _)| *gid == id) {
            let (_, was) = self.gone.remove(pos).expect("found");
            if was != vfy {
                self.note(format!(
                    "{name} reconnected with a new verify code (was {}, now {}) - if you had compared codes with them, compare the new one",
                    hex::groups(&was),
                    hex::groups(&vfy)
                ));
            }
        }
        self.file_offer_all(slot);
        self.check_trust(slot);
        self.tell_came_with(slot);
        if let Some(n) = self.code_ok_note(slot) {
            self.note(n);
        }
        self.tell_build(slot);
        let info = self.peer_info(slot);
        self.events.push_back(Event::PeerJoined(info));
        self.emit_timer_if_changed();
    }

    /// A peer gone: it said so, or timed out.
    pub(super) fn drop_peer(&mut self, slot: usize, reason: LeaveReason) {
        let name = self.peer_name(slot);
        let p = self.peer(slot);
        let (was_ok, id, vfy, vfy_set, addr) = (p.ok, p.id, p.vfy, p.vfy_set, p.addr);
        if was_ok && vfy_set {
            if self.gone.len() >= GONE_MAX {
                self.gone.pop_front();
            }
            self.gone.push_back((id, vfy));
        }
        // One that timed out may come back with the same id (its session still runs): what it
        // never acked is kept for it, and its last address is worth a hi.
        let hold = reason == LeaveReason::TimedOut && was_ok;
        self.forget_peer_holding(slot, hold);
        if hold && addr.is_udp() {
            self.add_candidate(addr);
        }
        if was_ok {
            let why = match reason {
                LeaveReason::Left => "left",
                LeaveReason::Offline => "went offline",
                LeaveReason::TimedOut => "timed out",
            };
            let online = self.live_count() + 1;
            self.note(format!("{name} {why} ({online} online)"));
            self.events.push_back(Event::PeerLeft {
                id: PeerId(id),
                name,
                reason,
            });
            self.emit_timer_if_changed();
            // The peer that left may have published the room service last: point it back at us.
            if self.mode == RouteMode::Tor && self.tor.hosting && self.tor.republish_at == 0.0 {
                self.tor.republish_at = self.now + 5.0 + Self::jitter(25.0);
            }
        }
    }

    pub(super) fn forget_peer(&mut self, slot: usize) {
        self.forget_peer_holding(slot, false);
    }

    fn forget_peer_holding(&mut self, slot: usize, hold: bool) {
        let name = self.peer_name(slot);
        let Some(mut p) = self.peers[slot].take() else { return };
        self.keep_move_key(&p);
        let pending = std::mem::take(&mut p.pending);
        let mine: Vec<_> = pending.into_iter().filter(|pm| pm.own.is_some()).collect();
        if hold && !mine.is_empty() {
            let since = self.now;
            self.held
                .entry(p.id)
                .or_insert(Held { since, items: Vec::new() })
                .items
                .extend(mine);
        } else {
            let owns: Vec<u64> = mine.iter().filter_map(|pm| pm.own).collect();
            for own in owns {
                self.own_missed(own, &p.id, &name);
            }
        }
    }
}
