// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Messages: their ids, the ones seen lately, replies, and delivering what's typed.
//!
//! Reliable sending: every message is acked, and sent again until it is, sealed afresh on the
//! peer's current chain each time (so a rekey can't lose one). Our own messages keep trying for
//! as long as the peer is connected, backing off; copies passed on for others try a few times.
//! A peer that times out may come back with the same id (its session kept running), so what it
//! never acked is held for it a while, and sent again once it's back and trusted. The UI hears,
//! peer by peer, when each of our messages arrived, and when nothing more will be heard.

use super::peer::Pending;
use super::*;
use crate::protocol::crypto::sodium;
use crate::protocol::hex;
use crate::protocol::text;
use zeroize::Zeroizing;

/// What a peer without "l" reads of a message: older builds cut a longer one off, so it goes to
/// them in parts, each a message of its own.
pub(super) const OLD_MAX_TEXT: usize = 250;
pub(super) const MAX_TEXT_PARTS: usize = 8;
/// "mr" carries the id of what it answers too, and still has to fit a frame.
pub(super) const MAX_REPLY_TEXT: usize = MAX_TEXT - 8 - 2;
const RECENT_MAX: usize = 64;
const QUOTE_MAX: usize = 80;
/// How many times a copy passed on for someone else is sent.
const RELAYED_TRIES: u32 = 5;
/// Ours: tried while the peer stays connected, backing off, up to this many times.
const OWN_TRIES: u32 = 24;
/// Resends come at a steady pace for this many tries (a re-handshake can hide a peer for a
/// while), then further apart, up to the cap.
const STEADY_TRIES: u32 = 6;
const RESEND_BACKOFF_CAP: f64 = 30.0;
/// A peer that timed out gets this long to come back for what it never acked.
pub(super) const HOLD_FOR: f64 = 600.0;
const RELAY_ROUND_TRIP: f64 = 4.0;
const UDP_ROUND_TRIP: f64 = 1.0;
/// The peers a held-back message names before it counts the rest.
const HELD_NAMES: usize = 3;

/// A message's id: four random bytes, as hex.
pub(super) fn gen_mid() -> String {
    hex::encode(&sodium::random_array::<4>())
}

/// A part's id: the same whoever splits the message, so a part passed on by several peers is
/// still shown once.
pub(super) fn part_mid(mid: &str, i: usize) -> String {
    hex::encode(&sodium::sha256(&[format!("{mid}/{i}").as_bytes()])[..4])
}

fn mid_key(mid: &str) -> u32 {
    let mut v = 0u32;
    for c in mid.chars().take(8) {
        let Some(h) = c.to_digit(16) else { break };
        v = (v << 4) | h;
    }
    v
}

impl Session {
    pub(super) fn seen_has(&self, mid: &str) -> bool {
        self.seen_set.contains(&mid_key(mid))
    }

    pub(super) fn seen_add(&mut self, mid: &str) {
        let k = mid_key(mid);
        if self.seen.len() >= SEEN_MIDS
            && let Some(old) = self.seen.pop_front()
            && !self.seen.contains(&old)
        {
            self.seen_set.remove(&old);
        }
        self.seen.push_back(k);
        self.seen_set.insert(k);
    }

    pub(super) fn recent_add(&mut self, mid: &str, origin: [u8; 16], nick: &str, body: &str) {
        if self.recent.len() >= RECENT_MAX {
            self.recent.pop_front();
        }
        self.recent.push_back(Recent {
            mid: mid.to_string(),
            origin,
            nick: nick.to_string(),
            quote: text::quote(body, QUOTE_MAX),
            at: self.now,
        });
    }

    pub(super) fn recent_find(&self, mid: &str) -> Option<&Recent> {
        self.recent.iter().find(|r| r.mid == mid)
    }

    /// Messages older than the timer go from the ones a reply can quote.
    pub(super) fn expire_recent(&mut self) {
        let (timer, _) = self.timer();
        if timer > 0 {
            let now = self.now;
            self.recent.retain(|r| now - r.at <= f64::from(timer));
        }
    }

    /// Who said what a reply answers, and the start of it: "↪ NICK: QUOTE · ".
    pub(super) fn reply_prefix(&self, reply_mid: &str) -> String {
        match self.recent_find(reply_mid) {
            Some(r) => format!("\u{21aa} {}: {} \u{b7} ", r.nick, r.quote),
            None => "\u{21aa} a message you don't have \u{b7} ".to_string(),
        }
    }

    /// How long a resend waits for the ack's round trip: the message waits for a slot here, the
    /// ack for one there, and relays are slower than UDP.
    pub(super) fn resend_delay(&self, slot: usize) -> f64 {
        let slots = 2.0 * self.cover_interval(slot) * 1.25;
        slots
            + if matches!(self.peer(slot).addr, Addr::Relay(_)) {
                RELAY_ROUND_TRIP + Self::jitter(RELAY_ROUND_TRIP / 4.0)
            } else {
                UDP_ROUND_TRIP + Self::jitter(UDP_ROUND_TRIP / 2.0)
            }
    }

    /// Keeps a record for resending until the peer acks it.
    pub(super) fn track(&mut self, slot: usize, mid: &str, record: &str, own: Option<u64>) {
        let next_retry = self.now + self.resend_delay(slot);
        let p = self.peer_mut(slot);
        let id = p.id;
        p.pending.push(Pending {
            mid: mid.to_string(),
            record: Zeroizing::new(record.to_string()),
            tries: 1,
            next_retry,
            own,
        });
        if let Some(own) = own {
            *self
                .own
                .entry(own)
                .or_insert_with(|| OwnTrack { waiting: HashMap::new() })
                .waiting
                .entry(id)
                .or_insert(0) += 1;
        }
    }

    /// An "m" to a peer: whole, or for one that reads no more than 250 bytes, in parts. Each is
    /// kept for resending until acked. Returns whether any went.
    pub(super) fn send_message(&mut self, slot: usize, mid: &str, origin_hex: &str, nick: &str, body: &str, own: Option<u64>) -> bool {
        let long = self.peer(slot).caps.long_text;
        let b = body.as_bytes();
        let (mut pos, mut sent) = (0, false);
        for i in 0..MAX_TEXT_PARTS {
            if pos >= b.len() {
                break;
            }
            let n = if long {
                b.len() - pos
            } else {
                text::part_len(&b[pos..], OLD_MAX_TEXT)
            };
            let pmid = if n == b.len() { mid.to_string() } else { part_mid(mid, i) };
            // part_len only cuts between characters, so this is valid UTF-8.
            let part = std::str::from_utf8(&b[pos..pos + n]).unwrap_or_default();
            let record = format!("m\t{pmid}\t{origin_hex}\t{nick}\t{part}");
            // Ours is kept for resending even when the peer's queue is full for now: a retry
            // queues it once there's room, so it's never silently dropped.
            let queued = self.send_peer(slot, &record);
            if queued || own.is_some() {
                sent = true;
                self.track(slot, &pmid, &record, own);
            }
            pos += n;
            while pos < b.len() && b[pos] == b' ' {
                pos += 1;
            }
        }
        sent
    }

    /// A reply: "mr" to a peer that reads it, otherwise an "m" with the quote in front.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn send_reply(
        &mut self,
        slot: usize,
        mid: &str,
        reply_mid: &str,
        origin_hex: &str,
        nick: &str,
        body: &str,
        prefix: &str,
        own: Option<u64>,
    ) -> bool {
        if !self.peer(slot).caps.can_reply {
            let joined = text::clean_str(&format!("{prefix}{body}"), MAX_TEXT);
            return self.send_message(slot, mid, origin_hex, nick, &joined, own);
        }
        let record = format!("mr\t{mid}\t{reply_mid}\t{origin_hex}\t{nick}\t{body}");
        if !self.send_peer(slot, &record) && own.is_none() {
            return false;
        }
        self.track(slot, mid, &record, own);
        true
    }

    /// A message from us to the room, or with `reply`, an answer to one.
    pub(super) fn send_text(&mut self, input: &str, reply: Option<String>) -> Result<Outcome, CommandError> {
        let line = text::clean_str(input, if reply.is_some() { MAX_REPLY_TEXT } else { MAX_TEXT });
        if line.is_empty() {
            return Err(CommandError::Empty);
        }
        if !self.ready() {
            return Err(CommandError::NotOpen);
        }
        let mid = gen_mid();
        self.seen_add(&mid);
        let prefix = reply.as_deref().map(|r| self.reply_prefix(r)).unwrap_or_default();
        self.own_seq += 1;
        let own = self.own_seq;
        let msg = Message {
            mid: mid.clone(),
            from: PeerId(self.my_id),
            nick: self.nick.clone(),
            name: self.nick.clone(),
            peer: None,
            colour: Some(self.colour),
            mine: true,
            own: Some(own),
            direct: false,
            mention: false,
            relayed: false,
            text: format!("{prefix}{line}"),
            quote_len: prefix.len(),
            reply_to: reply.clone(),
            file: None,
            at: self.unix,
        };
        self.events.push_back(Event::Message(msg));
        let (my_id, nick, my_idhex) = (self.my_id, self.nick.clone(), self.my_idhex.clone());
        self.recent_add(&mid, my_id, &nick, &line);
        let (mut to, mut held) = (0usize, Vec::new());
        for slot in self.live() {
            // A peer whose code wasn't compared may be someone in the middle: it gets nothing.
            if !self.trusted(self.peer(slot)) {
                held.push(self.peer_name(slot));
                continue;
            }
            let sent = match &reply {
                Some(r) => self.send_reply(slot, &mid, r, &my_idhex, &nick, &line, &prefix, Some(own)),
                None => self.send_message(slot, &mid, &my_idhex, &nick, &line, Some(own)),
            };
            to += usize::from(sent);
        }
        if to > 0 {
            self.check_settled(own);
        }
        if !held.is_empty() {
            let mut names = held.iter().take(HELD_NAMES).cloned().collect::<Vec<_>>().join(", ");
            if held.len() > HELD_NAMES {
                names.push_str(" and others");
            }
            self.note(format!("not sent to {names}: compare verify codes first"));
        } else if to == 0 {
            self.note("nobody else is here yet, message not delivered");
        }
        Ok(Outcome::Sent {
            own,
            mid,
            to,
            held: held.len(),
        })
    }

    /// A direct message: only to the peer named, never through anyone else, and only to one
    /// whose build reads it (an older one would drop it without a word).
    pub(super) fn send_direct(&mut self, peer: PeerId, input: &str) -> Result<Outcome, CommandError> {
        let slot = self
            .find_peer(&peer.0)
            .filter(|&s| self.peer(s).ok)
            .ok_or(CommandError::NoSuchPeer)?;
        let line = text::clean_str(input, MAX_TEXT);
        if line.is_empty() {
            return Err(CommandError::Empty);
        }
        let name = self.peer_name(slot);
        let p = self.peer(slot);
        if !p.caps.can_pm {
            return Err(CommandError::TooOld(name));
        }
        if !self.trusted(p) {
            return Err(if p.code_ok == peer::CodeOk::Different {
                CommandError::CodesDiffer(name)
            } else {
                CommandError::NotCompared(name)
            });
        }
        let mid = gen_mid();
        self.seen_add(&mid);
        let record = format!("pm\t{mid}\t{line}");
        if !self.send_peer(slot, &record) {
            return Err(CommandError::Invalid(format!(
                "couldn't send that to {name}: too much is waiting for them"
            )));
        }
        self.own_seq += 1;
        let own = self.own_seq;
        self.track(slot, &mid, &record, Some(own));
        let msg = Message {
            mid: mid.clone(),
            from: PeerId(self.my_id),
            nick: self.nick.clone(),
            name: self.nick.clone(),
            peer: Some(peer),
            colour: Some(self.colour),
            mine: true,
            own: Some(own),
            direct: true,
            mention: false,
            relayed: false,
            text: line,
            quote_len: 0,
            reply_to: None,
            file: None,
            at: self.unix,
        };
        self.events.push_back(Event::Message(msg));
        Ok(Outcome::Sent { own, mid, to: 1, held: 0 })
    }

    pub(super) fn on_ack(&mut self, slot: usize, mid: &str) {
        let name = self.peer_name(slot);
        let p = self.peer_mut(slot);
        let id = p.id;
        let mut acked = Vec::new();
        p.pending.retain(|pm| {
            if pm.mid == mid {
                acked.extend(pm.own);
                false
            } else {
                true
            }
        });
        for own in acked {
            self.own_record_done(own, &id, &name, true);
        }
    }

    /// One record of our message `own` is done with for this peer: acked, or given up on.
    fn own_record_done(&mut self, own: u64, peer: &[u8; 16], name: &str, acked: bool) {
        let Some(track) = self.own.get_mut(&own) else { return };
        let Some(left) = track.waiting.get_mut(peer) else { return };
        if acked {
            *left = left.saturating_sub(1);
            if *left > 0 {
                return;
            }
        }
        track.waiting.remove(peer);
        let delivery = if acked {
            Delivery::Delivered {
                peer: PeerId(*peer),
                name: name.to_string(),
            }
        } else {
            Delivery::Missed {
                peer: PeerId(*peer),
                name: name.to_string(),
            }
        };
        self.events.push_back(Event::Delivery { own, delivery });
        self.check_settled(own);
    }

    /// A peer never acked our message `own` (any of its parts).
    pub(super) fn own_missed(&mut self, own: u64, peer: &[u8; 16], name: &str) {
        self.own_record_done(own, peer, name, false);
    }

    /// Once nothing waits for an ack of our message, the UI hears it's settled.
    pub(super) fn check_settled(&mut self, own: u64) {
        if self.own.get(&own).is_some_and(|t| t.waiting.is_empty()) {
            self.own.remove(&own);
            self.events.push_back(Event::Delivery {
                own,
                delivery: Delivery::Settled,
            });
        }
    }

    /// Sends again what wasn't acked, and gives up on what has had its tries.
    pub(super) fn resend_messages(&mut self) {
        let now = self.now;
        for slot in self.live() {
            if self.peer(slot).pending.iter().all(|pm| now < pm.next_retry) {
                continue;
            }
            let delay = self.resend_delay(slot);
            let name = self.peer_name(slot);
            let p = self.peer_mut(slot);
            let id = p.id;
            let mut resend = Vec::new();
            let mut gave_up = Vec::new();
            p.pending.retain_mut(|pm| {
                if now < pm.next_retry {
                    return true;
                }
                // Ours (messages, file offers, moves) keep trying; copies passed on, a few times.
                let ours = ["fo\t", "mv\t", "mk\t"].iter().any(|r| pm.record.starts_with(r));
                let max = if pm.own.is_some() || ours { OWN_TRIES } else { RELAYED_TRIES };
                if pm.tries >= max {
                    gave_up.extend(pm.own);
                    return false;
                }
                resend.push(pm.record.clone());
                pm.tries += 1;
                pm.next_retry = now + (delay * 1.5f64.powi(pm.tries.saturating_sub(STEADY_TRIES).min(8) as i32)).min(RESEND_BACKOFF_CAP);
                true
            });
            for r in resend {
                self.send_peer(slot, &r);
            }
            for own in gave_up {
                self.own_missed(own, &id, &name);
            }
        }
    }

    /// What a peer that timed out never acked: sent again once it's back (and trusted), or given
    /// up on when it doesn't come back in time.
    pub(super) fn deliver_held(&mut self) {
        if self.held.is_empty() {
            return;
        }
        let now = self.now;
        let ids: Vec<[u8; 16]> = self.held.keys().copied().collect();
        for id in ids {
            let back = self.find_peer(&id).filter(|&s| {
                let p = self.peer(s);
                p.ok && p.announced && self.trusted(p)
            });
            if let Some(slot) = back {
                let held = self.held.remove(&id).expect("listed");
                let delay = self.resend_delay(slot);
                for mut pm in held.items {
                    self.send_peer(slot, &pm.record);
                    pm.tries = 1;
                    pm.next_retry = now + delay;
                    self.peer_mut(slot).pending.push(pm);
                }
            } else if now - self.held[&id].since > HOLD_FOR {
                let held = self.held.remove(&id).expect("listed");
                let name = format!("#{}", hex::encode(&id[..4]));
                let owns: Vec<u64> = held.items.iter().filter_map(|pm| pm.own).collect();
                for own in owns {
                    self.own_missed(own, &id, &name);
                }
            }
        }
    }
}
