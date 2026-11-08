// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Sending: each peer's slots, the records and room frames queued for them, and a frame's way
//! out. A connected peer gets exactly one datagram per slot, whether there's anything to say or
//! not, so the timing and amount of traffic say nothing about what was said.

use super::peer::{QueuedRecord, QueuedRoom};
use super::*;
use crate::protocol::crypto::{SEAL_MAX_BODY, SESSION_PAD_TARGET, room_seal, udp_mask};
use crate::protocol::wire::{self, ROOM_FRAME_MAX, UDP_CELL};
use std::net::{IpAddr, Ipv4Addr};
use zeroize::Zeroizing;

/// The most one session frame carries over UDP: a record, or several joined by newlines.
pub(super) const RECORD_MAX: usize = SESSION_PAD_TARGET - 2;
/// Through the relays every event is the same size anyway, so a peer that reads several records
/// a frame gets frames as big as it can read.
pub(super) const RELAY_RECORD_MAX: usize = SEAL_MAX_BODY - 2;
/// What waits for one peer's slots.
const SENDQ_PER_PEER: usize = 256;
/// Room frames queued for a peer; past these (junk replayed at it), they're lost like datagrams.
const ROOMQ_PER_PEER: usize = 4;
/// Records may go ahead of a waiting room frame, but not for more than this many slots in a row,
/// and only one while a re-handshake runs with the peer, so it isn't spread out (and the time
/// messages wait during it with it).
const ROOM_OVERTAKE_MAX: u32 = 2;
const ROOM_OVERTAKE_REHANDSHAKE: u32 = 1;
const BATCH_MAX: usize = 16;

/// Each peer has a slot this often, plus up to a quarter more at random.
const COVER_INTERVAL: f64 = 1.5;
/// With many peers the slots spread out, to keep the total near this many a second.
const COVER_MAX_RATE: f64 = 8.0;
/// Through the relays: slots at least this far apart, and fewer with more relayed peers.
const NOSTR_COVER_INTERVAL: f64 = 5.0;
const NOSTR_MAX_RATE: f64 = 0.33;

impl Session {
    /// Every datagram leaves through here: over UDP masked, so the network sees random bytes;
    /// through the relays (or Tor) as a whole frame, which they hide themselves.
    pub(super) fn xmit(&mut self, data: Vec<u8>, to: Addr, lan: bool) {
        match to {
            Addr::Relay(_) => {
                if self.nostr != NostrMode::Off {
                    self.transmits.push_back(Transmit { to, data, lan: false });
                }
            }
            Addr::Tor(_) => self.transmits.push_back(Transmit { to, data, lan: false }),
            Addr::Udp(_) => {
                if self.port == 0 {
                    return;
                }
                let mut d = data;
                if udp_mask(&self.keys.udp, &mut d) {
                    self.transmits.push_back(Transmit { to, data: d, lan });
                }
            }
        }
    }

    fn live_peer_at(&self, a: Addr) -> Option<usize> {
        (0..SLOTS).find(|&i| self.peers[i].as_ref().is_some_and(|p| p.ok && p.addr == a))
    }

    fn queue_room(&mut self, slot: usize, frame: Vec<u8>, to: Addr, kind: &str) {
        self.queue_seq += 1;
        let seq = self.queue_seq;
        let p = self.peer_mut(slot);
        // A handshake step that hasn't started going is out of date once a newer one of its kind
        // is queued (a hi with keys since replaced, a kx for keys since rotated), and it would
        // only hold the newer one up, a few slots per piece.
        p.roomq.retain(|q| q.kind != kind || q.next_piece > 0);
        if p.roomq.len() >= ROOMQ_PER_PEER {
            return;
        }
        let pieces = wire::pieces(frame.len());
        p.roomq.push_back(QueuedRoom {
            seq,
            kind: kind.to_string(),
            to,
            id: sodium::random_array(),
            next_piece: 0,
            pieces,
            frame,
        });
    }

    /// A record to the room (a handshake or a beacon). A connected peer's waits for its slots,
    /// like everything else sent to it.
    pub(super) fn send_room(&mut self, text: &str, to: Addr, lan: bool) {
        let Some(frame) = room_seal(&self.keys.room, text.as_bytes()) else {
            return;
        };
        if frame.len() > ROOM_FRAME_MAX {
            return;
        }
        if !lan && let Some(slot) = self.live_peer_at(to) {
            let kind = text.split('\t').next().unwrap_or_default();
            self.queue_room(slot, frame, to, kind);
            return;
        }
        if !to.is_udp() {
            self.xmit(frame, to, lan);
            return;
        }
        let id: [u8; 4] = sodium::random_array();
        let n = wire::pieces(frame.len());
        for i in 0..n {
            let c = wire::cell(&frame, &id, i, n);
            self.xmit(c, to, lan);
        }
    }

    /// Queues a record for the peer's next slot. One identical to a record already waiting isn't
    /// queued again, so a retry, or an "rk" sent again, only goes once.
    pub(super) fn queue_record(&mut self, slot: usize, text: &str, old_chain: bool) -> bool {
        if text.is_empty() || text.len() > RECORD_MAX {
            return false;
        }
        let p = self.peer(slot);
        if p.sendq.iter().any(|q| q.old_chain == old_chain && *q.text == text) {
            return true;
        }
        if p.sendq.len() >= SENDQ_PER_PEER {
            return false;
        }
        self.queue_seq += 1;
        let seq = self.queue_seq;
        self.peer_mut(slot).sendq.push_back(QueuedRecord {
            seq,
            old_chain,
            text: Zeroizing::new(text.to_string()),
        });
        true
    }

    pub(super) fn send_peer(&mut self, slot: usize, text: &str) -> bool {
        self.queue_record(slot, text, false)
    }

    pub(super) fn send_to_live(&mut self, text: &str) {
        for slot in self.live() {
            self.send_peer(slot, text);
        }
    }

    /// Sent at once, outside the slots: only the "bye" or "off" of a session that's ending.
    pub(super) fn send_now(&mut self, slot: usize, text: &str) {
        let p = self.peer_mut(slot);
        let to = p.addr;
        if let Some(frame) = p.send_chain().seal_next(text.as_bytes(), SESSION_PAD_TARGET) {
            self.xmit(frame, to, false);
        }
    }

    pub(super) fn relayed_count(&self) -> usize {
        self.peers
            .iter()
            .flatten()
            .filter(|p| p.ok && matches!(p.addr, Addr::Relay(_)))
            .count()
    }

    /// How far apart a peer's slots are.
    pub(super) fn cover_interval(&self, slot: usize) -> f64 {
        let live = self.live_count().max(1) as f64;
        let mut iv = COVER_INTERVAL * (live / (COVER_MAX_RATE * COVER_INTERVAL)).max(1.0);
        if matches!(self.peer(slot).addr, Addr::Relay(_)) {
            iv = iv.max((self.relayed_count() as f64 / NOSTR_MAX_RATE).max(NOSTR_COVER_INTERVAL));
        }
        iv
    }

    /// A peer's slot: exactly one datagram. The oldest thing waiting goes first: a piece of a
    /// room frame, or a record and, for a peer that reads several a frame, the ones after it on
    /// the same chain while they fit. With nothing waiting, a "nop".
    ///
    /// During a re-handshake our new chain starts before the peer can read it (it needs our kx,
    /// and its side of the handshake takes a few room frames, each a few slots). Whatever is
    /// sealed on it then is lost, so records go on the old chain, which the peer still reads,
    /// until a frame from the peer confirms the new one; the nops go on the new chain, which is
    /// how the peer confirms it. With no old chain (a first handshake), records wait.
    pub(super) fn run_slot(&mut self, slot: usize) {
        let p = self.peer(slot);
        let rq_seq = p.roomq.front().map(|q| q.seq);
        let first = p.sendq.front().map(|q| (q.seq, q.old_chain));
        let on_old = p.records_on_old();
        let readable = !p.records_wait();
        // Records may go ahead of a waiting room frame for a couple of slots, so a re-handshake
        // doesn't hold up a conversation; for only one while it runs with this peer, since every
        // slot taken from it spreads the handshake out, and with it how long messages wait.
        let rehandshaking = self.rehandshaking_with(p);
        let max = if rehandshaking {
            ROOM_OVERTAKE_REHANDSHAKE
        } else {
            ROOM_OVERTAKE_MAX
        };
        // Chunks of a file it asked for are something to say too, after any records, and go on
        // the chain records would. They're bulk: they never hold up a re-handshake.
        let chunks = readable && p.serve.active && (rq_seq.is_none() || !rehandshaking);
        let has = first.is_some() || chunks;
        let overtake = rq_seq.is_some() && has && readable && p.room_waited < max;
        // Records can't go ahead of an older room frame unless they overtake (chunks are always
        // newer); and when they can't go at all, a room frame (our kx, which is what lets the
        // peer read the new chain) never waits behind them.
        if let Some(rs) = rq_seq
            && (!has || !readable || (!overtake && first.is_none_or(|f| rs < f.0)))
        {
            let p = self.peer_mut(slot);
            p.room_waited = 0;
            let q = p.roomq.front_mut().expect("some");
            let to = q.to;
            let data = if to.is_udp() {
                let c = wire::cell(&q.frame, &q.id, q.next_piece, q.pieces);
                q.next_piece += 1;
                if q.next_piece >= q.pieces {
                    p.roomq.pop_front();
                }
                c
            } else {
                p.roomq.pop_front().expect("some").frame
            };
            self.xmit(data, to, false);
            return;
        }

        let big = p.caps.batches && matches!(p.addr, Addr::Relay(_));
        let cap = if big { RELAY_RECORD_MAX } else { RECORD_MAX };
        // Records go in a run on one chain (the current one, or the old
        // one for an "rk"); while our new chain is unproven, every one goes on the old chain.
        let old_chain = on_old || first.is_some_and(|f| f.1);
        let mut text = Zeroizing::new(String::new());
        let mut taken = Vec::new();
        if readable {
            for (i, q) in p.sendq.iter().enumerate() {
                if !on_old && q.old_chain != old_chain {
                    break;
                }
                if rq_seq.is_some_and(|rs| q.seq > rs) && !overtake {
                    break;
                }
                if !taken.is_empty() && (!p.caps.batches || text.len() + 1 + q.text.len() > cap || taken.len() == BATCH_MAX) {
                    break;
                }
                if !taken.is_empty() {
                    text.push('\n');
                }
                text.push_str(&q.text);
                taken.push(i);
            }
        }
        // Space left over: the next chunks of a file this peer asked for. Over UDP a chunk takes
        // a slot of its own, one that would otherwise carry a nop; through the relays, as many
        // as fit after the rest.
        let mut chunked = false;
        if chunks && (big || taken.is_empty()) && (rq_seq.is_none() || overtake) {
            while self.peer(slot).serve.active && self.next_chunk(slot, &mut text, cap) {
                chunked = true;
            }
        }
        if text.is_empty() {
            text.push_str("nop");
        }
        let body = if big { SEAL_MAX_BODY } else { SESSION_PAD_TARGET };
        let p = self.peer_mut(slot);
        let to = p.addr;
        let chain = if ((!taken.is_empty() && old_chain) || (chunked && on_old)) && p.old_avail() {
            &mut p.old_send
        } else {
            p.send_chain()
        };
        // No chain yet (a responder waiting for the kx): what's queued waits too.
        let Some(frame) = chain.seal_next(text.as_bytes(), body) else {
            return;
        };
        for i in taken.into_iter().rev() {
            p.sendq.remove(i);
        }
        if rq_seq.is_some() {
            p.room_waited += 1;
        }
        self.xmit(frame, to, false);
    }

    /// Our LAN beacon's two destinations: the broadcast address and loopback.
    pub(super) fn lan_targets(&self) -> [Addr; 2] {
        let port = self.keys.lan_port;
        [
            Addr::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), port)),
            Addr::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)),
        ]
    }
}

const _: () = assert!(UDP_CELL == 1004);
