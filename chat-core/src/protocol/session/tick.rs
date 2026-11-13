// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! What a session does as time passes: candidates and hellos, resends, keeping each peer's
//! path alive (and falling back to the relays when it goes quiet), beacons, the DHT, rekeys,
//! timeouts, and every peer's slots.

use super::files::{FAST_BURST_MAX, FILE_FAST_INTERVAL};
use super::peer::Peer;
use super::*;

/// A peer that has sent nothing for this long gets a hi, in case it lost the session.
const KEEPALIVE: f64 = 10.0;
const KEEPALIVE_SPREAD: f64 = 3.0;
const PEER_TIMEOUT: f64 = 40.0;
/// A peer still handshaking is forgotten after this long.
const PENDING_TTL: f64 = 45.0;
const LONELY_HINT_AFTER: f64 = 15.0;
/// A peer's own path counts as broken after this long without a frame, and its traffic moves to
/// the relays.
pub(super) const UDP_STALE: f64 = 25.0;
/// With the relays on fallback, they stay connected this long after they were last needed.
const RELAY_LINGER: f64 = 60.0;
const NOSTR_BEACON_ALONE: f64 = 20.0;
const NOSTR_BEACON_CONNECTED: f64 = 90.0;
const BEACON_JITTER: f64 = 0.3;
const LAN_EVERY: f64 = 5.0;
const LAN_SPREAD: f64 = 2.0;
const REKEY_JITTER: f64 = 0.2;
/// A rekey waits up to this long for messages still waiting for acks.
const REKEY_DRAIN_GRACE: f64 = 20.0;
/// And up to this long while any re-handshake still runs: one that overlapped it would restart
/// with keys the other side hasn't seen.
const REKEY_DEFER_MAX: f64 = 120.0;
const RK_RESEND: f64 = 6.0;
/// The join waits this long for "k" before it's announced anyway.
const JOIN_WAIT: f64 = 5.0;
/// Tor: one who joined and hasn't reached anyone by then hosts a room service itself.
const TOR_HOST_AFTER: f64 = 120.0;
const K_SENDS: u32 = 3;

/// The next rekey: the interval, and up to a fifth more.
pub(super) fn rekey_after(interval: f64) -> f64 {
    interval + Session::jitter(interval * REKEY_JITTER)
}

impl Session {
    pub(super) fn run_tick(&mut self) {
        if self.left {
            return;
        }
        self.expire_recent();
        self.trust_changes();
        if self.nostr != NostrMode::Off && self.relays_needed() {
            self.relays_until = self.now + RELAY_LINGER;
        }
        self.beacon_tick();
        self.tor_tick();
        self.dht_tick();
        self.try_candidates();
        self.resend_messages();
        self.hello_pending();
        self.keep_paths();
        self.alive_tick();
        self.lan_tick();
        self.rekeys_and_timeouts();
        self.rekey_tick();
        self.files_tick();
        self.move_tick();
        self.run_slots();
        self.deliver_held();
        self.deliver_outbox();
        self.lonely_hint();
        self.emit_timer_if_changed();
        let net = self.net_status();
        if self.last_net.as_ref() != Some(&net) {
            self.last_net = Some(net.clone());
            self.events.push_back(Event::Net(net));
        }
    }

    /// The verified or ignored keys changed (here or in another room): every peer is checked again.
    fn trust_changes(&mut self) {
        let version = self.trust.lock().map(|t| t.version()).unwrap_or(0);
        if version == self.trust_seen {
            return;
        }
        self.trust_seen = version;
        for slot in self.live() {
            let p = self.peer(slot);
            let still = p.ident.as_ref().is_some_and(|i| {
                i.state == SignatureState::Verified && self.trust.lock().is_ok_and(|t| t.verified_by_key(&i.public).is_some())
            });
            if p.trust == peer::TrustMatch::Key && !still {
                self.peer_mut(slot).trust = peer::TrustMatch::Unknown;
            }
            if self.peer(slot).announced {
                self.check_trust(slot);
                self.peer_changed(slot);
            }
        }
        // Checking peers may itself have updated a nick in the list.
        self.trust_seen = self.trust.lock().map(|t| t.version()).unwrap_or(0);
    }

    fn relays_needed(&self) -> bool {
        if self.nostr == NostrMode::Always || self.live_count() == 0 {
            return true;
        }
        self.peers
            .iter()
            .flatten()
            .any(|p| matches!(p.addr, Addr::Relay(_)) || (p.ok && self.now - p.seen > UDP_STALE / 2.0))
            || self.cands.iter().any(|c| matches!(c.addr, Addr::Relay(_)))
    }

    /// While the relays are up, a beacon tells the room we're there: often while alone, rarely
    /// once connected.
    fn beacon_tick(&mut self) {
        if self.nostr == NostrMode::Off || self.relays_up == 0 || self.now < self.next_beacon {
            return;
        }
        let every = if self.live_count() > 0 {
            NOSTR_BEACON_CONNECTED
        } else {
            NOSTR_BEACON_ALONE
        };
        self.next_beacon = self.now + every + Self::jitter(every * BEACON_JITTER);
        let beacon = format!("nb\t{}", self.my_idhex);
        self.send_room(&beacon, Addr::Relay(PeerId::EVERYONE), false);
    }

    /// Tor: our onion to peers when it's (re)published, a room service to host once we've reached
    /// someone (or after a while alone), and the hosted one published again when asked.
    fn tor_tick(&mut self) {
        if self.mode != RouteMode::Tor {
            return;
        }
        if self.tor.status.onion.is_some() && self.tor.status.onion != self.tor.told {
            self.tor.told = self.tor.status.onion.clone();
            for slot in self.live() {
                self.send_onion(slot);
            }
        }
        if !self.tor.hosting && (self.ever_connected || self.now - self.start > TOR_HOST_AFTER) {
            self.tor.hosting = true;
            self.requests.push_back(Request::TorHostRoom { slot: None });
        }
        if self.tor.republish_at > 0.0 && self.now >= self.tor.republish_at {
            self.tor.republish_at = 0.0;
            self.requests.push_back(Request::TorRepublishRoom);
        }
    }

    /// Tor: a hi to each of the room's services we don't host. Members hosting different ones only
    /// find each other this way; one with a stream open already had its hi.
    fn knock_room_slots(&mut self) {
        let hi = self.hi_msg.clone();
        for (i, id) in self.tor.room_targets.into_iter().enumerate() {
            let a = Addr::Tor(id);
            if self.tor.status.hosted_slot == Some(i as u8) || self.known_addr(a) || self.tor.status.busy.contains(&id) {
                continue;
            }
            self.send_room(&hi, a, false);
        }
    }

    fn dht_tick(&mut self) {
        let live = self.live_count() > 0;
        let (now, unix) = (self.now, self.unix);
        let Some(dht) = &mut self.dht else { return };
        dht.peers_now = live;
        if dht.take_resolve_request(now) {
            let [want_v4, want_v6] = dht.wants();
            self.requests.push_back(Request::ResolveDhtBootstrap { want_v4, want_v6 });
        }
        let finished = dht.step(now, unix);
        let (out, found) = dht.drain();
        let counts = dht.counts();
        for (to, data) in out {
            // The DHT's own messages are never masked: they're ordinary DHT traffic.
            self.transmits.push_back(Transmit {
                to: Addr::Udp(to),
                data,
                lan: false,
            });
        }
        for a in found {
            self.add_candidate(Addr::udp(a));
        }
        if finished && !self.dht_summary_done {
            self.dht_summary_done = true;
            self.net_news(format!(
                "dht: lookup done - {} of {} nodes answered, {} address{} found for this room",
                counts.answered[0] + counts.answered[1],
                counts.queried[0] + counts.queried[1],
                counts.found,
                if counts.found == 1 { "" } else { "es" }
            ));
        }
    }

    fn try_candidates(&mut self) {
        let mut i = 0;
        while i < self.cands.len() {
            let a = self.cands[i].addr;
            // Already reached at this address (or, on the relays, under this id).
            if self.candidate_reached(a) {
                self.cands.remove(i);
                continue;
            }
            if self.now >= self.cands[i].next_try {
                if !self.probe.take(self.now, PROBE_RATE, PROBE_BURST) {
                    break;
                }
                let hi = self.hi_msg.clone();
                self.send_room(&hi, a, false);
                let c = &mut self.cands[i];
                c.next_try = self.now + Self::retry_delay(c.tries);
                c.tries += 1;
                let tries = c.tries;
                self.net_detail(|| format!("hi to {} (candidate, try {tries}/{CAND_MAX_TRIES})", handshake::where_str(a, None)));
                if tries >= CAND_MAX_TRIES {
                    self.cands.remove(i);
                    continue;
                }
            }
            i += 1;
        }
    }

    /// A peer we have no session with yet gets our hi again, and our kx if we start it.
    fn hello_pending(&mut self) {
        let now = self.now;
        for slot in self.used().collect::<Vec<_>>() {
            let p = self.peer(slot);
            if p.ok {
                continue;
            }
            if now - p.born > PENDING_TTL {
                self.forget_peer(slot);
            } else if now >= p.next_hello {
                let (addr, tries) = (p.addr, p.hello_tries);
                let initiate = p.send.started() && self.we_initiate(p);
                let p = self.peer_mut(slot);
                p.next_hello = now + Self::retry_delay(tries);
                p.hello_tries += 1;
                let hi = self.hi_msg.clone();
                self.send_room(&hi, addr, false);
                if initiate {
                    self.send_kx(slot, addr);
                }
            }
        }
    }

    fn keep_paths(&mut self) {
        let now = self.now;
        for slot in self.live() {
            let relays = self.nostr != NostrMode::Off;
            let p = self.peer_mut(slot);
            // Its path (UDP, or a Tor stream) has gone quiet, so try the relays. Frames that come
            // back through them move it there.
            if relays && !matches!(p.addr, Addr::Relay(_)) && now - p.seen > UDP_STALE {
                p.prev_addr = Some(p.addr);
                p.addr = Addr::Relay(p.peer_id());
                let nick = p.nick.clone();
                self.net_detail(|| format!("{nick} went quiet - trying the relays"));
            }
            let p = self.peer(slot);
            if p.k_sent > 0 && p.k_sent < K_SENDS && now >= p.next_k {
                self.send_k_now(slot);
                let p = self.peer_mut(slot);
                p.k_sent += 1;
                p.next_k = now + receive::K_EVERY;
            }
            // Slots keep a live peer's path busy, so a hi only goes to one that went quiet (it may
            // have lost the session) or hasn't re-handshaken with our new keys. Through the
            // relays a hi costs every member an event, so there only the re-handshake gets one.
            let p = self.peer(slot);
            let quiet = now - p.seen > KEEPALIVE && !matches!(p.addr, Addr::Relay(_));
            let stuck = self.keygen > 1 && (p.keygen != self.keygen || !p.chain_confirmed);
            if (quiet || stuck) && now >= p.next_rehello && p.roomq.is_empty() {
                let addr = p.addr;
                self.peer_mut(slot).next_rehello = now + Self::jittered(handshake::REHELLO_EVERY);
                let hi = self.hi_msg.clone();
                self.send_room(&hi, addr, false);
                let nick = self.peer(slot).nick.clone();
                self.net_detail(|| format!("hi to {nick} ({})", if stuck { "re-handshake" } else { "quiet" }));
            }
        }
    }

    fn alive_tick(&mut self) {
        if self.now >= self.next_alive {
            self.next_alive = self.now + KEEPALIVE + Self::jitter(KEEPALIVE_SPREAD);
            for sa in self.static_peers.clone() {
                self.add_candidate(Addr::Udp(sa));
            }
            if self.mode == RouteMode::Tor && self.tor.status.ready {
                self.knock_room_slots();
            }
        }
    }

    fn lan_tick(&mut self) {
        if !self.lan || self.now < self.next_lan {
            return;
        }
        self.next_lan = self.now + LAN_EVERY + Self::jitter(LAN_SPREAD);
        self.net_detail(|| "lan: beacon sent".to_string());
        let beacon = format!("lan\t{}\t{}", self.my_idhex, self.port);
        for to in self.lan_targets() {
            self.send_room(&beacon, to, true);
        }
    }

    /// A re-handshake still running with this peer: ours (not on our keys yet, or not sure it has
    /// the new chains), or its (a key it announced that we haven't re-handshaken with).
    pub(super) fn rehandshaking_with(&self, p: &Peer) -> bool {
        p.keygen != self.keygen || !p.chain_confirmed || p.next_pub.is_some_and(|n| n != p.public)
    }

    fn send_rk(&mut self, slot: usize, old: bool) {
        let rk = format!("rk\t{}", crate::protocol::hex::encode(&self.x.public));
        self.queue_record(slot, &rk, old);
    }

    fn rekeys_and_timeouts(&mut self) {
        let now = self.now;
        for slot in self.used().collect::<Vec<_>>() {
            let p = self.peer(slot);
            // Until the peer re-handshakes with our new key, we keep announcing it on the chain
            // it can still read.
            if p.ok && p.caps.announces_rekey && self.keygen > 1 && now >= p.next_rk && (p.keygen != self.keygen || !p.chain_confirmed) {
                let (behind, old) = (p.keygen != self.keygen, p.old_until > 0.0 && p.old_send.started());
                self.peer_mut(slot).next_rk = now + RK_RESEND;
                if behind {
                    self.send_rk(slot, false);
                } else if old {
                    self.send_rk(slot, true);
                }
            }
            let p = self.peer_mut(slot);
            if p.old_until > 0.0 && now > p.old_until {
                p.drop_overlap();
            }
            // Through the relays a re-handshake takes most of a minute, longer than the timeout, so
            // there it gets the overlap on top.
            let p = self.peer(slot);
            let timeout = PEER_TIMEOUT
                + if matches!(p.addr, Addr::Relay(_)) && self.rehandshaking_with(p) {
                    handshake::REKEY_OVERLAP
                } else {
                    0.0
                };
            if p.ok && now - p.seen > timeout {
                self.drop_peer(slot, LeaveReason::TimedOut);
            }
        }
    }

    fn rekey_tick(&mut self) {
        if self.now < self.next_rekey {
            return;
        }
        let due = *self.rekey_due.get_or_insert(self.now);
        let waited = self.now - due;
        let pending = self.peers.iter().flatten().any(|p| !p.pending.is_empty());
        let rehandshaking = self.peers.iter().flatten().any(|p| p.ok && self.rehandshaking_with(p));
        if (!pending || waited > REKEY_DRAIN_GRACE) && (!rehandshaking || waited > REKEY_DEFER_MAX) {
            self.rekey();
            self.rekey_due = None;
            self.next_rekey = self.now + rekey_after(self.rekey_every);
        }
    }

    /// New X25519 and ML-KEM keys and a new cookie secret, then a re-handshake with everyone. The
    /// new key is announced over the current session first, so a member in the middle can't
    /// swap in its own.
    fn rekey(&mut self) {
        self.x = X25519Keypair::generate();
        self.kem = KemKeypair::generate();
        self.prev_cookie_secret = Some(self.cookie_secret);
        self.cookie_secret = sodium::random_array();
        self.keygen += 1;
        self.refresh_hi();
        let now = self.now;
        let slots: Vec<usize> = self.used().collect();
        for &slot in &slots {
            if self.peer(slot).ok {
                self.send_rk(slot, false);
                self.peer_mut(slot).next_rk = now + RK_RESEND;
            }
            let addr = self.peer(slot).addr;
            let hi = self.hi_msg.clone();
            self.send_room(&hi, addr, false);
            let p = self.peer_mut(slot);
            p.hello_tries = 0;
            p.next_hello = now + Self::retry_delay(0);
            p.next_rehello = now + Self::jittered(handshake::REHELLO_EVERY);
        }
        let (generation, n) = (self.keygen, slots.len());
        self.net_detail(|| {
            format!(
                "rekey: fresh session keys (generation {generation}), re-handshaking {n} peer{}",
                if n == 1 { "" } else { "s" }
            )
        });
    }

    fn run_slots(&mut self) {
        let now = self.now;
        for slot in self.used().collect::<Vec<_>>() {
            let p = self.peer(slot);
            if p.ok && !p.announced && now - p.ok_since >= JOIN_WAIT {
                self.announce_join(slot);
            }
            // Slots start once there's a chain to send on: before a peer is connected, our first
            // frame is what connects it.
            let p = self.peer_mut(slot);
            if !p.ok && !p.send_chain().started() {
                continue;
            }
            if p.serve.active {
                p.serve.at = now;
            }
            let iv = self.cover_interval(slot);
            let fast = self.fast_interval(slot, iv);
            let p = self.peer_mut(slot);
            if p.next_cover == 0.0 {
                p.next_cover = now + Self::jitter(iv);
                continue;
            }
            if now < p.next_cover {
                continue;
            }
            // Fast transfers over UDP or Tor: a slot every few milliseconds, as many as are due
            // since the last tick.
            if fast == Some(FILE_FAST_INTERVAL) {
                for _ in 0..FAST_BURST_MAX {
                    if self.peers[slot].as_ref().is_none_or(|p| now < p.next_cover) {
                        break;
                    }
                    self.run_slot(slot);
                    if let Some(p) = self.peers[slot].as_mut() {
                        p.next_cover += FILE_FAST_INTERVAL;
                    }
                }
                if let Some(p) = self.peers[slot].as_mut()
                    && now >= p.next_cover
                {
                    p.next_cover = now + FILE_FAST_INTERVAL;
                }
                continue;
            }
            self.run_slot(slot);
            if let Some(p) = self.peers[slot].as_mut() {
                p.next_cover = now + Self::jittered(fast.unwrap_or(iv));
            }
        }
    }

    fn lonely_hint(&mut self) {
        if self.created || self.warned_lonely || self.ever_connected || self.now - self.start <= LONELY_HINT_AFTER {
            return;
        }
        self.warned_lonely = true;
        self.note("nobody has answered for this session yet - check the id and password with whoever shared them, or they may not have started their app yet");
        if self.mode == RouteMode::Tor {
            self.note("through Tor, publishing and finding onion services takes a minute or two; the Nostr relays find members faster");
        }
        if self.nostr == NostrMode::Off {
            self.note(match self.mode {
                RouteMode::Tor => {
                    "Nostr relays are off here, so members on direct routing can't reach you, and finding anyone takes longer"
                }
                RouteMode::Direct => "Nostr relays are off here, so members behind strict NATs, and members using Tor, can't reach you",
            });
        }
        self.net_report();
    }

    /// The network report and diagnosis, as notices.
    pub(super) fn net_report(&mut self) {
        let st = &self.st;
        let route = match self.mode {
            RouteMode::Tor => "tor".to_string(),
            RouteMode::Direct => format!("udp/{}", self.port),
        };
        let mut lines = vec![format!(
            "net: {route} \u{b7} {} connected \u{b7} {} handshaking \u{b7} {} to try",
            self.live_count(),
            self.pending_peer_count(),
            self.cands.len()
        )];
        if self.mode == RouteMode::Tor {
            let t = &self.tor.status;
            lines.push(format!(
                "tor: {} \u{b7} our onion {} \u{b7} room service {}",
                if t.ready { "connected" } else { "connecting" },
                if t.onion.is_some() { "published" } else { "not up yet" },
                t.hosted_slot.map_or("not hosted".to_string(), |s| format!("{s} hosted"))
            ));
        }
        match &self.dht {
            None if self.mode == RouteMode::Tor => {}
            Some(d) => {
                let c = d.counts();
                let fam = |f: usize, name: &str| {
                    if !d.wants()[f] {
                        format!("{name} off")
                    } else if c.queried[f] == 0 {
                        format!("{name} no nodes yet")
                    } else {
                        format!("{name} {} of {} nodes answered", c.answered[f], c.queried[f])
                    }
                };
                let left = d.next_lookup() - self.now;
                let when = if d.looking() {
                    "looking now".to_string()
                } else if left < 1.0 {
                    "starting a lookup".into()
                } else if left < 60.0 {
                    format!("next lookup in {} s", left as u64)
                } else {
                    format!("next lookup in {} min", ((left + 59.0) / 60.0) as u64)
                };
                lines.push(format!(
                    "dht: {} \u{b7} {} \u{b7} {} address{} found for this room \u{b7} {when}",
                    fam(0, "IPv4"),
                    fam(1, "IPv6"),
                    c.found,
                    if c.found == 1 { "" } else { "es" }
                ));
            }
            None => lines.push("dht: off".into()),
        }
        let relayed = self.relayed_count();
        lines.push(match self.nostr {
            NostrMode::Off => "nostr: off".into(),
            _ if !self.relays_wanted() => format!("nostr: not connected - nothing needs them now ({} relays)", self.relays_total),
            _ => format!(
                "nostr: {}/{} relays up \u{b7} {relayed} peer{} reached through them",
                self.relays_up,
                self.relays_total,
                if relayed == 1 { "" } else { "s" }
            ),
        });
        if let Some((_, text)) = &self.portmap {
            lines.push(format!("port mapping: {text}"));
        }
        lines.push(format!("lan: {}", if self.lan { "on" } else { "off" }));
        lines.push(format!(
            "rx: {} datagram{} \u{b7} {} with the room's key (hi {}, ck {}, hi2 {}{}, kx {}, lan {}) \u{b7} {} from connected peers \u{b7} {} dht \u{b7} {} unreadable",
            st.rx,
            if st.rx == 1 { "" } else { "s" },
            st.room_ok,
            st.hi,
            st.ck,
            st.hi2,
            if st.hi2_bad > 0 { format!(" ({} with a bad cookie)", st.hi2_bad) } else { String::new() },
            st.kx,
            st.lan,
            st.session_ok,
            st.dht,
            st.other
        ));
        // DHT answers come back through any NAT, so only what came for the room says it can be reached.
        let heard = st.rx - st.dht;
        let why = if heard == 0 && self.mode == RouteMode::Tor {
            "nothing has reached this session through Tor yet - publishing and finding onion services takes a minute or two"
        } else if heard == 0 && st.dht > 0 {
            "nothing but DHT answers has reached this session - a firewall or NAT is blocking inbound UDP, or nobody is sending to you yet"
        } else if heard == 0 {
            "nothing at all has reached this session - a firewall or NAT is blocking inbound UDP, or nobody is sending to you yet"
        } else if st.room_ok == 0 && st.other > 0 {
            "packets arrive but none are readable - wrong session id or password, or the other side runs an incompatible build"
        } else if st.hi > 0 && st.connects == 0 {
            "a handshake started but never finished - typically a NAT that can't be hole-punched, or handshake pieces being lost"
        } else if st.connects > 0 {
            "connected to at least one peer"
        } else {
            "no handshake traffic yet"
        };
        lines.push(format!("diagnosis: {why}"));
        for l in lines {
            self.note(l);
        }
    }

    pub(super) fn leave_now(&mut self) {
        if self.left {
            return;
        }
        for slot in self.live() {
            let off = self.coming_back && self.peer(slot).caps.can_offline;
            self.send_now(slot, if off { "off" } else { "bye" });
        }
        self.left = true;
    }
}
