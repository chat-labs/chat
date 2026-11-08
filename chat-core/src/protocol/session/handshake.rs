// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Finding peers and connecting to them: candidates, the handshake (hi, ck, hi2, kx), "k",
//! peer exchange, and checking a peer's build.
//!
//! A hi carries our id, X25519 key and ML-KEM key. A hi that would change anything must answer
//! a cookie first (ck, hi2), so a recorded one can't be replayed from elsewhere. Both sides
//! then derive a partial key from X25519; the one with the lower id encapsulates to the other's
//! ML-KEM key (kx), and both seal everything after on chains from the two secrets together.

use super::peer::{CodeOk, Peer};
use super::*;
use crate::protocol::api::BuildState;
use crate::protocol::crypto::{self, Ratchet, SESSION_PAD_TARGET, kem, minisign};
use crate::protocol::hex;
use crate::protocol::record::{fields, str_field};

pub(super) const PX_MAX_PEERS: usize = 24;
pub(super) const PX_READ_MAX: usize = 12;
/// A peer that hasn't sent our new keys back yet gets our hi again this often.
pub(super) const REHELLO_EVERY: f64 = 20.0;
/// Old chains are kept this long after a re-handshake, while its pieces go through the slots.
pub(super) const REKEY_OVERLAP: f64 = 90.0;
const RK_GRACE: f64 = 10.0;
const RK_WARN_EVERY: f64 = 30.0;

/// 0.3.0 sent "v" before binaries carried their list: its binaries' published hashes.
const LISTLESS_RELEASES: &[(&str, [&str; 2])] = &[(
    "0.3.0",
    [
        "aa35cb3847b48a957522241dc21462ac1ad2d73da5f439a6d8c348791fdbe839",
        "f18f1d9b3f07f5f811c0a6a6afcb536f2eef28a2aa96b5b1a8f8990b02c86933",
    ],
)];

/// A version as a peer may give it: short, and nothing a terminal or a URL treats specially.
pub(super) fn version_ok(v: &str) -> bool {
    !v.is_empty() && v.len() <= 15 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

impl Session {
    pub(super) fn refresh_hi(&mut self) {
        self.hi_msg = format!(
            "hi\t{}\t{}\t{}",
            self.my_idhex,
            hex::encode(&self.x.public),
            hex::encode(self.kem.public())
        );
    }

    pub(super) fn we_initiate(&self, p: &Peer) -> bool {
        self.my_id < p.id
    }

    /// One of our own addresses, or one a peer is at: not worth a hi.
    pub(super) fn known_addr(&self, a: Addr) -> bool {
        self.self_addrs.contains(&a) || self.peers.iter().flatten().any(|p| p.addr == a)
    }

    pub(super) fn add_candidate(&mut self, a: Addr) {
        if matches!(a, Addr::Udp(sa) if sa.port() == 0) || self.known_addr(a) {
            return;
        }
        if self.cands.iter().any(|c| c.addr == a) {
            return;
        }
        if let Addr::Udp(sa) = a {
            let same_host = self
                .cands
                .iter()
                .filter(|c| matches!(c.addr, Addr::Udp(b) if b.ip() == sa.ip()))
                .count();
            if same_host >= CAND_PER_HOST {
                return;
            }
        }
        if self.cands.len() < MAX_CANDS {
            self.cands.push(Cand {
                addr: a,
                tries: 0,
                next_try: 0.0,
            });
        }
    }

    /// Already reached at this address, or (relays) under this id.
    pub(super) fn candidate_reached(&self, a: Addr) -> bool {
        self.peers
            .iter()
            .flatten()
            .any(|p| p.ok && (p.addr == a || matches!(a, Addr::Relay(id) if id.0 == p.id)))
    }

    /// Our own hi came back from this address: it's ours, and never a candidate.
    fn note_self_addr(&mut self, a: Addr) {
        if a.is_udp() && !self.self_addrs.contains(&a) && self.self_addrs.len() < MAX_SELF_ADDRS {
            self.self_addrs.push(a);
        }
    }

    pub(super) fn send_kx(&mut self, slot: usize, to: Addr) {
        let kx = format!("kx\t{}\t{}", self.my_idhex, hex::encode(&self.peer(slot).kem_ct[..]));
        self.send_room(&kx, to, false);
    }

    fn k_record(&self, slot: usize) -> String {
        let p = self.peer(slot);
        let (idtype, idpub, sig) = match &self.identity {
            Some((kind, kp)) => {
                let (mine, theirs) = p.signed_pubs();
                let sig = kp.sign_session(&mine, &self.my_id, &theirs, &p.id);
                (kind.wire(), hex::encode(&kp.public), hex::encode(&sig))
            }
            None => (0, String::new(), String::new()),
        };
        // After the history flag, what this build reads that older ones may not: "r" announces
        // rekeys, "b" several records a frame, "l" long messages, "p" direct messages, "q"
        // replies, "o" going offline, "m" moving rooms, "t" keeps to message timers (then ours).
        format!(
            "k\t{}\t{}\t{}rblmpqot{}\t{}\t{}\t{}",
            self.nick,
            self.colour.hex(),
            u8::from(self.persist),
            self.timer,
            idtype,
            idpub,
            sig
        )
    }

    pub(super) fn send_k_now(&mut self, slot: usize) {
        // In a room we moved to, "mp" goes ahead of "k", so it's read before the join is
        // announced (which would ask to compare codes).
        if let Some(mp) = self.move_proof(slot) {
            self.send_peer(slot, &mp);
        }
        let k = self.k_record(slot);
        self.send_peer(slot, &k);
        if let Some(v) = self.v_record(slot) {
            self.send_peer(slot, &v);
        }
    }

    /// "v": our version, our executable's hash keyed to this peer, and our release's signed list
    /// of binaries (empty for a build without one), which the peer checks the hash against.
    fn v_record(&self, slot: usize) -> Option<String> {
        let b = self.build.as_ref()?;
        let proof = crypto::build_proof(&b.hash, &self.my_id, &self.peer(slot).id);
        Some(format!("v\t{}\t{}\t{}\t{}", b.version, hex::encode(&proof), b.list, b.list_sig))
    }

    /// A hi from a peer, cookie checked or changing nothing: the peer made or updated, and its
    /// chains if we're the initiator. Returns its slot, and whether the handshake is new.
    fn do_hello(&mut self, id: [u8; 16], addr: Addr, their_pub: [u8; 32], their_kem: &[u8; kem::PUB_LEN]) -> Option<(usize, bool)> {
        let now = self.now;
        let existing = self.find_peer(&id);
        if let Some(slot) = existing {
            let keygen = self.keygen;
            let p = self.peer_mut(slot);
            if p.public == their_pub && p.keygen == keygen {
                if !p.ok {
                    p.addr = addr;
                }
                return Some((slot, false));
            }
            // A room member in the middle could swap in its own key at a rekey. A peer that
            // announces rekeys sent its new key over the current session, which the middle can't
            // change, so a key it never announced is refused, and after a grace period warned about.
            if p.ok && p.caps.announces_rekey && p.public != their_pub && p.next_pub != Some(their_pub) {
                if p.rk_refused_since == 0.0 {
                    p.rk_refused_since = now;
                }
                if now - p.rk_refused_since > RK_GRACE && now >= p.next_rk_warn {
                    p.next_rk_warn = now + RK_WARN_EVERY;
                    let name = self.peer_name(slot);
                    self.warn(format!(
                        "warning: a new key for {name} arrived that {name} never announced - refused. Someone may be \
                         intercepting; if it continues, compare verify codes over another channel"
                    ));
                }
                return None;
            }
        } else if self.pending_peer_count() >= MAX_PENDING_PEERS || self.live_count() >= MAX_PEERS {
            return None;
        }
        let slot = existing.or_else(|| self.peers.iter().position(Option::is_none))?;
        let shared = self.x.shared(&their_pub)?;
        let partial = crypto::session_prk_partial(&self.keys.master, &shared, &self.x.public, &self.my_id, &their_pub, &id);

        let carry = self.peers[slot].take();
        let mut p = Peer::new(id, addr, now);
        p.next_hello = now + Self::retry_delay(0);
        p.keygen = self.keygen;
        p.public = their_pub;
        p.my_pub = self.x.public;
        let mut early_kx = None;
        if let Some(mut c) = carry {
            // The same peer keeps what it had, and what waits to go to it: a rekey loses nothing.
            p.sendq = std::mem::take(&mut c.sendq);
            p.roomq = std::mem::take(&mut c.roomq);
            p.pending = std::mem::take(&mut c.pending);
            if c.ok {
                // The chains kept for the overlap are the last ones known to work. Usually those
                // are the current ones; but when the handshake before this one never got a frame
                // through (rekeys that overlapped), they're the ones from before it, and its own
                // unconfirmed chains would leave nothing either side can read.
                let keep_old = !c.chain_confirmed && c.old_until > 0.0 && c.old_recv.started();
                if keep_old {
                    p.prev_keys = c.prev_keys;
                    p.old_send = c.old_send.clone();
                    p.old_recv = c.old_recv.clone();
                } else {
                    p.prev_keys = Some((c.public, c.my_pub));
                    p.old_send = c.send.clone();
                    p.old_recv = c.recv.clone();
                }
                p.old_until = now + REKEY_OVERLAP;
                p.nick = std::mem::take(&mut c.nick);
                p.skel = std::mem::take(&mut c.skel);
                p.colour = c.colour;
                p.persists = c.persists;
                p.timer = c.timer;
                p.ok = true;
                p.ok_since = c.ok_since;
                p.k_seen = c.k_seen;
                p.announced = c.announced;
                p.ident = c.ident.take();
                p.vfy = c.vfy;
                p.vfy_set = c.vfy_set;
                // The same "v" comes again after the rekey, and isn't warned about twice.
                p.build_version = c.build_version.take();
                p.build_state = c.build_state;
                p.build_warn = c.build_warn;
                p.next_cover = c.next_cover;
                p.caps = c.caps;
                // A file it's fetching from us continues from where it was.
                p.serve = c.serve;
                p.mv = std::mem::take(&mut c.mv);
                // The same peer, as the rk it announced proves, so a compared code stays compared.
                p.code_ok = c.code_ok;
                p.trust = c.trust;
                p.next_rehello = c.next_rehello;
                if c.kx_early {
                    early_kx = Some(c.kem_ct.clone());
                }
            }
        }
        self.peers[slot] = Some(p);

        if self.my_id < id {
            let Some((ct, ss)) = kem::encapsulate(their_kem) else {
                self.forget_peer(slot);
                return None;
            };
            let prk = crypto::session_prk(&partial, &ss);
            let p = self.peer_mut(slot);
            p.initiator = true;
            p.kem_ct = ct;
            p.send = Ratchet::seed(&prk, &p.my_pub);
            p.recv = Ratchet::seed(&prk, &their_pub);
            if !p.vfy_set {
                p.vfy = crypto::verify_code(&prk);
                p.vfy_set = true;
            }
        } else {
            self.peer_mut(slot).prk_partial = partial;
            if let Some(ct) = early_kx {
                self.finish_kem_decap(slot, &ct);
            }
        }
        Some((slot, true))
    }

    /// The responder's side of the kx: its chains from the ML-KEM secret.
    fn finish_kem_decap(&mut self, slot: usize, ct: &[u8; kem::CT_LEN]) {
        if self.we_initiate(self.peer(slot)) {
            return;
        }
        let p = self.peer_mut(slot);
        if p.chain_confirmed {
            // Its kx for a re-handshake can come while ours still waits for a cookie.
            if p.kem_ct[..] != ct[..] {
                p.kem_ct.copy_from_slice(ct);
                p.kx_early = true;
            }
            return;
        }
        // A recorded kx can be replayed, so a different one may replace it until the peer's
        // frames show which chains are right.
        if p.send.started() && p.kem_ct[..] == ct[..] {
            return;
        }
        let Some(ss) = self.kem.decapsulate(ct) else { return };
        let my_pub = self.x.public;
        let p = self.peer_mut(slot);
        p.kem_ct.copy_from_slice(ct);
        let prk = crypto::session_prk(&p.prk_partial, &ss);
        p.send = Ratchet::seed(&prk, &my_pub);
        p.recv = Ratchet::seed(&prk, &p.public);
        // vfy_set waits for the first frame that opens on these chains.
        if !p.vfy_set {
            p.vfy = crypto::verify_code(&prk);
        }
        self.send_k_now(slot);
    }

    fn connect_peer(&mut self, id: [u8; 16], addr: Addr, their_pub: [u8; 32], their_kem: &[u8; kem::PUB_LEN]) {
        let Some((slot, fresh)) = self.do_hello(id, addr, their_pub, their_kem) else {
            return;
        };
        if fresh {
            let hi = self.hi_msg.clone();
            self.send_room(&hi, addr, false);
        }
        let p = self.peer(slot);
        if p.send.started() {
            // The kx goes again until the peer's frames show it arrived: the first can be lost,
            // or reach it before its side of a re-handshake is ready.
            if self.we_initiate(p) && (fresh || !p.chain_confirmed) {
                let to = p.addr;
                self.send_kx(slot, to);
            }
            self.send_k_now(slot);
        }
    }

    /// A connected peer's hi came over a better path than the one we use. A hi proves nothing,
    /// so instead a session frame goes back that way: once the peer opens it, the path is proven
    /// on its side, and its frames then move us too.
    fn probe_path(&mut self, slot: usize, addr: Addr) {
        let p = self.peer_mut(slot);
        if !p.ok || addr.rank() <= p.addr.rank() {
            return;
        }
        if let Some(frame) = p.send_chain().seal_next(b"nop", SESSION_PAD_TARGET) {
            self.xmit(frame, addr, false);
        }
    }

    /// How to reach a peer, for "px": its UDP address, or through Tor its onion. Peers only
    /// reached through the relays have none, since the relays already connect them.
    fn px_entry(&self, slot: usize) -> Option<String> {
        let p = self.peer(slot);
        match (self.mode, p.addr) {
            (RouteMode::Tor, _) => p.onion.as_ref().map(|o| format!("{o}.onion")),
            (RouteMode::Direct, Addr::Udp(sa)) => Some(sa.to_string()),
            _ => None,
        }
    }

    /// Through Tor, tells a peer our onion, which it passes on in "px".
    pub(super) fn send_onion(&mut self, slot: usize) {
        if let Some(onion) = self.tor.status.onion.clone() {
            self.send_peer(slot, &format!("ta\t{onion}"));
        }
    }

    /// A new peer hears where everyone is, and everyone where it is.
    pub(super) fn introduce(&mut self, newp: usize) {
        let mut list = String::new();
        let mut total = 0;
        let mut lists = Vec::new();
        for slot in self.live() {
            if slot == newp || total >= PX_MAX_PEERS {
                continue;
            }
            let Some(entry) = self.px_entry(slot) else { continue };
            let need = entry.len() + usize::from(!list.is_empty());
            if list.len() + need + 4 > send::RECORD_MAX {
                lists.push(std::mem::take(&mut list));
            }
            if !list.is_empty() {
                list.push(',');
            }
            list.push_str(&entry);
            total += 1;
        }
        if !list.is_empty() {
            lists.push(list);
        }
        for l in lists {
            self.send_peer(newp, &format!("px\t{l}"));
        }
        let Some(entry) = self.px_entry(newp) else { return };
        for slot in self.live() {
            if slot != newp {
                self.send_peer(slot, &format!("px\t{entry}"));
            }
        }
    }

    /// "px": other members' addresses to try: onions through Tor, otherwise numeric IP addresses
    /// only (a name here would have us look up whatever a peer sends, and an onion would mean
    /// nothing to UDP).
    pub(super) fn on_px(&mut self, list: &[u8]) {
        let Ok(list) = std::str::from_utf8(list) else { return };
        for item in list.split(',').take(PX_READ_MAX) {
            match (self.mode, item.strip_suffix(".onion")) {
                (RouteMode::Tor, Some(onion)) => {
                    if crypto::onion_key(onion).is_none() || self.tor.status.onion.as_deref() == Some(onion) {
                        continue;
                    }
                    let id = crypto::tor_target_id(onion);
                    self.requests.push_back(Request::TorTarget {
                        id,
                        onion: onion.to_string(),
                    });
                    self.add_candidate(Addr::Tor(id));
                }
                (RouteMode::Direct, None) => {
                    if let Ok(sa) = item.parse::<SocketAddr>() {
                        self.add_candidate(Addr::udp(sa));
                    }
                }
                _ => {}
            }
        }
    }

    /// Checks the build a peer's "v" names: its hash against the release's signed list, and
    /// warns about one that isn't a release binary (once its join is announced).
    pub(super) fn check_build(&mut self, slot: usize, version: &str, proof: &[u8; 32], list: Option<(&str, &str)>) {
        let hashes: Vec<[u8; 32]> = match list {
            Some((list, sig)) => signed_list(version, list, sig).unwrap_or_default(),
            None => LISTLESS_RELEASES
                .iter()
                .filter(|(v, _)| *v == version)
                .flat_map(|(_, h)| h.iter().filter_map(|x| hex::decode_array::<32>(x)))
                .collect(),
        };
        let my_id = self.my_id;
        let p = self.peer_mut(slot);
        let again = p.build_state == BuildState::Modified && p.build_version.as_deref() == Some(version);
        p.build_version = Some(version.to_string());
        let official = hashes.iter().any(|h| sodium::ct_eq(&crypto::build_proof(h, &p.id, &my_id), proof));
        p.build_state = if official { BuildState::Official } else { BuildState::Modified };
        if official {
            p.build_warn = false;
        } else if !again {
            p.build_warn = true;
        }
        self.tell_build(slot);
    }

    pub(super) fn tell_build(&mut self, slot: usize) {
        let p = self.peer(slot);
        if !p.build_warn || !p.announced {
            return;
        }
        let version = p.build_version.clone().unwrap_or_default();
        self.peer_mut(slot).build_warn = false;
        let name = self.peer_name(slot);
        self.note(format!(
            "{name} runs a modified client - it says v{version}, but isn't one of that release's binaries"
        ));
    }

    /// A record sealed with the room key: the handshake, and the beacons.
    pub(super) fn on_room(&mut self, plain: &[u8], addr: Addr) {
        let f = fields(plain);
        let n = f.len();
        let name = f[0];
        let idhex_ok = |i: usize| f.get(i).is_some_and(|x| x.len() == 32);
        if name == b"hi" && n == 4 && idhex_ok(1) && f[2].len() == 64 && f[3].len() == kem::PUB_LEN * 2 {
            if f[1] == self.my_idhex.as_bytes() {
                self.note_self_addr(addr);
                self.cands.retain(|c| c.addr != addr);
                return;
            }
            let (Some(id), Some(pubk), Some(kemk)) = (
                str_field(&f, 1).and_then(hex::decode_array::<16>),
                str_field(&f, 2).and_then(hex::decode_array::<32>),
                str_field(&f, 3).and_then(hex::decode_array::<{ kem::PUB_LEN }>),
            ) else {
                return;
            };
            self.st.hi += 1;
            let existing = self.find_peer(&id);
            self.net_detail(|| {
                format!(
                    "hi from {} ({})",
                    where_str(addr, Some(&id)),
                    if existing.is_some() { "known" } else { "new" }
                )
            });
            // Anyone who recorded a hi can replay it from anywhere: only one that changes nothing
            // is taken without a cookie.
            let trusted = existing.is_some_and(|s| {
                let p = self.peer(s);
                p.keygen == self.keygen && p.public == pubk && (p.ok || p.addr == addr)
            });
            if trusted {
                self.connect_peer(id, addr, pubk, &kemk);
                if let Some(slot) = self.find_peer(&id) {
                    self.probe_path(slot, addr);
                }
            } else if self.ck.take(self.now, CK_RATE, CK_BURST) {
                let cookie = crypto::cookie(&self.cookie_secret, &addr.to_string(), &id, &pubk);
                let msg = format!("ck\t{}\t{}", hex::encode(&id), hex::encode(&cookie));
                self.send_room(&msg, addr, false);
                self.net_detail(|| format!("cookie challenge to {}", where_str(addr, Some(&id))));
            }
        } else if name == b"ck" && n == 3 && f[1] == self.my_idhex.as_bytes() && f[2].len() == 32 && f[2].iter().all(u8::is_ascii_hexdigit)
        {
            self.st.ck += 1;
            self.net_detail(|| format!("cookie challenge from {} - answering with hi2", where_str(addr, None)));
            let cookie = String::from_utf8_lossy(f[2]).into_owned();
            let msg = format!(
                "hi2\t{}\t{}\t{}\t{cookie}",
                self.my_idhex,
                hex::encode(&self.x.public),
                hex::encode(self.kem.public())
            );
            self.send_room(&msg, addr, false);
        } else if name == b"hi2" && n == 5 && idhex_ok(1) && f[2].len() == 64 && f[3].len() == kem::PUB_LEN * 2 && f[4].len() == 32 {
            if f[1] == self.my_idhex.as_bytes() {
                self.note_self_addr(addr);
                return;
            }
            let (Some(id), Some(pubk), Some(kemk), Some(given)) = (
                str_field(&f, 1).and_then(hex::decode_array::<16>),
                str_field(&f, 2).and_then(hex::decode_array::<32>),
                str_field(&f, 3).and_then(hex::decode_array::<{ kem::PUB_LEN }>),
                str_field(&f, 4).and_then(hex::decode_array::<16>),
            ) else {
                return;
            };
            let a = addr.to_string();
            self.st.hi2 += 1;
            let ok = [Some(self.cookie_secret), self.prev_cookie_secret]
                .into_iter()
                .flatten()
                .any(|secret| sodium::ct_eq(&given, &crypto::cookie(&secret, &a, &id, &pubk)));
            self.net_detail(|| {
                format!(
                    "hi2 from {} - cookie {}",
                    where_str(addr, Some(&id)),
                    if ok { "ok" } else { "MISMATCH" }
                )
            });
            if ok {
                self.connect_peer(id, addr, pubk, &kemk);
            } else {
                self.st.hi2_bad += 1;
            }
        } else if name == b"kx" && n == 3 && idhex_ok(1) && f[2].len() == kem::CT_LEN * 2 {
            let (Some(id), Some(ct)) = (
                str_field(&f, 1).and_then(hex::decode_array::<16>),
                str_field(&f, 2).and_then(hex::decode_array::<{ kem::CT_LEN }>),
            ) else {
                return;
            };
            self.st.kx += 1;
            let slot = self.find_peer(&id);
            self.net_detail(|| {
                format!(
                    "kx from {}{}",
                    where_str(addr, Some(&id)),
                    if slot.is_some() { "" } else { " (unknown peer, ignored)" }
                )
            });
            if let Some(slot) = slot {
                self.finish_kem_decap(slot, &ct);
            }
        } else if name == b"nb" && n == 2 && matches!(addr, Addr::Relay(_)) && idhex_ok(1) && f[1] != self.my_idhex.as_bytes() {
            // A member announcing itself on the relays. One we already hear from directly needs
            // nothing; anyone else gets a hi through the relays.
            let Some(id) = str_field(&f, 1).and_then(hex::decode_array::<16>) else {
                return;
            };
            if let Some(slot) = self.find_peer(&id) {
                let p = self.peer(slot);
                if p.ok && self.now - p.seen < tick::UDP_STALE {
                    return;
                }
            }
            self.add_candidate(Addr::Relay(PeerId(id)));
        } else if name == b"lan" && n == 3 && f[1] != self.my_idhex.as_bytes() {
            // Only a real broadcast shows where someone is on the LAN.
            let Addr::Udp(sa) = addr else { return };
            self.st.lan += 1;
            let digits: String = String::from_utf8_lossy(f[2]).chars().take_while(char::is_ascii_digit).collect();
            if let Ok(port) = digits.parse::<u16>()
                && port > 0
            {
                let a = Addr::Udp(SocketAddr::new(sa.ip(), port));
                self.add_candidate(a);
                self.net_detail(|| format!("lan: beacon from {a} - trying it"));
            }
        }
    }

    pub(super) fn code_ok_note(&self, slot: usize) -> Option<String> {
        let p = self.peer(slot);
        if p.code_ok != CodeOk::NotCompared {
            return None;
        }
        let name = self.peer_name(slot);
        let words = crate::protocol::names::bytewords(&p.vfy);
        let code = hex::groups(&p.vfy);
        // The room's password only proves someone is a member, and any member could sit between
        // two others. The code only matches on both ends if nobody is in the middle.
        Some(if self.verify_required {
            format!(
                "compare this code with {name} over another channel (in person, a call): {words} (in hex {code}) - \
                 until you confirm it matches, nothing you send reaches them"
            )
        } else {
            format!("verify code with {name}: {words} (in hex {code}) - compare it over another channel")
        })
    }
}

/// The hashes in a release's list, if the release key (or its backup) signed it for this version.
fn signed_list(version: &str, list: &str, sig: &str) -> Option<Vec<[u8; 32]>> {
    let mut content = format!("chat v{version}\n");
    let mut hashes = Vec::new();
    for item in list.split(',') {
        // Lowercase only, as sha256sum writes it, so the signed text has one spelling.
        if hashes.len() == 3 {
            return None;
        }
        hashes.push(hex::decode_array::<32>(item)?);
        content.push_str(item);
        content.push('\n');
    }
    if hashes.is_empty() {
        return None;
    }
    let keys = [minisign::RELEASE_KEY, minisign::RELEASE_BACKUP_KEY];
    keys.iter()
        .filter_map(|k| minisign::PublicKey::from_base64(k))
        .any(|k| k.verify(content.as_bytes(), sig))
        .then_some(hashes)
}

/// Where a packet came from or went, for the network log.
pub(super) fn where_str(a: Addr, id: Option<&[u8; 16]>) -> String {
    let short = |id: &[u8; 16]| hex::encode(&id[..4]);
    match (a, id) {
        (Addr::Relay(rid), _) => format!("{} over the relays", short(id.unwrap_or(&rid.0))),
        (Addr::Tor(t), None) => format!("Tor stream {}", short(&t)),
        (Addr::Tor(_), Some(id)) => format!("{} over Tor", short(id)),
        (Addr::Udp(sa), Some(id)) => format!("{} at {sa}", short(id)),
        (Addr::Udp(sa), None) => sa.to_string(),
    }
}
