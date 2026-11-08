// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Finding the room's members on the BitTorrent DHT (BEP 5), over IPv4 and IPv6 (BEP 32), as a
//! read-only node (BEP 43). Each hour has its own lookup key and node id, so nothing in the DHT
//! messages links one hour's lookups to the next. No I/O here: the session hands this the DHT's
//! datagrams and sends what it makes, and the runtime looks the bootstrap servers' names up.

use crate::protocol::crypto::{DHT_INFOHASH_LEN, KEY_LEN, dht_infohash, sodium};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use zeroize::Zeroize;

pub const BOOTSTRAP: &[(&str, u16)] = &[
    ("router.bittorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
    ("router.utorrent.com", 6881),
    ("dht.libtorrent.org", 25401),
];

const MAX_CANDS: usize = 128;
const MAX_INFLIGHT: usize = 8;
const MAX_QUERIED: usize = 80;
const RANK_TOP: usize = 12;
const ANNOUNCE_TOP: usize = 8;
const LOOKUP_TIMEOUT: f64 = 15.0;
const RELOOKUP_IDLE: f64 = 30.0;
const RELOOKUP_CONNECTED: f64 = 300.0;
const BOOT_MAX: usize = 12;
const RESOLVE_BACKOFF_BASE: f64 = 5.0;
const RESOLVE_BACKOFF_MAX: f64 = 300.0;
const EPOCH: u64 = 3600;
/// Either side of the hour, the other hour's key is looked up too: clocks differ.
const EPOCH_OVERLAP: u64 = 600;
const KNOWN_MAX: usize = 32;
const KNOWN_ENOUGH: usize = 8;
const QUERY_TIMEOUT: f64 = 3.0;
const STARVED_WAIT: f64 = 5.0;
const FOUND_MAX: usize = 16;
const TOKEN_MAX: usize = 64;

pub const V4: usize = 0;
pub const V6: usize = 1;

fn family(a: &SocketAddr) -> usize {
    if a.is_ipv6() { V6 } else { V4 }
}

#[derive(Clone)]
struct Cand {
    addr: SocketAddr,
    node_id: Option<[u8; 20]>,
    queried: bool,
    token: Option<Vec<u8>>,
}

struct Inflight {
    tid: [u8; 2],
    addr: SocketAddr,
    sent_at: f64,
}

#[derive(Default)]
struct Lookup {
    active: bool,
    t0: f64,
    cands: Vec<Cand>,
    inflight: Vec<Inflight>,
    found: usize,
    found_addr: Vec<SocketAddr>,
    answered: usize,
}

#[derive(Clone)]
struct Known {
    addr: SocketAddr,
    node_id: [u8; 20],
    ok_at: f64,
}

pub struct Dht {
    key: [u8; KEY_LEN],
    my_port: u16,
    explicit_port: bool,
    want: [bool; 2],
    boot: Vec<SocketAddr>,
    resolving: bool,
    next_resolve: f64,
    resolve_tries: u32,
    node_id: [u8; 20],
    ids: [Option<(u64, [u8; 20])>; 2],
    infohash: [u8; DHT_INFOHASH_LEN],
    alt_epoch: u64,
    alt_pending: bool,
    known: [Vec<Known>; 2],
    lk: [Lookup; 2],
    next_lookup: f64,
    /// Someone is connected, so lookups can be rarer.
    pub peers_now: bool,
    out: Vec<(SocketAddr, Vec<u8>)>,
    found: Vec<SocketAddr>,
}

impl Drop for Dht {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// What a lookup round did, for the network report.
#[derive(Clone, Copy, Debug, Default)]
pub struct DhtCounts {
    pub queried: [usize; 2],
    pub answered: [usize; 2],
    pub found: usize,
    pub known: usize,
}

impl Dht {
    pub fn new(key: &[u8; KEY_LEN], my_port: u16, want_v4: bool, want_v6: bool) -> Self {
        Dht {
            key: *key,
            my_port,
            explicit_port: false,
            want: [want_v4, want_v6],
            boot: Vec::new(),
            resolving: false,
            next_resolve: 0.0,
            resolve_tries: 0,
            node_id: [0; 20],
            ids: [None, None],
            infohash: [0; 20],
            alt_epoch: 0,
            alt_pending: false,
            known: [Vec::new(), Vec::new()],
            lk: [Lookup::default(), Lookup::default()],
            next_lookup: 0.0,
            peers_now: false,
            out: Vec::new(),
            found: Vec::new(),
        }
    }

    pub fn wants(&self) -> [bool; 2] {
        self.want
    }

    pub fn set_wants(&mut self, v4: bool, v6: bool) {
        if self.want != [v4, v6] {
            self.want = [v4, v6];
            // The bootstrap list only holds the families that were wanted.
            self.boot.clear();
            self.resolving = false;
            self.next_resolve = 0.0;
            self.resolve_tries = 0;
            self.next_lookup = 0.0;
        }
    }

    /// Announce this port instead of the one nodes see (a router's mapped port), or None.
    /// The session moved to another UDP port: announced from there, looked up again at once.
    pub fn set_port(&mut self, port: u16) {
        self.my_port = port;
        self.explicit_port = false;
        self.next_lookup = 0.0;
    }

    pub fn set_announce_port(&mut self, port: Option<u16>, local: u16) {
        match port {
            Some(p) if !self.explicit_port || self.my_port != p => {
                self.explicit_port = true;
                self.my_port = p;
                self.next_lookup = 0.0;
            }
            None if self.explicit_port => {
                self.explicit_port = false;
                self.my_port = local;
            }
            _ => {}
        }
    }

    /// Whether the bootstrap servers' names need looking up now. Once this says yes, the
    /// runtime looks them up and hands the addresses to [`Dht::bootstrap_resolved`].
    pub fn take_resolve_request(&mut self, now: f64) -> bool {
        if self.resolving || !self.boot.is_empty() || now < self.next_resolve {
            return false;
        }
        let shift = self.resolve_tries.min(6);
        self.next_resolve = now + (RESOLVE_BACKOFF_BASE * f64::from(1u32 << shift)).min(RESOLVE_BACKOFF_MAX);
        self.resolve_tries += 1;
        self.resolving = true;
        true
    }

    /// The bootstrap servers' addresses, at most half the slots for each family.
    pub fn bootstrap_resolved(&mut self, addrs: &[SocketAddr]) {
        self.resolving = false;
        let mut per = [0usize; 2];
        self.boot.clear();
        for a in addrs {
            let f = family(a);
            if !self.want[f] || per[f] >= BOOT_MAX / 2 || self.boot.contains(a) || self.boot.len() >= BOOT_MAX {
                continue;
            }
            self.boot.push(*a);
            per[f] += 1;
        }
    }

    /// Datagrams to send, and addresses found for the room since last asked.
    pub fn drain(&mut self) -> (Vec<(SocketAddr, Vec<u8>)>, Vec<SocketAddr>) {
        (std::mem::take(&mut self.out), std::mem::take(&mut self.found))
    }

    pub fn looking(&self) -> bool {
        self.lk[V4].active || self.lk[V6].active
    }

    pub fn next_lookup(&self) -> f64 {
        self.next_lookup
    }

    pub fn counts(&self) -> DhtCounts {
        let q = |f: usize| self.lk[f].cands.iter().filter(|c| c.queried).count();
        DhtCounts {
            queried: [q(V4), q(V6)],
            answered: [self.lk[V4].answered, self.lk[V6].answered],
            found: self.lk[V4].found + self.lk[V6].found,
            known: self.known[V4].len() + self.known[V6].len(),
        }
    }

    fn known_add(&mut self, a: SocketAddr, id: [u8; 20], now: f64) {
        let list = &mut self.known[family(&a)];
        if let Some(k) = list.iter_mut().find(|k| k.addr == a) {
            k.node_id = id;
            k.ok_at = now;
            return;
        }
        if list.len() >= KNOWN_MAX {
            let oldest = (0..list.len())
                .min_by(|&x, &y| list[x].ok_at.total_cmp(&list[y].ok_at))
                .expect("full");
            list.remove(oldest);
        }
        list.push(Known {
            addr: a,
            node_id: id,
            ok_at: now,
        });
    }

    fn use_node_id(&mut self, epoch: u64) {
        if let Some((_, id)) = self.ids.iter().flatten().find(|(e, _)| *e == epoch) {
            self.node_id = *id;
            return;
        }
        let slot = match (&self.ids[0], &self.ids[1]) {
            (None, _) => 0,
            (_, None) => 1,
            (Some((a, _)), Some((b, _))) => usize::from(a >= b),
        };
        let id: [u8; 20] = sodium::random_array();
        self.ids[slot] = Some((epoch, id));
        self.node_id = id;
    }

    fn pick_infohash(&mut self, unix: u64) {
        let epoch = unix / EPOCH;
        let into = unix % EPOCH;
        let mut use_epoch = epoch;
        if self.alt_pending {
            use_epoch = self.alt_epoch;
            self.alt_pending = false;
        } else if into < EPOCH_OVERLAP {
            self.alt_epoch = epoch.saturating_sub(1);
            self.alt_pending = true;
        } else if into >= EPOCH - EPOCH_OVERLAP {
            self.alt_epoch = epoch + 1;
            self.alt_pending = true;
        }
        self.infohash = dht_infohash(&self.key, use_epoch);
        self.use_node_id(use_epoch);
    }

    fn start_lookup(&mut self, fam: usize, now: f64) {
        let mut lk = Lookup {
            active: true,
            t0: now,
            ..Default::default()
        };
        for k in &self.known[fam] {
            lk.cands.push(Cand {
                addr: k.addr,
                node_id: Some(k.node_id),
                queried: false,
                token: None,
            });
        }
        if self.known[fam].len() < KNOWN_ENOUGH {
            for b in self.boot.iter().filter(|b| family(b) == fam) {
                if !lk.cands.iter().any(|c| c.addr == *b) {
                    lk.cands.push(Cand {
                        addr: *b,
                        node_id: None,
                        queried: false,
                        token: None,
                    });
                }
            }
        }
        self.lk[fam] = lk;
    }

    fn can_start(&self) -> bool {
        !self.boot.is_empty() || (0..2).any(|f| self.want[f] && self.known[f].len() >= KNOWN_ENOUGH)
    }

    /// Runs the lookups. Returns true when a round has just finished (and announced).
    pub fn step(&mut self, now: f64, unix: u64) -> bool {
        if !self.looking() {
            if now >= self.next_lookup && !self.resolving && self.can_start() {
                self.pick_infohash(unix);
                for fam in 0..2 {
                    if self.want[fam] {
                        self.start_lookup(fam, now);
                    }
                }
            }
            return false;
        }
        let mut finished = false;
        for fam in 0..2 {
            if self.lk[fam].active {
                finished |= self.lookup_step(fam, now);
            }
        }
        if finished && !self.looking() {
            self.next_lookup = if self.alt_pending {
                now
            } else {
                now + if self.peers_now { RELOOKUP_CONNECTED } else { RELOOKUP_IDLE }
            };
            return true;
        }
        false
    }

    /// Up to `n` candidates, nearest the infohash first (those without an id last).
    fn ranked(&self, fam: usize, n: usize, need_token: bool) -> Vec<usize> {
        let ih = self.infohash;
        let dist = |c: &Cand| c.node_id.map(|id| std::array::from_fn::<u8, 20, _>(|i| id[i] ^ ih[i]));
        let mut idx: Vec<usize> = (0..self.lk[fam].cands.len())
            .filter(|&i| !need_token || self.lk[fam].cands[i].token.is_some())
            .collect();
        // A stable sort keeps the earlier of equals first.
        idx.sort_by(|&a, &b| match (dist(&self.lk[fam].cands[a]), dist(&self.lk[fam].cands[b])) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        idx.truncate(n);
        idx
    }

    fn lookup_step(&mut self, fam: usize, now: f64) -> bool {
        // Unanswered queries time out, and a node known before isn't started from again.
        let (timed_out, kept): (Vec<Inflight>, Vec<Inflight>) = std::mem::take(&mut self.lk[fam].inflight)
            .into_iter()
            .partition(|f| now - f.sent_at > QUERY_TIMEOUT);
        self.lk[fam].inflight = kept;
        for f in timed_out {
            let list = &mut self.known[family(&f.addr)];
            list.retain(|k| k.addr != f.addr);
        }
        let top = self.ranked(fam, RANK_TOP, false);
        let mut queried = self.lk[fam].cands.iter().filter(|c| c.queried).count();
        let mut all_top_queried = true;
        for i in top {
            if self.lk[fam].cands[i].queried {
                continue;
            }
            all_top_queried = false;
            if self.lk[fam].inflight.len() < MAX_INFLIGHT && queried < MAX_QUERIED {
                self.lk[fam].cands[i].queried = true;
                queried += 1;
                let tid: [u8; 2] = sodium::random_array();
                let addr = self.lk[fam].cands[i].addr;
                self.lk[fam].inflight.push(Inflight { tid, addr, sent_at: now });
                let msg = self.get_peers(&tid);
                self.out.push((addr, msg));
            }
        }
        let lk = &self.lk[fam];
        let starved = lk.cands.is_empty() && now - lk.t0 < STARVED_WAIT;
        if (lk.inflight.is_empty() && all_top_queried && !starved) || now - lk.t0 > LOOKUP_TIMEOUT {
            for i in self.ranked(fam, ANNOUNCE_TOP, true) {
                let c = &self.lk[fam].cands[i];
                let tid: [u8; 2] = sodium::random_array();
                let msg = self.announce(&tid, c.token.as_deref().unwrap_or_default());
                self.out.push((c.addr, msg));
            }
            self.lk[fam].active = false;
            return true;
        }
        false
    }

    fn want_field(&self) -> &'static [u8] {
        match self.want {
            [true, true] => b"4:wantl2:n42:n6e",
            [false, true] => b"4:wantl2:n6e",
            _ => b"",
        }
    }

    fn get_peers(&self, tid: &[u8; 2]) -> Vec<u8> {
        let mut b = Vec::with_capacity(160);
        b.extend_from_slice(b"d1:ad2:id20:");
        b.extend_from_slice(&self.node_id);
        b.extend_from_slice(b"9:info_hash20:");
        b.extend_from_slice(&self.infohash);
        b.extend_from_slice(self.want_field());
        b.extend_from_slice(b"e1:q9:get_peers2:roi1e1:t2:");
        b.extend_from_slice(tid);
        b.extend_from_slice(b"1:y1:qe");
        b
    }

    fn announce(&self, tid: &[u8; 2], token: &[u8]) -> Vec<u8> {
        let mut b = Vec::with_capacity(256);
        b.extend_from_slice(b"d1:ad2:id20:");
        b.extend_from_slice(&self.node_id);
        b.extend_from_slice(if self.explicit_port {
            b"12:implied_porti0e9:info_hash20:"
        } else {
            b"12:implied_porti1e9:info_hash20:"
        });
        b.extend_from_slice(&self.infohash);
        b.extend_from_slice(format!("4:porti{}e5:token{}:", self.my_port, token.len()).as_bytes());
        b.extend_from_slice(token);
        b.extend_from_slice(b"1:q13:announce_peer2:roi1e1:t2:");
        b.extend_from_slice(tid);
        b.extend_from_slice(b"1:y1:qe");
        b
    }

    fn add_nodes(&mut self, nodes: Option<&Bencode>, fam: usize) {
        let Some(Bencode::Bytes(nodes)) = nodes else { return };
        if !self.want[fam] || !self.lk[fam].active {
            return;
        }
        let iplen = if fam == V6 { 16 } else { 4 };
        for e in nodes.chunks_exact(20 + iplen + 2) {
            if fam == V6 && e[20..32] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                continue;
            }
            let Some(a) = compact(&e[20..]) else { continue };
            let lk = &mut self.lk[fam];
            let pos = match lk.cands.iter().position(|c| c.addr == a) {
                Some(p) => p,
                None if lk.cands.len() < MAX_CANDS => {
                    lk.cands.push(Cand {
                        addr: a,
                        node_id: None,
                        queried: false,
                        token: None,
                    });
                    lk.cands.len() - 1
                }
                None => continue,
            };
            if lk.cands[pos].node_id.is_none() {
                lk.cands[pos].node_id = Some(e[..20].try_into().expect("20 bytes"));
            }
        }
    }

    /// A datagram that may be a DHT message. Returns whether it was one (answer or not).
    pub fn on_packet(&mut self, data: &[u8], from: SocketAddr, now: f64) -> bool {
        if data.first() != Some(&b'd') {
            return false;
        }
        let Some(msg) = Bencode::parse(data) else { return false };
        let Some(Bencode::Bytes(y)) = msg.get(b"y") else { return false };
        if y.len() != 1 {
            return false;
        }
        if y[0] != b'r' || !self.looking() {
            return true;
        }
        let Some(Bencode::Bytes(t)) = msg.get(b"t") else { return true };
        if t.len() != 2 {
            return true;
        }
        let mut hit = None;
        for fam in 0..2 {
            if !self.lk[fam].active {
                continue;
            }
            if let Some(i) = self.lk[fam].inflight.iter().position(|f| f.tid == t[..] && f.addr == from) {
                hit = Some((fam, i));
                break;
            }
        }
        let Some((fam, slot)) = hit else { return true };
        self.lk[fam].inflight.remove(slot);
        let Some(r @ Bencode::Dict(_)) = msg.get(b"r") else { return true };
        self.lk[fam].answered += 1;
        let lk = &mut self.lk[fam];
        let pos = match lk.cands.iter().position(|c| c.addr == from) {
            Some(p) => p,
            None if lk.cands.len() < MAX_CANDS => {
                lk.cands.push(Cand {
                    addr: from,
                    node_id: None,
                    queried: true,
                    token: None,
                });
                lk.cands.len() - 1
            }
            None => return true,
        };
        lk.cands[pos].queried = true;
        if let Some(Bencode::Bytes(id)) = r.get(b"id")
            && id.len() == 20
        {
            let id: [u8; 20] = id[..].try_into().expect("20 bytes");
            if lk.cands[pos].node_id.is_none() {
                lk.cands[pos].node_id = Some(id);
            }
            self.known_add(from, id, now);
        }
        if let Some(Bencode::Bytes(token)) = r.get(b"token")
            && token.len() <= TOKEN_MAX
        {
            self.lk[fam].cands[pos].token = Some(token.to_vec());
        }
        self.add_nodes(r.get(b"nodes"), V4);
        self.add_nodes(r.get(b"nodes6"), V6);
        if let Some(Bencode::List(values)) = r.get(b"values") {
            for v in values {
                let Bencode::Bytes(v) = v else { continue };
                if v.len() != 6 && v.len() != 18 {
                    continue;
                }
                let Some(a) = compact(v) else { continue };
                let lk = &mut self.lk[fam];
                if !lk.found_addr.contains(&a) {
                    if lk.found_addr.len() < FOUND_MAX {
                        lk.found_addr.push(a);
                    }
                    lk.found += 1;
                }
                self.found.push(a);
            }
        }
        true
    }
}

/// A compact address (BEP 5, BEP 32): the IP, then the port. None for port 0.
fn compact(e: &[u8]) -> Option<SocketAddr> {
    let (ip, port) = match e.len() {
        6 => (IpAddr::V4(Ipv4Addr::new(e[0], e[1], e[2], e[3])), [e[4], e[5]]),
        18 => (IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&e[..16]).ok()?)), [e[16], e[17]]),
        _ => return None,
    };
    let port = u16::from_be_bytes(port);
    (port != 0).then(|| crate::protocol::wire::canonical(SocketAddr::new(ip, port)))
}

/// Bencode, strictly: what a DHT message can hold, no deeper than a few levels.
#[derive(Debug, PartialEq)]
pub enum Bencode<'a> {
    Int(i64),
    Bytes(&'a [u8]),
    List(Vec<Bencode<'a>>),
    Dict(Vec<(&'a [u8], Bencode<'a>)>),
}

const BENCODE_DEPTH: usize = 8;
const BENCODE_ITEMS: usize = 512;

impl<'a> Bencode<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Bencode<'a>> {
        let mut pos = 0;
        let mut items = 0;
        let v = Self::value(data, &mut pos, 0, &mut items)?;
        (pos == data.len()).then_some(v)
    }

    fn value(d: &'a [u8], pos: &mut usize, depth: usize, items: &mut usize) -> Option<Bencode<'a>> {
        *items += 1;
        if depth > BENCODE_DEPTH || *items > BENCODE_ITEMS {
            return None;
        }
        match *d.get(*pos)? {
            b'i' => {
                let end = *pos + 1 + d[*pos + 1..].iter().position(|&b| b == b'e')?;
                let s = std::str::from_utf8(&d[*pos + 1..end]).ok()?;
                *pos = end + 1;
                Some(Bencode::Int(s.parse().ok()?))
            }
            b'l' => {
                *pos += 1;
                let mut v = Vec::new();
                while *d.get(*pos)? != b'e' {
                    v.push(Self::value(d, pos, depth + 1, items)?);
                }
                *pos += 1;
                Some(Bencode::List(v))
            }
            b'd' => {
                *pos += 1;
                let mut v = Vec::new();
                while *d.get(*pos)? != b'e' {
                    let Bencode::Bytes(k) = Self::value(d, pos, depth + 1, items)? else {
                        return None;
                    };
                    let val = Self::value(d, pos, depth + 1, items)?;
                    v.push((k, val));
                }
                *pos += 1;
                Some(Bencode::Dict(v))
            }
            b'0'..=b'9' => {
                let colon = *pos + d[*pos..].iter().position(|&b| b == b':')?;
                let n: usize = std::str::from_utf8(&d[*pos..colon]).ok()?.parse().ok()?;
                let start = colon + 1;
                let end = start.checked_add(n)?;
                if end > d.len() {
                    return None;
                }
                *pos = end;
                Some(Bencode::Bytes(&d[start..end]))
            }
            _ => None,
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<&Bencode<'a>> {
        match self {
            Bencode::Dict(v) => v.iter().find(|(k, _)| *k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bencode() {
        let v = Bencode::parse(b"d1:ad2:id3:abce1:lli1ei-2ee1:y1:re").unwrap();
        assert_eq!(v.get(b"y"), Some(&Bencode::Bytes(b"r")));
        assert_eq!(v.get(b"a").unwrap().get(b"id"), Some(&Bencode::Bytes(b"abc")));
        assert_eq!(v.get(b"l"), Some(&Bencode::List(vec![Bencode::Int(1), Bencode::Int(-2)])));
        assert!(Bencode::parse(b"d1:a").is_none());
        assert!(Bencode::parse(b"5:ab").is_none());
    }

    #[test]
    fn compact_addresses() {
        assert_eq!(compact(&[1, 2, 3, 4, 0x1a, 0xe1]), Some("1.2.3.4:6881".parse().unwrap()));
        assert_eq!(compact(&[1, 2, 3, 4, 0, 0]), None);
        let mut v6 = [0u8; 18];
        v6[15] = 1;
        v6[17] = 80;
        assert_eq!(compact(&v6), Some("[::1]:80".parse().unwrap()));
    }

    #[test]
    fn a_lookup_queries_then_announces() {
        let mut d = Dht::new(&[1; 32], 4000, true, false);
        assert!(d.take_resolve_request(0.0));
        assert!(!d.take_resolve_request(0.0));
        d.bootstrap_resolved(&["10.0.0.1:6881".parse().unwrap()]);
        assert!(!d.step(0.0, 1_000_000));
        assert!(!d.step(0.0, 1_000_000));
        let (out, _) = d.drain();
        assert_eq!(out.len(), 1);
        assert!(out[0].1.windows(9).any(|w| w == b"get_peers"));
        let tid = &out[0].1[out[0].1.len() - 9..out[0].1.len() - 7];
        // The node answers with a token and one peer for the room.
        let mut reply = b"d1:rd2:id20:aaaaaaaaaaaaaaaaaaaa5:token2:tk6:valuesl6:".to_vec();
        reply.extend_from_slice(&[9, 9, 9, 9, 0x0f, 0xa0]);
        reply.extend_from_slice(b"ee1:t2:");
        reply.extend_from_slice(tid);
        reply.extend_from_slice(b"1:y1:re");
        assert!(d.on_packet(&reply, "10.0.0.1:6881".parse().unwrap(), 0.5));
        assert!(d.step(1.0, 1_000_000));
        let (out, found) = d.drain();
        assert_eq!(found, vec!["9.9.9.9:4000".parse::<SocketAddr>().unwrap()]);
        assert!(out.iter().any(|(_, m)| m.windows(13).any(|w| w == b"announce_peer")));
    }
}
