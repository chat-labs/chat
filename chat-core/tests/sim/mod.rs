// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! An in-memory network for sessions: simulated time, UDP between numbered hosts, the LAN's
//! broadcast, and a relay that delivers every member's events, with loss and links that can be
//! cut. Nothing touches a socket or a clock.

#![allow(dead_code)]

use chat_core::protocol::crypto::RoomKeys;
use chat_core::protocol::session::{Now, Request, TorStatus};
use chat_core::protocol::trust::{SharedTrust, TrustStore};
use chat_core::protocol::wire::Addr;
use chat_core::protocol::{Session, SessionConfig};
use chat_core::{Event, PeerId};
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const PORT: u16 = 4000;

pub struct Node {
    pub s: Session,
    pub ip: Ipv4Addr,
    pub events: Vec<Event>,
    /// When each event came out, in simulated seconds.
    pub event_times: Vec<f64>,
    pub trust: SharedTrust,
    /// Off the network entirely (a laptop lid shut).
    pub down: bool,
}

impl Node {
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(self.ip), PORT)
    }

    pub fn id(&self) -> PeerId {
        self.s.my_id()
    }

    pub fn messages(&self) -> Vec<&chat_core::Message> {
        self.events
            .iter()
            .filter_map(|e| if let Event::Message(m) = e { Some(m) } else { None })
            .collect()
    }

    /// When a message from someone else with this text arrived.
    pub fn arrived_at(&self, body: &str) -> Option<f64> {
        self.events
            .iter()
            .position(|e| matches!(e, Event::Message(m) if !m.mine && m.body() == body))
            .map(|i| self.event_times[i])
    }

    pub fn received(&self, body: &str) -> Option<&chat_core::Message> {
        self.messages().into_iter().find(|m| !m.mine && m.body() == body)
    }

    pub fn notices(&self) -> Vec<String> {
        self.events
            .iter()
            .filter_map(|e| {
                if let Event::Notice { text, .. } = e {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn joined(&self) -> usize {
        self.events.iter().filter(|e| matches!(e, Event::PeerJoined(_))).count()
    }
}

pub struct Net {
    pub nodes: Vec<Node>,
    pub now: f64,
    pub unix: u64,
    /// Fraction of UDP datagrams lost, 0.0 to 1.0.
    pub loss: f64,
    /// UDP between these pairs of nodes is cut (both ways).
    pub cut: HashSet<(usize, usize)>,
    /// Members on the relay; it's off when this is false.
    pub relay: bool,
    rng: u64,
    pub delivered: u64,
    pub relayed: u64,
    /// Tor: which node each target (a room service or a member's onion) reaches.
    pub tor_targets: HashMap<[u8; 16], usize>,
    /// Tor streams: (node, the id it knows the stream by) to (the node at the other end, its id).
    tor_streams: HashMap<(usize, [u8; 16]), (usize, [u8; 16])>,
    tor_status: Vec<TorStatus>,
    /// :move: the node each node moved to, which gets the keys it passes on.
    pub move_links: HashMap<usize, usize>,
}

/// A config for Tor routing: no UDP, the room found through its onion services.
pub fn tor_config(nick: &str) -> SessionConfig {
    let mut c = config(nick);
    c.mode = chat_core::RouteMode::Tor;
    c
}

pub fn config(nick: &str) -> SessionConfig {
    let mut c = SessionConfig::new("SIMROOM234", nick);
    c.mode = chat_core::RouteMode::Direct;
    c.port = PORT;
    c.dht_v4 = false;
    c.dht_v6 = false;
    c.lan = false;
    c.nostr = chat_core::NostrMode::Off;
    c.relays = 0;
    c
}

impl Net {
    pub fn new() -> Self {
        Net {
            nodes: Vec::new(),
            now: 1000.0,
            unix: 1_800_000_000,
            loss: 0.0,
            cut: HashSet::new(),
            relay: false,
            rng: 0x2545F4914F6CDD1D,
            delivered: 0,
            relayed: 0,
            tor_targets: HashMap::new(),
            tor_streams: HashMap::new(),
            tor_status: Vec::new(),
            move_links: HashMap::new(),
        }
    }

    pub fn time(&self) -> Now {
        Now {
            secs: self.now,
            unix: self.unix + (self.now - 1000.0) as u64,
        }
    }

    /// A node with this config, at 10.0.0.(n+1), sharing the room's keys (a fixed master key, to
    /// skip Argon2id) and with a trust store of its own.
    pub fn add(&mut self, cfg: SessionConfig) -> usize {
        self.add_in(cfg, [42u8; 32])
    }

    /// A node in the room with this master key: another room than `add`'s.
    pub fn add_in(&mut self, cfg: SessionConfig, master: [u8; 32]) -> usize {
        let keys = RoomKeys::from_master(&master);
        let trust = TrustStore::shared();
        let s = Session::new(cfg, keys, trust.clone(), self.time());
        let ip = Ipv4Addr::new(10, 0, 0, self.nodes.len() as u8 + 1);
        let i = self.nodes.len();
        self.nodes.push(Node {
            s,
            ip,
            events: Vec::new(),
            event_times: Vec::new(),
            trust,
            down: false,
        });
        // Its own onion service, up at once.
        let onion = chat_core::protocol::crypto::onion_address(&[i as u8 + 1; 32]);
        self.tor_targets.insert(chat_core::protocol::crypto::tor_target_id(&onion), i);
        self.tor_status.push(TorStatus {
            ready: true,
            onion: Some(onion),
            hosted_slot: None,
            busy: Vec::new(),
        });
        let st = self.tor_status[i].clone();
        self.nodes[i].s.set_tor_status(st);
        i
    }

    fn random(&mut self) -> f64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng >> 11) as f64 / (1u64 << 53) as f64
    }

    fn is_cut(&self, a: usize, b: usize) -> bool {
        self.cut.contains(&(a, b)) || self.cut.contains(&(b, a))
    }

    pub fn cut_link(&mut self, a: usize, b: usize) {
        self.cut.insert((a, b));
    }

    pub fn heal_link(&mut self, a: usize, b: usize) {
        self.cut.remove(&(a, b));
        self.cut.remove(&(b, a));
    }

    fn node_at(&self, sa: SocketAddr) -> Option<usize> {
        self.nodes.iter().position(|n| n.addr() == sa)
    }

    /// One step of `dt` seconds: every node ticks, and everything sent is delivered.
    pub fn step(&mut self, dt: f64) {
        self.now += dt;
        let now = self.time();
        for i in 0..self.nodes.len() {
            self.nodes[i].s.tick(now);
        }
        // Deliver until nothing more is sent this step (answers can come at once).
        for _ in 0..8 {
            let mut any = false;
            for i in 0..self.nodes.len() {
                while let Some(r) = self.nodes[i].s.poll_request() {
                    match r {
                        Request::ResolveDhtBootstrap { .. } => self.nodes[i].s.dht_bootstrap(&[]),
                        Request::TorHostRoom { slot } => {
                            let keys = self.nodes[i].s.tor_room_keys();
                            let taken = |s: usize| {
                                let id =
                                    chat_core::protocol::crypto::tor_target_id(&chat_core::protocol::crypto::onion_address(&keys[s].1));
                                self.tor_targets.contains_key(&id)
                            };
                            let slot = slot.map(usize::from).unwrap_or_else(|| (1..6).find(|&s| !taken(s)).unwrap_or(1));
                            let id = chat_core::protocol::crypto::tor_target_id(&chat_core::protocol::crypto::onion_address(&keys[slot].1));
                            self.tor_targets.insert(id, i);
                            self.tor_status[i].hosted_slot = Some(slot as u8);
                            let st = self.tor_status[i].clone();
                            self.nodes[i].s.set_tor_status(st);
                        }
                        Request::MoveKey { public, nick } => {
                            if let Some(&j) = self.move_links.get(&i) {
                                self.nodes[j].s.came_with(public, &nick);
                            }
                        }
                        Request::TorRepublishRoom | Request::TorTarget { .. } => {}
                    }
                }
                while let Some(t) = self.nodes[i].s.poll_transmit() {
                    any = true;
                    self.deliver(i, t.to, t.data, t.lan, now);
                }
            }
            if !any {
                break;
            }
        }
        let t = self.now;
        for n in &mut self.nodes {
            while let Some(e) = n.s.poll_event() {
                n.events.push(e);
                n.event_times.push(t);
            }
        }
    }

    fn deliver(&mut self, from: usize, to: Addr, data: Vec<u8>, lan: bool, now: Now) {
        if self.nodes[from].down {
            return;
        }
        match to {
            Addr::Udp(sa) => {
                let src_port = if lan { self.nodes[from].s.lan_port() } else { PORT };
                let src = SocketAddr::new(IpAddr::V4(self.nodes[from].ip), src_port);
                let targets: Vec<usize> = if sa.ip() == IpAddr::V4(Ipv4Addr::BROADCAST) {
                    (0..self.nodes.len()).filter(|&j| j != from).collect()
                } else if sa.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) {
                    Vec::new()
                } else {
                    // The LAN socket's port reaches the same host's session in this model.
                    self.nodes
                        .iter()
                        .position(|n| {
                            n.ip == match sa.ip() {
                                IpAddr::V4(v4) => v4,
                                _ => Ipv4Addr::UNSPECIFIED,
                            }
                        })
                        .into_iter()
                        .collect()
                };
                let _ = self.node_at(sa);
                for j in targets {
                    if self.nodes[j].down || self.is_cut(from, j) || (self.loss > 0.0 && self.random() < self.loss) {
                        continue;
                    }
                    self.delivered += 1;
                    self.nodes[j].s.handle_udp(src, &data, now);
                }
            }
            Addr::Relay(id) => {
                if !self.relay {
                    return;
                }
                let sender = self.nodes[from].id();
                for j in 0..self.nodes.len() {
                    if j == from || self.nodes[j].down || (id != PeerId::EVERYONE && self.nodes[j].id() != id) {
                        continue;
                    }
                    self.relayed += 1;
                    self.nodes[j].s.handle_relayed(Addr::Relay(sender), &data, now);
                }
            }
            Addr::Tor(id) => {
                // An open stream, or a new one to the target's node.
                let (to, their_id) = match self.tor_streams.get(&(from, id)) {
                    Some(&(n, their)) => (n, their),
                    None => {
                        let Some(&n) = self.tor_targets.get(&id) else { return };
                        if n == from {
                            return;
                        }
                        let their: [u8; 16] = chat_core::protocol::crypto::sodium::random_array();
                        self.tor_streams.insert((from, id), (n, their));
                        self.tor_streams.insert((n, their), (from, id));
                        (n, their)
                    }
                };
                if self.nodes[to].down || self.is_cut(from, to) {
                    return;
                }
                self.delivered += 1;
                self.nodes[to].s.handle_relayed(Addr::Tor(their_id), &data, now);
            }
        }
    }

    pub fn run(&mut self, seconds: f64) {
        let steps = (seconds / 0.05).ceil() as usize;
        for _ in 0..steps {
            self.step(0.05);
        }
    }

    /// Runs until the condition holds, or panics after `limit` simulated seconds.
    pub fn run_until(&mut self, limit: f64, what: &str, mut cond: impl FnMut(&Net) -> bool) {
        let end = self.now + limit;
        while self.now < end {
            self.step(0.05);
            if cond(self) {
                return;
            }
        }
        panic!("{what}: not within {limit} simulated seconds");
    }

    pub fn connected(&self, a: usize, b: usize) -> bool {
        let id = self.nodes[b].id();
        self.nodes[a].s.peers().iter().any(|p| p.id == id && p.announced)
    }

    pub fn all_connected(&self) -> bool {
        (0..self.nodes.len()).all(|a| (0..self.nodes.len()).all(|b| a == b || self.connected(a, b)))
    }

    pub fn send(&mut self, i: usize, cmd: chat_core::Command) -> Result<chat_core::Outcome, chat_core::CommandError> {
        let now = self.time();
        self.nodes[i].s.command(cmd, now)
    }
}
