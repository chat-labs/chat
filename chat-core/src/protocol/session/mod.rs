// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! A session: one member in one room, from the first hello to messages, and the protocol's
//! timers. No I/O: see the crate's documentation for how it's driven.

mod commands;
mod files;
mod handshake;
mod messages;
mod moving;
mod peer;
mod receive;
mod send;
mod tick;

use crate::protocol::api::*;
use crate::protocol::crypto::identity::{IdentityKeypair, IdentityKind};
use crate::protocol::crypto::kem::KemKeypair;
use crate::protocol::crypto::{RoomKeys, X25519Keypair, sodium};
use crate::protocol::dht::Dht;
use crate::protocol::names::Colour;
use crate::protocol::trust::SharedTrust;
use crate::protocol::wire::{Addr, Reassembly};
pub use files::OwnFile;
pub use moving::MoveTo;
use peer::Peer;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;

pub const MAX_PEERS: usize = 50;
pub const MAX_PENDING_PEERS: usize = 64;
const SLOTS: usize = MAX_PEERS + MAX_PENDING_PEERS;
pub const MAX_TEXT: usize = 880;

const MAX_CANDS: usize = 64;
const CAND_MAX_TRIES: u32 = 12;
/// Candidates come unchecked (from the DHT and other peers), and a hello is 2.6 KB: a few per
/// host and a rate limit stop chat being used as a traffic reflector.
const CAND_PER_HOST: usize = 4;
const PROBE_RATE: f64 = 4.0;
const PROBE_BURST: f64 = 16.0;
/// A cookie answer is as big as the hello it answers, and a hello can be replayed from a forged
/// address, so they're rate limited too.
const CK_RATE: f64 = 8.0;
const CK_BURST: f64 = 32.0;
/// A session frame from an unknown address is tried against every peer's chain: rare for real
/// (a peer that moved), so junk of the right size can't use up the CPU.
const ROAM_RATE: f64 = 50.0;
const ROAM_BURST: f64 = 100.0;
/// Timers wait up to this much longer, at random, so they don't line up between peers.
const JITTER: f64 = 0.25;
const SEEN_MIDS: usize = 2048;
const GONE_MAX: usize = 16;
const IGNORED_MAX: usize = 64;
const MAX_SELF_ADDRS: usize = 8;

/// When to send something now: on the protocol's clock (seconds, any origin, never going back)
/// and the wall clock (Unix seconds, for the DHT's and relays' epochs).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Now {
    pub secs: f64,
    pub unix: u64,
}

/// What a session needs to start. The room's keys come separately ([`RoomKeys::derive`]), since
/// deriving them takes seconds and 512 MiB, which a runtime does off its event loop.
#[derive(Clone)]
pub struct SessionConfig {
    pub room: String,
    pub nick: String,
    pub colour: Option<Colour>,
    /// We made the room: it's open at once, instead of when someone answers.
    pub created: bool,
    /// Nothing goes to a peer until its verify code was compared.
    pub verify_required: bool,
    /// Tell peers we keep a history of the room.
    pub keeps_history: bool,
    /// A message timer to ask for, in seconds (0: none).
    pub timer: u32,
    pub identity: Option<(IdentityKind, IdentityKeypair)>,
    /// Kept to come back to: leaving says "off", not "bye".
    pub coming_back: bool,
    pub net_log: NetLog,
    /// Tor (the default) or direct.
    pub mode: RouteMode,
    /// The UDP port the runtime bound, which beacons and the DHT announce (direct only).
    pub port: u16,
    pub lan: bool,
    pub dht_v4: bool,
    pub dht_v6: bool,
    pub nostr: NostrMode,
    /// How many relays the runtime has, for the network status.
    pub relays: usize,
    /// Peers to reach straight away.
    pub static_peers: Vec<SocketAddr>,
    /// Seconds between rekeys (300, the protocol's; tests shorten it).
    pub rekey_interval: f64,
    /// Files bigger than this need "anyway" to be fetched (0: 8 MB).
    pub file_limit: u64,
    /// Fast transfers: a peer's slots come every few milliseconds while a file goes either way.
    pub fast_files: bool,
    /// We moved here from another room (:move): the key we showed there, which signs our
    /// sessions here so codes compared there count here.
    pub moved: Option<IdentityKeypair>,
    /// This program's build, told to peers in "v" (None: its executable couldn't be read).
    pub build: Option<Build>,
}

/// A build as peers are told it: its version, its executable's SHA-256 (without the list a release
/// appends), and that release's signed list of binaries (both empty for a build without one).
#[derive(Clone, Debug, Default)]
pub struct Build {
    pub version: String,
    pub hash: [u8; 32],
    /// The list's hashes, hex, comma-separated.
    pub list: String,
    /// The list's signature line.
    pub list_sig: String,
}

impl SessionConfig {
    pub fn new(room: &str, nick: &str) -> Self {
        SessionConfig {
            room: room.to_string(),
            nick: nick.to_string(),
            colour: None,
            created: false,
            verify_required: false,
            keeps_history: false,
            timer: 0,
            identity: None,
            coming_back: false,
            net_log: NetLog::Normal,
            mode: RouteMode::Tor,
            port: 0,
            lan: true,
            dht_v4: true,
            dht_v6: true,
            nostr: NostrMode::Fallback,
            relays: 0,
            static_peers: Vec::new(),
            rekey_interval: 300.0,
            file_limit: 0,
            fast_files: false,
            moved: None,
            build: None,
        }
    }
}

/// A datagram to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    pub to: Addr,
    /// Over UDP: masked and ready (or a DHT message). Through the relays: a whole frame.
    pub data: Vec<u8>,
    /// From the LAN beacon socket rather than the session's own.
    pub lan: bool,
}

/// Something only the runtime can do for the session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Look up the DHT's bootstrap servers and hand their addresses to
    /// [`Session::dht_bootstrap`].
    ResolveDhtBootstrap { want_v4: bool, want_v6: bool },
    /// Tor: host one of the room's onion services (the slot, or None for one nobody answered on).
    TorHostRoom { slot: Option<u8> },
    /// Tor: publish the hosted room service again (whoever published it last may have left).
    TorRepublishRoom,
    /// Tor: this onion is a member's; frames to `id` go to it.
    TorTarget { id: [u8; 16], onion: String },
    /// :move: a key a peer moving with us showed here, for the room we moved to
    /// ([`Session::came_with`] there).
    MoveKey { public: [u8; 32], nick: String },
}

/// What the Tor transport tells the session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TorStatus {
    /// It has reached the Tor network.
    pub ready: bool,
    /// Our own onion service's address, once it's up.
    pub onion: Option<String>,
    /// The room service we host, once it's up.
    pub hosted_slot: Option<u8>,
    /// Targets with a stream open or opening, or waiting before another try: not worth a hi now.
    pub busy: Vec<[u8; 16]>,
}

/// The session's own Tor state.
struct TorState {
    status: TorStatus,
    /// The onion our peers were last told.
    told: Option<String>,
    hosting: bool,
    republish_at: f64,
    room_targets: [[u8; 16]; crate::protocol::crypto::TOR_ROOM_SLOTS],
}

/// A token bucket: `rate` a second, up to `burst`.
#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: f64,
}

impl Bucket {
    fn new(burst: f64, now: f64) -> Self {
        Bucket { tokens: burst, at: now }
    }
    fn take(&mut self, now: f64, rate: f64, burst: f64) -> bool {
        if now > self.at {
            self.tokens += (now - self.at) * rate;
        }
        self.tokens = self.tokens.min(burst);
        self.at = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

struct Cand {
    addr: Addr,
    tries: u32,
    next_try: f64,
}

/// A recent message, for a reply to pick and quote.
struct Recent {
    mid: String,
    origin: [u8; 16],
    nick: String,
    quote: String,
    at: f64,
}

/// Messages for a peer that dropped, kept in case it comes back with the same id.
struct Held {
    since: f64,
    items: Vec<peer::Pending>,
}

/// What we track of one of our messages: the peers it went to, and how many of its records each
/// still has to ack.
struct OwnTrack {
    waiting: HashMap<[u8; 16], u32>,
}

#[derive(Default)]
struct NetStats {
    rx: u64,
    rx_chunks: u64,
    rx_chunk_done: u64,
    room_ok: u64,
    hi: u64,
    ck: u64,
    hi2: u64,
    hi2_bad: u64,
    kx: u64,
    lan: u64,
    session_ok: u64,
    dht: u64,
    other: u64,
    connects: u64,
}

pub struct Session {
    room: String,
    keys: RoomKeys,
    my_id: [u8; 16],
    my_idhex: String,
    x: X25519Keypair,
    kem: KemKeypair,
    cookie_secret: [u8; 32],
    /// The one before our last rekey, so a hi2 answering a cookie sent just before still counts.
    prev_cookie_secret: Option<[u8; 32]>,
    keygen: u32,
    hi_msg: String,
    nick: String,
    skel: String,
    colour: Colour,
    created: bool,
    verify_required: bool,
    persist: bool,
    timer: u32,
    identity: Option<(IdentityKind, IdentityKeypair)>,
    coming_back: bool,
    net_log: NetLog,
    port: u16,
    lan: bool,
    nostr: NostrMode,
    relays_total: usize,
    relays_up: usize,
    relays_until: f64,
    next_beacon: f64,
    trust: SharedTrust,
    trust_seen: u64,

    peers: Vec<Option<Peer>>,
    cands: Vec<Cand>,
    static_peers: Vec<SocketAddr>,
    self_addrs: Vec<Addr>,
    recent: VecDeque<Recent>,
    seen: VecDeque<u32>,
    seen_set: HashSet<u32>,
    gone: VecDeque<([u8; 16], [u8; 16])>,
    ignored: VecDeque<[u8; 16]>,
    held: HashMap<[u8; 16], Held>,
    own: HashMap<u64, OwnTrack>,
    reasm: Reassembly,
    probe: Bucket,
    ck: Bucket,
    roam: Bucket,
    queue_seq: u64,
    own_seq: u64,

    dht: Option<Dht>,
    dht_summary_done: bool,
    mode: RouteMode,
    tor: TorState,

    start: f64,
    now: f64,
    unix: u64,
    next_alive: f64,
    next_lan: f64,
    next_rekey: f64,
    rekey_every: f64,
    rekey_due: Option<f64>,
    warned_lonely: bool,
    ever_connected: bool,
    st: NetStats,
    last_net: Option<NetStatus>,
    last_timer: (u32, Option<String>),
    left: bool,

    files: files::Files,
    moving: moving::Moving,
    build: Option<Build>,
    /// Direct, with port mapping on: the port the router forwards to us (None until it does),
    /// and how the mapping is going.
    portmap: Option<(Option<u16>, String)>,

    transmits: VecDeque<Transmit>,
    events: VecDeque<Event>,
    requests: VecDeque<Request>,
}

impl Session {
    pub fn new(cfg: SessionConfig, keys: RoomKeys, trust: SharedTrust, now: Now) -> Self {
        let my_id: [u8; 16] = sodium::random_array();
        let nick = crate::protocol::text::clean_nick(cfg.nick.as_bytes());
        // Through Tor nothing goes over UDP: no socket, no LAN, no DHT.
        let tor = cfg.mode == RouteMode::Tor;
        let cfg = SessionConfig {
            port: if tor { 0 } else { cfg.port },
            lan: cfg.lan && !tor,
            ..cfg
        };
        let room_targets = std::array::from_fn(|i| {
            let (_, public) = crate::protocol::crypto::tor_room_key(&keys.master, i as u8);
            crate::protocol::crypto::tor_target_id(&crate::protocol::crypto::onion_address(&public))
        });
        let dht = (cfg.port != 0 && (cfg.dht_v4 || cfg.dht_v6)).then(|| Dht::new(&keys.dht, cfg.port, cfg.dht_v4, cfg.dht_v6));
        let static_peers = cfg
            .static_peers
            .iter()
            .copied()
            .map(crate::protocol::wire::canonical)
            .take(16)
            .collect();
        let trust_seen = trust.lock().map(|t| t.version()).unwrap_or(0);
        let mut s = Session {
            room: cfg.room,
            keys,
            my_id,
            my_idhex: crate::protocol::hex::encode(&my_id),
            x: X25519Keypair::generate(),
            kem: KemKeypair::generate(),
            cookie_secret: sodium::random_array(),
            prev_cookie_secret: None,
            keygen: 1,
            hi_msg: String::new(),
            skel: crate::protocol::text::nick_skeleton(&nick),
            nick,
            colour: cfg.colour.unwrap_or_else(Colour::random),
            created: cfg.created,
            verify_required: cfg.verify_required,
            persist: cfg.keeps_history,
            timer: if cfg.timer == 0 || (crate::protocol::names::TIMER_MIN..=crate::protocol::names::TIMER_MAX).contains(&cfg.timer) {
                cfg.timer
            } else {
                0
            },
            identity: cfg.identity,
            coming_back: cfg.coming_back,
            net_log: cfg.net_log,
            port: cfg.port,
            lan: cfg.lan && cfg.port != 0,
            relays_total: if cfg.nostr == NostrMode::Off { 0 } else { cfg.relays },
            nostr: if cfg.relays == 0 { NostrMode::Off } else { cfg.nostr },
            relays_up: 0,
            relays_until: 0.0,
            next_beacon: 0.0,
            trust,
            trust_seen,
            peers: (0..SLOTS).map(|_| None).collect(),
            cands: Vec::new(),
            static_peers,
            self_addrs: Vec::new(),
            recent: VecDeque::new(),
            seen: VecDeque::new(),
            seen_set: HashSet::new(),
            gone: VecDeque::new(),
            ignored: VecDeque::new(),
            held: HashMap::new(),
            own: HashMap::new(),
            reasm: Reassembly::default(),
            probe: Bucket::new(PROBE_BURST, now.secs),
            ck: Bucket::new(CK_BURST, now.secs),
            roam: Bucket::new(ROAM_BURST, now.secs),
            queue_seq: 0,
            own_seq: 0,
            dht,
            dht_summary_done: false,
            mode: cfg.mode,
            tor: TorState {
                status: TorStatus::default(),
                told: None,
                hosting: false,
                republish_at: 0.0,
                room_targets,
            },
            start: now.secs,
            now: now.secs,
            unix: now.unix,
            next_alive: 0.0,
            next_lan: 0.0,
            next_rekey: now.secs + tick::rekey_after(cfg.rekey_interval),
            rekey_every: cfg.rekey_interval.max(10.0),
            rekey_due: None,
            warned_lonely: false,
            ever_connected: false,
            st: NetStats::default(),
            last_net: None,
            last_timer: (0, None),
            left: false,
            files: files::Files::new(cfg.file_limit, cfg.fast_files),
            moving: moving::Moving::new(cfg.moved.clone()),
            build: cfg.build,
            portmap: None,
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            requests: VecDeque::new(),
        };
        s.refresh_hi();
        if tor && s.created {
            // The room's maker hosts its first onion service, so the first to join find it.
            s.tor.hosting = true;
            s.requests.push_back(Request::TorHostRoom { slot: Some(0) });
        }
        s.emit_timer_if_changed();
        s
    }

    // ---- driving it ----

    /// A datagram from the session's UDP socket (or the LAN beacon socket), as received.
    pub fn handle_udp(&mut self, from: SocketAddr, data: &[u8], now: Now) {
        self.set_now(now);
        self.on_udp(Addr::udp(from), data);
    }

    /// A whole frame from a relayed transport: the relays (from a member's id) or a Tor stream.
    pub fn handle_relayed(&mut self, from: Addr, frame: &[u8], now: Now) {
        self.set_now(now);
        self.st.rx += 1;
        if !self.on_frame(frame, from) {
            self.st.other += 1;
        }
    }

    /// The time passing: slots, resends, handshakes, rekeys and timeouts. Call it often (every
    /// few tens of milliseconds) and after every input.
    pub fn tick(&mut self, now: Now) {
        self.set_now(now);
        self.run_tick();
    }

    /// What the user asks for.
    pub fn command(&mut self, cmd: Command, now: Now) -> Result<Outcome, CommandError> {
        self.set_now(now);
        self.run_command(cmd)
    }

    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn poll_request(&mut self) -> Option<Request> {
        self.requests.pop_front()
    }

    /// The DHT's bootstrap servers, looked up as [`Request::ResolveDhtBootstrap`] asked.
    /// The Tor transport's news.
    pub fn set_tor_status(&mut self, status: TorStatus) {
        self.tor.status = status;
    }

    /// The room's onion service keys (expanded secret and public key, slot by slot), which the
    /// Tor transport hosts as it's asked to.
    pub fn tor_room_keys(&self) -> Vec<(zeroize::Zeroizing<[u8; 64]>, [u8; 32])> {
        (0..crate::protocol::crypto::TOR_ROOM_SLOTS as u8)
            .map(|i| crate::protocol::crypto::tor_room_key(&self.keys.master, i))
            .collect()
    }

    pub fn mode(&self) -> RouteMode {
        self.mode
    }

    pub fn dht_bootstrap(&mut self, addrs: &[SocketAddr]) {
        if let Some(d) = &mut self.dht {
            d.bootstrap_resolved(addrs);
        }
    }

    /// How many relays have a connection now.
    pub fn set_relays_up(&mut self, up: usize) {
        self.relays_up = up;
    }

    /// Whether the relays should be connected now: always when set to; otherwise while nobody
    /// is reached, while a peer is reached only through them, or while a peer's own path has
    /// gone quiet and they may be needed next (and a minute after).
    pub fn relays_wanted(&self) -> bool {
        self.nostr != NostrMode::Off && self.now < self.relays_until
    }

    /// The router's port mapping (the runtime's): the port it forwards to us, which the DHT is
    /// given instead of the one it sees, and how it's going, for the net report.
    pub fn set_portmap(&mut self, external: Option<u16>, text: String) {
        if let Some(d) = self.dht.as_mut() {
            d.set_announce_port(external, self.port);
        }
        self.portmap = Some((external, text));
    }

    /// Signs with another key from now on, or (None) stops signing. Every peer gets "k" again,
    /// a few times as always, since nothing acks it.
    pub fn set_identity(&mut self, identity: Option<(IdentityKind, IdentityKeypair)>, now: Now) {
        self.set_now(now);
        self.identity = identity;
        let next = self.now + receive::K_EVERY;
        for slot in self.live() {
            self.send_k_now(slot);
            let p = self.peer_mut(slot);
            p.k_sent = 1;
            p.next_k = next;
        }
    }

    /// Leaves the room: "bye" (or "off", for a room kept to come back to) to everyone, at once.
    pub fn leave(&mut self, now: Now) {
        self.set_now(now);
        self.leave_now();
    }

    // ---- what it is ----

    pub fn room(&self) -> &str {
        &self.room
    }
    pub fn my_id(&self) -> PeerId {
        PeerId(self.my_id)
    }
    pub fn nick(&self) -> &str {
        &self.nick
    }
    pub fn colour(&self) -> Colour {
        self.colour
    }
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The runtime moved the room to another UDP port: peers follow the source address of our next
    /// hello, which goes at once, as do a LAN beacon and a DHT announce from the new port.
    pub fn set_port(&mut self, port: u16) {
        self.port = port;
        self.next_alive = 0.0;
        self.next_lan = 0.0;
        if let Some(d) = self.dht.as_mut() {
            d.set_port(port);
        }
    }
    pub fn lan_port(&self) -> u16 {
        self.keys.lan_port
    }
    pub fn keeps_history(&self) -> bool {
        self.persist
    }
    pub fn verify_required(&self) -> bool {
        self.verify_required
    }
    pub fn created(&self) -> bool {
        self.created
    }
    /// Created here, or someone answered: messages can be sent.
    pub fn ready(&self) -> bool {
        self.created || self.ever_connected
    }
    pub fn history_id(&self) -> [u8; 16] {
        self.keys.history_id()
    }
    /// The relays' keys (tag and wrap) and our id there, for the relay transport.
    pub fn relay_keys(&self) -> ([u8; 32], [u8; 32], PeerId) {
        (self.keys.nostr_tag, self.keys.nostr_wrap, PeerId(self.my_id))
    }
    pub fn has_left(&self) -> bool {
        self.left
    }

    pub fn peers(&self) -> Vec<PeerInfo> {
        (0..SLOTS)
            .filter(|&i| self.peers[i].as_ref().is_some_and(|p| p.ok))
            .map(|i| self.peer_info(i))
            .collect()
    }

    pub fn net_status(&self) -> NetStatus {
        NetStatus {
            ready: self.ready(),
            online: self.live_count(),
            pending: self.pending_peer_count(),
            candidates: self.cands.len(),
            rx: self.st.rx,
            dht: self.dht.as_ref().map(|d| d.counts().known > 0),
            dht_found: self.dht.as_ref().map_or(0, |d| d.counts().found),
            relays: (self.nostr != NostrMode::Off).then(|| RelayStatus {
                used: self.relays_wanted(),
                up: self.relays_up,
                total: self.relays_total,
            }),
            lan: self.lan,
            mode: self.mode,
            tor_ready: self.tor.status.ready,
            onion_up: self.tor.status.onion.is_some(),
            portmap: self.portmap.as_ref().map(|(p, _)| p.is_some()),
        }
    }

    /// The message timer kept to: the shortest we or any trusted peer asks for, and who asked.
    pub fn timer(&self) -> (u32, Option<String>) {
        let mut best = self.timer;
        let mut who = (best > 0).then(|| "you".to_string());
        for i in 0..SLOTS {
            let Some(p) = &self.peers[i] else { continue };
            if !p.ok || p.timer == 0 || (best > 0 && p.timer >= best) || !self.trusted(p) {
                continue;
            }
            best = p.timer;
            who = Some(self.peer_name(i));
        }
        (best, who)
    }

    /// Each peer's handshake and queue state, for debugging and tests.
    #[doc(hidden)]
    pub fn debug_state(&self) -> String {
        let mut out = format!("gen {} ", self.keygen);
        for p in self.peers.iter().flatten() {
            out += &format!(
                "[{} ok={} gen={} confirmed={} send={} on_old={} old_until={:.0} sendq={}({} old) roomq={:?} pending={} next_pub={}] ",
                crate::protocol::hex::encode(&p.id[..2]),
                p.ok,
                p.keygen,
                p.chain_confirmed,
                p.send.started(),
                p.sending_on_old(),
                (p.old_until - self.now).max(0.0),
                p.sendq.len(),
                p.sendq.iter().filter(|q| q.old_chain).count(),
                p.roomq
                    .iter()
                    .map(|q| format!("{}:{}/{}", q.kind, q.next_piece, q.pieces))
                    .collect::<Vec<_>>(),
                p.pending.len(),
                p.next_pub.is_some_and(|n| n != p.public),
            );
        }
        out
    }

    // ---- shared helpers ----

    fn set_now(&mut self, now: Now) {
        self.now = self.now.max(now.secs);
        self.unix = now.unix;
    }

    fn peer(&self, slot: usize) -> &Peer {
        self.peers[slot].as_ref().expect("a used slot")
    }

    fn peer_mut(&mut self, slot: usize) -> &mut Peer {
        self.peers[slot].as_mut().expect("a used slot")
    }

    fn used(&self) -> impl Iterator<Item = usize> + '_ {
        (0..SLOTS).filter(|&i| self.peers[i].is_some())
    }

    /// The slots of connected peers.
    fn live(&self) -> Vec<usize> {
        (0..SLOTS).filter(|&i| self.peers[i].as_ref().is_some_and(|p| p.ok)).collect()
    }

    fn live_count(&self) -> usize {
        self.peers.iter().flatten().filter(|p| p.ok).count()
    }

    fn pending_peer_count(&self) -> usize {
        self.peers.iter().flatten().filter(|p| !p.ok).count()
    }

    fn find_peer(&self, id: &[u8; 16]) -> Option<usize> {
        (0..SLOTS).find(|&i| self.peers[i].as_ref().is_some_and(|p| p.id == *id))
    }

    /// Whether a peer gets what's sent: never with a code that differs, and with comparing
    /// required, only once compared.
    fn trusted(&self, p: &Peer) -> bool {
        p.code_ok != peer::CodeOk::Different && (!self.verify_required || p.code_ok == peer::CodeOk::Same)
    }

    /// A peer's nick as shown, with "#" and its id's start when another's (or ours) looks the same.
    fn peer_name(&self, slot: usize) -> String {
        let p = self.peer(slot);
        let clash =
            p.skel == self.skel || (0..SLOTS).any(|i| i != slot && self.peers[i].as_ref().is_some_and(|q| q.ok && q.skel == p.skel));
        if clash {
            format!("{}#{}", p.nick, crate::protocol::hex::encode(&p.id[..4]))
        } else {
            p.nick.clone()
        }
    }

    fn code_state(&self, p: &Peer) -> CodeState {
        match p.code_ok {
            peer::CodeOk::Different => CodeState::Differs,
            peer::CodeOk::Same => CodeState::Compared,
            peer::CodeOk::NotCompared if p.trust == peer::TrustMatch::OtherKey => CodeState::KeyChanged,
            peer::CodeOk::NotCompared if self.verify_required => CodeState::Compare,
            peer::CodeOk::NotCompared => CodeState::Nothing,
        }
    }

    fn peer_info(&self, slot: usize) -> PeerInfo {
        let p = self.peer(slot);
        PeerInfo {
            id: p.peer_id(),
            nick: p.nick.clone(),
            name: self.peer_name(slot),
            colour: p.colour,
            code: p.vfy_set.then(|| VerifyCode {
                words: crate::protocol::names::bytewords(&p.vfy),
                hex: crate::protocol::hex::groups(&p.vfy),
            }),
            code_state: self.code_state(p),
            identity: p.ident.as_ref().map(|i| PeerIdentity {
                kind: i.kind,
                public: crate::protocol::hex::encode(&i.public),
                fingerprint: crate::protocol::hex::groups(&i.fingerprint),
                signature: i.state,
            }),
            build: p.build_state,
            version: p.build_version.clone(),
            keeps_history: p.persists,
            ignored: self.is_ignored(&p.id),
            can_dm: p.caps.can_pm,
            path: match p.addr {
                Addr::Udp(_) => PathKind::Direct,
                Addr::Relay(_) => PathKind::Relays,
                Addr::Tor(_) => PathKind::Tor,
            },
            announced: p.announced,
        }
    }

    fn is_ignored(&self, id: &[u8; 16]) -> bool {
        self.ignored.contains(id)
    }

    fn set_ignored(&mut self, id: &[u8; 16], on: bool) {
        if on {
            if !self.ignored.contains(id) {
                if self.ignored.len() >= IGNORED_MAX {
                    self.ignored.pop_front();
                }
                self.ignored.push_back(*id);
            }
        } else {
            self.ignored.retain(|x| x != id);
        }
    }

    fn note(&mut self, text: impl Into<String>) {
        self.events.push_back(Event::Notice {
            level: Level::Note,
            text: text.into(),
        });
    }

    fn warn(&mut self, text: impl Into<String>) {
        self.events.push_back(Event::Notice {
            level: Level::Warn,
            text: text.into(),
        });
    }

    /// A network line, shown as the net log setting allows: news unless it's off, a detail only
    /// when verbose, a problem always.
    fn net_news(&mut self, text: impl Into<String>) {
        if self.net_log >= NetLog::Normal {
            self.events.push_back(Event::Log { text: text.into() });
        }
    }

    fn net_detail(&mut self, text: impl FnOnce() -> String) {
        if self.net_log >= NetLog::Verbose {
            self.events.push_back(Event::Log { text: text() });
        }
    }

    fn peer_changed(&mut self, slot: usize) {
        if self.peers[slot].as_ref().is_some_and(|p| p.ok && p.announced) {
            let info = self.peer_info(slot);
            self.events.push_back(Event::PeerChanged(info));
        }
    }

    fn emit_timer_if_changed(&mut self) {
        let t = self.timer();
        if t != self.last_timer {
            self.last_timer = t.clone();
            self.events.push_back(Event::Timer { seconds: t.0, who: t.1 });
        }
    }

    fn jitter(spread: f64) -> f64 {
        spread * sodium::random_unit()
    }

    /// d, and up to a quarter more.
    fn jittered(d: f64) -> f64 {
        d + Self::jitter(d * JITTER)
    }

    fn retry_delay(tries: u32) -> f64 {
        Self::jittered((2.0 * f64::from(1u32 << tries.min(5))).min(32.0))
    }
}
