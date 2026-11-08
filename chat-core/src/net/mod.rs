// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The runtime: rooms on real networks. Each room runs the protocol engine on a task of its own,
//! with its transports: Tor (the default), the Nostr relays, and for direct routing UDP, the LAN
//! and the BitTorrent DHT.

mod bridges;
pub mod device;
mod driver;
pub mod files;
pub mod history;
pub mod memlock;
pub mod nostr;
mod portmap;
pub mod sandbox;
pub mod saves;
pub mod seckey;
pub mod settings;
pub mod tor;
pub mod tor_ext;
pub mod tpm2;
mod udp;
pub mod update;

use crate::protocol::crypto::RoomKeys;
use crate::protocol::session::SessionConfig;
use crate::protocol::{
    Command, CommandError, Event, FileInfo, NetLog, NetStatus, NostrMode, Outcome, PeerId, PeerInfo, RouteMode,
    crypto::identity::{IdentityKeypair, IdentityKind},
    names::Colour,
    trust::{SharedTrust, TrustStore},
};
use crate::protocol::{Session, names};
pub use bridges::Bridges;

/// What every interface calls first: no core dumps, which would write keys and the conversation to
/// disk, and on Linux, no other process of ours (or a debugger) reading this one's memory.
pub fn harden_process() {
    #[cfg(unix)]
    {
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: setrlimit and prctl only read their arguments.
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &none);
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            // Nothing chat runs needs to gain privileges through exec.
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        }
        lock_memory();
    }
}

/// Keeps keys, passphrases and the conversation out of swap. With no limit on locked memory, all of
/// the process's memory is locked. With one, locking everything would make a big allocation (a
/// passphrase's 512 MiB Argon2id) fail, so a locked region of what the limit allows is set up
/// instead, for the code that handles secrets to allocate from ([`memlock`]).
#[cfg(unix)]
fn lock_memory() {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit writes into the struct it's given; setrlimit and mlockall only read theirs.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) != 0 {
            return;
        }
        // A finite limit: a locked region, which the code that handles secrets allocates from.
        if lim.rlim_max != libc::RLIM_INFINITY {
            return memlock::init();
        }
        lim.rlim_cur = libc::RLIM_INFINITY;
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim);
        #[cfg(target_os = "linux")]
        let flags = libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT;
        #[cfg(not(target_os = "linux"))]
        let flags = libc::MCL_CURRENT | libc::MCL_FUTURE;
        libc::mlockall(flags);
    }
}
use driver::{Ask, Clock, Driver};
pub use files::FileOptions;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

/// How a room reaches its peers.
///
/// The default is Tor: onion services, so nobody learns your IP address, peers included, with the
/// Nostr relays (reached through Tor) as the fallback, and the bridge to members on direct
/// routing. Relays also make finding each other faster: members meet there at once, while onion
/// services take a minute or two to publish and be found.
///
/// [`RouteMode::Direct`] is the faster alternative: UDP straight between peers, found on the LAN
/// and through the BitTorrent DHT. Every peer, and the DHT, sees your IP address.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Route {
    pub mode: RouteMode,
    /// Direct: the UDP port (0: any free one).
    pub port: u16,
    /// Direct: peers to reach straight away, "host:port".
    pub peers: Vec<String>,
    /// Direct: the BitTorrent DHT over IPv4 and IPv6.
    pub dht: bool,
    pub ipv6: bool,
    /// Direct: beacons on the local network.
    pub lan: bool,
    /// Direct: ask the router to forward our port (PCP, NAT-PMP or UPnP).
    pub portmap: bool,
    /// The Nostr relays: through Tor on Tor routing. They find members faster, and are where
    /// members on the two routings meet.
    pub nostr: NostrMode,
    /// Nostr relays (wss://); the defaults when empty.
    pub relays: Vec<String>,
}

impl Default for Route {
    fn default() -> Self {
        Route {
            mode: RouteMode::Tor,
            port: 0,
            peers: Vec::new(),
            dht: true,
            ipv6: true,
            lan: true,
            portmap: true,
            nostr: NostrMode::Fallback,
            relays: nostr::DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// What a room to open is, and how to be in it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RoomConfig {
    /// The room's id. None: a new one.
    pub room: Option<String>,
    /// Its password. None: random words for a new room, blank for one joined.
    pub password: Option<String>,
    /// An invite ("chat:ID:PASSWORD:CHECK") in place of the id and password.
    pub invite: Option<String>,
    /// We make the room: it opens at once, instead of when someone answers. Implied without a room.
    pub create: bool,
    pub nick: String,
    pub colour: Option<Colour>,
    /// Nothing goes to a peer until its verify code was compared.
    pub verify_required: bool,
    /// Tell the room we keep a history of it.
    pub history: bool,
    /// A message timer to ask for, in seconds (0: none).
    pub timer: u32,
    /// Kept to come back to: leaving says we went offline, not that we left.
    pub kept: bool,
    pub net_log: Option<NetLog>,
    pub route: Route,
    /// Seconds between rekeys: None for the protocol's 300. Only tests need another.
    pub rekey_interval: Option<f64>,
    pub files: FileOptions,
    #[serde(skip)]
    pub identity: Option<(IdentityKind, IdentityKeypair)>,
    /// Moved here from another room (:move): the key shown there, and that room's id.
    #[serde(skip)]
    pub moved: Option<(IdentityKeypair, String)>,
}

impl RoomConfig {
    /// A new room, with a random id and password.
    pub fn create(nick: &str) -> Self {
        RoomConfig {
            create: true,
            nick: nick.into(),
            ..Default::default()
        }
    }

    /// A room someone shared with an invite.
    pub fn invite(invite: &str, nick: &str) -> Self {
        RoomConfig {
            invite: Some(invite.into()),
            nick: nick.into(),
            ..Default::default()
        }
    }
}

/// An open room, as its UI shows it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoomInfo {
    pub room: String,
    pub password: String,
    pub invite: Option<String>,
    pub created: bool,
    pub me: PeerId,
    pub nick: String,
    pub colour: Colour,
    pub mode: RouteMode,
    /// Direct: the UDP port it's on.
    pub port: u16,
    pub history: bool,
    pub verify_required: bool,
    /// The room :move brought us here from.
    pub moved_from: Option<String>,
    /// What a save names this room's history by: worked out from its id and password, so the
    /// name doesn't say which room it is.
    #[serde(skip)]
    pub history_id: [u8; 16],
}

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error(transparent)]
    Invite(#[from] names::InviteError),
    #[error("a room id is 1 to 64 characters, and a password at most 255")]
    BadRoom,
    #[error(transparent)]
    Kdf(#[from] crate::protocol::crypto::KdfError),
    #[error("could not open a UDP socket: {0}")]
    Socket(std::io::Error),
    #[error("{0} isn't a host:port to reach")]
    BadPeer(String),
    #[error("{0}")]
    Tor(String),
}

/// What all of a client's rooms share: the signing keys verified or ignored, and one Tor.
#[derive(Clone, Default)]
pub struct Client {
    trust: SharedTrust,
    /// The Tor rooms opened from now on use, once one has started; emptied when the settings
    /// change which, and rooms already open keep theirs.
    tor: Arc<tokio::sync::Mutex<Option<Arc<tor::Tor>>>>,
    /// Where Tor keeps its state, and whether that folder is ours to delete on exit.
    tor_dir: Option<(std::path::PathBuf, bool)>,
    /// Held while Tor starts, so bridges set meanwhile aren't missed.
    bridges: Arc<tokio::sync::Mutex<Bridges>>,
    /// Whether to use a tor that's already running, and where it is.
    tor_use: Arc<std::sync::Mutex<tor_ext::TorUse>>,
}

impl Client {
    pub fn new() -> Self {
        // This build as peers are told it, read now, before an update can replace the file.
        let _ = update::self_build();
        Client {
            trust: TrustStore::shared(),
            tor: Arc::default(),
            tor_dir: None,
            bridges: Arc::default(),
            tor_use: Arc::default(),
        }
    }

    /// Keeps Tor's state (its entry guards and directory) in this folder between runs: a quicker
    /// start, and the same guards for months, as Tor intends. Without it, Tor starts afresh each run
    /// in a private folder that's deleted on exit.
    pub fn with_tor_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.tor_dir = Some((dir, false));
        self
    }

    /// Starts Tor from the state a save kept ([`Client::tor_state`]): its entry guards and copy of the
    /// directory, so it keeps the same guards and connects in seconds. The folder they go in is
    /// private and deleted on exit. A folder given by [`Client::with_tor_dir`] wins; state that
    /// can't be read is left out, and Tor starts afresh.
    pub fn with_tor_state(mut self, state: &[u8]) -> Self {
        if self.tor_dir.is_none()
            && let Ok(dir) = tor::private_dir()
        {
            if !tor::unpack_dir(state, &dir) {
                let _ = std::fs::remove_dir_all(&dir);
                let _ = std::fs::create_dir(&dir);
            }
            self.tor_dir = Some((dir, true));
        }
        self
    }

    /// The client's Tor if it has started, without starting it.
    pub fn tor_now(&self) -> Option<Arc<tor::Tor>> {
        self.tor.try_lock().ok()?.clone()
    }

    /// Tor's state as it is now, for a save to keep: None if Tor hasn't started.
    pub fn tor_state(&self) -> Option<Vec<u8>> {
        self.tor.try_lock().ok()?.as_ref().map(|t| t.state())
    }

    /// Whether to use a tor that's already running (torlaunch auto or never) and where it is, or
    /// the built-in one (always). It's read when Tor starts, the first time a room needs it.
    pub fn set_tor_use(&self, u: tor_ext::TorUse) {
        let mut cur = self.tor_use.lock().expect("tor settings");
        if *cur != u {
            *cur = u;
            // Rooms opened from now on start the Tor these settings choose.
            if let Ok(mut t) = self.tor.try_lock() {
                *t = None;
            }
        }
    }

    /// The client's Tor, started the first time a room needs it: a running tor, if one answers
    /// and the settings let it, otherwise the built-in one.
    pub async fn tor(&self) -> Result<Arc<tor::Tor>, JoinError> {
        // The bridges first, as change_bridges takes them.
        let bridges = self.bridges.lock().await;
        let mut cur = self.tor.lock().await;
        if let Some(t) = cur.as_ref() {
            return Ok(t.clone());
        }
        let u = self.tor_use.lock().expect("tor settings").clone();
        // With bridges set, auto means chat's own: a running tor's bridges are its own.
        if u.launch == "never" || (u.launch == "auto" && bridges.is_empty()) {
            let defaults = tor_ext::TorUse::default();
            let mut tries = vec![u.clone()];
            // With the default ports, Tor Browser's too.
            if u.socks == defaults.socks && u.control == defaults.control {
                tries.push(tor_ext::TorUse {
                    socks: "127.0.0.1:9150".into(),
                    control: "127.0.0.1:9151".into(),
                    ..u.clone()
                });
            }
            let mut why = String::new();
            for t in &tries {
                match tor_ext::ExtTor::connect(t).await {
                    Ok(ext) => {
                        let t = tor::Tor::running(ext);
                        *cur = Some(t.clone());
                        return Ok(t);
                    }
                    Err(e) if why.is_empty() => why = e,
                    Err(_) => {}
                }
            }
            if u.launch == "never" {
                return Err(JoinError::Tor(format!(
                    "{why} - and with torlaunch never, chat doesn't use its own"
                )));
            }
        }
        // Chat's own: the tor program set, or the built-in one.
        let t = if u.path.is_empty() {
            tor::Tor::start(self.tor_dir.clone(), &bridges).map_err(JoinError::Tor)?
        } else {
            tor::Tor::launched(&u.path, self.tor_dir.clone(), &bridges)
                .await
                .map_err(JoinError::Tor)?
        };
        *cur = Some(t.clone());
        Ok(t)
    }

    /// Bridges for Tor, as typed ("LINE; LINE"; empty for none). With any, Tor reaches the Tor
    /// network only through them: from its start, or at once if it's running (circuits already
    /// open run on until they close). On an error nothing changes. Says how many there are and
    /// their transports, never the lines.
    pub async fn set_bridges(&self, typed: &str) -> Result<String, String> {
        self.change_bridges(|b| b.set_lines(typed)).await.map(|b| b.describe())
    }

    /// The folder with the bridges' transport programs (lyrebird, snowflake-client); None looks on
    /// PATH and in the usual folders. Says which were found.
    pub async fn set_transports(&self, dir: Option<std::path::PathBuf>) -> Result<String, String> {
        self.change_bridges(|b| b.set_transports(dir))
            .await
            .map(|b| b.describe_transports())
    }

    /// The bridges as [`Client::set_bridges`] and [`Client::set_transports`] describe them.
    pub async fn bridges(&self) -> (String, String) {
        let b = self.bridges.lock().await;
        (b.describe(), b.describe_transports())
    }

    async fn change_bridges(&self, f: impl FnOnce(&mut Bridges) -> Result<(), String>) -> Result<Bridges, String> {
        let mut cur = self.bridges.lock().await;
        let mut next = cur.clone();
        f(&mut next)?;
        let mut t = self.tor.lock().await;
        match t.as_ref() {
            // A running tor's bridges are its own: rooms opened from now on start chat's own.
            Some(running) if running.is_running() => *t = None,
            Some(own) => own.set_bridges(&next)?,
            None => {}
        }
        *cur = next.clone();
        Ok(next)
    }

    /// The verified and ignored signing keys, shared by every room. A UI keeps them, if it keeps
    /// anything, and loads them here; each change bumps [`TrustStore::version`].
    pub fn trust(&self) -> &SharedTrust {
        &self.trust
    }

    /// Opens a room. Deriving its key takes a few seconds and 512 MiB, off the async runtime.
    pub async fn join(&self, cfg: RoomConfig) -> Result<(Room, RoomEvents), JoinError> {
        let (room, password, created) = match &cfg.invite {
            Some(inv) => {
                let (r, p) = names::parse_invite(inv)?;
                (r, p, cfg.create)
            }
            None => match &cfg.room {
                Some(r) => (r.clone(), cfg.password.clone().unwrap_or_default(), cfg.create),
                None => (
                    names::random_room_id(),
                    cfg.password.clone().unwrap_or_else(names::random_password),
                    true,
                ),
            },
        };
        if room.is_empty() || room.len() > names::MAX_ROOM_ID || password.len() > names::MAX_PASSWORD {
            return Err(JoinError::BadRoom);
        }
        let tor_mode = cfg.route.mode == RouteMode::Tor;
        let mut peers = Vec::new();
        for p in cfg.route.peers.iter().filter(|_| !tor_mode) {
            let found: Vec<SocketAddr> = tokio::net::lookup_host(p.as_str())
                .await
                .map_err(|_| JoinError::BadPeer(p.clone()))?
                .collect();
            peers.extend(found.into_iter().take(2));
        }
        let (r2, p2) = (room.clone(), password.clone());
        let keys = tokio::task::spawn_blocking(move || RoomKeys::derive(&r2, &p2))
            .await
            .expect("the key derivation task")?;

        // Through Tor nothing goes over UDP: there's no socket at all.
        let tor = if tor_mode { Some(self.tor().await?) } else { None };
        let udp = if tor_mode {
            None
        } else {
            Some(udp::Udp::bind(cfg.route.port).map_err(JoinError::Socket)?)
        };
        let port = udp.as_ref().map_or(0, |u| u.port());
        let lan = if cfg.route.lan && !tor_mode {
            udp::Udp::bind_lan(keys.lan_port).ok()
        } else {
            None
        };
        let relays: Vec<String> = if cfg.route.nostr == NostrMode::Off {
            Vec::new()
        } else {
            cfg.route.relays.iter().filter(|u| nostr::url_ok(u)).cloned().collect()
        };

        let mut sc = SessionConfig::new(&room, if cfg.nick.is_empty() { "anon" } else { &cfg.nick });
        sc.colour = cfg.colour;
        sc.created = created;
        sc.verify_required = cfg.verify_required;
        sc.keeps_history = cfg.history;
        sc.timer = cfg.timer;
        sc.identity = cfg.identity.clone();
        sc.coming_back = cfg.kept;
        sc.net_log = cfg.net_log.unwrap_or(NetLog::Normal);
        sc.mode = cfg.route.mode;
        sc.port = port;
        sc.lan = lan.is_some();
        sc.dht_v4 = cfg.route.dht;
        sc.dht_v6 = cfg.route.dht && cfg.route.ipv6;
        sc.nostr = cfg.route.nostr.clone();
        sc.relays = relays.len();
        sc.static_peers = peers;
        if let Some(r) = cfg.rekey_interval {
            sc.rekey_interval = r;
        }
        sc.file_limit = cfg.files.limit;
        sc.fast_files = cfg.files.fast;
        sc.moved = cfg.moved.as_ref().map(|(key, _)| key.clone());
        sc.build = update::self_build().cloned();

        let clock = Clock::new();
        let mut session = Session::new(sc, keys, self.trust.clone(), clock.now());
        let file_options: files::SharedOptions = Arc::new(std::sync::Mutex::new(cfg.files.clone()));
        session.set_disk(Box::new(files::FsDisk {
            options: file_options.clone(),
        }));
        let info = RoomInfo {
            invite: names::invite(&room, &password),
            room,
            password,
            created,
            me: session.my_id(),
            nick: session.nick().to_string(),
            colour: session.colour(),
            mode: session.mode(),
            port,
            history: session.keeps_history(),
            verify_required: session.verify_required(),
            moved_from: cfg.moved.as_ref().map(|(_, from)| from.clone()),
            history_id: session.history_id(),
        };
        let (relay_tx, relay_rx) = mpsc::unbounded_channel();
        let (log_tx, net_log) = mpsc::unbounded_channel();
        let relays = (!relays.is_empty()).then(|| {
            let (tag, wrap, me) = session.relay_keys();
            nostr::Relays::spawn(&relays, tag, wrap, me, relay_tx, log_tx.clone(), tor.clone())
        });
        let (tor_tx, tor_rx) = mpsc::unbounded_channel();
        let portmap = (cfg.route.portmap && port != 0).then(|| portmap::PortMap::spawn(port, log_tx.clone()));
        let portmap_log = (cfg.route.portmap && port != 0).then(|| log_tx.clone());
        let tor = tor.map(|t| tor::RoomTor::spawn(t, session.tor_room_keys(), tor_tx, log_tx));
        let (ask_tx, asks) = mpsc::unbounded_channel();
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        let driver = Driver {
            session,
            udp,
            lan,
            relays,
            relay_rx,
            tor,
            tor_rx,
            net_log,
            asks,
            events: ev_tx,
            clock,
            move_to: None,
            portmap,
            portmap_log,
        };
        // The room's keys, chains and messages are allocated where they can't be swapped out.
        tokio::spawn(memlock::Locked(driver.run()));
        Ok((
            Room {
                tx: ask_tx,
                info: Arc::new(info),
                files: file_options,
                client: self.clone(),
                cfg: Arc::new(cfg),
            },
            RoomEvents(ev_rx),
        ))
    }
}

/// What happens in a room, in order. It ends once the room has closed.
pub struct RoomEvents(mpsc::UnboundedReceiver<Event>);

impl RoomEvents {
    pub async fn recv(&mut self) -> Option<Event> {
        self.0.recv().await
    }

    pub fn try_recv(&mut self) -> Option<Event> {
        self.0.try_recv().ok()
    }
}

/// A handle to an open room. Clones share the room; once every one is dropped, it leaves.
#[derive(Clone)]
pub struct Room {
    tx: mpsc::UnboundedSender<Ask>,
    info: Arc<RoomInfo>,
    files: files::SharedOptions,
    /// What opened it, for the room a move goes to.
    client: Client,
    cfg: Arc<RoomConfig>,
}

impl Room {
    pub fn info(&self) -> &RoomInfo {
        &self.info
    }

    pub async fn command(&self, cmd: Command) -> Result<Outcome, CommandError> {
        if let Command::Offer { path, asis } = cmd {
            return self.offer(&path, asis).await;
        }
        let (tx, rx) = oneshot::channel();
        self.tx.send(Ask::Command(cmd, tx)).map_err(|_| closed())?;
        rx.await.map_err(|_| closed())?
    }

    pub async fn send(&self, text: &str) -> Result<Outcome, CommandError> {
        self.command(Command::Send { text: text.into() }).await
    }

    pub async fn reply(&self, mid: &str, text: &str) -> Result<Outcome, CommandError> {
        self.command(Command::Reply {
            mid: mid.into(),
            text: text.into(),
        })
        .await
    }

    pub async fn dm(&self, peer: PeerId, text: &str) -> Result<Outcome, CommandError> {
        self.command(Command::Dm { peer, text: text.into() }).await
    }

    pub async fn verify(&self, peer: PeerId, same: bool) -> Result<Outcome, CommandError> {
        self.command(Command::Verify { peer, same }).await
    }

    /// Offers a file to the room. A picture goes cleaned of what could tell where, when or with
    /// what it was made, unless `asis`.
    pub async fn offer(&self, path: &str, asis: bool) -> Result<Outcome, CommandError> {
        let path = files::typed_path_here(path);
        let noise = self.files.lock().expect("file options").noise;
        let own = tokio::task::spawn_blocking(move || files::prepare(&path, asis, noise))
            .await
            .map_err(|_| closed())?
            .map_err(CommandError::Invalid)?;
        let (tx, rx) = oneshot::channel();
        self.tx.send(Ask::Offer(own, tx)).map_err(|_| closed())?;
        rx.await.map_err(|_| closed())?
    }

    /// Fetches file `num`: to show it (a picture) or to save it in `dir` (None: the room's folder,
    /// else Downloads). `anyway`: even over the size limit.
    pub async fn fetch(&self, num: u32, show: bool, anyway: bool, dir: Option<&str>) -> Result<Outcome, CommandError> {
        let dir = dir.map(files::typed_path_here);
        self.command(Command::Fetch { num, show, anyway, dir }).await
    }

    /// Stops fetching file `num`, or stops offering one of ours.
    pub async fn cancel(&self, num: u32) -> Result<Outcome, CommandError> {
        self.command(Command::Cancel { num }).await
    }

    /// Direct: the room's UDP port, or with Some, a move to another (0 picks a free one).
    pub async fn port(&self, want: Option<u16>) -> Result<u16, String> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Ask::Port(want, tx)).map_err(|_| "the room has closed".to_string())?;
        rx.await.map_err(|_| "the room has closed".to_string())?
    }

    /// New Tor circuits, and a new onion address that peers are told. False if the room doesn't
    /// go through Tor.
    pub async fn newtor(&self) -> bool {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Ask::NewTor(tx)).is_ok() && rx.await.unwrap_or(false)
    }

    /// Signs with another key from now on, or (None) stops signing.
    pub fn set_identity(&self, identity: Option<(IdentityKind, IdentityKeypair)>) {
        let _ = self.tx.send(Ask::SetIdentity(identity));
    }

    /// The files offered here and ours.
    pub async fn files(&self) -> Vec<FileInfo> {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Ask::Files(tx)).is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    /// A picture's bytes, if a copy here still matches its offer (shown before, saved, or ours).
    pub async fn picture(&self, num: u32) -> Option<Vec<u8>> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(Ask::Picture(num, tx)).ok()?;
        rx.await.ok().flatten()
    }

    pub fn file_options(&self) -> FileOptions {
        self.files.lock().expect("file options").clone()
    }

    /// Changes how this room handles files, at once.
    pub async fn set_file_options(&self, o: FileOptions) -> Result<Outcome, CommandError> {
        let (limit, fast) = (o.limit, o.fast);
        *self.files.lock().expect("file options") = o;
        self.command(Command::SetFileOptions { limit, fast }).await
    }

    /// Answers :move. `false` stays when a peer asked. `true` goes where a peer asked, or moves
    /// the room ourselves, with the peers whose codes were compared: the new room opens (its
    /// handle and events are returned, for the UI to use from now on), and this one stays only
    /// until those moving with us have our key and we theirs, then leaves on its own.
    pub async fn answer_move(&self, yes: bool) -> Result<Option<(Room, RoomEvents)>, CommandError> {
        if !yes {
            return self.command(Command::Move { answer: Some(false) }).await.map(|_| None);
        }
        let (tx, rx) = oneshot::channel();
        self.tx.send(Ask::MoveYes(tx)).map_err(|_| closed())?;
        let (to, nick, colour, history) = rx.await.map_err(|_| closed())??;
        let cfg = RoomConfig {
            room: Some(to.room.clone()),
            password: Some(to.password.clone()),
            invite: None,
            create: to.created,
            nick,
            colour: Some(colour),
            history,
            files: self.file_options(),
            moved: Some((to.key.clone(), to.from.clone())),
            // This room keeps its port while it lingers; the new one is found by discovery.
            route: Route {
                port: 0,
                peers: Vec::new(),
                ..self.cfg.route.clone()
            },
            ..(*self.cfg).clone()
        };
        let (room, events) = self
            .client
            .join(cfg)
            .await
            .map_err(|e| CommandError::Invalid(format!("couldn't open the new room: {e}")))?;
        self.tx.send(Ask::MoveGo(to, room.tx.clone())).map_err(|_| closed())?;
        // This room lingers for the keys of those moving with us, then leaves.
        let old = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let (tx, rx) = oneshot::channel();
                if old.tx.send(Ask::MoveFinished(tx)).is_err() || rx.await.unwrap_or(true) {
                    break;
                }
            }
            old.leave().await;
        });
        Ok(Some((room, events)))
    }

    pub async fn peers(&self) -> Vec<PeerInfo> {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Ask::Peers(tx)).is_err() {
            return Vec::new();
        }
        rx.await.unwrap_or_default()
    }

    pub async fn net(&self) -> NetStatus {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Ask::Net(tx)).is_err() {
            return NetStatus::default();
        }
        rx.await.unwrap_or_default()
    }

    /// The message timer kept to, and who asked for it.
    pub async fn timer(&self) -> (u32, Option<String>) {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Ask::Timer(tx)).is_err() {
            return (0, None);
        }
        rx.await.unwrap_or((0, None))
    }

    /// Leaves, telling everyone, and waits until the room has closed.
    pub async fn leave(&self) {
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Ask::Leave(tx)).is_ok() {
            let _ = rx.await;
        }
    }
}

fn closed() -> CommandError {
    CommandError::Invalid("the room has closed".into())
}
