// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Tor, embedded: Arti, the Tor Project's own Rust implementation, so nothing needs installing.
//!
//! Each room publishes an onion service of its own, with a new key every time, and when asked one
//! of the room's six services, whose keys every member derives from the id and password. Members
//! knock on the room's services to find the room, then connect to each other's own services.
//! Frames go over Tor streams, each after its length (two bytes, big-endian), at most 4096 bytes.
//!
//! Every room's streams use circuits of their own, and the onion keys live in memory only. Tor's
//! state (its guards and its copy of the directory) is kept in a private folder deleted on exit,
//! unless the client is given a folder to keep it in.

use super::bridges::Bridges;
use super::tor_ext::ExtTor;
use crate::protocol::crypto::{onion_address, sodium};
use crate::protocol::session::TorStatus;
use arti_client::TorClient;
use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::config::{TorClientConfig, TorClientConfigBuilder};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, timeout};
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hscrypto::pk::HsIdKeypair;
use tor_hsservice::{HsNickname, RunningOnionService, StreamRequest};
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::PreferredRuntime;
use zeroize::Zeroizing;

/// The port every member's service listens on.
pub const VPORT: u16 = 7474;
const FRAME_MAX: usize = 4096;
const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(120);
const STREAM_IDLE: Duration = Duration::from_secs(150);
/// A target whose streams fail is tried again after a delay that doubles each time, up to the max.
const RETRY_BASE: f64 = 5.0;
const RETRY_MAX: f64 = 80.0;
/// A stream still opening holds a few frames; any more are lost, as with UDP.
const OPENING_QUEUE: usize = 32;
const REPUBLISH_MIN_GAP: Duration = Duration::from_secs(60);

pub type Client = TorClient<PreferredRuntime>;

/// A folder only we can read, deleted when it's dropped.
struct PrivateDir(PathBuf, bool);

impl Drop for PrivateDir {
    fn drop(&mut self) {
        if self.1 {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

pub(crate) fn private_dir() -> std::io::Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("chat-tor-{}", crate::protocol::hex::encode(&sodium::random_array::<8>())));
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(&dir)?;
    Ok(dir)
}

/// Tor's configuration: its folders, onion addresses allowed, onion keys in memory only, and the
/// bridges.
fn config(base: &Path, bridges: &Bridges) -> Result<TorClientConfig, String> {
    let mut b = TorClientConfigBuilder::from_directories(base.join("state"), base.join("cache"));
    b.address_filter().allow_onion_addrs(true);
    b.storage().keystore().primary().kind(tor_config::ExplicitOrAuto::Explicit(
        tor_keymgr::config::ArtiKeystoreKind::Ephemeral,
    ));
    bridges.apply(&mut b)?;
    b.build().map_err(|e| format!("Tor's configuration: {e}"))
}

const STATE_MAGIC: &[u8; 4] = b"CTS1";

/// A folder's files as one blob: "CTS1", then for each file its path (u16 length, '/' between its
/// parts), then its bytes (u32 length).
pub fn pack_dir(dir: &Path) -> Vec<u8> {
    fn walk(base: &Path, rel: &str, out: &mut Vec<u8>) {
        let Ok(rd) = std::fs::read_dir(base.join(rel)) else { return };
        for e in rd.filter_map(|e| e.ok()) {
            let Ok(name) = e.file_name().into_string() else { continue };
            let path = if rel.is_empty() { name } else { format!("{rel}/{name}") };
            match e.file_type() {
                Ok(t) if t.is_dir() => walk(base, &path, out),
                Ok(t) if t.is_file() => {
                    if let Ok(data) = std::fs::read(base.join(&path))
                        && path.len() <= u16::MAX as usize
                        && data.len() <= u32::MAX as usize
                    {
                        out.extend_from_slice(&(path.len() as u16).to_be_bytes());
                        out.extend_from_slice(path.as_bytes());
                        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
                        out.extend_from_slice(&data);
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = STATE_MAGIC.to_vec();
    walk(dir, "", &mut out);
    out
}

/// A blob from [`pack_dir`] back into files under `dir`. Only paths that stay inside it are
/// written; false if it isn't such a blob.
pub fn unpack_dir(blob: &[u8], dir: &Path) -> bool {
    let Some(mut rest) = blob.strip_prefix(&STATE_MAGIC[..]) else {
        return false;
    };
    let take = |r: &mut &[u8], n: usize| -> Option<Vec<u8>> {
        let (a, b) = (r.get(..n)?, r.get(n..)?);
        *r = b;
        Some(a.to_vec())
    };
    while !rest.is_empty() {
        let Some(n) = take(&mut rest, 2).map(|b| u16::from_be_bytes([b[0], b[1]]) as usize) else {
            return false;
        };
        let Some(path) = take(&mut rest, n).and_then(|p| String::from_utf8(p).ok()) else {
            return false;
        };
        let Some(len) = take(&mut rest, 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize) else {
            return false;
        };
        let Some(data) = take(&mut rest, len) else { return false };
        if path.split('/').any(|c| c.is_empty() || c == "." || c == ".." || c.contains('\\')) {
            return false;
        }
        let target = dir.join(&path);
        if let Some(parent) = target.parent() {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            if b.create(parent).is_err() {
                return false;
            }
        }
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        if o.open(&target).and_then(|mut f| std::io::Write::write_all(&mut f, &data)).is_err() {
            return false;
        }
    }
    true
}

/// A stream through Tor: the built-in one's, or a running tor's.
pub trait TorStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TorStream for T {}
pub type BoxStream = Box<dyn TorStream>;

/// The Tor a whole client shares between its rooms: the built-in one, or a tor that's already
/// running (see [`super::tor_ext`]).
pub struct Tor {
    backend: Backend,
}

enum Backend {
    BuiltIn(Arc<Client>, PrivateDir),
    /// A tor that was running, or one chat started (with its folder).
    Running(Arc<ExtTor>, Option<PrivateDir>),
}

/// A room's own circuits: an isolated client of the built-in Tor, or SOCKS credentials of its own
/// for a running tor.
enum Iso {
    BuiltIn(Arc<Client>),
    Running(Arc<ExtTor>, String),
}

impl Iso {
    fn new(tor: &Tor) -> Iso {
        match &tor.backend {
            Backend::BuiltIn(c, _) => Iso::BuiltIn(c.isolated_client()),
            Backend::Running(e, _) => Iso::Running(e.clone(), crate::protocol::hex::encode(&sodium::random_array::<8>())),
        }
    }

    async fn connect(&self, host: &str, port: u16) -> Result<BoxStream, String> {
        match self {
            Iso::BuiltIn(c) => c
                .connect((host, port))
                .await
                .map(|s| Box::new(s) as BoxStream)
                .map_err(|e| e.to_string()),
            Iso::Running(e, user) => e.stream(host, port, user).await.map(|s| Box::new(s) as BoxStream),
        }
    }
}

/// An onion service of ours: the built-in Tor's, one a running tor hosts, or one being set up.
/// Held, not read: dropping one takes its service down.
#[allow(dead_code)]
enum Svc {
    BuiltIn(Arc<RunningOnionService>),
    Running(RunningOnion),
    Starting,
}

/// A service a running tor hosts for us: taken down when it's dropped.
struct RunningOnion {
    tor: Arc<ExtTor>,
    id: String,
    accept: tokio::task::JoinHandle<()>,
}

impl Drop for RunningOnion {
    fn drop(&mut self) {
        self.accept.abort();
        let (tor, id) = (self.tor.clone(), std::mem::take(&mut self.id));
        tokio::spawn(async move { tor.del_onion(&id).await });
    }
}

impl Tor {
    /// Starts Tor and begins connecting to the Tor network in the background, only through the
    /// bridges if there are any. `keep`: a folder to keep its state in between runs (the same entry
    /// guards, a quicker start); otherwise a private one that's deleted on exit.
    /// `dir`: a folder to keep its state in, and whether it's ours to delete on exit.
    pub fn start(dir: Option<(PathBuf, bool)>, bridges: &Bridges) -> Result<Arc<Tor>, String> {
        let (base, owned) = match dir {
            Some(d) => d,
            None => (private_dir().map_err(|e| format!("can't make Tor's folder: {e}"))?, true),
        };
        let dir = PrivateDir(base, owned);
        let client = TorClient::builder()
            .config(config(&dir.0, bridges)?)
            .create_unbootstrapped()
            .map_err(|e| format!("can't start Tor: {e}"))?;
        let c = client.clone();
        tokio::spawn(async move {
            let _ = c.bootstrap().await;
        });
        Ok(Arc::new(Tor {
            backend: Backend::BuiltIn(client, dir),
        }))
    }

    /// A tor that's already running, logged in to.
    pub fn running(tor: Arc<ExtTor>) -> Arc<Tor> {
        Arc::new(Tor {
            backend: Backend::Running(tor, None),
        })
    }

    /// The tor program at `program`, started as chat's own tor, its data in `dir` (or a private
    /// folder deleted on exit).
    pub async fn launched(program: &str, dir: Option<(PathBuf, bool)>, bridges: &Bridges) -> Result<Arc<Tor>, String> {
        let (base, owned) = match dir {
            Some(d) => d,
            None => (private_dir().map_err(|e| format!("can't make tor's folder: {e}"))?, true),
        };
        let dir = PrivateDir(base, owned);
        let ext = super::tor_ext::launch(program, &dir.0, bridges).await?;
        Ok(Arc::new(Tor {
            backend: Backend::Running(ext, Some(dir)),
        }))
    }

    /// New bridges for a running Tor: new circuits go only through them (or, with none, through
    /// the usual entry guards). Those already open run on until they close. Nothing changes if
    /// Tor won't take them.
    pub fn set_bridges(&self, bridges: &Bridges) -> Result<(), String> {
        match &self.backend {
            Backend::BuiltIn(c, dir) => c
                .reconfigure(&config(&dir.0, bridges)?, tor_config::Reconfigure::AllOrNothing)
                .map_err(|e| format!("Tor won't take them: {e}")),
            Backend::Running(..) => Err("chat is using a running tor, whose bridges are set in its own torrc".into()),
        }
    }

    /// Whether it's a tor that was already running, not chat's own.
    pub fn is_running(&self) -> bool {
        matches!(self.backend, Backend::Running(..))
    }

    /// Its folder's files packed together, for a save to keep (see [`unpack_dir`]). Nothing for a
    /// running tor, which keeps its own.
    pub fn state(&self) -> Vec<u8> {
        match &self.backend {
            Backend::BuiltIn(_, dir) | Backend::Running(_, Some(dir)) => pack_dir(&dir.0),
            Backend::Running(_, None) => Vec::new(),
        }
    }

    /// Whether it has reached the Tor network and can carry traffic.
    pub fn ready(&self) -> bool {
        match &self.backend {
            Backend::BuiltIn(c, _) => c.bootstrap_status().ready_for_traffic(),
            Backend::Running(e, _) => e.ready(),
        }
    }

    /// How far it has got, for the network report.
    pub fn progress(&self) -> String {
        match &self.backend {
            Backend::BuiltIn(c, _) => c.bootstrap_status().to_string(),
            Backend::Running(e, _) => e.progress(),
        }
    }

    /// A stream through Tor on circuits of its own (a relay connection, say).
    pub async fn connect_isolated(&self, host: &str, port: u16) -> Result<BoxStream, String> {
        Iso::new(self).connect(host, port).await
    }
}

/// What a room asks of its Tor transport.
pub enum TorCmd {
    Send([u8; 16], Vec<u8>),
    Host(Option<u8>),
    Republish,
    Target([u8; 16], String),
    /// :newtor: new circuits for the streams we open, and a new onion address for ours.
    Renew,
}

/// One room's Tor: its services and streams. Dropping it takes them down.
pub struct RoomTor {
    tx: mpsc::UnboundedSender<TorCmd>,
    pub status: watch::Receiver<TorStatus>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for RoomTor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl RoomTor {
    /// Frames from members come out on `deliver`, by stream id; the transport's news on `log`.
    pub fn spawn(
        tor: Arc<Tor>,
        room_keys: Vec<(Zeroizing<[u8; 64]>, [u8; 32])>,
        deliver: mpsc::UnboundedSender<([u8; 16], Vec<u8>)>,
        log: mpsc::UnboundedSender<String>,
    ) -> RoomTor {
        let (tx, rx) = mpsc::unbounded_channel();
        let (status_tx, status) = watch::channel(TorStatus::default());
        let mut targets = HashMap::new();
        let mut room_ids = Vec::new();
        for (_, public) in &room_keys {
            let onion = onion_address(public);
            let id = crate::protocol::crypto::tor_target_id(&onion);
            room_ids.push(id);
            targets.insert(
                id,
                Target {
                    onion,
                    next_try: Instant::now(),
                    fails: 0,
                    opened: false,
                },
            );
        }
        let (inner_tx, inner_rx) = mpsc::unbounded_channel();
        let task = Task {
            client: Iso::new(&tor),
            tor,
            keys: room_keys,
            targets,
            room_ids,
            streams: HashMap::new(),
            inner_tx,
            me: None,
            room: None,
            last_republish: Instant::now(),
            status_tx,
            deliver,
            log,
            told_ready: false,
        };
        let task = tokio::spawn(task.run(rx, inner_rx));
        RoomTor { tx, status, task }
    }

    pub fn send(&self, cmd: TorCmd) {
        let _ = self.tx.send(cmd);
    }
}

struct Target {
    onion: String,
    next_try: Instant,
    fails: u32,
    /// A stream to it opened once: someone hosts it.
    opened: bool,
}

enum Stream {
    Opening(Vec<Vec<u8>>),
    Open(mpsc::UnboundedSender<Vec<u8>>),
}

/// What the stream and service tasks tell the room's task.
enum Inner {
    Connected([u8; 16], Result<BoxStream, String>),
    Incoming(BoxStream),
    Closed([u8; 16]),
    /// A running tor's answer to hosting our service (None) or the room's (its slot).
    Hosted(Option<u8>, Result<(String, tokio::net::TcpListener), String>),
}

struct Task {
    tor: Arc<Tor>,
    client: Iso,
    keys: Vec<(Zeroizing<[u8; 64]>, [u8; 32])>,
    targets: HashMap<[u8; 16], Target>,
    room_ids: Vec<[u8; 16]>,
    streams: HashMap<[u8; 16], Stream>,
    inner_tx: mpsc::UnboundedSender<Inner>,
    me: Option<(Svc, String)>,
    room: Option<(Svc, u8)>,
    last_republish: Instant,
    status_tx: watch::Sender<TorStatus>,
    deliver: mpsc::UnboundedSender<([u8; 16], Vec<u8>)>,
    log: mpsc::UnboundedSender<String>,
    told_ready: bool,
}

fn nickname(kind: &str) -> HsNickname {
    HsNickname::new(format!(
        "chat-{kind}-{}",
        crate::protocol::hex::encode(&sodium::random_array::<6>())
    ))
    .expect("a valid nickname")
}

impl Task {
    async fn run(mut self, mut rx: mpsc::UnboundedReceiver<TorCmd>, mut inner: mpsc::UnboundedReceiver<Inner>) {
        let _ = self.log.send("tor: connecting to the Tor network".into());
        self.launch_me();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                cmd = rx.recv() => match cmd {
                    None => return,
                    Some(c) => self.command(c),
                },
                Some(i) = inner.recv() => self.inner(i),
                _ = tick.tick() => {
                    if !self.told_ready && self.tor.ready() {
                        self.told_ready = true;
                        let _ = self.log.send("tor: connected to the Tor network".into());
                    }
                }
            }
            self.publish_status();
        }
    }

    fn publish_status(&self) {
        let now = Instant::now();
        let mut busy: Vec<[u8; 16]> = self.streams.keys().copied().collect();
        busy.extend(self.targets.iter().filter(|(_, t)| now < t.next_try).map(|(id, _)| *id));
        busy.sort();
        busy.dedup();
        let status = TorStatus {
            ready: self.tor.ready(),
            onion: self
                .me
                .as_ref()
                .filter(|(s, _)| !matches!(s, Svc::Starting))
                .map(|(_, o)| o.clone()),
            hosted_slot: self.room.as_ref().filter(|(s, _)| !matches!(s, Svc::Starting)).map(|(_, s)| *s),
            busy,
        };
        if *self.status_tx.borrow() != status {
            let _ = self.status_tx.send(status);
        }
    }

    /// Our own service, with a new key: what peers connect to once they know it.
    fn launch_me(&mut self) {
        let client = match &self.client {
            Iso::BuiltIn(c) => c.clone(),
            Iso::Running(e, _) => {
                self.me = Some((Svc::Starting, String::new()));
                let (e, tx) = (e.clone(), self.inner_tx.clone());
                tokio::spawn(async move {
                    let _ = tx.send(Inner::Hosted(None, e.add_onion(None, VPORT).await));
                });
                return;
            }
        };
        let Ok(config) = OnionServiceConfigBuilder::default().nickname(nickname("me")).build() else {
            return;
        };
        match client.launch_onion_service(config) {
            Ok(Some((svc, requests))) => {
                let Some(id) = svc.onion_address() else { return };
                let public: [u8; 32] = *id.as_ref();
                let onion = onion_address(&public);
                let _ = self.log.send("tor: our onion service is starting".into());
                self.accept(requests);
                self.me = Some((Svc::BuiltIn(svc), onion));
            }
            Ok(None) => {}
            Err(e) => {
                let _ = self.log.send(format!("tor: can't start our onion service: {e}"));
            }
        }
    }

    /// One of the room's services, with the key every member derives: the one asked for, or one
    /// nobody answered on (not the maker's while others are free).
    fn host(&mut self, slot: Option<u8>) {
        if self.room.is_some() {
            return;
        }
        let slot = slot.unwrap_or_else(|| {
            let free: Vec<u8> = (1..self.room_ids.len() as u8)
                .filter(|&s| !self.targets[&self.room_ids[usize::from(s)]].opened)
                .collect();
            if free.is_empty() {
                1 + sodium::random_below(self.room_ids.len() as u32 - 1) as u8
            } else {
                free[sodium::random_below(free.len() as u32) as usize]
            }
        });
        self.launch_room(slot);
    }

    fn launch_room(&mut self, slot: u8) {
        let Some((expanded, _)) = self.keys.get(usize::from(slot)) else {
            return;
        };
        let client = match &self.client {
            Iso::BuiltIn(c) => c.clone(),
            Iso::Running(e, _) => {
                self.room = Some((Svc::Starting, slot));
                let (e, tx, key) = (e.clone(), self.inner_tx.clone(), expanded.clone());
                tokio::spawn(async move {
                    let _ = tx.send(Inner::Hosted(Some(slot), e.add_onion(Some(&key), VPORT).await));
                });
                return;
            }
        };
        let Some(keypair) = ExpandedKeypair::from_secret_key_bytes(**expanded) else {
            return;
        };
        let Ok(config) = OnionServiceConfigBuilder::default().nickname(nickname("room")).build() else {
            return;
        };
        match client.launch_onion_service_with_hsid(config, HsIdKeypair::from(keypair)) {
            Ok(Some((svc, requests))) => {
                let _ = self.log.send(format!("tor: hosting the room's onion service {slot}"));
                self.accept(requests);
                self.room = Some((Svc::BuiltIn(svc), slot));
                self.last_republish = Instant::now();
            }
            Ok(None) => {}
            Err(e) => {
                let _ = self.log.send(format!("tor: can't host the room's onion service: {e}"));
            }
        }
    }

    /// Streams to a service, to port 7474 only.
    fn accept(&self, requests: impl futures_util::Stream<Item = tor_hsservice::RendRequest> + Send + 'static) {
        let tx = self.inner_tx.clone();
        tokio::spawn(async move {
            let mut streams = std::pin::pin!(tor_hsservice::handle_rend_requests(requests));
            while let Some(req) = streams.next().await {
                let req: StreamRequest = req;
                let ok = matches!(req.request(), IncomingStreamRequest::Begin(b) if b.port() == VPORT);
                if !ok {
                    let _ = req.reject(End::new_with_reason(EndReason::DONE)).await;
                    continue;
                }
                if let Ok(stream) = req.accept(Connected::new_empty()).await
                    && tx.send(Inner::Incoming(Box::new(stream))).is_err()
                {
                    return;
                }
            }
        });
    }

    fn command(&mut self, cmd: TorCmd) {
        match cmd {
            TorCmd::Send(id, frame) => self.send(id, frame),
            TorCmd::Host(slot) => self.host(slot),
            TorCmd::Republish => {
                // Whoever published the room's service last may have gone: ours goes up again.
                // A running tor publishes its services again by itself.
                if let Some((Svc::BuiltIn(_), slot)) = &self.room
                    && self.last_republish.elapsed() > REPUBLISH_MIN_GAP
                {
                    let slot = *slot;
                    self.room = None;
                    self.launch_room(slot);
                }
            }
            TorCmd::Renew => {
                // Streams peers opened to us stay, since they're how those peers reach us; ours
                // close, and open again on new circuits.
                self.client = Iso::new(&self.tor);
                if let Iso::Running(e, _) = &self.client {
                    let e = e.clone();
                    tokio::spawn(async move { e.newnym().await });
                }
                let targets = &mut self.targets;
                self.streams.retain(|id, _| !targets.contains_key(id));
                for t in targets.values_mut() {
                    t.next_try = Instant::now();
                }
                // Dropping the old service takes its onion down; the session tells peers the new one.
                self.me = None;
                self.launch_me();
            }
            TorCmd::Target(id, onion) => {
                self.targets.entry(id).or_insert(Target {
                    onion,
                    next_try: Instant::now(),
                    fails: 0,
                    opened: false,
                });
            }
        }
    }

    fn send(&mut self, id: [u8; 16], frame: Vec<u8>) {
        if frame.is_empty() || frame.len() > FRAME_MAX {
            return;
        }
        match self.streams.get_mut(&id) {
            Some(Stream::Open(tx)) => {
                let _ = tx.send(frame);
            }
            Some(Stream::Opening(q)) => {
                if q.len() < OPENING_QUEUE {
                    q.push(frame);
                }
            }
            None => self.open(id, frame),
        }
    }

    /// A stream to a target, opened on demand.
    fn open(&mut self, id: [u8; 16], frame: Vec<u8>) {
        let Some(t) = self.targets.get_mut(&id) else { return };
        let now = Instant::now();
        if now < t.next_try {
            return;
        }
        // Until it opens, no second one.
        t.next_try = now + STREAM_OPEN_TIMEOUT;
        let host = format!("{}.onion", t.onion);
        self.streams.insert(id, Stream::Opening(vec![frame]));
        let (client, tx) = (
            match &self.client {
                Iso::BuiltIn(c) => Iso::BuiltIn(c.clone()),
                Iso::Running(e, u) => Iso::Running(e.clone(), u.clone()),
            },
            self.inner_tx.clone(),
        );
        tokio::spawn(async move {
            let r = match timeout(STREAM_OPEN_TIMEOUT, client.connect(&host, VPORT)).await {
                Ok(r) => r,
                Err(_) => Err("timed out".into()),
            };
            let _ = tx.send(Inner::Connected(id, r));
        });
    }

    fn inner(&mut self, i: Inner) {
        match i {
            Inner::Connected(id, Ok(stream)) => {
                let queued = match self.streams.remove(&id) {
                    Some(Stream::Opening(q)) => q,
                    _ => Vec::new(),
                };
                if let Some(t) = self.targets.get_mut(&id) {
                    t.fails = 0;
                    t.opened = true;
                    t.next_try = Instant::now();
                }
                let tx = self.run_stream(id, stream);
                for f in queued {
                    let _ = tx.send(f);
                }
                self.streams.insert(id, Stream::Open(tx));
            }
            Inner::Connected(id, Err(e)) => {
                self.streams.remove(&id);
                if let Some(t) = self.targets.get_mut(&id) {
                    let delay = (RETRY_BASE * f64::from(1u32 << t.fails.min(4))).min(RETRY_MAX);
                    t.fails += 1;
                    t.next_try = Instant::now() + Duration::from_secs_f64(delay);
                    if t.fails == 1 && !self.room_ids.contains(&id) {
                        let _ = self.log.send(format!("tor: can't reach a member's onion service yet ({e})"));
                    }
                }
            }
            Inner::Incoming(stream) => {
                let id: [u8; 16] = sodium::random_array();
                let tx = self.run_stream(id, stream);
                self.streams.insert(id, Stream::Open(tx));
            }
            Inner::Closed(id) => {
                self.streams.remove(&id);
            }
            Inner::Hosted(slot, r) => self.hosted(slot, r),
        }
    }

    /// A running tor has set up a service of ours, or couldn't. One set up after it stopped being
    /// wanted (a :newtor since) goes again at once.
    fn hosted(&mut self, slot: Option<u8>, r: Result<(String, tokio::net::TcpListener), String>) {
        let Backend::Running(tor, _) = &self.tor.backend else { return };
        let wanted = match slot {
            None => matches!(self.me, Some((Svc::Starting, _))),
            Some(s) => matches!(self.room, Some((Svc::Starting, x)) if x == s),
        };
        let (id, listener) = match r {
            Ok(ok) => ok,
            Err(e) => {
                let _ = self.log.send(format!(
                    "tor: can't host {}: {e}",
                    if slot.is_some() {
                        "the room's onion service"
                    } else {
                        "our onion service"
                    }
                ));
                if wanted {
                    match slot {
                        None => self.me = None,
                        Some(_) => self.room = None,
                    }
                }
                return;
            }
        };
        // Only tor itself connects, from this machine.
        let tx = self.inner_tx.clone();
        let accept = tokio::spawn(async move {
            while let Ok((s, from)) = listener.accept().await {
                if from.ip().is_loopback() && tx.send(Inner::Incoming(Box::new(s))).is_err() {
                    return;
                }
            }
        });
        let svc = Svc::Running(RunningOnion {
            tor: tor.clone(),
            id: id.clone(),
            accept,
        });
        if !wanted {
            return;
        }
        match slot {
            None => {
                let _ = self.log.send("tor: our onion service is starting".into());
                self.me = Some((svc, id));
            }
            Some(s) => {
                let _ = self.log.send(format!("tor: hosting the room's onion service {s}"));
                self.room = Some((svc, s));
                self.last_republish = Instant::now();
            }
        }
    }

    /// Reads frames off a stream and writes ours to it, until either side ends it or it goes quiet.
    fn run_stream(&self, id: [u8; 16], stream: BoxStream) -> mpsc::UnboundedSender<Vec<u8>> {
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (deliver, inner) = (self.deliver.clone(), self.inner_tx.clone());
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(stream);
            let reader = async {
                loop {
                    let mut len = [0u8; 2];
                    if !matches!(timeout(STREAM_IDLE, r.read_exact(&mut len)).await, Ok(Ok(_))) {
                        return;
                    }
                    let n = usize::from(u16::from_be_bytes(len));
                    if n == 0 || n > FRAME_MAX {
                        return;
                    }
                    let mut frame = vec![0u8; n];
                    if r.read_exact(&mut frame).await.is_err() || deliver.send((id, frame)).is_err() {
                        return;
                    }
                }
            };
            let writer = async {
                while let Some(f) = rx.recv().await {
                    let mut buf = Vec::with_capacity(2 + f.len());
                    buf.extend_from_slice(&(f.len() as u16).to_be_bytes());
                    buf.extend_from_slice(&f);
                    if w.write_all(&buf).await.is_err() || w.flush().await.is_err() {
                        return;
                    }
                }
            };
            tokio::select! {
                _ = reader => {}
                _ = writer => {}
            }
            let _ = inner.send(Inner::Closed(id));
        });
        tx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_packs_and_unpacks_inside_its_folder_only() {
        let base = std::env::temp_dir().join(format!(
            "chat-tor-test-{}",
            crate::protocol::hex::encode(&sodium::random_array::<6>())
        ));
        let (a, b) = (base.join("a"), base.join("b"));
        std::fs::create_dir_all(a.join("state/x")).unwrap();
        std::fs::write(a.join("state/x/guards.json"), b"{}").unwrap();
        std::fs::write(a.join("cache.db"), vec![7u8; 1000]).unwrap();
        let blob = pack_dir(&a);
        std::fs::create_dir_all(&b).unwrap();
        assert!(unpack_dir(&blob, &b));
        assert_eq!(std::fs::read(b.join("state/x/guards.json")).unwrap(), b"{}");
        assert_eq!(std::fs::read(b.join("cache.db")).unwrap().len(), 1000);
        let mut evil = STATE_MAGIC.to_vec();
        evil.extend_from_slice(&5u16.to_be_bytes());
        evil.extend_from_slice(b"../xx");
        evil.extend_from_slice(&0u32.to_be_bytes());
        assert!(!unpack_dir(&evil, &b));
        assert!(!base.join("xx").exists());
        let _ = std::fs::remove_dir_all(base);
    }
}
