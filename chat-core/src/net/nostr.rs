// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Datagrams over Nostr relays, for peers that can't reach each other directly.
//!
//! Relays see as little as possible. Each datagram is one ephemeral event, signed with a key
//! made for that event alone, with a random ephemeral kind and a timestamp a few seconds off.
//! Its one tag changes every ten minutes and only room members can work it out. Its content is
//! the same size every time: sender, recipient, datagram and random padding, sealed under the
//! room's wrap key. So a relay can't tell which events come from whom, who they're for, or what
//! they hold. Each ten-minute tag gets its own connection to each relay, with its own
//! subscription id; around the change the next opens a little early and the last closes a
//! little late, to allow for clocks that differ.

use crate::protocol::PeerId;
use crate::protocol::crypto::{NOSTR_WRAP_PLAIN, nostr_tag, nostr_unwrap, nostr_wrap, sodium};
use crate::protocol::{base64, hex};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use zeroize::Zeroizing;

pub const DEFAULT_RELAYS: &[&str] = &["wss://relay.primal.net", "wss://relay.snort.social", "wss://relay.nostr.net"];
pub const MAX_RELAYS: usize = 6;

const EPOCH: u64 = 600;
/// The next ten minutes' connection opens up to this long before they start, the last one
/// closes up to this long after they end.
const LEAD: f64 = 120.0;
const TAIL: f64 = 120.0;
/// A subscription asks for what came this long before it.
const REQ_SINCE: u64 = 120;
/// An event's time is moved back by up to this, at random.
const CREATED_FUZZ: u32 = 30;
const STEP_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(100);
const PING_EVERY: Duration = Duration::from_secs(30);
const RESUB_DELAY: Duration = Duration::from_secs(30);
const BACKOFF_BASE: f64 = 5.0;
const BACKOFF_MAX: f64 = 300.0;
/// A connection that lasted this long was fine, so the backoff starts again.
const CONN_GOOD_AFTER: f64 = 60.0;
/// Relays rate limit writes, some strictly: a handshake is a short burst, and normal traffic one
/// event per peer every few seconds.
const SEND_RATE: f64 = 0.5;
const SEND_BURST: f64 = 8.0;
const PAUSE_MIN: f64 = 30.0;
const PAUSE_MAX: f64 = 900.0;
/// Refusals without a known reason before a relay is only read from.
const ODD_REFUSALS_MAX: u32 = 3;
const SEEN_IDS: usize = 512;
const KIND_EPHEMERAL: u32 = 20000;
const KIND_EPHEMERAL_END: u32 = 30000;
const KIND_AUTH: u32 = 22242;
const ID_LEN: usize = 16;
const WRAP_HDR: usize = 2 * ID_LEN + 2;
/// The largest datagram an event carries.
pub const DGRAM_MAX: usize = NOSTR_WRAP_PLAIN - WRAP_HDR;

/// Whether chat can use a relay URL: `wss://host[:port][/path]`, or `ws://` to a local test relay.
pub fn url_ok(url: &str) -> bool {
    let rest = match url.strip_prefix("wss://").or_else(|| url.strip_prefix("ws://")) {
        Some(r) => r,
        None => return false,
    };
    let host_end = rest.find([':', '/']).unwrap_or(rest.len());
    let host = &rest[..host_end];
    if host.is_empty() || host.len() >= 100 || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
        return false;
    }
    let mut p = &rest[host_end..];
    if let Some(port) = p.strip_prefix(':') {
        let digits: String = port.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() || digits.len() > 5 || !matches!(digits.parse::<u32>(), Ok(1..=65535)) {
            return false;
        }
        p = &port[digits.len()..];
    }
    (p.is_empty() || p.starts_with('/')) && p.len() < 128 && p.bytes().all(|b| b > 0x20 && b < 0x7f)
}

fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest[..rest.find([':', '/']).unwrap_or(rest.len())].to_string()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn random_seconds(max: f64) -> f64 {
    f64::from(sodium::random_below((max * 1000.0) as u32)) / 1000.0
}

/// Kinds 20000-29999 are ephemeral: relays pass them on and don't keep them. A few mean
/// something relays act on; the rest are picked at random, so the kind says nothing.
fn random_kind() -> u32 {
    loop {
        let k = KIND_EPHEMERAL + sodium::random_below(KIND_EPHEMERAL_END - KIND_EPHEMERAL);
        let reserved = k == KIND_AUTH || matches!(k, 23194 | 23195 | 24133 | 27235) || (21000..21100).contains(&k);
        if !reserved {
            return k;
        }
    }
}

/// An event signed with a key made just for it (NIP-01, BIP-340).
fn build_event(kind: u32, tags: Value, content: &str) -> Option<Value> {
    let kp = loop {
        let sk = Zeroizing::new(sodium::random_array::<32>());
        if let Ok(kp) = secp256k1::Keypair::from_secret_bytes(*sk) {
            break kp;
        }
    };
    let pk = hex::encode(&kp.x_only_public_key().0.to_byte_array());
    // Slightly off the real time, so it doesn't show exactly when it was written.
    let created = unix_now().saturating_sub(u64::from(sodium::random_below(CREATED_FUZZ)));
    let ser = serde_json::to_string(&json!([0, pk, created, kind, tags, content])).ok()?;
    let id = sodium::sha256(&[ser.as_bytes()]);
    let aux: [u8; 32] = sodium::random_array();
    let sig = secp256k1::schnorr::sign_with_aux_rand(&id, &kp, &aux);
    Some(json!({
        "id": hex::encode(&id),
        "pubkey": pk,
        "created_at": created,
        "kind": kind,
        "tags": tags,
        "content": content,
        "sig": hex::encode(&sig.to_byte_array()),
    }))
}

/// What the room shares on the relays, and what came lately.
struct Shared {
    tag_key: Zeroizing<[u8; 32]>,
    wrap_key: Zeroizing<[u8; 32]>,
    my_id: PeerId,
    /// The start of each event's sealed content seen lately: every relay sends its own copy, and
    /// our own events come back to us.
    seen: Mutex<VecDeque<[u8; 8]>>,
    deliver: mpsc::UnboundedSender<(PeerId, Vec<u8>)>,
    log: mpsc::UnboundedSender<String>,
}

impl Shared {
    fn seen_before(&self, id: [u8; 8]) -> bool {
        let mut seen = self.seen.lock().expect("seen lock");
        if seen.contains(&id) {
            return true;
        }
        if seen.len() >= SEEN_IDS {
            seen.pop_front();
        }
        seen.push_back(id);
        false
    }

    fn on_event(&self, ev: &Value, tag: &str) {
        let Some(content) = ev.get("content").and_then(Value::as_str) else {
            return;
        };
        if content.len() != base64::encoded_len(crate::protocol::crypto::NOSTR_WRAP_LEN) {
            return;
        }
        let Some(kind) = ev.get("kind").and_then(Value::as_u64) else {
            return;
        };
        if !(u64::from(KIND_EPHEMERAL)..u64::from(KIND_EPHEMERAL_END)).contains(&kind) {
            return;
        }
        let ours = ev.get("tags").and_then(Value::as_array).is_some_and(|tags| {
            tags.iter()
                .any(|t| t.get(0).and_then(Value::as_str) == Some("e") && t.get(1).and_then(Value::as_str) == Some(tag))
        });
        if !ours {
            return;
        }
        // The relay checks the signature itself. Ours is the wrap, which only members can seal:
        // a throwaway key's signature proves nothing more.
        let Some(wrapped) = base64::decode_strict(content) else { return };
        if self.seen_before(wrapped[..8].try_into().expect("8 bytes")) {
            return;
        }
        let Some(plain) = nostr_unwrap(&self.wrap_key, &wrapped) else {
            return;
        };
        let from = PeerId(plain[..ID_LEN].try_into().expect("16 bytes"));
        let to = PeerId(plain[ID_LEN..2 * ID_LEN].try_into().expect("16 bytes"));
        let len = usize::from(u16::from_be_bytes([plain[2 * ID_LEN], plain[2 * ID_LEN + 1]]));
        if from == self.my_id || from == PeerId::EVERYONE || (to != self.my_id && to != PeerId::EVERYONE) || len == 0 || len > DGRAM_MAX {
            return;
        }
        let _ = self.deliver.send((from, plain[WRAP_HDR..WRAP_HDR + len].to_vec()));
    }
}

/// What a connection tells its relay.
enum ConnEvent {
    Open,
    /// The relay took or refused an event.
    Ok {
        accepted: bool,
        why: String,
    },
    Closed {
        why: String,
        lasted: f64,
    },
}

struct Conn {
    epoch: u64,
    tag: String,
    open: bool,
    out: mpsc::UnboundedSender<String>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Relay {
    url: String,
    host: String,
    conns: Vec<Conn>,
    next_try: f64,
    fails: u32,
    warned: bool,
    refusals: u32,
    tokens: f64,
    tokens_at: f64,
    paused_until: f64,
    pause: f64,
    read_only: bool,
    odd_refusals: u32,
    plan_epoch: Option<u64>,
    open_next_at: f64,
    close_last_at: f64,
}

pub enum RelayCmd {
    /// A frame to one member, or with [`PeerId::EVERYONE`], to all.
    Send {
        to: PeerId,
        frame: Vec<u8>,
    },
    Active(bool),
    /// Close every connection and open them again.
    Reconnect,
}

/// The relays for one room. Dropping it closes every connection.
pub struct Relays {
    pub tx: mpsc::UnboundedSender<RelayCmd>,
    /// How many relays have a connection open.
    pub up: watch::Receiver<usize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Relays {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Relays {
    /// Starts the relays, inactive until [`RelayCmd::Active`] turns them on. Frames from members
    /// arrive on `deliver`, and the relays' news on `log`.
    pub fn spawn(
        urls: &[String],
        tag_key: [u8; 32],
        wrap_key: [u8; 32],
        my_id: PeerId,
        deliver: mpsc::UnboundedSender<(PeerId, Vec<u8>)>,
        log: mpsc::UnboundedSender<String>,
        via: Option<Arc<crate::net::tor::Tor>>,
    ) -> Relays {
        let shared = Arc::new(Shared {
            tag_key: Zeroizing::new(tag_key),
            wrap_key: Zeroizing::new(wrap_key),
            my_id,
            seen: Mutex::new(VecDeque::new()),
            deliver,
            log,
        });
        let relays: Vec<Relay> = urls
            .iter()
            .filter(|u| url_ok(u))
            .take(MAX_RELAYS)
            .map(|u| Relay {
                url: u.clone(),
                host: host_of(u),
                conns: Vec::new(),
                next_try: 0.0,
                fails: 0,
                warned: false,
                refusals: 0,
                tokens: SEND_BURST,
                tokens_at: 0.0,
                paused_until: 0.0,
                pause: 0.0,
                read_only: false,
                odd_refusals: 0,
                plan_epoch: None,
                open_next_at: 0.0,
                close_last_at: 0.0,
            })
            .collect();
        let (tx, rx) = mpsc::unbounded_channel();
        let (up_tx, up) = watch::channel(0);
        let task = tokio::spawn(manager(relays, shared, rx, up_tx, via));
        Relays { tx, up, task }
    }

    pub fn send(&self, to: PeerId, frame: Vec<u8>) {
        let _ = self.tx.send(RelayCmd::Send { to, frame });
    }

    pub fn set_active(&self, on: bool) {
        let _ = self.tx.send(RelayCmd::Active(on));
    }
}

async fn manager(
    mut relays: Vec<Relay>,
    shared: Arc<Shared>,
    mut rx: mpsc::UnboundedReceiver<RelayCmd>,
    up: watch::Sender<usize>,
    via: Option<Arc<crate::net::tor::Tor>>,
) {
    let start = Instant::now();
    let clock = move || start.elapsed().as_secs_f64();
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<(usize, u64, ConnEvent)>();
    let mut active = false;
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        tokio::select! {
            cmd = rx.recv() => match cmd {
                None => return,
                Some(RelayCmd::Active(on)) if on != active => {
                    active = on;
                    for r in &mut relays {
                        r.conns.clear();
                        r.next_try = 0.0;
                        r.plan_epoch = None;
                    }
                    let _ = shared.log.send(if on { "nostr: connecting to the relays".into() } else { "nostr: off the relays - nothing needs them now".into() });
                }
                Some(RelayCmd::Active(_)) => {}
                Some(RelayCmd::Reconnect) => {
                    for r in &mut relays {
                        r.conns.clear();
                        r.next_try = 0.0;
                        r.fails = 0;
                    }
                }
                Some(RelayCmd::Send { to, frame }) => {
                    if active {
                        publish(&mut relays, &shared, to, &frame, clock());
                    }
                }
            },
            Some((i, epoch, ev)) = ev_rx.recv() => conn_event(&mut relays[i], &shared, epoch, ev, clock()),
            _ = tick.tick() => {
                if active {
                    // Through Tor, nothing connects until Tor has reached the network.
                    if via.as_ref().is_none_or(|t| t.ready()) {
                        for (i, r) in relays.iter_mut().enumerate() {
                            plan(r, i, &shared, &ev_tx, clock(), &via);
                        }
                    }
                }
            }
        }
        let n = relays.iter().filter(|r| r.conns.iter().any(|c| c.open)).count();
        if *up.borrow() != n {
            let _ = up.send(n);
        }
    }
}

fn conn_event(r: &mut Relay, shared: &Shared, epoch: u64, ev: ConnEvent, now: f64) {
    match ev {
        ConnEvent::Open => {
            if let Some(c) = r.conns.iter_mut().find(|c| c.epoch == epoch) {
                c.open = true;
            }
            let _ = shared.log.send(if r.warned {
                format!("nostr: {} is back", r.host)
            } else {
                format!("nostr: connected to {}", r.host)
            });
            r.warned = false;
        }
        ConnEvent::Ok { accepted: true, .. } => {
            if r.pause > PAUSE_MIN && now > r.paused_until {
                r.pause /= 2.0;
            }
        }
        ConnEvent::Ok { accepted: false, why } => {
            // NIP-01's prefixes: back off on rate limits, stop writing on policy. The other
            // relays carry on.
            let mut action = "";
            if why.starts_with("rate-limited") || why.starts_with("banned") {
                r.pause = if r.pause > 0.0 { r.pause * 2.0 } else { PAUSE_MIN };
                if why.starts_with("banned") && r.pause < PAUSE_MAX / 2.0 {
                    r.pause = PAUSE_MAX / 2.0;
                }
                r.pause = r.pause.min(PAUSE_MAX);
                r.paused_until = r.paused_until.max(now + r.pause);
                action = " - pausing writes there";
            } else if ["blocked", "restricted", "pow", "invalid"].iter().any(|p| why.starts_with(p)) || {
                r.odd_refusals += 1;
                r.odd_refusals >= ODD_REFUSALS_MAX
            } {
                // A policy (web of trust, payment, proof of work) that throwaway keys won't meet.
                r.read_only = true;
                action = " - only reading from it now";
            }
            r.refusals += 1;
            if r.refusals == 1 {
                let why = if why.is_empty() { "no reason given".to_string() } else { why };
                let _ = shared.log.send(format!("nostr: {} refused an event: {why}{action}", r.host));
            }
        }
        ConnEvent::Closed { why, lasted } => {
            let was_open = r.conns.iter().any(|c| c.epoch == epoch && c.open);
            r.conns.retain(|c| c.epoch != epoch);
            if was_open && lasted > CONN_GOOD_AFTER {
                r.fails = 0;
            }
            let delay = (BACKOFF_BASE * f64::from(1u32 << r.fails.min(6))).min(BACKOFF_MAX);
            r.fails += 1;
            r.next_try = now + delay;
            let state = if was_open { "dropped" } else { "unreachable" };
            if !r.warned {
                r.warned = true;
                let _ = shared
                    .log
                    .send(format!("nostr: {} {state}: {why} - retrying in the background", r.host));
            }
        }
    }
}

/// Which connections a relay should have now: the one for these ten minutes, the next one from
/// a little before it starts, and the last one until a little after it ended.
fn plan(
    r: &mut Relay,
    index: usize,
    shared: &Arc<Shared>,
    ev_tx: &mpsc::UnboundedSender<(usize, u64, ConnEvent)>,
    now: f64,
    via: &Option<Arc<crate::net::tor::Tor>>,
) {
    let wall = unix_now() as f64;
    let e = unix_now() / EPOCH;
    if r.plan_epoch != Some(e) {
        let (start, next) = ((e * EPOCH) as f64, ((e + 1) * EPOCH) as f64);
        r.open_next_at = next - LEAD / 2.0 - random_seconds(LEAD / 2.0);
        r.close_last_at = start + TAIL / 2.0 + random_seconds(TAIL / 2.0);
        r.plan_epoch = Some(e);
    }
    r.conns
        .retain(|c| c.epoch == e || c.epoch == e + 1 || (c.epoch + 1 == e && wall < r.close_last_at));
    if now < r.next_try {
        return;
    }
    let mut want = vec![e];
    if wall >= r.open_next_at {
        want.push(e + 1);
    }
    for epoch in want {
        if r.conns.iter().any(|c| c.epoch == epoch) || r.conns.len() >= 2 {
            continue;
        }
        let tag = nostr_tag(&shared.tag_key, epoch);
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(connection(
            r.url.clone(),
            tag.clone(),
            shared.clone(),
            out_rx,
            ev_tx.clone(),
            index,
            epoch,
            via.clone(),
        ));
        r.conns.push(Conn {
            epoch,
            tag,
            open: false,
            out: out_tx,
            task,
        });
    }
}

/// The connection to publish on: these ten minutes', otherwise the last one while it's open,
/// otherwise the next. An event only carries the tag its connection asks for.
fn publish_conn(r: &Relay) -> Option<&Conn> {
    let e = unix_now() / EPOCH;
    [e, e.wrapping_sub(1), e + 1]
        .into_iter()
        .find_map(|ep| r.conns.iter().find(|c| c.epoch == ep && c.open))
}

fn publish(relays: &mut [Relay], shared: &Shared, to: PeerId, frame: &[u8], now: f64) {
    if frame.is_empty() || frame.len() > DGRAM_MAX {
        return;
    }
    let mut plain = Zeroizing::new([0u8; NOSTR_WRAP_PLAIN]);
    plain[..ID_LEN].copy_from_slice(&shared.my_id.0);
    plain[ID_LEN..2 * ID_LEN].copy_from_slice(&to.0);
    plain[2 * ID_LEN..WRAP_HDR].copy_from_slice(&(frame.len() as u16).to_be_bytes());
    plain[WRAP_HDR..WRAP_HDR + frame.len()].copy_from_slice(frame);
    sodium::random(&mut plain[WRAP_HDR + frame.len()..]);
    let wrapped = nostr_wrap(&shared.wrap_key, &plain);
    // Already seen, so the relays' copies of our own event are dropped before unwrapping.
    shared.seen_before(wrapped[..8].try_into().expect("8 bytes"));
    let content = base64::encode(&wrapped);
    let kind = random_kind();
    // One event per tag: every relay with a connection for the same ten minutes gets the same one.
    let mut built: HashMap<String, String> = HashMap::new();
    for r in relays.iter_mut() {
        if r.read_only || now < r.paused_until {
            continue;
        }
        let Some((tag, out)) = publish_conn(r).map(|c| (c.tag.clone(), c.out.clone())) else {
            continue;
        };
        r.tokens = (r.tokens + (now - r.tokens_at) * SEND_RATE).min(SEND_BURST);
        r.tokens_at = now;
        if r.tokens < 1.0 {
            continue;
        }
        let msg = match built.get(&tag) {
            Some(m) => m.clone(),
            None => {
                let Some(ev) = build_event(kind, json!([["e", tag]]), &content) else {
                    continue;
                };
                let m = json!(["EVENT", ev]).to_string();
                built.insert(tag.clone(), m.clone());
                m
            }
        };
        if out.send(msg).is_ok() {
            r.tokens -= 1.0;
        }
    }
}

/// A byte stream to a relay: a TCP connection, or a stream through Tor.
trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<Box<dyn Io>>>;

fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CONFIG
        .get_or_init(|| {
            // Mozilla's roots, built in: nothing is read from the system, so it runs anywhere.
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(cfg)
        })
        .clone()
}

/// A relay's host and port, from its URL.
fn host_port(url: &str) -> (String, u16) {
    let tls = url.starts_with("wss://");
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let hostport = &rest[..rest.find('/').unwrap_or(rest.len())];
    match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(if tls { 443 } else { 80 })),
        None => (hostport.to_string(), if tls { 443 } else { 80 }),
    }
}

/// The websocket to a relay: over TCP, or through Tor on circuits of its own, where the relay's
/// name is looked up at the exit, so local DNS is never used.
async fn connect(url: &str, via: &Option<Arc<crate::net::tor::Tor>>) -> Result<Ws, String> {
    let (host, port) = host_port(url);
    let io: Box<dyn Io> = match via {
        Some(tor) => {
            let tor_timeout = Duration::from_secs(90);
            Box::new(
                timeout(tor_timeout, tor.connect_isolated(&host, port))
                    .await
                    .map_err(|_| "Tor didn't reach the relay in time".to_string())??,
            )
        }
        None => Box::new(
            timeout(STEP_TIMEOUT, tokio::net::TcpStream::connect((host.as_str(), port)))
                .await
                .map_err(|_| "timed out".to_string())?
                .map_err(|e| e.to_string())?,
        ),
    };
    let connector = tokio_tungstenite::Connector::Rustls(tls_config());
    let cfg = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(64 * 1024))
        .max_frame_size(Some(64 * 1024));
    match timeout(
        STEP_TIMEOUT,
        tokio_tungstenite::client_async_tls_with_config(url, io, Some(cfg), Some(connector)),
    )
    .await
    {
        Ok(Ok((ws, _))) => Ok(ws),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("timed out".into()),
    }
}

fn subid() -> String {
    // A new one for each connection: the same at several relays, or across connections, would
    // link them to one member.
    hex::encode(&sodium::random_array::<8>())
}

/// NIP-42: proves to the relay that we hold the key it sees an event signed with.
fn auth_message(url: &str, challenge: &str) -> Option<String> {
    let ev = build_event(KIND_AUTH, json!([["relay", url], ["challenge", challenge]]), "")?;
    Some(json!(["AUTH", ev]).to_string())
}

#[allow(clippy::too_many_arguments)]
async fn connection(
    url: String,
    tag: String,
    shared: Arc<Shared>,
    mut out: mpsc::UnboundedReceiver<String>,
    events: mpsc::UnboundedSender<(usize, u64, ConnEvent)>,
    index: usize,
    epoch: u64,
    via: Option<Arc<crate::net::tor::Tor>>,
) {
    let opened = Instant::now();
    let why = match run_connection(&url, &tag, &shared, &mut out, &events, index, epoch, &via).await {
        Ok(()) => "closed".to_string(),
        Err(e) => e,
    };
    let _ = events.send((
        index,
        epoch,
        ConnEvent::Closed {
            why,
            lasted: opened.elapsed().as_secs_f64(),
        },
    ));
}

#[allow(clippy::too_many_arguments)]
async fn run_connection(
    url: &str,
    tag: &str,
    shared: &Shared,
    out: &mut mpsc::UnboundedReceiver<String>,
    events: &mpsc::UnboundedSender<(usize, u64, ConnEvent)>,
    index: usize,
    epoch: u64,
    via: &Option<Arc<crate::net::tor::Tor>>,
) -> Result<(), String> {
    let mut ws = connect(url, via).await?;
    let sub = subid();
    let req = |sub: &str| json!(["REQ", sub, {"#e": [tag], "since": unix_now().saturating_sub(REQ_SINCE)}]).to_string();
    ws.send(WsMessage::text(req(&sub))).await.map_err(|e| e.to_string())?;
    let _ = events.send((index, epoch, ConnEvent::Open));
    let mut subscribed = true;
    let mut challenge: Option<String> = None;
    let mut last_rx = Instant::now();
    let mut ping = tokio::time::interval(PING_EVERY);
    ping.tick().await;
    let resub = sleep(Duration::from_secs(3600 * 24));
    tokio::pin!(resub);
    loop {
        tokio::select! {
            msg = ws.next() => {
                let msg = match msg {
                    None => return Err("closed by the relay".into()),
                    Some(Err(e)) => return Err(e.to_string()),
                    Some(Ok(m)) => m,
                };
                last_rx = Instant::now();
                let text = match msg {
                    WsMessage::Text(t) => t,
                    WsMessage::Close(_) => return Err("closed by the relay".into()),
                    _ => continue,
                };
                let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
                let Some(arr) = v.as_array() else { continue };
                match arr.first().and_then(Value::as_str) {
                    Some("EVENT") if arr.get(1).and_then(Value::as_str) == Some(&sub) => {
                        if let Some(ev) = arr.get(2) {
                            shared.on_event(ev, tag);
                        }
                    }
                    Some("OK") => {
                        let accepted = arr.get(2).and_then(Value::as_bool).unwrap_or(false);
                        let why = crate::protocol::text::clean_str(arr.get(3).and_then(Value::as_str).unwrap_or(""), 119);
                        let _ = events.send((index, epoch, ConnEvent::Ok { accepted, why }));
                    }
                    Some("CLOSED") => {
                        subscribed = false;
                        if let Some(ch) = &challenge {
                            if let Some(a) = auth_message(url, ch) {
                                ws.send(WsMessage::text(a)).await.map_err(|e| e.to_string())?;
                            }
                            ws.send(WsMessage::text(req(&sub))).await.map_err(|e| e.to_string())?;
                            subscribed = true;
                        } else {
                            resub.as_mut().reset(Instant::now() + RESUB_DELAY);
                        }
                    }
                    Some("AUTH") => {
                        let Some(ch) = arr.get(1).and_then(Value::as_str).filter(|c| c.len() < 160) else { continue };
                        challenge = Some(ch.to_string());
                        if let Some(a) = auth_message(url, ch) {
                            ws.send(WsMessage::text(a)).await.map_err(|e| e.to_string())?;
                        }
                        if !subscribed {
                            ws.send(WsMessage::text(req(&sub))).await.map_err(|e| e.to_string())?;
                            subscribed = true;
                        }
                    }
                    _ => {}
                }
            }
            msg = out.recv() => {
                let Some(msg) = msg else { return Ok(()) };
                ws.send(WsMessage::text(msg)).await.map_err(|e| e.to_string())?;
            }
            _ = ping.tick() => {
                if last_rx.elapsed() > IDLE_TIMEOUT {
                    return Err("went quiet".into());
                }
                ws.send(WsMessage::Ping(b"p".to_vec().into())).await.map_err(|e| e.to_string())?;
            }
            _ = &mut resub, if !subscribed => {
                ws.send(WsMessage::text(req(&sub))).await.map_err(|e| e.to_string())?;
                subscribed = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert!(url_ok("wss://relay.primal.net"));
        assert!(url_ok("wss://relay.example:4443/path"));
        assert!(url_ok("ws://127.0.0.1:7777"));
        assert!(!url_ok("https://relay.primal.net"));
        assert!(!url_ok("wss://bad host"));
        assert!(!url_ok("wss://x:99999"));
        assert_eq!(host_of("wss://relay.primal.net/x"), "relay.primal.net");
    }

    #[test]
    fn events_are_signed_and_verify() {
        let ev = build_event(20001, json!([["e", "ab"]]), "content").unwrap();
        let ser = serde_json::to_string(&json!([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]])).unwrap();
        let id = sodium::sha256(&[ser.as_bytes()]);
        assert_eq!(ev["id"].as_str().unwrap(), hex::encode(&id));
        let pk = secp256k1::XOnlyPublicKey::from_byte_array(hex::decode_array::<32>(ev["pubkey"].as_str().unwrap()).unwrap()).unwrap();
        let sig = secp256k1::schnorr::Signature::from_byte_array(hex::decode_array::<64>(ev["sig"].as_str().unwrap()).unwrap());
        assert!(secp256k1::schnorr::verify(&sig, &id, &pk).is_ok());
        for _ in 0..1000 {
            let k = random_kind();
            assert!((20000..30000).contains(&k) && k != KIND_AUTH);
        }
    }
}
