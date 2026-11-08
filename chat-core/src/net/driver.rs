// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! One room's task: the engine, its sockets, its relays and its timers, all in one place, so the
//! engine is only ever touched from here.

use crate::net::nostr::Relays;
use crate::net::tor::{RoomTor, TorCmd};
use crate::net::udp::Udp;
use crate::protocol::crypto::identity::{IdentityKeypair, IdentityKind};
use crate::protocol::names::Colour;
use crate::protocol::session::{MoveTo, Now, OwnFile, Request};
use crate::protocol::wire::Addr;
use crate::protocol::{Command, CommandError, Event, FileInfo, NetStatus, Outcome, PeerId, PeerInfo, Session};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

/// How often the engine's timers run, at most: its slots are 1.5 s apart, so this is plenty.
const TICK: Duration = Duration::from_millis(25);
/// How long the relays get to carry a last "bye" before they close.
const BYE_GRACE: Duration = Duration::from_secs(2);

pub(crate) enum Ask {
    Command(Command, oneshot::Sender<Result<Outcome, CommandError>>),
    Offer(OwnFile, oneshot::Sender<Result<Outcome, CommandError>>),
    /// :move, yes: where to go, and who we are now (nick, colour, history flag) to go there as.
    MoveYes(oneshot::Sender<Result<(MoveTo, String, Colour, bool), CommandError>>),
    /// The new room is open: this one asks those coming, then only waits for their keys, which
    /// go to the new room's driver.
    MoveGo(MoveTo, mpsc::UnboundedSender<Ask>),
    MoveFinished(oneshot::Sender<bool>),
    SetIdentity(Option<(IdentityKind, IdentityKeypair)>),
    /// New Tor circuits and onion address: whether the room goes through Tor.
    NewTor(oneshot::Sender<bool>),
    /// Direct: the UDP port, or (Some) a move to another (0 picks a free one).
    Port(Option<u16>, oneshot::Sender<Result<u16, String>>),
    /// In the room moved to: a key shown in the old one by a peer whose code we compared there.
    CameWith([u8; 32], String),
    Files(oneshot::Sender<Vec<FileInfo>>),
    Picture(u32, oneshot::Sender<Option<Vec<u8>>>),
    Peers(oneshot::Sender<Vec<PeerInfo>>),
    Net(oneshot::Sender<NetStatus>),
    Timer(oneshot::Sender<(u32, Option<String>)>),
    Leave(oneshot::Sender<()>),
}

/// The protocol's clock: seconds since the room opened, from a start well away from 0, and the
/// wall clock for the DHT's and relays' epochs.
#[derive(Clone, Copy)]
pub(crate) struct Clock(Instant);

impl Clock {
    pub fn new() -> Self {
        Clock(Instant::now())
    }
    pub fn now(&self) -> Now {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Now {
            secs: 1000.0 + self.0.elapsed().as_secs_f64(),
            unix,
        }
    }
}

pub(crate) struct Driver {
    pub session: Session,
    pub udp: Option<Udp>,
    pub lan: Option<Udp>,
    pub relays: Option<Relays>,
    pub relay_rx: mpsc::UnboundedReceiver<(PeerId, Vec<u8>)>,
    pub tor: Option<RoomTor>,
    pub tor_rx: mpsc::UnboundedReceiver<([u8; 16], Vec<u8>)>,
    /// The relays' and Tor's news.
    pub net_log: mpsc::UnboundedReceiver<String>,
    pub asks: mpsc::UnboundedReceiver<Ask>,
    pub events: mpsc::UnboundedSender<Event>,
    pub clock: Clock,
    /// Moved out (:move): the room moved to, which gets the keys that come here. Nothing more
    /// from this room is for the UI.
    pub move_to: Option<mpsc::UnboundedSender<Ask>>,
    /// Direct: the router's port mapping, removed when the room closes.
    pub portmap: Option<crate::net::portmap::PortMap>,
    /// Where a new port mapping reports, if the room maps its port.
    pub portmap_log: Option<mpsc::UnboundedSender<String>>,
}

async fn recv_on(sock: &Option<Udp>, buf: &mut [u8]) -> Option<(usize, SocketAddr)> {
    match sock {
        Some(s) => s.recv(buf).await.ok(),
        None => std::future::pending().await,
    }
}

async fn resolve_bootstrap(want_v4: bool, want_v6: bool) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for (host, port) in crate::protocol::dht::BOOTSTRAP {
        if let Ok(Ok(addrs)) = tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host((*host, *port))).await {
            out.extend(addrs.filter(|a| (a.is_ipv4() && want_v4) || (a.is_ipv6() && want_v6)));
        }
    }
    out
}

impl Driver {
    /// The room's UDP socket swapped for one on another port, and its port mapping with it.
    async fn change_port(&mut self, want: Option<u16>) -> Result<u16, String> {
        let Some(udp) = &self.udp else {
            return Err("this room goes through Tor, and has no UDP port of its own".into());
        };
        let now = udp.port();
        let Some(want) = want.filter(|w| *w == 0 || *w != now) else {
            return Ok(now);
        };
        let new = Udp::bind(want).map_err(|e| format!("can't use UDP port {want} ({e}) - staying on {now}"))?;
        let got = new.port();
        self.udp = Some(new);
        self.session.set_port(got);
        // The old mapping pointed at the old port.
        if let Some(pm) = self.portmap.take() {
            pm.stop().await;
        }
        if let Some(log) = &self.portmap_log {
            self.portmap = Some(crate::net::portmap::PortMap::spawn(got, log.clone()));
        }
        Ok(got)
    }

    pub async fn run(mut self) {
        let mut buf = vec![0u8; 4096];
        let mut lan_buf = vec![0u8; 4096];
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let (dns_tx, mut dns_rx) = mpsc::unbounded_channel::<Vec<SocketAddr>>();
        let mut relays_active = false;
        let mut relays_up = self.relays.as_ref().map(|r| r.up.clone());
        let mut tor_status = self.tor.as_ref().map(|t| t.status.clone());
        let mut portmap = self.portmap.as_ref().map(|p| p.status.clone());
        let mut leave_reply: Option<oneshot::Sender<()>> = None;
        loop {
            let now = self.clock.now();
            tokio::select! {
                ask = self.asks.recv() => match ask {
                    // Every handle to the room is gone: it leaves.
                    None => self.session.leave(now),
                    Some(Ask::Command(cmd, reply)) => {
                        let _ = reply.send(self.session.command(cmd, now));
                    }
                    Some(Ask::Offer(f, reply)) => {
                        let _ = reply.send(self.session.offer_file(f, now));
                    }
                    Some(Ask::Files(reply)) => { let _ = reply.send(self.session.files()); }
                    Some(Ask::MoveYes(reply)) => {
                        let s = &mut self.session;
                        let _ = reply.send(s.move_yes(now).map(|to| (to, s.nick().to_string(), s.colour(), s.keeps_history())));
                    }
                    Some(Ask::MoveGo(to, there)) => {
                        self.session.move_go(&to, now);
                        self.move_to = Some(there);
                    }
                    Some(Ask::MoveFinished(reply)) => { let _ = reply.send(self.session.move_finished()); }
                    Some(Ask::SetIdentity(id)) => self.session.set_identity(id, now),
                    Some(Ask::NewTor(reply)) => {
                        self.tor_cmd(TorCmd::Renew);
                        let _ = reply.send(self.tor.is_some());
                    }
                    Some(Ask::Port(want, reply)) => {
                        let r = self.change_port(want).await;
                        portmap = self.portmap.as_ref().map(|p| p.status.clone());
                        let _ = reply.send(r);
                    }
                    Some(Ask::CameWith(public, nick)) => self.session.came_with(public, &nick),
                    Some(Ask::Picture(num, reply)) => { let _ = reply.send(self.session.picture_bytes(num)); }
                    Some(Ask::Peers(reply)) => { let _ = reply.send(self.session.peers()); }
                    Some(Ask::Net(reply)) => { let _ = reply.send(self.session.net_status()); }
                    Some(Ask::Timer(reply)) => { let _ = reply.send(self.session.timer()); }
                    Some(Ask::Leave(reply)) => {
                        self.session.leave(now);
                        leave_reply = Some(reply);
                    }
                },
                Some((n, from)) = recv_on(&self.udp, &mut buf) => self.session.handle_udp(from, &buf[..n], now),
                Some((n, from)) = recv_on(&self.lan, &mut lan_buf) => self.session.handle_udp(from, &lan_buf[..n], now),
                Some((from, frame)) = self.relay_rx.recv() => self.session.handle_relayed(Addr::Relay(from), &frame, now),
                Some((id, frame)) = self.tor_rx.recv() => self.session.handle_relayed(Addr::Tor(id), &frame, now),
                Ok(()) = async { match &mut tor_status { Some(w) => w.changed().await, None => std::future::pending().await } } => {
                    if let Some(w) = &tor_status {
                        let st = w.borrow().clone();
                        self.session.set_tor_status(st);
                    }
                }
                Some(line) = self.net_log.recv() => {
                    let _ = self.events.send(Event::Log { text: line });
                }
                Some(addrs) = dns_rx.recv() => self.session.dht_bootstrap(&addrs),
                Ok(()) = async { match &mut portmap { Some(w) => w.changed().await, None => std::future::pending().await } } => {
                    if let Some(w) = &portmap {
                        let st = w.borrow().clone();
                        self.session.set_portmap(st.external_port, st.text);
                    }
                }
                Ok(()) = async { match &mut relays_up { Some(w) => w.changed().await, None => std::future::pending().await } } => {
                    let up = relays_up.as_ref().map_or(0, |w| *w.borrow());
                    self.session.set_relays_up(up);
                }
                _ = tick.tick() => self.session.tick(now),
            }
            self.flush(&dns_tx, &mut relays_active);
            if self.session.has_left() {
                break;
            }
        }
        // Whatever the relays still have to carry (a "bye") gets a moment before they close.
        if let Some(relays) = self.relays.take() {
            tokio::spawn(async move {
                tokio::time::sleep(BYE_GRACE).await;
                drop(relays);
            });
        }
        if let Some(pm) = self.portmap.take() {
            pm.stop().await;
        }
        if let Some(r) = leave_reply {
            let _ = r.send(());
        }
    }

    fn tor_cmd(&self, cmd: TorCmd) {
        if let Some(t) = &self.tor {
            t.send(cmd);
        }
    }

    fn flush(&mut self, dns_tx: &mpsc::UnboundedSender<Vec<SocketAddr>>, relays_active: &mut bool) {
        // Requests first: a Tor target is known before anything is sent to it.
        while let Some(req) = self.session.poll_request() {
            match req {
                Request::ResolveDhtBootstrap { want_v4, want_v6 } => {
                    let tx = dns_tx.clone();
                    tokio::spawn(async move {
                        let _ = tx.send(resolve_bootstrap(want_v4, want_v6).await);
                    });
                }
                Request::TorHostRoom { slot } => self.tor_cmd(TorCmd::Host(slot)),
                Request::TorRepublishRoom => self.tor_cmd(TorCmd::Republish),
                Request::TorTarget { id, onion } => self.tor_cmd(TorCmd::Target(id, onion)),
                Request::MoveKey { public, nick } => {
                    if let Some(there) = &self.move_to {
                        let _ = there.send(Ask::CameWith(public, nick));
                    }
                }
            }
        }
        while let Some(t) = self.session.poll_transmit() {
            match t.to {
                Addr::Udp(sa) => {
                    let sock = if t.lan { &self.lan } else { &self.udp };
                    if let Some(s) = sock {
                        s.send(&t.data, sa);
                    }
                }
                Addr::Relay(id) => {
                    if let Some(r) = &self.relays {
                        r.send(id, t.data);
                    }
                }
                Addr::Tor(id) => self.tor_cmd(TorCmd::Send(id, t.data)),
            }
        }
        if let Some(r) = &self.relays {
            let want = self.session.relays_wanted();
            if want != *relays_active {
                *relays_active = want;
                r.set_active(want);
            }
        }
        while let Some(e) = self.session.poll_event() {
            if self.move_to.is_none() {
                let _ = self.events.send(e);
            }
        }
    }
}
