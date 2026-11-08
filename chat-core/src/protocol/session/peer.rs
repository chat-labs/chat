// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! One peer of a session: its keys and chains, what its "k" said, and what waits to go to it.

use crate::protocol::api::{BuildState, PeerId, SignatureState};
use crate::protocol::crypto::identity::IdentityKind;
use crate::protocol::crypto::{KEY_LEN, PUB_LEN, Ratchet, VERIFY_LEN, kem};
use crate::protocol::names::Colour;
use crate::protocol::wire::Addr;
use std::collections::VecDeque;
use zeroize::{Zeroize, Zeroizing};

/// The user's comparison of a peer's verify code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CodeOk {
    NotCompared,
    Same,
    Different,
}

/// Its signing key against the verified keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrustMatch {
    Unknown,
    /// Its key is a verified one.
    Key,
    /// A verified key has its nick, but it signs with another (warned once).
    OtherKey,
}

#[derive(Clone)]
pub(crate) struct PeerIdent {
    pub kind: IdentityKind,
    pub public: [u8; 32],
    pub fingerprint: [u8; 16],
    pub state: SignatureState,
}

/// What its "k" says its build can do.
#[derive(Clone, Copy, Default)]
pub(crate) struct Caps {
    /// "r": announces each new key over the current session ("rk") before it rekeys.
    pub announces_rekey: bool,
    /// "b": reads several records in one frame.
    pub batches: bool,
    /// "l": reads messages longer than 250 bytes.
    pub long_text: bool,
    /// "m": can move to a new room with us.
    pub can_move: bool,
    /// "p": reads direct messages.
    pub can_pm: bool,
    /// "q": reads replies.
    pub can_reply: bool,
    /// "o": reads "off".
    pub can_offline: bool,
    /// "t": keeps to message timers.
    pub can_timer: bool,
}

/// A record waiting for the peer's next slot. `old_chain`: sealed on the chain it reads from
/// before our rekey (an "rk" sent again during the overlap).
pub(crate) struct QueuedRecord {
    pub seq: u64,
    pub old_chain: bool,
    pub text: Zeroizing<String>,
}

/// A room frame for a connected peer (a re-handshake's hi, ck, hi2 or kx), sent in its slots:
/// over UDP a piece per slot, through the relays whole.
pub(crate) struct QueuedRoom {
    pub seq: u64,
    /// Its record's name ("hi", "ck", "hi2", "kx"): a newer one of the same kind replaces it.
    pub kind: String,
    pub to: Addr,
    pub id: [u8; 4],
    pub next_piece: usize,
    pub pieces: usize,
    pub frame: Vec<u8>,
}

/// A message waiting for its ack. It keeps the record, not the sealed frame: each try is sealed
/// again on the peer's current chain, since the peer can't open an old index once any later
/// frame has reached it.
pub(crate) struct Pending {
    pub mid: String,
    pub record: Zeroizing<String>,
    pub tries: u32,
    pub next_retry: f64,
    /// Ours (numbered for deliveries), or None for a copy passed on for someone else.
    pub own: Option<u64>,
}

pub(crate) struct Peer {
    pub id: [u8; 16],
    pub nick: String,
    pub skel: String,
    pub addr: Addr,
    /// The address before `addr`: a peer that just moved keeps arriving there for a while.
    pub prev_addr: Option<Addr>,
    pub seen: f64,
    pub born: f64,
    pub next_hello: f64,
    pub hello_tries: u32,
    /// A frame from it opened on our chains: it's connected.
    pub ok: bool,
    pub ok_since: f64,
    pub k_seen: bool,
    pub announced: bool,
    /// Our "k" goes a few times, a little apart, since nothing acks it.
    pub k_sent: u32,
    pub next_k: f64,
    pub room_waited: u32,
    pub public: [u8; PUB_LEN],
    pub send: Ratchet,
    pub recv: Ratchet,
    pub vfy: [u8; VERIFY_LEN],
    pub vfy_set: bool,
    pub colour: Colour,
    pub persists: bool,
    pub timer: u32,
    pub ident: Option<PeerIdent>,
    pub build_version: Option<String>,
    pub build_state: BuildState,
    pub build_warn: bool,
    /// When a frame last came over each kind of path.
    pub path_seen: [f64; 3],
    pub onion: Option<String>,
    pub prk_partial: Zeroizing<[u8; KEY_LEN]>,
    pub kem_ct: Box<[u8; kem::CT_LEN]>,
    pub keygen: u32,
    pub next_cover: f64,
    /// A frame opened on the current receive chain. Until then a replayed kx can't lock in bad chains.
    pub chain_confirmed: bool,
    /// Responder: a kx that came before its re-handshake, kept for when that's ready.
    pub kx_early: bool,
    /// We encapsulated (the lower id): the peer can't read our new chain until it has our kx.
    pub initiator: bool,
    pub caps: Caps,
    /// The key it announced in "rk", and when an unannounced one was refused.
    pub next_pub: Option<[u8; PUB_LEN]>,
    pub rk_refused_since: f64,
    pub next_rk_warn: f64,
    pub next_rk: f64,
    pub next_rehello: f64,
    pub code_ok: CodeOk,
    pub trust: TrustMatch,
    pub old_send: Ratchet,
    pub old_recv: Ratchet,
    pub old_until: f64,
    /// Our session key with it, and both keys of the session before its last re-handshake: "k"
    /// signs them, and a record signed then can still arrive.
    pub my_pub: [u8; PUB_LEN],
    pub prev_keys: Option<([u8; PUB_LEN], [u8; PUB_LEN])>,
    pub sendq: VecDeque<QueuedRecord>,
    pub roomq: VecDeque<QueuedRoom>,
    pub pending: Vec<Pending>,
    /// Chunks of one of our files it asked for, sent in slots that would carry a nop.
    pub serve: super::files::Serve,
    /// Its part in a move.
    pub mv: super::moving::PeerMove,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.vfy.zeroize();
        self.kem_ct.zeroize();
    }
}

impl Peer {
    pub fn new(id: [u8; 16], addr: Addr, now: f64) -> Self {
        Peer {
            id,
            nick: "anon".into(),
            skel: crate::protocol::text::nick_skeleton("anon"),
            addr,
            prev_addr: None,
            seen: now,
            born: now,
            next_hello: 0.0,
            hello_tries: 0,
            ok: false,
            ok_since: 0.0,
            k_seen: false,
            announced: false,
            k_sent: 0,
            next_k: 0.0,
            room_waited: 0,
            public: [0; PUB_LEN],
            send: Ratchet::default(),
            recv: Ratchet::default(),
            vfy: [0; VERIFY_LEN],
            vfy_set: false,
            colour: Colour([0x8B, 0x8D, 0x98]),
            persists: false,
            timer: 0,
            ident: None,
            build_version: None,
            build_state: BuildState::Unknown,
            build_warn: false,
            path_seen: [0.0; 3],
            onion: None,
            prk_partial: Zeroizing::new([0; KEY_LEN]),
            kem_ct: Box::new([0; kem::CT_LEN]),
            keygen: 0,
            next_cover: 0.0,
            chain_confirmed: false,
            kx_early: false,
            initiator: false,
            caps: Caps::default(),
            next_pub: None,
            rk_refused_since: 0.0,
            next_rk_warn: 0.0,
            next_rk: 0.0,
            next_rehello: 0.0,
            code_ok: CodeOk::NotCompared,
            trust: TrustMatch::Unknown,
            old_send: Ratchet::default(),
            old_recv: Ratchet::default(),
            old_until: 0.0,
            my_pub: [0; PUB_LEN],
            prev_keys: None,
            sendq: VecDeque::new(),
            roomq: VecDeque::new(),
            pending: Vec::new(),
            serve: Default::default(),
            mv: Default::default(),
        }
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId(self.id)
    }

    pub fn set_nick(&mut self, raw: &[u8]) {
        self.nick = crate::protocol::text::clean_nick(raw);
        self.skel = crate::protocol::text::nick_skeleton(&self.nick);
    }

    /// The chain to seal on now: the new one once it's started, else the old one in the overlap.
    pub fn send_chain(&mut self) -> &mut Ratchet {
        if !self.send.started() && self.old_until > 0.0 && self.old_send.started() {
            &mut self.old_send
        } else {
            &mut self.send
        }
    }

    pub fn sending_on_old(&self) -> bool {
        !self.send.started() && self.old_until > 0.0 && self.old_send.started()
    }

    pub fn drop_overlap(&mut self) {
        self.old_send = Ratchet::default();
        self.old_recv = Ratchet::default();
        self.old_until = 0.0;
    }

    pub fn old_avail(&self) -> bool {
        self.old_until > 0.0 && self.old_send.started()
    }

    /// Our new chain may not be readable by the peer yet: we started it (the initiator's starts
    /// before the peer has our kx), and no frame from the peer has confirmed it. A responder's is
    /// readable at once: the initiator made the same chains when it encapsulated.
    pub fn new_chain_unproven(&self) -> bool {
        self.initiator && self.send.started() && !self.chain_confirmed
    }

    /// Records go on the old chain: before the new one starts, and while it's unproven and the
    /// old one lasts, since the peer reads that one until it has finished its side.
    pub fn records_on_old(&self) -> bool {
        self.sending_on_old() || (self.new_chain_unproven() && self.old_avail())
    }

    /// Records wait: a first handshake's new chain, before our kx has gone (nothing sealed on it
    /// could be read yet, and there's no old chain to use instead).
    pub fn records_wait(&self) -> bool {
        self.new_chain_unproven() && !self.old_avail() && self.roomq.iter().any(|q| q.kind == "kx")
    }

    /// The session keys "k" and "mp" sign: those of the chain records go on now. A peer that
    /// hasn't finished its side of a re-handshake checks against the old keys; one that has,
    /// against both.
    pub fn signed_pubs(&self) -> ([u8; PUB_LEN], [u8; PUB_LEN]) {
        match self.prev_keys {
            Some((theirs, mine)) if self.records_on_old() => (mine, theirs),
            _ => (self.my_pub, self.public),
        }
    }
}
