// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! What a session tells its UI, and what a UI asks of it. Every type here serializes, so the
//! same events reach a Rust UI in-process, a GUI over JSON, or a phone app over FFI.

use crate::protocol::crypto::identity::IdentityKind;
use crate::protocol::names::Colour;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// A member's id in one session: 16 random bytes, new every time it joins. Written as 32 hex
/// digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub [u8; 16]);

impl PeerId {
    pub const EVERYONE: PeerId = PeerId([0; 16]);

    pub fn hex(&self) -> String {
        crate::protocol::hex::encode(&self.0)
    }

    /// The first 8 hex digits, which tell peers with lookalike nicks apart.
    pub fn short(&self) -> String {
        crate::protocol::hex::encode(&self.0[..4])
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self.short())
    }
}

impl FromStr for PeerId {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        crate::protocol::hex::decode_array::<16>(&s.to_ascii_lowercase())
            .map(PeerId)
            .ok_or("a peer id is 32 hex digits")
    }
}

impl Serialize for PeerId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

/// The user's comparison of a peer's verify code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CodeState {
    /// Nothing to do: comparing isn't required here.
    Nothing,
    /// To be compared before anything is sent to them.
    Compare,
    Compared,
    /// The user said the codes differ: someone may be in the middle.
    Differs,
    /// They have the nick of a verified key but sign with another key, or none.
    KeyChanged,
}

/// Whether a peer's signing identity checked out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureState {
    Unverified,
    Verified,
    Failed,
}

/// What a peer's "v" says about the build it runs. A peer can lie, so Official is only a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildState {
    /// It sent none: a build from before "v", or one that couldn't read its own executable.
    Unknown,
    Unchecked,
    Official,
    Modified,
}

/// How a peer is reached now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathKind {
    Direct,
    Relays,
    Tor,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub kind: IdentityKind,
    /// The Ed25519 public key, 64 hex digits.
    pub public: String,
    /// The fingerprint, in groups of four hex digits.
    pub fingerprint: String,
    pub signature: SignatureState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyCode {
    pub words: String,
    pub hex: String,
}

/// A connected peer, as a UI shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: PeerId,
    pub nick: String,
    /// The nick as shown: with "#" and the start of the id when another looks the same.
    pub name: String,
    pub colour: Colour,
    pub code: Option<VerifyCode>,
    pub code_state: CodeState,
    pub identity: Option<PeerIdentity>,
    pub build: BuildState,
    /// The version its "v" names, if it sent one.
    pub version: Option<String>,
    pub keeps_history: bool,
    pub ignored: bool,
    /// Its build reads direct messages.
    pub can_dm: bool,
    pub path: PathKind,
    /// Announced in the room (its nick and identity are in).
    pub announced: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaveReason {
    Left,
    /// It's coming back to the room later (a kept room).
    Offline,
    TimedOut,
}

/// A message, ours or a peer's, to the room or direct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    /// Its id (8 hex digits), which a reply names.
    pub mid: String,
    /// Who wrote it: for one passed on by another peer, only what that peer says.
    pub from: PeerId,
    pub nick: String,
    /// How the author is shown: the peer's name, or for a message passed on, "nick#1a2b3c4d".
    pub name: String,
    /// The peer it came from, or a direct message is to or from. None for ours to the room.
    pub peer: Option<PeerId>,
    /// The author's colour, when it came straight from them.
    pub colour: Option<Colour>,
    pub mine: bool,
    /// Ours: the number deliveries are reported under.
    pub own: Option<u64>,
    pub direct: bool,
    /// It names us, answers us, or is a direct message to us.
    pub mention: bool,
    /// Passed on by `peer` for an author we aren't connected to.
    pub relayed: bool,
    /// The text as shown, a reply's quote first.
    pub text: String,
    /// How many bytes at the start of `text` are the quote of what it answers.
    pub quote_len: usize,
    /// The message it answers.
    pub reply_to: Option<String>,
    /// Unix time it arrived (or was sent).
    pub at: u64,
    /// A file's offer: the file's number, as [`FileInfo`] has it. Its text says what's offered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<u32>,
}

impl Message {
    /// The text without a reply's quote.
    pub fn body(&self) -> &str {
        &self.text[self.quote_len.min(self.text.len())..]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Worth seeing in passing.
    Note,
    /// The user should see this at once (a verified peer's key changing, say).
    Warn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetLog {
    /// Only the network's problems.
    Off,
    /// Its news too.
    Normal,
    /// Every handshake packet too.
    Verbose,
}

/// How the room reaches its peers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetStatus {
    /// Created here, or someone has answered: messages can be sent.
    pub ready: bool,
    pub online: usize,
    pub pending: usize,
    /// Addresses found that may be members, not yet tried or answered.
    #[serde(default)]
    pub candidates: usize,
    /// Datagrams received.
    pub rx: u64,
    /// The DHT: None when off, else whether it knows nodes yet.
    pub dht: Option<bool>,
    pub dht_found: usize,
    /// Relays: None when off; whether they're in use, connected of total.
    pub relays: Option<RelayStatus>,
    pub lan: bool,
    pub mode: RouteMode,
    /// Tor: whether it has reached the Tor network, and our onion service is up.
    pub tor_ready: bool,
    pub onion_up: bool,
    /// Direct, with port mapping on: whether the router forwards our port.
    pub portmap: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayStatus {
    pub used: bool,
    pub up: usize,
    pub total: usize,
}

/// What became of one of our messages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Delivery {
    /// This peer has it.
    Delivered { peer: PeerId, name: String },
    /// This peer never acked it: it gave up, or left and didn't come back in time.
    Missed { peer: PeerId, name: String },
    /// Nothing more will be heard: every peer it went to has it, or as many as will.
    Settled,
}

/// Something that happened in a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// A room we joined was answered: it's open now.
    Opened,
    Message(Message),
    Delivery {
        own: u64,
        delivery: Delivery,
    },
    PeerJoined(PeerInfo),
    /// A connected peer changed: its nick, colour, code, identity or path.
    PeerChanged(PeerInfo),
    PeerLeft {
        id: PeerId,
        name: String,
        reason: LeaveReason,
    },
    /// The message timer kept to here, and who asked for it.
    Timer {
        seconds: u32,
        who: Option<String>,
    },
    /// Something for the user to read: joins, warnings, the answers to commands.
    Notice {
        level: Level,
        text: String,
    },
    /// The network's own notes, as the net log setting allows.
    Log {
        text: String,
    },
    Net(NetStatus),
    /// The files offered here and ours, when they change (at most twice a second).
    Files {
        list: Vec<FileInfo>,
    },
    /// A peer asks us to move the room (answer with `Room::answer_move`), or (None) nothing is
    /// asked any more.
    MoveAsked {
        ask: Option<MoveAsk>,
    },
    /// A picture fetched to be shown has arrived, matching its offer, or one of ours was offered.
    /// These are the bytes as they came: decode them with [`crate::protocol::picture::decode`], never
    /// with a library that would run whatever else a peer put in them.
    Picture {
        num: u32,
        name: String,
        #[serde(with = "bytes_b64")]
        data: Vec<u8>,
    },
}

/// Bytes in JSON as base64.
mod bytes_b64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::protocol::base64::encode(data))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        crate::protocol::base64::decode_strict(&s).ok_or_else(|| serde::de::Error::custom("not base64"))
    }
}

/// A file offered here, by us or a peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileInfo {
    /// What commands call it.
    pub num: u32,
    pub name: String,
    pub size: u64,
    pub mine: bool,
    /// Who offered it: None for ours.
    pub from: Option<PeerId>,
    /// Their name ("you" for ours, "someone who left" once they've gone).
    pub from_name: String,
    /// Offered as a PNG, JPEG or GIF (only decoding it says it is one).
    pub image: bool,
    /// Unix time it was offered.
    pub at: u64,
    pub state: FileState,
    /// Fetched (or being fetched) to be shown rather than saved.
    pub show: bool,
    /// Where it was last saved.
    pub saved: Option<String>,
    /// Shown here and kept in memory: saving it needs no fetch.
    pub shown: bool,
    /// A fetch also saves or shows it once it's here, as asked while it was on its way.
    pub then_save: bool,
    pub then_show: bool,
    /// Ours: the peers fetching it now.
    pub sending: Option<Sending>,
    /// Ours: who it went to in full, the first few by name, and how many in all.
    pub sent_to: Vec<String>,
    pub sent_count: usize,
}

/// Ours, being fetched: by how many, and the one furthest along.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sending {
    pub count: usize,
    pub name: String,
    pub permille: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum FileState {
    /// Theirs: nothing fetched yet. Ours: offered.
    Offered,
    /// Ours, no longer offered.
    Withdrawn,
    Fetching {
        got: u64,
        eta: Eta,
    },
    /// Waits for another file from the same sender, `after` (None: for the sender to be back).
    Queued {
        after: Option<u32>,
    },
    Done,
    Failed {
        why: String,
    },
}

/// How long the rest of a fetch takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Eta {
    Seconds(u64),
    /// Its sender is away.
    WaitingSender,
    /// Its sender came back with a new verify code, to compare first.
    WaitingVerify,
}

/// How a room reaches its peers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    /// Onion services: nobody, peers included, learns your IP address. The default.
    #[default]
    Tor,
    /// Direct UDP, found through the LAN and the BitTorrent DHT: faster, but every peer, and the
    /// DHT, sees your IP address.
    #[serde(alias = "udp")]
    Direct,
}

impl RouteMode {
    /// What a settings screen says about each.
    pub fn describe(self) -> &'static str {
        match self {
            RouteMode::Tor => "Tor (private): onion services, so nobody learns your IP address, peers included",
            RouteMode::Direct => "direct (faster): UDP, the LAN and the BitTorrent DHT - shows your IP address to peers",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NostrMode {
    Off,
    /// Only while something needs them.
    Fallback,
    Always,
}

/// What a UI asks a session to do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    Send {
        text: String,
    },
    Reply {
        mid: String,
        text: String,
    },
    Dm {
        peer: PeerId,
        text: String,
    },
    /// The user compared the peer's code: the same, or not.
    Verify {
        peer: PeerId,
        same: bool,
    },
    Ignore {
        peer: PeerId,
        on: bool,
    },
    SetNick {
        nick: String,
    },
    SetColour {
        colour: Colour,
    },
    SetTimer {
        seconds: u32,
    },
    SetHistory {
        on: bool,
    },
    SetVerifyRequired {
        on: bool,
    },
    SetNetLog {
        level: NetLog,
    },
    /// Kept to come back to: leaving tells peers we went offline, not that we left.
    SetComingBack {
        on: bool,
    },
    /// A network report, as notices.
    NetReport,
    /// Fetch file `num`: to show it (a picture, which comes as [`Event::Picture`]) or to save it
    /// in `dir` (None: the Downloads folder). `anyway`: even if it's over the size limit.
    Fetch {
        num: u32,
        #[serde(default)]
        show: bool,
        #[serde(default)]
        anyway: bool,
        #[serde(default)]
        dir: Option<String>,
    },
    /// Offer a file to the room. A picture goes cleaned of what could tell where, when or with
    /// what it was made, unless `asis`. The runtime reads the file ([`crate::Room::offer`]);
    /// a bare [`Session`](crate::protocol::Session) takes it ready, through `offer_file`.
    Offer {
        path: String,
        #[serde(default)]
        asis: bool,
    },
    /// Moving the room: None for the plan (who'd come, who'd stay), `false` to stay when asked.
    /// `true` (go, or move the room ourselves) opens a new room, which the runtime does:
    /// `Room::answer_move`.
    Move {
        #[serde(default)]
        answer: Option<bool>,
    },
    /// Stop fetching file `num`, or stop offering one of ours.
    Cancel {
        num: u32,
    },
    /// The size over which a file needs `anyway` (0: the default, 8 MB), and fast transfers:
    /// while one runs with a peer, slots to it come every few milliseconds instead of every
    /// second or so. Faster, but the burst can be seen.
    SetFileOptions {
        limit: u64,
        fast: bool,
    },
    /// Leave the room, telling everyone.
    Leave,
}

/// What a command did, for the UI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Done,
    /// Our message, numbered for its deliveries: how many peers it went to, and how many it was
    /// held back from until their codes are compared.
    Sent {
        own: u64,
        mid: String,
        to: usize,
        held: usize,
    },
    /// One of our files, offered under this number.
    Offered {
        num: u32,
    },
    /// Who a move would take along, and who it would leave behind.
    MovePlan(MovePlan),
}

/// Who moving the room would take along (peers whose verify codes were compared, whose builds
/// can move), and who it would leave behind, each with why: "bob (code not compared)".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MovePlan {
    pub coming: Vec<String>,
    pub left: Vec<String>,
}

/// A peer asks us to move the room to a new one with them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveAsk {
    /// New for each request.
    pub seq: u32,
    /// Who asks, with a mark once their code was compared.
    pub from: String,
    /// Who else is asked along, by our names for them.
    pub coming: Vec<String>,
    /// Unix time the request came.
    pub at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum CommandError {
    #[error("not connected yet: the room opens once someone answers")]
    NotOpen,
    #[error("nobody else is here yet")]
    Alone,
    #[error("there's nothing to send")]
    Empty,
    #[error("no connected peer has that id")]
    NoSuchPeer,
    #[error("{0}'s chat is too old for direct messages")]
    TooOld(String),
    #[error("compare verify codes with {0} first")]
    NotCompared(String),
    #[error("your verify codes with {0} differ: nothing you send reaches them")]
    CodesDiffer(String),
    #[error("that message is too old to answer")]
    NoSuchMessage,
    #[error("{0}")]
    Invalid(String),
}
