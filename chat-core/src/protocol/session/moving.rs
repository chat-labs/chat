// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Moving the room (:move).
//!
//! With no server, nobody can be put out of a room, and a password that leaked can't be changed.
//! A move instead takes the peers whose verify codes were compared, and whose builds can move, to
//! a new room with an id and password made up on the spot, and leaves everyone else in this one.
//! Each of them is sent the new room over its session ("mv") and asked whether to go. Everyone
//! moving shows the others a key of its own for the move, over the sessions here ("mk", or in
//! "mv"), and signs its sessions in the new room with it ("mp"), so codes compared here count
//! there.
//!
//! The engine does its part in each room; the runtime opens the new room, links the two (the
//! keys shown here go there as [`Request::MoveKey`]), and closes this one once
//! [`Session::move_finished`].

use super::messages::gen_mid;
use super::peer::CodeOk;
use super::*;
use crate::protocol::crypto::identity::{self, IdentityKeypair};
use crate::protocol::{hex, names, record};

/// The longest the room being left stays open, waiting for the keys of those moving with us.
const MOVE_LINGER: f64 = 90.0;

/// Where a move goes, to open the new room with: its id and password, the room it's from, and
/// the key shown here, which signs our sessions there. `created`: we're the one moving the room.
#[derive(Clone)]
pub struct MoveTo {
    pub room: String,
    pub password: String,
    pub from: String,
    pub key: IdentityKeypair,
    pub created: bool,
}

/// A peer's part in a move.
#[derive(Clone, Default)]
pub(crate) struct PeerMove {
    /// In the room being left: the key it showed us for the move ("mv" or "mk"), whether the
    /// room we moved to has it, whether it moves with us, and whether it has our key.
    pub key: Option<[u8; 32]>,
    pub passed: bool,
    pub with: bool,
    pub key_sent: bool,
    /// In the room moved to: its last "mp", kept until a key it can be checked with arrives,
    /// and which of those it matched.
    pub sig: Option<[u8; 64]>,
    pub came_with: Option<usize>,
}

/// A request to move that came.
struct MoveReq {
    from: [u8; 16],
    name: String,
    at: u64,
    room: String,
    password: String,
    /// The peers asked along, as the start of each one's id in hex, comma-separated.
    coming: String,
    told: bool,
    asked: bool,
}

#[derive(Default)]
pub(super) struct Moving {
    /// Ours, shown to those moving with us; made the first time a move needs it.
    key: Option<IdentityKeypair>,
    /// The key shown in the room we moved here from, which signs our "mp" here.
    pub moved_key: Option<IdentityKeypair>,
    req: Option<MoveReq>,
    seq: u32,
    /// Since when we've been leaving: only waiting for the keys of those moving with us.
    leaving: Option<f64>,
    /// Keys shown to us in the room we moved from, by peers whose codes we compared there, with
    /// their nicks there. A peer here that signs its session with one counts as compared.
    came_with: Vec<([u8; 32], String)>,
    /// Keys of compared peers that left before we moved: the one who moved the room leaves as
    /// soon as it has our key, which can be before we answer.
    gone_keys: Vec<([u8; 32], String)>,
}

fn short_hex(id: &[u8; 16]) -> String {
    hex::encode(&id[..4])
}

fn in_id_list(list: &str, id: &[u8; 16]) -> bool {
    let want = short_hex(id);
    list.split(',').any(|s| s == want)
}

/// A room's id or password as "mv" may give them: printable ASCII, with spaces only in a password.
fn move_text_ok(s: &str, max: usize, spaces: bool) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|c| c <= b'~' && c >= if spaces { b' ' } else { b'!' })
}

impl Moving {
    pub fn new(moved_key: Option<IdentityKeypair>) -> Self {
        Moving {
            moved_key,
            ..Default::default()
        }
    }
}

impl Session {
    fn move_comes(&self, p: &Peer) -> bool {
        p.ok && p.code_ok == CodeOk::Same && p.caps.can_move
    }

    fn own_move_key(&mut self) -> IdentityKeypair {
        self.moving.key.get_or_insert_with(IdentityKeypair::generate).clone()
    }

    // ---- the API ----

    /// Who a move would take along (peers whose codes were compared, whose builds can move),
    /// and who it would leave behind, with why.
    pub fn move_plan(&self) -> MovePlan {
        let mut plan = MovePlan::default();
        for slot in self.live() {
            let p = self.peer(slot);
            let name = self.peer_name(slot);
            if self.move_comes(p) {
                plan.coming.push(name);
            } else {
                let why = match p.code_ok {
                    CodeOk::Different => "codes differ",
                    CodeOk::NotCompared => "code not compared",
                    CodeOk::Same => "an older version",
                };
                plan.left.push(format!("{name} ({why})"));
            }
        }
        plan
    }

    /// The request to move that waits for an answer.
    pub fn move_asked(&self) -> Option<MoveAsk> {
        self.moving.req.as_ref().filter(|r| r.asked).map(|_| self.move_ask_info())
    }

    /// Yes to moving: where to go. Answers a peer's request, or (without one) moves the room
    /// ourselves, with a new id and password. The runtime opens that room, then calls
    /// [`Session::move_go`].
    pub fn move_yes(&mut self, now: Now) -> Result<MoveTo, CommandError> {
        self.set_now(now);
        let from = self.room.clone();
        if let Some(r) = self.moving.req.as_ref().filter(|r| r.asked) {
            let (room, password) = (r.room.clone(), r.password.clone());
            return Ok(MoveTo {
                room,
                password,
                from,
                key: self.own_move_key(),
                created: false,
            });
        }
        let plan = self.move_plan();
        if plan.coming.is_empty() {
            return Err(CommandError::Invalid(if plan.left.is_empty() {
                "nobody else is here to move with".into()
            } else {
                "nobody can move with you yet - compare verify codes with them first".into()
            }));
        }
        Ok(MoveTo {
            room: names::random_room_id(),
            password: names::random_password(),
            from,
            key: self.own_move_key(),
            created: true,
        })
    }

    /// The new room is open: the one moving the room now asks those coming. From now on this
    /// room only waits for the keys of those moving with us ([`Request::MoveKey`], for the new
    /// room), until [`Session::move_finished`].
    pub fn move_go(&mut self, to: &MoveTo, now: Now) {
        self.set_now(now);
        if to.created {
            // Everyone asked gets the whole list, and names the others from it as it knows them.
            let coming: Vec<usize> = self.live().into_iter().filter(|&s| self.move_comes(self.peer(s))).collect();
            let list = coming.iter().map(|&s| short_hex(&self.peer(s).id)).collect::<Vec<_>>().join(",");
            let key = hex::encode(&to.key.public);
            for slot in coming {
                let mid = gen_mid();
                let rec = format!("mv\t{mid}\t{}\t{}\t{key}\t{list}", to.room, to.password);
                if self.send_peer(slot, &rec) {
                    self.track(slot, &mid, &rec, None);
                }
                let p = self.peer_mut(slot);
                p.mv.with = true;
                p.mv.key_sent = true;
            }
        } else if let Some(r) = self.moving.req.take() {
            for slot in self.live() {
                let p = self.peer_mut(slot);
                if p.id == r.from || in_id_list(&r.coming, &p.id) {
                    p.mv.with = true;
                }
            }
            self.events.push_back(Event::MoveAsked { ask: None });
        }
        self.moving.leaving = Some(self.now);
        self.pass_move_keys();
    }

    /// No to a request to move: we stay, and where it went is forgotten.
    pub(super) fn move_no(&mut self) -> Result<Outcome, CommandError> {
        let Some(r) = self.moving.req.take() else {
            return Err(CommandError::Invalid("nobody has asked you to move".into()));
        };
        self.note(format!("you stay in this room - where {} moved it is forgotten", r.name));
        self.events.push_back(Event::MoveAsked { ask: None });
        Ok(Outcome::Done)
    }

    /// A room moved out of has done its part: those moving with us have our key and we theirs,
    /// or it has waited long enough. It can be closed.
    pub fn move_finished(&self) -> bool {
        let Some(since) = self.moving.leaving else { return false };
        if self.now - since > MOVE_LINGER {
            return true;
        }
        // Every key that came has gone on to the new room, too.
        self.moving.gone_keys.is_empty()
            && self.live().into_iter().all(|s| {
                let p = self.peer(s);
                let waiting = p
                    .pending
                    .iter()
                    .any(|pm| pm.record.starts_with("mv\t") || pm.record.starts_with("mk\t"));
                let unpassed = p.mv.key.is_some() && !p.mv.passed && p.code_ok == CodeOk::Same;
                !waiting && !unpassed && !(p.mv.with && p.mv.key.is_none())
            })
    }

    /// In the room moved to: a key shown in the room we moved from by a peer whose code we had
    /// compared there, with its nick there.
    pub fn came_with(&mut self, public: [u8; 32], nick: &str) {
        if self.moving.came_with.iter().any(|(k, _)| *k == public) || self.moving.came_with.len() >= MAX_PEERS {
            return;
        }
        self.moving.came_with.push((public, nick.to_string()));
        for slot in self.live() {
            self.check_came_with(slot);
        }
    }

    // ---- the protocol ----

    /// "mv": a peer moves the room, and asks us along.
    pub(super) fn on_move(&mut self, slot: usize, f: &[&[u8]]) {
        if !self.ack_record(slot, f[1]) {
            return;
        }
        let mid = String::from_utf8_lossy(f[1]).into_owned();
        if self.seen_has(&mid) {
            return;
        }
        self.seen_add(&mid);
        let (Some(room), Some(password), Some(key), Some(coming)) = (
            record::str_field(f, 2).filter(|s| move_text_ok(s, names::MAX_ROOM_ID, false)),
            record::str_field(f, 3).filter(|s| move_text_ok(s, names::MAX_PASSWORD, true)),
            record::str_field(f, 4).and_then(hex::decode_array::<32>),
            record::str_field(f, 5).filter(|s| s.len() < MAX_PEERS * 9 + 1),
        ) else {
            return;
        };
        if self.moving.leaving.is_some() || self.peer(slot).code_ok == CodeOk::Different {
            return;
        }
        let p = self.peer_mut(slot);
        p.mv.key = Some(key);
        p.mv.passed = false;
        let (from, name) = (p.id, self.peer_name(slot));
        if let Some(old) = &self.moving.req
            && old.from != from
        {
            let old_name = old.name.clone();
            self.note(format!("{name}'s request to move replaces {old_name}'s"));
        }
        self.moving.req = Some(MoveReq {
            from,
            name,
            at: self.unix,
            room: room.to_string(),
            password: password.to_string(),
            coming: coming.to_string(),
            told: false,
            asked: false,
        });
        self.move_ask_now();
    }

    /// "mk": its key for the move, which the room we moved to checks its "mp" against.
    pub(super) fn on_move_key(&mut self, slot: usize, f: &[&[u8]]) {
        let Some(key) = record::str_field(f, 2).and_then(hex::decode_array::<32>) else {
            return;
        };
        if !self.ack_record(slot, f[1]) {
            return;
        }
        let p = self.peer_mut(slot);
        if p.mv.key != Some(key) {
            p.mv.key = Some(key);
            p.mv.passed = false;
        }
    }

    /// "mp": in the room moved to, its session signed with the key it showed in the old one.
    pub(super) fn on_move_proof(&mut self, slot: usize, f: &[&[u8]]) {
        let Some(sig) = record::str_field(f, 1).and_then(hex::decode_array::<64>) else {
            return;
        };
        self.peer_mut(slot).mv.sig = Some(sig);
        self.check_came_with(slot);
    }

    /// Our "mp", ahead of "k": this session's keys signed with the key we showed in the room we
    /// moved here from.
    pub(super) fn move_proof(&self, slot: usize) -> Option<String> {
        let key = self.moving.moved_key.as_ref()?;
        let p = self.peer(slot);
        let (mine, theirs) = p.signed_pubs();
        let sig = key.sign_move(&mine, &self.my_id, &theirs, &p.id);
        Some(format!("mp\t{}", hex::encode(&sig)))
    }

    /// Whether a peer's join waits for its "mp": in a room we moved to, one who came along sends
    /// it ahead of each "k", so its join isn't announced asking to compare codes compared already.
    pub(super) fn join_waits_for_proof(&self, p: &Peer) -> bool {
        self.moving.moved_key.is_some() && p.mv.sig.is_none()
    }

    /// Shows the request to move once its sender's code was compared, and sends our key to the
    /// sender and the others it asks along, so codes compared here count in the new room whatever
    /// we answer. Until then it says to compare codes. It's dropped if they differ, or the sender
    /// leaves first.
    pub(super) fn move_ask_now(&mut self) {
        let Some(r) = self.moving.req.as_ref().filter(|r| !r.asked) else {
            return;
        };
        let from = r.from;
        let slot = self.find_peer(&from).filter(|&s| self.peer(s).ok);
        let Some(slot) = slot.filter(|&s| self.peer(s).code_ok != CodeOk::Different) else {
            let r = self.moving.req.take().expect("checked");
            self.note(format!(
                "{}'s request to move this room is dropped: {}",
                r.name,
                if slot.is_some() {
                    "your verify codes differ"
                } else {
                    "they left before you compared verify codes with them"
                }
            ));
            return;
        };
        let name = self.peer_name(slot);
        let compared = self.peer(slot).code_ok == CodeOk::Same;
        let r = self.moving.req.as_mut().expect("checked");
        r.name = name.clone();
        if !compared {
            if !r.told {
                r.told = true;
                self.warn(format!(
                    "{name} wants to move this room to a new one, but you haven't compared verify codes with them. Compare \
                     them soon, while they're still here, and you'll be asked whether to go"
                ));
            }
            return;
        }
        r.asked = true;
        let coming = r.coming.clone();
        self.moving.seq += 1;
        for s in self.live() {
            let p = self.peer(s);
            if p.id == from || in_id_list(&coming, &p.id) {
                self.send_move_key(s);
            }
        }
        let ask = self.move_ask_info();
        let with = if ask.coming.is_empty() {
            String::new()
        } else {
            format!(", with {}", names::list(&ask.coming))
        };
        self.warn(format!("{name} wants to move this room to a new one{with} - answer whether to go"));
        self.events.push_back(Event::MoveAsked { ask: Some(ask) });
    }

    fn move_ask_info(&self) -> MoveAsk {
        let r = self.moving.req.as_ref().expect("asked");
        let from_slot = self.find_peer(&r.from);
        let mut coming = Vec::new();
        let mut strangers = 0;
        let (mine, theirs) = (short_hex(&self.my_id), short_hex(&r.from));
        for s in r.coming.split(',').filter(|s| s.len() == 8 && *s != mine && *s != theirs) {
            match self.live().into_iter().find(|&q| short_hex(&self.peer(q).id) == s) {
                Some(q) => coming.push(self.peer_name(q)),
                None => strangers += 1,
            }
        }
        match strangers {
            0 => {}
            1 => coming.push("a peer you aren't connected to".into()),
            n => coming.push(format!("{n} peers you aren't connected to")),
        }
        let mark = from_slot.map(|s| self.peer(s).code_ok == CodeOk::Same).unwrap_or(false);
        MoveAsk {
            seq: self.moving.seq,
            from: format!("{}{}", r.name, if mark { " \u{2713}" } else { "" }),
            coming,
            at: r.at,
        }
    }

    /// "mk": our key for the move, to a peer moving with us, acked and retried like a message.
    fn send_move_key(&mut self, slot: usize) {
        let key = self.own_move_key();
        let p = self.peer_mut(slot);
        if p.mv.key_sent || p.code_ok == CodeOk::Different {
            return;
        }
        p.mv.key_sent = true;
        let mid = gen_mid();
        let rec = format!("mk\t{mid}\t{}", hex::encode(&key.public));
        if self.send_peer(slot, &rec) {
            self.track(slot, &mid, &rec, None);
        }
    }

    /// A peer leaves: the key it showed us for a move is kept, if we compared its code, in case
    /// we move after it.
    pub(super) fn keep_move_key(&mut self, p: &Peer) {
        if let Some(key) = p.mv.key.filter(|_| p.code_ok == CodeOk::Same && !p.mv.passed)
            && self.moving.gone_keys.len() < MAX_PEERS
        {
            self.moving.gone_keys.push((key, p.nick.clone()));
        }
    }

    /// The room we moved to gets the keys shown to us here by peers whose codes we compared, as
    /// they come.
    pub(super) fn pass_move_keys(&mut self) {
        if self.moving.leaving.is_none() {
            return;
        }
        for (public, nick) in std::mem::take(&mut self.moving.gone_keys) {
            self.requests.push_back(Request::MoveKey { public, nick });
        }
        for slot in self.live() {
            let p = self.peer_mut(slot);
            let Some(public) = p.mv.key.filter(|_| !p.mv.passed && p.code_ok == CodeOk::Same) else {
                continue;
            };
            p.mv.passed = true;
            let nick = p.nick.clone();
            self.requests.push_back(Request::MoveKey { public, nick });
        }
    }

    /// A peer that signs its session here ("mp") with a key shown to us in the room we moved
    /// from, by a peer whose code we compared there, is that peer: its code counts as compared.
    pub(super) fn check_came_with(&mut self, slot: usize) {
        let my_id = self.my_id;
        let p = self.peer(slot);
        let Some(sig) = p.mv.sig.filter(|_| p.code_ok == CodeOk::NotCompared) else {
            return;
        };
        let matched = self.moving.came_with.iter().position(|(key, _)| {
            identity::verify_move(key, &sig, &p.public, &p.id, &p.my_pub, &my_id)
                || p.prev_keys
                    .is_some_and(|(theirs, mine)| identity::verify_move(key, &sig, &theirs, &p.id, &mine, &my_id))
        });
        let Some(i) = matched else { return };
        let trusted_before = self.trusted(self.peer(slot));
        let p = self.peer_mut(slot);
        p.code_ok = CodeOk::Same;
        p.mv.came_with = Some(i);
        if p.announced {
            self.tell_came_with(slot);
            self.peer_changed(slot);
            if !trusted_before {
                self.file_offer_all(slot);
            }
        }
    }

    pub(super) fn tell_came_with(&mut self, slot: usize) {
        let Some(i) = self.peer(slot).mv.came_with else { return };
        let name = self.peer_name(slot);
        let was = &self.moving.came_with[i].1;
        let text = if *was == self.peer(slot).nick {
            format!("{name} came along from the room you moved from, where you compared verify codes - no need to compare them again")
        } else {
            format!("{name} is {was} from the room you moved from, where you compared verify codes - no need to compare them again")
        };
        self.note(text);
    }

    /// Each tick: a request waiting for a compared code is shown once it is, and keys go on to
    /// the room we moved to.
    pub(super) fn move_tick(&mut self) {
        if self.moving.req.as_ref().is_some_and(|r| !r.asked) {
            self.move_ask_now();
        }
        self.pass_move_keys();
    }
}
