// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Files, as `protocol::files` describes them: offers ("fo"), requests for a window of chunks
//! ("fg"), the chunks themselves, sent in slots that would carry a nop ("fd"), and "not offered
//! any more" ("fx").
//!
//! A fetch asks its sender for a window of chunks at a time. Each chunk goes in its place in the
//! window; a run of missing ones is asked for again. A complete window is written in order and
//! hashed, and the file is only kept if the hash matches the offer. One file at a time comes from
//! each sender; others wait their turn.

use super::messages::gen_mid;
use super::*;
use crate::protocol::files::{Disk, FILE_CACHE_MAX, FILE_CAP_DEFAULT, FILE_HARD_MAX, FILE_VIEW_MAX, Part, Source};
use crate::protocol::files::{clean_name, format_duration, format_size};
use crate::protocol::{base64, hex, picture, record};
use zeroize::Zeroizing;

/// A chunk's bytes, base64'd into one record: "fd" FID OFFSET DATA.
pub(super) const FILE_CHUNK: usize = 690;
const FILE_WINDOW: usize = 64;
/// Slots during a fast transfer, over UDP or Tor.
pub(super) const FILE_FAST_INTERVAL: f64 = 0.005;
/// At most this many fast slots at once, however late a tick is.
pub(super) const FAST_BURST_MAX: u32 = 64;
const FILE_RETRIES: u32 = 8;
/// A fetch waits up to this long for its sender to come back (a Tor circuit or a relay can stall
/// a peer), and continues from where it was if they do.
const FILE_OWNER_GRACE: f64 = 120.0;
/// One of ours counts as being fetched by a peer until it has gone this long without asking for
/// more, since requests come a window at a time.
const FILE_SENDING_QUIET: f64 = 30.0;
const FILE_OFFERS_MAX: usize = 64;
/// A peer over this many offers replaces its own oldest, so nobody can push out everyone else's.
const FILE_OFFERS_PER_PEER: usize = 16;
/// The peers one of ours went to in full that are named; beyond those it's only counted.
const FILE_SENT_MAX: usize = 4;
const ETA_MIN_CHUNKS: u64 = 4;
/// The next chunk of a run counts as lost after this many of the gaps chunks have been coming
/// at, and a little more for the path's jitter.
const CHUNK_LATE: f64 = 6.0;
const CHUNK_LATE_MARGIN: f64 = 1.0;
/// The file list goes to the UI at most this often.
const FILES_EVENT_EVERY: f64 = 0.5;
/// Through the relays a fast transfer can't burst: slots come no more than this often a second
/// for all relayed peers together, and never closer than this.
const NOSTR_FAST_RATE: f64 = 0.4;
const NOSTR_FAST_INTERVAL: f64 = 2.5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dl {
    None,
    Active,
    Done,
    Failed,
    /// Asked for while another file from the same sender is coming: it starts after that one.
    Queued,
}

/// One of ours, ready to offer: read, hashed and (for a picture) cleaned by the runtime.
pub struct OwnFile {
    /// The name it's offered under (already through `files::clean_name`).
    pub name: String,
    pub size: u64,
    pub sha: [u8; 32],
    pub image: bool,
    /// Where its chunks are read from.
    pub source: Box<dyn Source>,
    /// A picture's bytes, to show here.
    pub picture: Option<Zeroizing<Vec<u8>>>,
    /// Cleaned: what was taken out (`picture::CLEAN_` flags), and its old name if that was
    /// replaced because it told too much.
    pub cleaned: Option<(u32, Option<String>)>,
    /// A kind of file chat can't clean that may say where and when it was made.
    pub cannot: Option<&'static str>,
}

/// A peer fetching one of ours: the chunks it asked for, sent in its slots.
#[derive(Clone, Copy, Default)]
pub(crate) struct Serve {
    pub active: bool,
    pub fid: [u8; 8],
    pub next: u64,
    pub end: u64,
    /// When it last asked, or was sent a chunk.
    pub at: f64,
}

struct Entry {
    num: u32,
    mine: bool,
    owner: [u8; 16],
    fid: [u8; 8],
    size: u64,
    sha: [u8; 32],
    name: String,
    image: bool,
    at: u64,
    /// Ours, while it's offered.
    source: Option<Box<dyn Source>>,

    dl: Dl,
    view: bool,
    also_show: bool,
    also_save: bool,
    save_dir: Option<String>,
    saved: Option<String>,
    /// A picture shown here, checked against the offer, for showing and saving again.
    cache: Option<Zeroizing<Vec<u8>>>,
    part: Option<Box<dyn Part>>,
    mem: Option<Zeroizing<Vec<u8>>>,
    /// Bytes in order, written and hashed.
    done: u64,
    hash: Option<sodium::Sha256>,
    /// The window asked for: `win_n` chunks from `win_off`, and which of them have come.
    win_off: u64,
    win_n: usize,
    win_got: u64,
    /// The chunk after the run last asked for.
    req_end: usize,
    win: Option<Zeroizing<Vec<u8>>>,
    retry_at: f64,
    retries: u32,
    /// When the last chunk came, and roughly how far apart they come: a sender with fast
    /// transfers on sends them milliseconds apart, so a lost one is asked for again sooner.
    last_chunk: f64,
    chunk_gap: f64,
    since: f64,
    gone_since: f64,
    why: String,
    sent: Vec<([u8; 16], String)>,
    n_sent: usize,
}

impl Entry {
    fn new(num: u32) -> Self {
        Entry {
            num,
            mine: false,
            owner: [0; 16],
            fid: [0; 8],
            size: 0,
            sha: [0; 32],
            name: String::new(),
            image: false,
            at: 0,
            source: None,
            dl: Dl::None,
            view: false,
            also_show: false,
            also_save: false,
            save_dir: None,
            saved: None,
            cache: None,
            part: None,
            mem: None,
            done: 0,
            hash: None,
            win_off: 0,
            win_n: 0,
            win_got: 0,
            req_end: 0,
            win: None,
            retry_at: 0.0,
            retries: 0,
            last_chunk: 0.0,
            chunk_gap: 0.0,
            since: 0.0,
            gone_since: 0.0,
            why: String::new(),
            sent: Vec::new(),
            n_sent: 0,
        }
    }

    fn coming(&self) -> bool {
        matches!(self.dl, Dl::Active | Dl::Queued)
    }

    /// "photo.jpg (230 KB, image)".
    fn desc(&self) -> String {
        format!(
            "{} ({}{})",
            self.name,
            format_size(self.size),
            if self.image { ", image" } else { "" }
        )
    }

    /// Bytes received, including any in the window not written yet.
    fn got(&self) -> u64 {
        let mut got = self.done;
        for i in 0..self.win_n {
            if self.win_got >> i & 1 == 0 {
                continue;
            }
            let off = self.win_off + (i * FILE_CHUNK) as u64;
            got += (self.size - off.min(self.size)).min(FILE_CHUNK as u64);
        }
        got.min(self.size)
    }

    /// Stops a download: the part file goes, and anything in memory is wiped.
    fn stop(&mut self, to: Dl) {
        self.part = None;
        self.mem = None;
        self.win = None;
        self.hash = None;
        self.done = 0;
        self.win_off = 0;
        self.win_got = 0;
        self.win_n = 0;
        self.dl = to;
    }

    fn fail(&mut self, why: &str) {
        self.stop(Dl::Failed);
        self.why = why.to_string();
    }
}

/// The session's files.
pub(super) struct Files {
    entries: Vec<Entry>,
    seq: u32,
    cap: u64,
    pub fast: bool,
    disk: Option<Box<dyn Disk>>,
    changed: bool,
    last_event: f64,
}

impl Files {
    pub fn new(cap: u64, fast: bool) -> Self {
        Files {
            entries: Vec::new(),
            seq: 0,
            cap: if cap == 0 { FILE_CAP_DEFAULT } else { cap },
            fast,
            disk: None,
            changed: false,
            last_event: f64::NEG_INFINITY,
        }
    }
}

/// What a copy saved before, or a picture held here, was good for.
enum Local {
    Saved,
    /// No copy here that still matches the offer.
    NoCopy,
    /// It couldn't be written (already said why).
    Failed(String),
}

impl Session {
    // ---- the API ----

    /// Where fetched files are saved. Without one, files can only be fetched to be shown.
    pub fn set_disk(&mut self, disk: Box<dyn Disk>) {
        self.files.disk = Some(disk);
    }

    /// Offers one of ours to everyone here, and to whoever joins.
    pub fn offer_file(&mut self, f: OwnFile, now: Now) -> Result<Outcome, CommandError> {
        self.set_now(now);
        self.offer_own(f).map(|num| Outcome::Offered { num })
    }

    fn offer_own(&mut self, f: OwnFile) -> Result<u32, CommandError> {
        if f.size > FILE_HARD_MAX {
            return Err(CommandError::Invalid(format!("files go up to {}", format_size(FILE_HARD_MAX))));
        }
        let Some(i) = self.file_new(None) else {
            return Err(CommandError::Invalid(
                "can't offer more files at once - cancel one you offered first".into(),
            ));
        };
        let unix = self.unix;
        let my_id = self.my_id;
        let e = &mut self.files.entries[i];
        e.mine = true;
        e.owner = my_id;
        e.fid = sodium::random_array();
        e.name = f.name;
        e.size = f.size;
        e.sha = f.sha;
        e.image = f.image;
        e.at = unix;
        e.source = Some(f.source);
        let (num, desc) = (e.num, e.desc());
        if let Some(pic) = f.picture.filter(|p| p.len() as u64 == f.size) {
            self.cache_keep(i, pic);
        }
        self.events.push_back(Event::Message(Message {
            mid: String::new(),
            from: PeerId(self.my_id),
            nick: self.nick.clone(),
            name: self.nick.clone(),
            peer: None,
            colour: Some(self.colour),
            mine: true,
            own: None,
            direct: false,
            mention: false,
            relayed: false,
            text: format!("offered {desc} as file {num}"),
            quote_len: 0,
            reply_to: None,
            at: unix,
            file: Some(num),
        }));
        if let Some((took, old_name)) = f.cleaned {
            let mut what: Vec<String> = picture::describe(took).into_iter().map(String::from).collect();
            if let Some(old) = old_name {
                what.push(format!("its name ({old})"));
            }
            let noise = if took & picture::CLEAN_NOISE != 0 {
                "; added noise nobody can see, so it matches no other copy"
            } else {
                ""
            };
            if what.is_empty() {
                self.note(format!("file {num}: nothing in it to take out{noise}"));
            } else {
                self.note(format!(
                    "file {num}: took out {}{noise} - offering a picture \"as is\" leaves it all in",
                    what.join(", ")
                ));
            }
        }
        if let Some(kind) = f.cannot {
            self.warn(format!(
                "file {num} is a {kind}, which chat can't clean: it may say where, when and with what it was made"
            ));
        }
        let (mut sent, mut held) = (0, 0);
        for slot in self.live() {
            if !self.trusted(self.peer(slot)) {
                held += 1;
                continue;
            }
            self.send_offer(slot, i);
            sent += 1;
        }
        if held > 0 {
            self.note(format!(
                "not offered to {held} peer{} whose verify code you haven't compared",
                if held == 1 { "" } else { "s" }
            ));
        } else if sent == 0 {
            self.note("nobody else is here yet - it's offered to whoever joins");
        }
        if self.files.entries[i].image {
            self.note(format!(
                "it's offered as a picture: others see it hidden until they choose to show file {num}"
            ));
            self.emit_picture(i);
        }
        self.files.changed = true;
        Ok(num)
    }

    /// The files offered here and ours, oldest first.
    pub fn files(&self) -> Vec<FileInfo> {
        let mut list: Vec<FileInfo> = (0..self.files.entries.len()).map(|i| self.file_info(i)).collect();
        list.sort_by_key(|f| f.num);
        list
    }

    /// A picture's bytes, checked against its offer: kept from when it was shown, a saved copy,
    /// or ours. None if there's none here.
    pub fn picture_bytes(&mut self, num: u32) -> Option<Vec<u8>> {
        if self.left {
            return None;
        }
        let i = self.file_idx(num)?;
        self.picture_here(i)?;
        self.files.entries[i].cache.as_ref().map(|c| c.to_vec())
    }

    // ---- commands ----

    pub(super) fn set_file_options(&mut self, limit: u64, fast: bool) {
        self.files.cap = if limit == 0 { FILE_CAP_DEFAULT } else { limit };
        self.files.fast = fast;
    }

    pub(super) fn fetch(&mut self, num: u32, view: bool, anyway: bool, dir: Option<String>) -> Result<Outcome, CommandError> {
        let bad = |s: String| Err(CommandError::Invalid(s));
        let Some(i) = self.file_idx(num) else {
            return bad(format!("there's no file {num}"));
        };
        let e = &self.files.entries[i];
        let (mine, image, size, coming) = (e.mine, e.image, e.size, e.coming());
        if mine && (!view || !image) {
            return bad(format!("file {num} is yours"));
        }
        if view && !image {
            return bad(format!("file {num} isn't offered as a picture - save it instead"));
        }
        let sz = format_size(size);
        if view && size > FILE_VIEW_MAX {
            return bad(format!("file {num} is too big to show ({sz})"));
        }
        if mine {
            if self.picture_here(i).is_none() {
                let why = if self.files.entries[i].source.is_some() {
                    "it changed after you offered it"
                } else {
                    "it isn't offered any more"
                };
                return bad(format!("can't show file {num}: {why}"));
            }
            self.emit_picture(i);
            return Ok(Outcome::Done);
        }
        if view {
            if self.files.entries[i].cache.is_none() && !coming {
                self.picture_here(i);
            }
            let e = &mut self.files.entries[i];
            if e.cache.is_some() {
                if !coming {
                    e.dl = Dl::Done;
                    e.why.clear();
                }
                self.emit_picture(i);
                self.files.changed = true;
                return Ok(Outcome::Done);
            }
            if coming {
                if e.view {
                    return bad(format!("file {num} is already on its way"));
                }
                e.also_show = true;
                self.files.changed = true;
                self.note(format!("file {num} is on its way to be saved, and is shown too once it's here"));
                return Ok(Outcome::Done);
            }
        } else {
            let want = dir.map(|d| d.trim_end_matches(['/', '\\']).to_string()).filter(|d| !d.is_empty());
            let e = &mut self.files.entries[i];
            if coming {
                if !e.view {
                    return bad(format!("file {num} is already on its way"));
                }
                e.also_save = true;
                e.save_dir = want;
                self.files.changed = true;
                self.note(format!("file {num} is on its way to be shown, and is saved too once it's here"));
                return Ok(Outcome::Done);
            }
            if want.is_none() && e.saved.is_some() {
                if self.check_saved(i, false).is_some() {
                    let at = self.files.entries[i].saved.clone().unwrap_or_default();
                    self.note(format!(
                        "file {num} is already saved at {at} - save it to another folder for another copy"
                    ));
                    return Ok(Outcome::Done);
                }
                self.files.entries[i].saved = None;
            }
            self.files.entries[i].save_dir = want;
            // Shown before, or saved somewhere else: copied from there instead of fetched again.
            let e = &self.files.entries[i];
            if e.cache.is_some() || e.saved.is_some() {
                match self.save_local(i, true) {
                    Local::Saved => {
                        let e = &mut self.files.entries[i];
                        e.dl = Dl::Done;
                        e.why.clear();
                        let at = e.saved.clone().unwrap_or_default();
                        self.files.changed = true;
                        self.note(format!("saved file {num} to {at}, from the copy already here"));
                        return Ok(Outcome::Done);
                    }
                    Local::Failed(why) => return bad(why),
                    Local::NoCopy => {}
                }
            }
        }
        let Some(slot) = self.file_owner(i) else {
            return bad(format!("whoever offered file {num} isn't here now - try again once they're back"));
        };
        let name = self.peer_name(slot);
        if !self.trusted(self.peer(slot)) {
            return bad(format!(
                "compare verify codes with {name} first: until then someone in the middle could be sending it"
            ));
        }
        let e = &mut self.files.entries[i];
        if e.size > self.files.cap && !anyway {
            return bad(format!(
                "file {num} is {sz}, over your {} limit - fetch it \"anyway\" to get it regardless",
                format_size(self.files.cap)
            ));
        }
        e.view = view;
        e.also_show = false;
        e.also_save = false;
        self.files.changed = true;
        // One file at a time from each sender. The others wait their turn in files_tick.
        let owner = e.owner;
        if self.downloading_from(&owner) {
            self.files.entries[i].dl = Dl::Queued;
            let after = self.queued_after(i).unwrap_or(0);
            self.note(format!("file {num} is queued: it starts once file {after} from {name} is done"));
            return Ok(Outcome::Done);
        }
        self.file_start(i, slot);
        Ok(Outcome::Done)
    }

    pub(super) fn cancel_file(&mut self, num: u32) -> Result<Outcome, CommandError> {
        let Some(i) = self.file_idx(num) else {
            return Err(CommandError::Invalid(format!("there's no file {num}")));
        };
        self.files.changed = true;
        let e = &mut self.files.entries[i];
        if e.mine {
            e.source = None;
            let fid = e.fid;
            for p in self.peers.iter_mut().flatten() {
                if p.serve.active && p.serve.fid == fid {
                    p.serve.active = false;
                }
            }
            self.note(format!("file {num} is no longer offered"));
        } else if e.dl == Dl::Active {
            e.stop(Dl::None);
            self.note(format!("stopped fetching file {num}"));
        } else if e.dl == Dl::Queued {
            e.dl = Dl::None;
            self.note(format!("file {num} is no longer queued"));
        } else {
            return Err(CommandError::Invalid(format!("file {num} isn't being fetched")));
        }
        Ok(Outcome::Done)
    }

    // ---- the protocol ----

    /// Our offers, to a peer that has just joined or whose code was just compared.
    pub(super) fn file_offer_all(&mut self, slot: usize) {
        let p = self.peer(slot);
        if !p.ok || !self.trusted(p) {
            return;
        }
        for i in 0..self.files.entries.len() {
            let e = &self.files.entries[i];
            if e.mine && e.source.is_some() {
                self.send_offer(slot, i);
            }
        }
    }

    fn send_offer(&mut self, slot: usize, i: usize) {
        let e = &self.files.entries[i];
        let mid = gen_mid();
        let rec = format!(
            "fo\t{mid}\t{}\t{}\t{}\t{}\t{}",
            hex::encode(&e.fid),
            e.size,
            hex::encode(&e.sha),
            if e.image { "image" } else { "file" },
            e.name
        );
        // Retried until acked, like a message.
        if self.send_peer(slot, &rec) {
            self.track(slot, &mid, &rec, None);
        }
    }

    /// A file record from a peer: an offer, a request for chunks of one of ours, a chunk, or
    /// "not offered any more".
    pub(super) fn on_file_record(&mut self, slot: usize, f: &[&[u8]]) {
        let fid = |s: &[u8]| std::str::from_utf8(s).ok().and_then(hex::decode_array::<8>);
        let num = |i: usize| record::str_field(f, i).and_then(record::parse_u64);
        match (f[0], f.len()) {
            (b"fo", 7) => {
                let (Some(id), Some(size), Some(sha)) =
                    (fid(f[2]), num(3), std::str::from_utf8(f[4]).ok().and_then(hex::decode_array::<32>))
                else {
                    return;
                };
                if !self.ack_record(slot, f[1]) {
                    return;
                }
                self.on_offer(slot, id, size, sha, f[5], f[6]);
            }
            (b"fg", 4) => {
                if let (Some(id), Some(off), Some(count)) = (fid(f[1]), num(2), num(3)) {
                    self.on_request(slot, id, off, count);
                }
            }
            (b"fd", 4) => {
                if let (Some(id), Some(off)) = (fid(f[1]), num(2)) {
                    self.on_chunk(slot, id, off, f[3]);
                }
            }
            (b"fx", 2) => {
                let Some(id) = fid(f[1]) else { return };
                let owner = self.peer(slot).id;
                let Some(i) = self.file_idx_fid(&owner, &id) else { return };
                if self.files.entries[i].dl != Dl::Active {
                    return;
                }
                self.files.entries[i].fail("isn't offered any more");
                self.files.changed = true;
                let (name, num) = (self.peer_name(slot), self.files.entries[i].num);
                self.note(format!("{name} no longer offers file {num}"));
            }
            _ => {}
        }
    }

    fn on_offer(&mut self, slot: usize, fid: [u8; 8], size: u64, sha: [u8; 32], kind: &[u8], name: &[u8]) {
        let p = self.peer(slot);
        let owner = p.id;
        if self.is_ignored(&owner) || size > FILE_HARD_MAX || (kind != b"image" && kind != b"file") {
            return;
        }
        // A retry of one we have.
        if self.file_idx_fid(&owner, &fid).is_some() {
            return;
        }
        let Some(i) = self.file_new(Some(owner)) else { return };
        let unix = self.unix;
        let e = &mut self.files.entries[i];
        e.owner = owner;
        e.fid = fid;
        e.size = size;
        e.sha = sha;
        e.image = kind == b"image";
        e.name = clean_name(name);
        e.at = unix;
        let (num, desc) = (e.num, e.desc());
        let over = if size > self.files.cap { " (over your limit)" } else { "" };
        let p = self.peer(slot);
        let msg = Message {
            mid: String::new(),
            from: PeerId(owner),
            nick: p.nick.clone(),
            name: self.peer_name(slot),
            peer: Some(PeerId(owner)),
            colour: Some(p.colour),
            mine: false,
            own: None,
            direct: false,
            mention: false,
            relayed: false,
            text: format!("offers {desc} as file {num}{over}"),
            quote_len: 0,
            reply_to: None,
            at: unix,
            file: Some(num),
        };
        self.events.push_back(Event::Message(msg));
        self.files.changed = true;
    }

    fn on_request(&mut self, slot: usize, fid: [u8; 8], off: u64, count: u64) {
        let my_id = self.my_id;
        // Only our files, still offered, to someone who would have been offered them. A file of
        // ours that isn't offered any more gets "fx". One that never was gets nothing, so made up
        // ids can't fill the queue.
        let Some(i) = self.file_idx_fid(&my_id, &fid) else { return };
        let e = &self.files.entries[i];
        if e.source.is_none() || !self.trusted(self.peer(slot)) {
            self.send_peer(slot, &format!("fx\t{}", hex::encode(&fid)));
            return;
        }
        if !(1..=FILE_WINDOW as u64).contains(&count) || !off.is_multiple_of(FILE_CHUNK as u64) || off >= e.size {
            return;
        }
        let end = (off + count * FILE_CHUNK as u64).min(e.size);
        let now = self.now;
        self.peer_mut(slot).serve = Serve {
            active: true,
            fid,
            next: off,
            end,
            at: now,
        };
        self.files.changed = true;
    }

    fn on_chunk(&mut self, slot: usize, fid: [u8; 8], off: u64, data: &[u8]) {
        let owner = self.peer(slot).id;
        let Some(i) = self.file_idx_fid(&owner, &fid) else { return };
        let e = &self.files.entries[i];
        if e.dl != Dl::Active || off < e.win_off || !off.is_multiple_of(FILE_CHUNK as u64) {
            return;
        }
        let idx = ((off - e.win_off) / FILE_CHUNK as u64) as usize;
        if idx >= e.win_n || e.win_got >> idx & 1 != 0 {
            return;
        }
        let want = (e.size - off).min(FILE_CHUNK as u64) as usize;
        let Some(bytes) = std::str::from_utf8(data).ok().and_then(base64::decode_strict) else {
            return;
        };
        let bytes = Zeroizing::new(bytes);
        if bytes.len() != want || data.len() != base64::encoded_len(want) {
            return;
        }
        let iv = self.transfer_interval(slot);
        let now = self.now;
        let e = &mut self.files.entries[i];
        let Some(win) = e.win.as_mut() else { return };
        win[idx * FILE_CHUNK..idx * FILE_CHUNK + want].copy_from_slice(&bytes);
        e.win_got |= 1 << idx;
        e.retries = 0;
        // The next chunk of a run comes a slot after this one: if it doesn't, it was lost.
        let gap = now - e.last_chunk;
        if e.last_chunk > 0.0 && gap < iv {
            e.chunk_gap = 0.8 * e.chunk_gap + 0.2 * gap.max(FILE_FAST_INTERVAL);
        } else if e.chunk_gap == 0.0 {
            e.chunk_gap = iv;
        }
        e.last_chunk = now;
        e.retry_at = now + CHUNK_LATE * e.chunk_gap.max(FILE_FAST_INTERVAL) + CHUNK_LATE_MARGIN;
        self.files.changed = true;
        let full = if e.win_n == 64 { u64::MAX } else { (1u64 << e.win_n) - 1 };
        if e.win_got != full {
            // The last of the run asked for has come and the window still has a gap: whatever
            // is in it was lost, so it's asked for now instead of when the retry is due. Through
            // the relays that saves half a minute.
            if idx + 1 == e.req_end {
                self.file_request(i, slot);
            }
            return;
        }
        // The window is complete: written in order, and added to the hash.
        let bytes = (e.size - e.win_off).min((e.win_n * FILE_CHUNK) as u64) as usize;
        let win = e.win.as_ref().expect("a fetch has a window");
        let ok = match (&mut e.mem, &mut e.part) {
            (Some(mem), _) => {
                mem.extend_from_slice(&win[..bytes]);
                true
            }
            (None, Some(part)) => part.write(&win[..bytes]),
            _ => false,
        };
        if !ok {
            let (num, desc) = (e.num, e.desc());
            e.fail("couldn't be written - is the disk full?");
            self.note(format!("couldn't write file {num} ({desc}) - is the disk full?"));
            return;
        }
        if let Some(h) = e.hash.as_mut() {
            h.update(&win[..bytes]);
        }
        e.done += bytes as u64;
        e.win_off += bytes as u64;
        e.win_n = 0;
        if e.done >= e.size {
            self.file_finish(i);
        } else {
            self.file_request(i, slot);
        }
    }

    /// The next chunk a peer asked for, added to text after what's there (instead of a nop if
    /// nothing is), if it fits in cap. Returns whether it was added.
    pub(super) fn next_chunk(&mut self, slot: usize, text: &mut String, cap: usize) -> bool {
        let s = self.peer(slot).serve;
        let my_id = self.my_id;
        let Some(i) = self
            .file_idx_fid(&my_id, &s.fid)
            .filter(|&i| self.files.entries[i].source.is_some())
        else {
            self.peer_mut(slot).serve.active = false;
            return false;
        };
        if s.next >= s.end {
            self.peer_mut(slot).serve.active = false;
            return false;
        }
        let want = (s.end - s.next).min(FILE_CHUNK as u64) as usize;
        let head = format!(
            "{}fd\t{}\t{}\t",
            if text.is_empty() { "" } else { "\n" },
            hex::encode(&s.fid),
            s.next
        );
        if text.len() + head.len() + base64::encoded_len(want) > cap {
            return false;
        }
        let mut buf = Zeroizing::new([0u8; FILE_CHUNK]);
        let e = &mut self.files.entries[i];
        if !e.source.as_mut().expect("offered").read_at(s.next, &mut buf[..want]) {
            self.peer_mut(slot).serve.active = false;
            return false;
        }
        text.push_str(&head);
        text.push_str(&base64::encode(&buf[..want]));
        let size = e.size;
        let p = self.peer_mut(slot);
        p.serve.next += want as u64;
        if p.serve.next >= p.serve.end {
            p.serve.active = false;
        }
        if p.serve.next >= size {
            self.file_sent(i, slot);
        }
        self.files.changed = true;
        true
    }

    /// Queued fetches start, stalled ones are asked again, and ones whose sender left for good
    /// fail. The file list goes to the UI when it has changed.
    pub(super) fn files_tick(&mut self) {
        let now = self.now;
        // Queued files start once nothing else is coming from their sender, the oldest first.
        loop {
            let next = (0..self.files.entries.len())
                .filter(|&i| self.files.entries[i].dl == Dl::Queued)
                .filter_map(|i| self.file_owner(i).map(|s| (i, s)))
                .filter(|&(i, s)| self.trusted(self.peer(s)) && !self.downloading_from(&self.files.entries[i].owner))
                .min_by_key(|&(i, _)| self.files.entries[i].num);
            let Some((i, slot)) = next else { break };
            self.file_start(i, slot);
        }
        for i in 0..self.files.entries.len() {
            if self.files.entries[i].dl != Dl::Active {
                continue;
            }
            let owner = self.file_owner(i).filter(|&s| self.trusted(self.peer(s)));
            let present = self.file_owner(i).is_some();
            let e = &mut self.files.entries[i];
            // Its sender may only have stalled for a moment (a Tor circuit, a relay). The fetch
            // waits for them, and if they come back with a new verify code, for that to be
            // compared again.
            let Some(slot) = owner else {
                if present || e.gone_since == 0.0 {
                    e.gone_since = now;
                }
                if present || now - e.gone_since < FILE_OWNER_GRACE {
                    continue;
                }
                e.fail("its sender left before it finished");
                let num = e.num;
                self.files.changed = true;
                self.note(format!(
                    "whoever offered file {num} left before it finished - fetch it again once they're back"
                ));
                continue;
            };
            // Back after a short time away. What it was sending was lost with its old session,
            // so it's asked for again from where it stopped.
            if e.gone_since > 0.0 {
                e.gone_since = 0.0;
                e.retries = 0;
                self.file_request(i, slot);
                continue;
            }
            if now < e.retry_at {
                continue;
            }
            // During a re-handshake with its sender, chunks can be lost while the new chains
            // start. The request goes again (on the chain the sender still reads), but isn't
            // counted against the fetch: if the re-handshake never finishes, the peer times out.
            let counted = !self.rehandshaking_with(self.peer(slot));
            let e = &mut self.files.entries[i];
            e.retries += u32::from(counted);
            if e.retries > FILE_RETRIES {
                e.fail("stopped coming");
                let num = e.num;
                self.files.changed = true;
                let name = self.peer_name(slot);
                self.note(format!("file {num} stopped downloading from {name} - try again later"));
                continue;
            }
            self.file_request(i, slot);
        }
        if self.files.changed && now - self.files.last_event >= FILES_EVENT_EVERY {
            self.files.changed = false;
            self.files.last_event = now;
            let list = self.files();
            self.events.push_back(Event::Files { list });
        }
    }

    /// A peer's slots during a fast transfer with it: every few milliseconds over UDP or Tor,
    /// or (sending through the relays) as often as they allow. None when it isn't fast.
    pub(super) fn fast_interval(&self, slot: usize, iv: f64) -> Option<f64> {
        let p = self.peer(slot);
        if !self.files.fast || !p.ok {
            return None;
        }
        if matches!(p.addr, Addr::Relay(_)) {
            if !p.serve.active {
                return None;
            }
            let fast = (self.relayed_count() as f64 / NOSTR_FAST_RATE).max(NOSTR_FAST_INTERVAL);
            return Some(fast.min(iv));
        }
        (p.serve.active || self.downloading_from(&p.id)).then_some(FILE_FAST_INTERVAL)
    }

    /// How far apart a peer's slots are for a transfer: what a request's retry waits for.
    fn transfer_interval(&self, slot: usize) -> f64 {
        let p = self.peer(slot);
        if self.files.fast && !matches!(p.addr, Addr::Relay(_)) {
            FILE_FAST_INTERVAL
        } else {
            self.cover_interval(slot)
        }
    }

    pub(super) fn downloading_from(&self, owner: &[u8; 16]) -> bool {
        self.files.entries.iter().any(|e| e.dl == Dl::Active && e.owner == *owner)
    }

    // ---- fetching ----

    /// Starts fetching file i from the peer in slot, to show or to save as `view` says.
    fn file_start(&mut self, i: usize, slot: usize) {
        let now = self.now;
        let e = &mut self.files.entries[i];
        e.last_chunk = 0.0;
        e.chunk_gap = 0.0;
        e.done = 0;
        e.win_off = 0;
        e.win_n = 0;
        e.win_got = 0;
        e.req_end = 0;
        e.retries = 0;
        e.gone_since = 0.0;
        e.why.clear();
        e.win = Some(Zeroizing::new(vec![0; FILE_WINDOW * FILE_CHUNK]));
        self.files.changed = true;
        if e.view {
            e.mem = Some(Zeroizing::new(Vec::with_capacity(e.size as usize)));
        } else {
            let dir = e.save_dir.clone();
            let made = match self.files.disk.as_mut() {
                Some(d) => d.create(dir.as_deref()),
                None => Err("files can't be saved here".to_string()),
            };
            match made {
                Ok(part) => self.files.entries[i].part = Some(part),
                Err(why) => {
                    let e = &mut self.files.entries[i];
                    e.fail(&why);
                    let num = e.num;
                    self.note(format!("can't fetch file {num}: {why}"));
                    return;
                }
            }
        }
        let e = &mut self.files.entries[i];
        e.hash = Some(sodium::Sha256::new());
        e.dl = Dl::Active;
        e.since = now;
        if e.size == 0 {
            self.file_finish(i);
            return;
        }
        self.file_request(i, slot);
        // How long it takes depends on the sender: fast transfers only speed up what you send.
        let name = self.peer_name(slot);
        let e = &self.files.entries[i];
        let (num, sz) = (e.num, format_size(e.size));
        let eta = match self.file_eta(i) {
            Eta::Seconds(s) => format_duration(s as f64),
            _ => "a while".into(),
        };
        if matches!(self.peer(slot).addr, Addr::Relay(_)) {
            self.note(format!(
                "fetching file {num} ({sz}) from {name} through the relays: {eta} at chat's normal rate, up to half that if \
                 {name} has fast transfers on"
            ));
        } else {
            self.note(format!(
                "fetching file {num} ({sz}) from {name}: {eta} at chat's normal rate, seconds if {name} has fast transfers on"
            ));
        }
    }

    /// Asks for the first run of the window that hasn't arrived (the whole window at the start).
    /// Anything that arrived after the run isn't asked for again.
    fn file_request(&mut self, i: usize, slot: usize) {
        let iv = self.transfer_interval(slot);
        let now = self.now;
        let e = &mut self.files.entries[i];
        if e.win_n == 0 {
            let left = e.size - e.win_off;
            e.win_n = left.div_ceil(FILE_CHUNK as u64).min(FILE_WINDOW as u64) as usize;
            e.win_got = 0;
        }
        let first = (0..e.win_n).find(|&k| e.win_got >> k & 1 == 0).unwrap_or(e.win_n);
        let end = (first..e.win_n).find(|&k| e.win_got >> k & 1 != 0).unwrap_or(e.win_n);
        e.req_end = end;
        e.retry_at = retry_at(now, iv);
        let rec = format!(
            "fg\t{}\t{}\t{}",
            hex::encode(&e.fid),
            e.win_off + (first * FILE_CHUNK) as u64,
            end - first
        );
        self.send_peer(slot, &rec);
    }

    fn file_finish(&mut self, i: usize) {
        let now = self.now;
        let e = &mut self.files.entries[i];
        let got = e.hash.take().map(sodium::Sha256::finish).unwrap_or_default();
        let (num, desc) = (e.num, e.desc());
        self.files.changed = true;
        if !sodium::ct_eq(&got, &e.sha) {
            e.fail("didn't match the offer, so it was thrown away");
            self.warn(format!("file {num} ({desc}) didn't match what was offered - it was thrown away"));
            return;
        }
        if e.view {
            let mem = e.mem.take().unwrap_or_default();
            e.stop(Dl::Done);
            self.cache_keep(i, mem);
            self.emit_picture(i);
            if std::mem::take(&mut self.files.entries[i].also_save) && matches!(self.save_local(i, false), Local::Saved) {
                let at = self.files.entries[i].saved.clone().unwrap_or_default();
                self.note(format!("saved file {num} to {at}"));
            }
            return;
        }
        let took = format_duration(now - e.since);
        let name = e.name.clone();
        let saved = e.part.take().and_then(|p| p.keep(&name));
        let e = &mut self.files.entries[i];
        let Some(path) = saved else {
            let dir = e.save_dir.clone();
            let where_ = self
                .files
                .disk
                .as_ref()
                .map_or("Downloads".into(), |d| d.folder_name(dir.as_deref()));
            let e = &mut self.files.entries[i];
            e.fail(&format!("couldn't be saved in {where_}"));
            self.warn(format!("file {num} ({desc}) downloaded, but couldn't be saved in {where_}"));
            return;
        };
        e.saved = Some(path.clone());
        e.stop(Dl::Done);
        let sz = format_size(e.size);
        self.note(format!("saved file {num} to {path} ({sz}, took {took})"));
        if std::mem::take(&mut self.files.entries[i].also_show) {
            match self.check_saved(i, true) {
                Some(Some(mem)) => {
                    self.cache_keep(i, mem);
                    self.emit_picture(i);
                }
                _ => self.note(format!("can't show file {num}: it changed after it was saved")),
            }
        }
    }

    /// p has been sent the last of one of ours.
    fn file_sent(&mut self, i: usize, slot: usize) {
        let id = self.peer(slot).id;
        let name = self.peer_name(slot);
        let e = &mut self.files.entries[i];
        if e.sent.iter().any(|(sid, _)| *sid == id) {
            return;
        }
        if e.sent.len() < FILE_SENT_MAX {
            e.sent.push((id, name.clone()));
        }
        e.n_sent += 1;
        let (num, fname) = (e.num, e.name.clone());
        self.note(format!("sent all of file {num} ({fname}) to {name}"));
    }

    // ---- what's here already ----

    /// The picture's bytes into its cache, if there's a copy here that still matches: ours, or
    /// a saved one. Some if it's cached now.
    fn picture_here(&mut self, i: usize) -> Option<()> {
        let e = &self.files.entries[i];
        if !e.image || e.size > FILE_VIEW_MAX {
            return None;
        }
        if e.cache.is_none() {
            let mem = if e.mine {
                self.read_own(i)
            } else if !e.coming() {
                self.check_saved(i, true).flatten()
            } else {
                None
            };
            if let Some(m) = mem {
                self.cache_keep(i, m);
            }
        }
        self.files.entries[i].cache.as_ref().map(|_| ())
    }

    /// One of ours as it is now, if it's still what was offered.
    fn read_own(&mut self, i: usize) -> Option<Zeroizing<Vec<u8>>> {
        let e = &mut self.files.entries[i];
        let (size, sha) = (e.size, e.sha);
        let src = e.source.as_mut()?;
        read_checked(src.as_mut(), size, &sha, true).flatten()
    }

    /// Whether the copy file i was saved as is still there and still matches the offer. Some
    /// if it does, with its bytes if `mem` (for one up to FILE_VIEW_MAX).
    fn check_saved(&mut self, i: usize, mem: bool) -> Option<Option<Zeroizing<Vec<u8>>>> {
        let e = &self.files.entries[i];
        let path = e.saved.clone()?;
        if mem && e.size > FILE_VIEW_MAX {
            return None;
        }
        let (size, sha) = (e.size, e.sha);
        let (got, mut src) = self.files.disk.as_mut()?.open(&path)?;
        if got != size {
            return None;
        }
        read_checked(src.as_mut(), size, &sha, mem)
    }

    /// Saves file i in its folder without fetching it: from its cache, or as a copy of where it
    /// was saved before (checked as it's read). `say`: tell the user when it can't be written.
    fn save_local(&mut self, i: usize, say: bool) -> Local {
        let e = &self.files.entries[i];
        let (num, size, sha, dir, name) = (e.num, e.size, e.sha, e.save_dir.clone(), e.name.clone());
        let mut copy = None;
        if e.cache.is_none() {
            let Some(path) = e.saved.clone() else { return Local::NoCopy };
            match self.files.disk.as_mut().and_then(|d| d.open(&path)) {
                Some((got, src)) if got == size => copy = Some(src),
                _ => {
                    self.files.entries[i].saved = None;
                    return Local::NoCopy;
                }
            }
        }
        let Some(disk) = self.files.disk.as_mut() else {
            return Local::Failed("files can't be saved here".into());
        };
        let where_ = disk.folder_name(dir.as_deref());
        let mut part = match disk.create(dir.as_deref()) {
            Ok(p) => p,
            Err(why) => {
                let why = format!("can't write a file in {where_}: {why}");
                if say {
                    self.note(why.clone());
                }
                return Local::Failed(why);
            }
        };
        let ok = match (&self.files.entries[i].cache, copy) {
            (Some(c), _) => part.write(c).then_some(true),
            (None, Some(mut src)) => copy_checked(src.as_mut(), part.as_mut(), size, &sha),
            (None, None) => Some(false),
        };
        match ok {
            Some(true) => {}
            Some(false) => {
                self.files.entries[i].saved = None;
                return Local::NoCopy;
            }
            None => {
                let why = format!("couldn't save file {num} in {where_}");
                if say {
                    self.note(why.clone());
                }
                return Local::Failed(why);
            }
        }
        match part.keep(&name) {
            Some(path) => {
                self.files.entries[i].saved = Some(path);
                Local::Saved
            }
            None => {
                let why = format!("couldn't save file {num} in {where_}");
                if say {
                    self.note(why.clone());
                }
                Local::Failed(why)
            }
        }
    }

    /// Keeps a whole file, checked, as file i's cache, dropping the oldest others to stay
    /// within FILE_CACHE_MAX.
    fn cache_keep(&mut self, i: usize, mem: Zeroizing<Vec<u8>>) {
        let entries = &mut self.files.entries;
        entries[i].cache = None;
        let size = entries[i].size;
        if size > FILE_CACHE_MAX {
            return;
        }
        loop {
            let total: u64 = size
                + entries
                    .iter()
                    .enumerate()
                    .filter(|(k, o)| *k != i && o.cache.is_some())
                    .map(|(_, o)| o.size)
                    .sum::<u64>();
            let oldest = (0..entries.len())
                .filter(|&k| k != i && entries[k].cache.is_some())
                .min_by_key(|&k| entries[k].num);
            match oldest {
                Some(k) if total > FILE_CACHE_MAX => entries[k].cache = None,
                _ => break,
            }
        }
        entries[i].cache = Some(mem);
    }

    fn emit_picture(&mut self, i: usize) {
        let e = &self.files.entries[i];
        if let Some(c) = &e.cache {
            let ev = Event::Picture {
                num: e.num,
                name: e.name.clone(),
                data: c.to_vec(),
            };
            self.events.push_back(ev);
        }
    }

    // ---- the list ----

    fn file_idx(&self, num: u32) -> Option<usize> {
        self.files.entries.iter().position(|e| e.num == num)
    }

    fn file_idx_fid(&self, owner: &[u8; 16], fid: &[u8; 8]) -> Option<usize> {
        self.files.entries.iter().position(|e| e.owner == *owner && e.fid == *fid)
    }

    /// Its sender, if connected.
    fn file_owner(&self, i: usize) -> Option<usize> {
        self.find_peer(&self.files.entries[i].owner).filter(|&s| self.peer(s).ok)
    }

    /// A new entry: a free one, or the oldest that isn't ours and isn't being fetched. For a
    /// peer over FILE_OFFERS_PER_PEER, its own oldest instead.
    fn file_new(&mut self, owner: Option<[u8; 16]>) -> Option<usize> {
        let entries = &self.files.entries;
        let theirs = owner.map_or(0, |o| entries.iter().filter(|e| !e.mine && e.owner == o).count());
        let pick = if theirs < FILE_OFFERS_PER_PEER && entries.len() < FILE_OFFERS_MAX {
            None
        } else {
            let k = (0..entries.len())
                .filter(|&k| !entries[k].mine && !entries[k].coming())
                .filter(|&k| theirs < FILE_OFFERS_PER_PEER || Some(entries[k].owner) == owner)
                .min_by_key(|&k| entries[k].num)?;
            Some(k)
        };
        self.files.seq += 1;
        let e = Entry::new(self.files.seq);
        Some(match pick {
            Some(k) => {
                self.files.entries[k] = e;
                k
            }
            None => {
                self.files.entries.push(e);
                self.files.entries.len() - 1
            }
        })
    }

    /// A queued file: the number of the file from the same sender it waits for.
    fn queued_after(&self, i: usize) -> Option<u32> {
        let e = &self.files.entries[i];
        if e.dl != Dl::Queued {
            return None;
        }
        self.files
            .entries
            .iter()
            .find(|o| o.dl == Dl::Active && o.owner == e.owner)
            .map(|o| o.num)
    }

    /// Roughly how long the rest of a fetch takes: at the rate so far, or before there is one,
    /// at the rate its path allows.
    fn file_eta(&self, i: usize) -> Eta {
        let Some(slot) = self.file_owner(i) else {
            return Eta::WaitingSender;
        };
        if !self.trusted(self.peer(slot)) {
            return Eta::WaitingVerify;
        }
        let e = &self.files.entries[i];
        let got = e.got();
        let left = (e.size - got) as f64;
        let took = self.now - e.since;
        let s = if got >= ETA_MIN_CHUNKS * FILE_CHUNK as u64 && took > 0.0 {
            left * took / got as f64
        } else {
            // A slot comes up to a quarter of its interval late, an eighth on average.
            let p = self.peer(slot);
            let per_slot = if p.caps.batches && matches!(p.addr, Addr::Relay(_)) {
                2.0
            } else {
                1.0
            } * FILE_CHUNK as f64;
            left / per_slot * self.cover_interval(slot) * (1.0 + JITTER / 2.0)
        };
        Eta::Seconds(s.round() as u64)
    }

    fn file_info(&self, i: usize) -> FileInfo {
        let e = &self.files.entries[i];
        let owner_slot = (!e.mine).then(|| self.find_peer(&e.owner)).flatten();
        let from_name = if e.mine {
            "you".to_string()
        } else {
            owner_slot.map_or("someone who left".into(), |s| self.peer_name(s))
        };
        let state = if e.mine {
            if e.source.is_some() {
                FileState::Offered
            } else {
                FileState::Withdrawn
            }
        } else {
            match e.dl {
                Dl::Active => FileState::Fetching {
                    got: e.got(),
                    eta: self.file_eta(i),
                },
                Dl::Queued => FileState::Queued {
                    after: self.queued_after(i),
                },
                Dl::Done => FileState::Done,
                Dl::Failed => FileState::Failed { why: e.why.clone() },
                Dl::None => FileState::Offered,
            }
        };
        let sending = e.mine.then(|| self.sending(i)).flatten();
        FileInfo {
            num: e.num,
            name: e.name.clone(),
            size: e.size,
            mine: e.mine,
            from: (!e.mine).then_some(PeerId(e.owner)),
            from_name,
            image: e.image,
            at: e.at,
            state,
            show: e.view,
            saved: e.saved.clone(),
            shown: e.cache.is_some(),
            then_save: e.also_save,
            then_show: e.also_show,
            sending,
            sent_to: e.sent.iter().map(|(_, n)| n.clone()).collect(),
            sent_count: e.n_sent,
        }
    }

    /// One of ours: how many peers are fetching it now, and the one furthest along.
    fn sending(&self, i: usize) -> Option<Sending> {
        let e = &self.files.entries[i];
        e.source.as_ref()?;
        let now = self.now;
        let mut best: Option<(u64, usize)> = None;
        let mut count = 0;
        for slot in self.live() {
            let s = self.peer(slot).serve;
            if s.fid != e.fid || s.next >= e.size || (!s.active && now - s.at > FILE_SENDING_QUIET) {
                continue;
            }
            count += 1;
            if best.is_none_or(|(n, _)| s.next > n) {
                best = Some((s.next, slot));
            }
        }
        let (next, slot) = best?;
        Some(Sending {
            count,
            name: self.peer_name(slot),
            permille: (next * 1000).checked_div(e.size).map_or(1000, |p| p as u32),
        })
    }
}

/// When a window's request is sent again if nothing comes: after a few slots, and some seconds
/// more.
fn retry_at(now: f64, slot_interval: f64) -> f64 {
    now + 6.0 * slot_interval + 4.0
}

/// Reads a whole file from its source, hashing it. Some if it's exactly `size` and matches
/// `sha`, with its bytes if `keep`.
fn read_checked(src: &mut dyn Source, size: u64, sha: &[u8; 32], keep: bool) -> Option<Option<Zeroizing<Vec<u8>>>> {
    let mut h = sodium::Sha256::new();
    let mut mem = keep.then(|| Zeroizing::new(Vec::with_capacity(size as usize)));
    let mut buf = Zeroizing::new(vec![0u8; 65536]);
    let mut off = 0;
    while off < size {
        let n = (size - off).min(buf.len() as u64) as usize;
        if !src.read_at(off, &mut buf[..n]) {
            return None;
        }
        h.update(&buf[..n]);
        if let Some(m) = mem.as_mut() {
            m.extend_from_slice(&buf[..n]);
        }
        off += n as u64;
    }
    sodium::ct_eq(&h.finish(), sha).then_some(mem)
}

/// Copies a file into a part, checking it as it's read. Some(true) if it matched, Some(false)
/// if it didn't, None if the part couldn't be written.
fn copy_checked(src: &mut dyn Source, part: &mut dyn Part, size: u64, sha: &[u8; 32]) -> Option<bool> {
    let mut h = sodium::Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; 65536]);
    let mut off = 0;
    while off < size {
        let n = (size - off).min(buf.len() as u64) as usize;
        if !src.read_at(off, &mut buf[..n]) {
            return Some(false);
        }
        h.update(&buf[..n]);
        if !part.write(&buf[..n]) {
            return None;
        }
        off += n as u64;
    }
    Some(sodium::ct_eq(&h.finish(), sha))
}
