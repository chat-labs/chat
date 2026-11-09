// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! What the TUI holds and how it reacts: rooms, what they say, the input line, dialogs.

use crate::identity::{Ident, Origin};
use crate::text::unix_now;
use chat_core::IdentityKind;
use chat_core::protocol::files::{format_duration, format_size, format_size_exact, parse_size};
use chat_core::protocol::picture::Thumb;
use chat_core::{
    Client, Colour, Command, CommandError, Delivery, Eta, Event, FileInfo, FileState, Level, Message, MoveAsk, NetStatus, NostrMode,
    Outcome, PeerId, PeerInfo, Room, RoomConfig, RoomEvents, RoomInfo, RouteMode,
};
use crossterm::event::{Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// What the rooms' tasks tell the UI.
pub enum Msg {
    /// A save's work off the UI's thread.
    Save(crate::saved::SaveMsg),
    Joined(usize, Result<(Room, RoomInfo), String>),
    Room(usize, Event),
    /// A picture fetched to be shown, decoded off the UI's thread.
    /// A picture decoded: for the chat, and bigger, for its own page.
    Picture(usize, u32, Result<(Thumb, Thumb), String>),
    /// A signing key made from a password, off the UI's thread.
    Identity(Result<Ident, String>),
    Closed(usize),
}

/// Pictures are decoded at most this big, and drawn smaller to fit.
const PICTURE_W: u32 = 160;
const PICTURE_H: u32 = 96;
/// A picture on its own page: at most this, scaled down to the screen.
const PAGE_W: u32 = 200;
const PAGE_H: u32 = 120;

pub enum EntryKind {
    Msg(Message),
    Note(Level, String),
    /// The network's own notes, shown only with F2.
    Log(String),
}

pub struct Entry {
    pub at: u64,
    pub kind: EntryKind,
}

/// What became of one of our messages.
#[derive(Default)]
pub struct Sent {
    pub to: usize,
    pub held: usize,
    pub delivered: usize,
    pub missed: Vec<String>,
    pub settled: bool,
}

pub enum RoomState {
    Joining,
    Open(Room),
    Failed(String),
    Closed,
}

pub struct RoomView {
    pub id: usize,
    pub label: String,
    pub state: RoomState,
    pub info: Option<RoomInfo>,
    pub entries: Vec<Entry>,
    pub peers: Vec<PeerInfo>,
    pub net: NetStatus,
    pub timer: u32,
    pub unread: usize,
    pub mentioned: bool,
    /// Rows scrolled back from the newest, in the chat and in the console.
    pub scroll: usize,
    pub console_scroll: usize,
    pub sent: HashMap<u64, Sent>,
    pub files: Vec<FileInfo>,
    /// Pictures fetched to be shown, and the ones hidden again.
    pub pictures: HashMap<u32, Thumb>,
    /// The same pictures bigger, for their own page, and why one couldn't be shown.
    pub picture_data: HashMap<u32, Thumb>,
    pub pic_why: HashMap<u32, String>,
    pub hidden: HashSet<u32>,
    /// A peer asks us to move the room.
    pub move_ask: Option<MoveAsk>,
    /// The request to move left for later with Esc, which doesn't come up by itself again.
    pub move_later: Option<u32>,
    /// A call (/call): the verified key it's with, its nick, and the day (UTC) its room is for.
    pub call: Option<([u8; 32], String, u64)>,
    /// Its history while it's kept, in the open save.
    pub history: Option<chat_core::net::history::History>,
}

impl RoomView {
    fn joining(id: usize, label: String) -> Self {
        RoomView {
            id,
            label,
            state: RoomState::Joining,
            info: None,
            entries: Vec::new(),
            peers: Vec::new(),
            net: NetStatus::default(),
            timer: 0,
            unread: 0,
            mentioned: false,
            scroll: 0,
            console_scroll: 0,
            sent: HashMap::new(),
            files: Vec::new(),
            pictures: HashMap::new(),
            picture_data: HashMap::new(),
            pic_why: HashMap::new(),
            hidden: HashSet::new(),
            move_ask: None,
            move_later: None,
            call: None,
            history: None,
        }
    }

    pub fn file(&self, num: u32) -> Option<&FileInfo> {
        self.files.iter().find(|f| f.num == num)
    }

    pub fn room(&self) -> Option<&Room> {
        match &self.state {
            RoomState::Open(r) => Some(r),
            _ => None,
        }
    }

    pub(crate) fn note(&mut self, level: Level, text: impl Into<String>) {
        self.entries.push(Entry {
            at: unix_now(),
            kind: EntryKind::Note(level, text.into()),
        });
    }

    /// A peer by what the user typed: its name as shown ("bob", "bob#1a2b3c4d"), its nick in any
    /// case, or a nick and the start of its id. An @ in front is fine.
    pub fn find_peer(&self, typed: &str) -> Result<PeerInfo, String> {
        let typed = typed.trim().trim_start_matches('@');
        let (nick, prefix) = typed.split_once('#').unwrap_or((typed, ""));
        let found: Vec<&PeerInfo> = self
            .peers
            .iter()
            .filter(|p| {
                p.name.eq_ignore_ascii_case(typed)
                    || (p.nick.eq_ignore_ascii_case(nick) && p.id.hex().starts_with(&prefix.to_ascii_lowercase()))
            })
            .collect();
        match found.as_slice() {
            [p] => Ok((*p).clone()),
            [] => Err(format!("nobody called {typed} is here")),
            _ => Err(format!("more than one {typed} is here - add the id People shows, as {nick}#1a2b")),
        }
    }

    /// "NICK TEXT", where the nick can hold spaces: the longest start that names a peer.
    fn peer_and_text(&self, arg: &str) -> Result<(PeerInfo, String), String> {
        let mut best = None;
        for (i, _) in arg.match_indices(' ') {
            if let Ok(p) = self.find_peer(&arg[..i]) {
                best = Some((p, arg[i + 1..].trim().to_string()));
            }
        }
        match best {
            Some((_, t)) if t.is_empty() => Err("there's nothing to send".into()),
            Some(b) => Ok(b),
            None => Err(match arg.split_once(' ') {
                Some((who, _)) => self.find_peer(who).err().unwrap_or_default(),
                None => "usage: name, then the text".into(),
            }),
        }
    }

    pub fn status_line(&self, spinner: char) -> String {
        match &self.state {
            RoomState::Joining => format!("{spinner} making the room's key"),
            RoomState::Failed(e) => format!("couldn't open: {e}"),
            RoomState::Closed => "left".into(),
            RoomState::Open(_) if self.net.mode == RouteMode::Tor && !self.net.tor_ready => format!("{spinner} connecting to Tor"),
            RoomState::Open(_) if !self.net.ready => format!("{spinner} waiting for someone to answer"),
            RoomState::Open(_) => {
                let n = self.peers.len();
                let via = if self.peers.iter().any(|p| p.path == chat_core::protocol::PathKind::Relays) {
                    " · some via relays"
                } else {
                    ""
                };
                match n {
                    0 => "nobody else here yet".into(),
                    1 => format!("1 other here{via}"),
                    n => format!("{n} others here{via}"),
                }
            }
        }
    }
}

/// A line of text being edited.
#[derive(Default, Clone)]
pub struct Input {
    pub chars: Vec<char>,
    pub cursor: usize,
}

impl Input {
    pub fn text(&self) -> String {
        self.chars.iter().collect()
    }
    pub fn set(&mut self, s: &str) {
        self.chars = s.chars().collect();
        self.cursor = self.chars.len();
    }
    fn take(&mut self) -> String {
        let s = self.text();
        self.set("");
        s
    }
    fn insert(&mut self, c: char) {
        self.chars.insert(self.cursor, c);
        self.cursor += 1;
    }
    /// Edits the line; true if the key was one it takes.
    pub(crate) fn edit(&mut self, k: &KeyEvent) -> bool {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Char('u') if ctrl => {
                self.chars.drain(..self.cursor);
                self.cursor = 0;
            }
            KeyCode::Char('w') if ctrl => {
                let mut i = self.cursor;
                while i > 0 && self.chars[i - 1] == ' ' {
                    i -= 1;
                }
                while i > 0 && self.chars[i - 1] != ' ' {
                    i -= 1;
                }
                self.chars.drain(i..self.cursor);
                self.cursor = i;
            }
            KeyCode::Char('a') if ctrl => self.cursor = 0,
            KeyCode::Char('e') if ctrl => self.cursor = self.chars.len(),
            KeyCode::Char(c) if !ctrl => self.insert(c),
            KeyCode::Backspace if self.cursor > 0 => {
                self.cursor -= 1;
                self.chars.remove(self.cursor);
            }
            KeyCode::Delete if self.cursor < self.chars.len() => {
                self.chars.remove(self.cursor);
            }
            KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Right => self.cursor = (self.cursor + 1).min(self.chars.len()),
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = self.chars.len(),
            _ => return false,
        }
        true
    }
}

pub enum PromptKind {
    Nick,
    /// A new room's password, a random one filled in.
    NewRoom,
    /// A room's id, or a whole invite.
    JoinId,
    /// The password for this room id.
    JoinPassword(String),
    /// A save's passphrase, as chat starts.
    Unlock(String),
    /// A save's authenticator code.
    Code,
    Install(crate::saved::Installing),
    /// "yes" deletes this save.
    Uninstall(String),
    /// The PIN the lock screen takes with no save open.
    SetPin,
    /// A shadow passphrase, then again.
    Shadow(Option<zeroize::Zeroizing<String>>),
    /// The new authenticator's code, to turn it on.
    NewCode,
    /// A text row, from the settings page.
    SetRow(&'static str),
    /// The security key's PIN: to open this save, or (None) to register a key for the open one.
    KeyPin(Option<String>),
    /// A signing key file's path, from the signing identity's page.
    KeyPath(IdentityKind),
    /// The password a signing key is made from: shown as dots.
    KeyPassword {
        kind: IdentityKind,
        with_nick: bool,
    },
}

impl PromptKind {
    /// Typed text shown as dots.
    pub fn secret(&self) -> bool {
        matches!(
            self,
            PromptKind::KeyPassword { .. }
                | PromptKind::JoinPassword(_)
                | PromptKind::Unlock(_)
                | PromptKind::SetPin
                | PromptKind::Shadow(_)
                | PromptKind::KeyPin(_)
                | PromptKind::Install(crate::saved::Installing::Pass(_) | crate::saved::Installing::Again(..))
        )
    }
}

pub enum Modal {
    Prompt {
        kind: PromptKind,
        title: String,
        hint: String,
        input: Input,
    },
    Verify {
        room: usize,
        peer: PeerInfo,
    },
    /// The help page, on this row.
    Help(usize),
    /// Lines to read; any key closes it.
    Info {
        title: String,
        lines: Vec<String>,
    },
    /// An invite as a QR code.
    /// The settings page.
    Settings(crate::settings_page::Page),
    /// A folder browser: for a key file, a file to send, or a folder to save a file or a key in.
    Browser(Box<crate::browser::Browser>),
    /// A box that asks before it does something: y, n, and Esc.
    Ask {
        title: &'static str,
        paras: Vec<String>,
        keys: &'static str,
        then: Ask,
    },
    /// A signing key being pasted in, from the signing identity's page.
    Paste {
        kind: IdentityKind,
        text: zeroize::Zeroizing<String>,
    },
    /// The files page: this room's files, on this one (by its number).
    Files(u32),
    /// A picture on a page of its own.
    Picture(u32),
    /// The rooms kept in the save, to join one: the one picked (the last is "another room"), and
    /// whether forgetting it is being asked.
    Rooms {
        sel: usize,
        forgetting: bool,
    },
    /// The saves to open one of, by name, and the one picked.
    PickSave {
        names: Vec<String>,
        sel: usize,
    },
    /// A link from the chat, before it's opened: (the link, who sent it, when), newest first.
    Link {
        links: Vec<(String, String, String)>,
        at: usize,
    },
    Qr {
        invite: String,
        qr: chat_core::protocol::qr::Qr,
        /// The line under it.
        note: String,
    },
    /// /update's progress. Closing it leaves the update running.
    Update,
}

impl Modal {
    /// Settings, a folder browser, the files, a picture and the help fill the screen; every other
    /// modal is a box over the chat, or over the page it was opened from.
    pub fn is_page(&self) -> bool {
        matches!(
            self,
            Modal::Settings(_) | Modal::Browser(_) | Modal::Files(_) | Modal::Picture(_) | Modal::Help(_)
        )
    }
}

/// What a box that asks is about.
pub enum Ask {
    /// /install (or /save): y goes on to the new save's passphrase, or saves the open one.
    Install(String),
    /// Saves are here and none is open: y uses one (this one, or one picked), n makes a new save.
    UseSave(Option<String>),
    /// A factor turned on with no save open: y installs, then sets it up.
    InstallFirst(&'static str),
    /// The device lock, turned on (true) or off: y does it.
    DeviceLock(bool),
    /// Over the files page or a picture: fetching a file over the size limit, or stopping one.
    File(crate::files_page::FileAsk, u32),
    /// /move: y moves to a new room with those whose codes were compared.
    Move,
    /// A peer's request to move (its seq): y goes, n stays, Esc leaves it for later.
    MoveAsked(u32),
    /// Keeping Tor's guards in the save: y turns it on.
    TorGuards,
    /// What's in use saved over another save, which opens with its own passphrase: y asks for it.
    Overwrite(String),
    /// A security key on or off, or the authenticator off: y does it.
    Factor(&'static str, bool),
}

pub struct App {
    pub client: Client,
    pub nick: String,
    pub colour: Option<Colour>,
    /// What every room starts from: routing and the rest.
    pub base: RoomConfig,
    pub rooms: Vec<RoomView>,
    pub current: usize,
    pub input: Input,
    pub modal: Option<Modal>,
    pub status: Option<(String, bool, Instant)>,
    /// The line's mode, and the command line while it's open.
    pub mode: crate::cmdline::Mode,
    pub cmdline: crate::cmdline::CmdLine,
    /// What the chat screen shows: the sidebar, the console and the chat.
    pub show_sidebar: bool,
    pub show_console: bool,
    pub show_chat: bool,
    /// The sidebar's lists: how they're scrolled, and where they were drawn.
    pub side: std::cell::Cell<crate::ui::SideState>,
    /// Where the console was in the last frame drawn, for the mouse wheel.
    pub console_at: std::cell::Cell<Option<ratatui::layout::Rect>>,
    /// Where the chat's links were in the last frame drawn, and where each goes.
    pub links: std::cell::RefCell<Vec<(ratatui::layout::Rect, String)>>,
    pub spinner: usize,
    pub tx: mpsc::UnboundedSender<Msg>,
    pub quit: bool,
    /// Ctrl+C's QUIT box, over whatever is showing.
    pub asking_quit: bool,
    next_id: usize,
    /// The signing identity rooms use.
    pub ident: Option<Ident>,
    /// The settings in use, as a save keeps them.
    pub settings: chat_core::net::settings::Settings,
    /// The command line's settings: they win over a save's for this run.
    pub overrides: Vec<(&'static str, String)>,
    pub saves: Option<chat_core::net::saves::Saves>,
    /// The save that's open.
    pub save: Option<chat_core::net::saves::Save>,
    pub pending_code: Option<Box<chat_core::net::saves::PendingCode>>,
    /// What the command line asked for, done once a save is open (or skipped): a new room, rooms to
    /// join, and whether to ask for a nick.
    pub start: Option<(bool, Vec<String>, bool)>,
    /// The lock screen, while it's up.
    pub locked: Option<crate::lock::Lock>,
    /// With no save open, the lock screen's PIN as Argon2id made it.
    pub pin: Option<chat_core::protocol::crypto::passlock::PassLock>,
    /// The panic key was pressed: quit at once, clearing the screen.
    pub panicked: bool,
    last_key: Instant,
    last_history_write: Instant,
    /// The info box open asks for a code once it's closed (the authenticator's QR code).
    pub prompt_after_info: bool,
    /// --tor-dir gave Tor a folder of its own, so a save's Tor state isn't used.
    pub tor_dir: Option<std::path::PathBuf>,
    /// The way into Tor that /update's downloads take, while it runs.
    update_proxy: Option<chat_core::net::update::TorProxy>,
    /// A security key being waited for: where it is, and a way to cancel it.
    pub key_wait: Option<std::sync::Arc<chat_core::net::seckey::Wait>>,
    /// A save being opened: its name and passphrase, kept while its security key is asked.
    pub pending_pass: Option<(String, zeroize::Zeroizing<String>)>,
    /// That save's security key secret, once its key gave it.
    pub pending_key: Option<zeroize::Zeroizing<[u8; 32]>>,
    /// What /copyid or /invite put on the clipboard comes off it then.
    clipboard_until: Option<Instant>,
    /// chat put it there itself (notify::clipboard_set), not the terminal.
    clipboard_native: bool,
    /// /quitall: no room is kept to reopen.
    quit_all: bool,
    /// chat is on the settings page it starts on, and goes on the network once that's left.
    pub onboarding: bool,
    /// Where the settings page was left, so it opens there again.
    pub settings_page: Option<crate::settings_page::Page>,
    /// The page (settings, or a browser) under a box opened from it, which it comes back to once
    /// the box closes.
    pub behind: Option<Box<Modal>>,
    /// Where the last file sent came from, and where the last one picked a folder for was saved.
    pub send_dir: Option<std::path::PathBuf>,
    pub save_dir: Option<std::path::PathBuf>,
    /// The factor (devicelock, securitykey, authenticator) /install was asked for, set up on the
    /// save it makes or opens.
    pub pending_factor: Option<&'static str>,
    /// --session without a password: the join box, with the room's id in it, once chat starts.
    pub pending_join: Option<String>,
    /// --identity: the signing key made or read as chat starts.
    pub identity_at_start: Option<String>,
    /// A running tor's control password (torpassword), kept for this run only.
    pub tor_password: zeroize::Zeroizing<String>,
    /// While a security key is waited for: the save it opens, or None while one is registered.
    pub key_save: Option<String>,
    /// When a request to move came up by itself: keys are ignored for a moment, so a word being
    /// typed doesn't answer it.
    pub move_shown: Instant,
    /// A save being opened to save what's in use over it, rather than to use what it holds.
    pub overwriting: bool,
}

pub const SPINNER: [char; 4] = ['◐', '◓', '◑', '◒'];

impl App {
    pub fn new(base: RoomConfig, nick: Option<String>, tx: mpsc::UnboundedSender<Msg>) -> Self {
        let mut app = App {
            client: Client::new(),
            nick: nick.clone().unwrap_or_else(chat_core::protocol::names::random_nick),
            colour: base.colour,
            base,
            rooms: Vec::new(),
            current: 0,
            input: Input::default(),
            modal: None,
            status: None,
            mode: Default::default(),
            cmdline: Default::default(),
            show_sidebar: true,
            show_console: true,
            show_chat: true,
            console_at: Default::default(),
            side: Default::default(),
            links: Default::default(),
            spinner: 0,
            tx,
            quit: false,
            asking_quit: false,
            next_id: 0,
            ident: None,
            settings: chat_core::net::settings::Settings::default(),
            overrides: Vec::new(),
            saves: chat_core::net::saves::Saves::new(),
            save: None,
            pending_code: None,
            start: None,
            locked: None,
            pin: None,
            panicked: false,
            last_key: Instant::now(),
            last_history_write: Instant::now(),
            prompt_after_info: false,
            tor_dir: None,
            update_proxy: None,
            key_wait: None,
            pending_pass: None,
            pending_key: None,
            clipboard_until: None,
            clipboard_native: false,
            quit_all: false,
            onboarding: false,
            settings_page: None,
            behind: None,
            send_dir: None,
            save_dir: None,
            pending_factor: None,
            pending_join: None,
            identity_at_start: None,
            tor_password: Default::default(),
            key_save: None,
            move_shown: Instant::now(),
            overwriting: false,
        };
        app.start = Some((false, Vec::new(), nick.is_none()));
        app
    }

    /// /open [N|LINK]: the newest link in this room's chat, the Nth newest, or one typed.
    fn open_command(&mut self, arg: &str) -> Result<(), String> {
        let links: Vec<(String, String, String)> = match arg.trim() {
            "" | "0" => self.room_links(),
            n if n.chars().all(|c| c.is_ascii_digit()) => self.room_links(),
            typed => {
                let found = chat_core::protocol::text::links(typed);
                let (a, n) = found.first().copied().ok_or("that isn't a link")?;
                vec![(typed[a..a + n].to_string(), "you".into(), String::new())]
            }
        };
        if links.is_empty() {
            return Err("no links in this room's chat".into());
        }
        let at = arg.trim().parse::<usize>().unwrap_or(1).max(1) - 1;
        if at >= links.len() {
            return Err(format!("there are only {} links here", links.len()));
        }
        self.modal = Some(Modal::Link { links, at });
        Ok(())
    }

    /// The links in this room's messages, newest first.
    fn room_links(&self) -> Vec<(String, String, String)> {
        let Some(r) = self.room() else { return Vec::new() };
        let mut out = Vec::new();
        for e in r.entries.iter().rev() {
            if let EntryKind::Msg(m) = &e.kind {
                let body = m.body();
                let who = if m.mine { self.nick.clone() } else { m.name.clone() };
                for (a, n) in chat_core::protocol::text::links(body).into_iter().rev() {
                    out.push((body[a..a + n].to_string(), who.clone(), crate::text::hhmm(e.at)));
                }
            }
        }
        out
    }

    /// The file options sent to every open room.
    pub(crate) async fn push_file_options(&mut self) {
        for r in &self.rooms {
            if let Some(room) = r.room() {
                let _ = room.set_file_options(self.base.files.clone()).await;
            }
        }
    }

    /// Once a save's settings are known, just before chat first reaches the network, so whatever it
    /// reads from there is read inside it: the sandbox, unless the save or --nosandbox turned it
    /// off, and the updater just before it, unless that's off.
    fn sandbox_up(&mut self) {
        use chat_core::net::update;
        if crate::SANDBOX.get().is_some() || !self.settings.on("sandbox") {
            return;
        }
        // tor, and the transport programs its bridges can need, even with none set yet.
        let mut bridges = chat_core::net::Bridges::default();
        let transports = self.settings.get("transports");
        if !transports.is_empty() {
            let _ = bridges.set_transports(Some(transports.into()));
        }
        let mut run = bridges.programs();
        let tor = self.settings.get("torpath");
        run.extend(chat_core::net::tor_ext::tor_program(if tor.is_empty() { "tor" } else { tor }));
        let write: Vec<_> = self.tor_dir.iter().cloned().collect();
        // Outside the sandbox, so /update can still replace chat.
        if self.settings.on("updater") {
            update::helper_start();
        }
        let sandbox = chat_core::net::sandbox::up(&run, &write);
        if !sandbox.files {
            update::helper_stop();
        }
        if let Some(why) = &sandbox.why {
            self.fail(format!("the sandbox isn't all up: {why}"));
        }
        let _ = crate::SANDBOX.set(sandbox);
    }

    /// Once a save is open (or skipped): the nick asked for if none is known, and what the
    /// command line asked for.
    pub(crate) fn start_rooms(&mut self) {
        let Some((new, joins, ask_nick)) = self.start.take() else { return };
        self.sandbox_up();
        // The key first, so the rooms opened now sign with it. One made from a password reads it
        // from CHAT_SIGN_PASSWORD, or asks for it.
        // shortcut: a key made from a password is ready seconds later, after rooms opened now; hold them back until it's made if that matters.
        if let Some(id) = self.identity_at_start.take() {
            let kind = if id.starts_with("pgp") {
                IdentityKind::Pgp
            } else {
                IdentityKind::Age
            };
            match id.as_str() {
                f if f.len() > 4 && (f.starts_with("age:") || f.starts_with("pgp:")) => {
                    self.load_key(kind, &chat_core::net::files::typed_path_here(&f[4..]));
                }
                "age" | "pgp" | "age-nonick" | "pgp-nonick" => {
                    let with_nick = !id.ends_with("-nonick");
                    match std::env::var("CHAT_SIGN_PASSWORD") {
                        Ok(p) => self.make_key(kind, &p, with_nick),
                        Err(_) => self.prompt_key_password(kind, with_nick),
                    }
                }
                other => self.fail(format!(
                    "--identity takes age, pgp, age-nonick, pgp-nonick, age:KEYFILE or pgp:KEYFILE, not {other}"
                )),
            }
        }
        if let Some(j) = self.pending_join.take() {
            self.join_prompt(&j);
        }
        self.join_saved_rooms();
        if new {
            self.create_room(None);
        }
        for j in &joins {
            self.join(j);
        }
        if ask_nick && self.settings.get("nick").is_empty() {
            let mut input = Input::default();
            input.set(&self.nick);
            self.modal = Some(Modal::Prompt {
                kind: PromptKind::Nick,
                title: " Your name ".into(),
                hint: "What others see you as. Enter keeps it; you can change it later with /nick.".into(),
                input,
            });
        }
    }

    pub fn room(&self) -> Option<&RoomView> {
        self.rooms.get(self.current)
    }

    fn room_mut(&mut self) -> Option<&mut RoomView> {
        self.rooms.get_mut(self.current)
    }

    fn by_id(&mut self, id: usize) -> Option<&mut RoomView> {
        self.rooms.iter_mut().find(|r| r.id == id)
    }

    /// A line in the console (a failure in the chat too), or with no room open, on the bottom row.
    fn console(&mut self, ok: bool, text: impl Into<String>) {
        match (self.room_mut(), ok) {
            (Some(r), true) => r.note(Level::Note, text),
            (Some(r), false) => r.note(Level::Warn, text),
            (None, true) => self.say(text),
            (None, false) => self.fail(text),
        }
    }

    /// /update: the newest release (with betas on, betas too) in place of this chat, by the
    /// updater if the sandbox is up. Its box shows how it goes; the result goes to the console.
    async fn update_command(&mut self) -> Result<(), String> {
        use chat_core::net::update;
        if !update::view().running {
            if crate::SANDBOX.get().is_some_and(|s| s.files) && !update::helper_running() {
                return Err(if self.settings.on("updater") {
                    "the sandbox keeps chat from replacing itself, and the updater isn't running - quit and run \
                     chat --update"
                        .into()
                } else {
                    "the sandbox keeps chat from replacing itself, and the updater is off - quit and run chat \
                     --update, or /set updater on for the next start"
                        .into()
                });
            }
            let mut proxy = None;
            if self.base.route.mode == RouteMode::Tor {
                let Some(tor) = self.client.tor_now().filter(|t| t.ready()) else {
                    self.console(
                        false,
                        "update: Tor mode downloads through Tor, and there's no tor yet - try again once it's connected",
                    );
                    return Ok(());
                };
                let p = update::tor_proxy(tor)
                    .await
                    .map_err(|e| format!("couldn't open a way into Tor: {e}"))?;
                proxy = Some(p);
            }
            let betas = self.settings.on("betas");
            if update::start(betas, proxy.as_ref().map(|p| p.addr.clone())) {
                self.update_proxy = proxy;
                self.console(
                    true,
                    format!(
                        "update: checking GitHub for a newer release{} (v{} here)...",
                        if betas { " or beta" } else { "" },
                        update::VERSION
                    ),
                );
            }
        }
        self.modal = Some(Modal::Update);
        Ok(())
    }

    /// On the clipboard for 30 seconds. A secret goes there by chat itself where it can, out of
    /// the clipboard's history; otherwise the terminal puts it there.
    fn copy_for_a_while(&mut self, text: &str, secret: bool) {
        self.clipboard_native = secret && crate::notify::clipboard_set(text);
        if !self.clipboard_native {
            copy_to_clipboard(text);
        }
        self.clipboard_until = Some(Instant::now() + Duration::from_secs(30));
    }

    pub(crate) fn say(&mut self, text: impl Into<String>) {
        self.status = Some((text.into(), false, Instant::now()));
    }

    pub(crate) fn fail(&mut self, text: impl Into<String>) {
        self.status = Some((text.into(), true, Instant::now()));
    }

    /// Opens a room in the background: its key takes a few seconds.
    pub fn open(&mut self, mut cfg: RoomConfig, label: String) {
        cfg.nick = self.nick.clone();
        cfg.colour = self.colour;
        let id = self.next_id;
        self.next_id += 1;
        self.rooms.push(RoomView::joining(id, label));
        self.current = self.rooms.len() - 1;
        let (client, tx) = (self.client.clone(), self.tx.clone());
        tokio::spawn(async move {
            match client.join(cfg).await {
                Ok((room, events)) => {
                    let info = room.info().clone();
                    let _ = tx.send(Msg::Joined(id, Ok((room, info))));
                    forward(id, events, tx).await;
                }
                Err(e) => {
                    let _ = tx.send(Msg::Joined(id, Err(e.to_string())));
                }
            }
        });
    }

    /// The signing key rooms use from now on, here and in every open room.
    pub(crate) fn use_identity(&mut self, ident: Option<Ident>) {
        self.base.identity = ident.as_ref().map(|i| (i.kind, i.kp.clone()));
        for r in &self.rooms {
            if let Some(room) = r.room() {
                room.set_identity(self.base.identity.clone());
            }
        }
        let lines = ident.as_ref().map(Ident::describe);
        self.ident = ident;
        let Some(lines) = lines else {
            return self.say("not signing now: peers see you as unverified");
        };
        match self.take_settings() {
            // Chosen from the signing identity's page: back to the settings, which show it.
            Some(mut p) => {
                p.pick = None;
                self.show_page(p);
            }
            None => {
                self.modal = Some(Modal::Info {
                    title: "SIGNING IDENTITY".into(),
                    lines,
                });
            }
        }
    }

    /// The settings page, from the screen, or from under the box or the folder browser over it.
    fn take_settings(&mut self) -> Option<crate::settings_page::Page> {
        if let Some(Modal::Settings(_)) = &self.modal
            && let Some(Modal::Settings(p)) = self.modal.take()
        {
            return Some(p);
        }
        match self.behind.take().map(|m| *m) {
            Some(Modal::Settings(p)) => Some(p),
            Some(Modal::Browser(b)) if matches!(b.back, crate::browser::Back::Page(_)) => match b.back {
                crate::browser::Back::Page(p) => Some(p),
                _ => None,
            },
            other => {
                self.behind = other.map(Box::new);
                None
            }
        }
    }

    fn prompt_key_password(&mut self, kind: IdentityKind, with_nick: bool) {
        let hint = if with_nick {
            format!(
                "The password your key is made from, with your nick ({}) and this device. The same three always make \
                 the same key, so keep them to keep your identity. Make it long: anyone who learns this device's id \
                 and your nick can guess at it. Nothing is written to disk.",
                self.nick
            )
        } else {
            "The password your key is made from, with this device (not your nick). The same password always makes the \
             same key here. Make it long. Nothing is written to disk."
                .to_string()
        };
        self.modal = Some(Modal::Prompt {
            kind: PromptKind::KeyPassword { kind, with_nick },
            title: format!("NATIVE {} KEY", if kind == IdentityKind::Pgp { "PGP" } else { "AGE" }),
            hint,
            input: Input::default(),
        });
    }

    /// Makes the key from its password off the UI's thread: Argon2id takes a few seconds.
    fn make_key(&mut self, kind: IdentityKind, password: &str, with_nick: bool) {
        if password.is_empty() {
            return self.fail("no password, so no key - /identity new makes one that lasts until chat exits");
        }
        let password = zeroize::Zeroizing::new(password.to_string());
        let nick = with_nick.then(|| self.nick.clone());
        let tx = self.tx.clone();
        self.say("making your key from the password...");
        tokio::spawn(async move {
            let made = tokio::task::spawn_blocking(move || Ident::from_password(kind, &password, nick.as_deref()))
                .await
                .unwrap_or_else(|_| Err("couldn't make the key".into()));
            let _ = tx.send(Msg::Identity(made));
        });
    }

    /// /identity: show it, or make, read or drop one.
    fn identity_command(&mut self, arg: &str) -> Result<(), String> {
        let mut words = arg.split_whitespace();
        let kind_of = |w: Option<&str>| match w {
            Some("pgp") => Some(IdentityKind::Pgp),
            Some("age") | None => Some(IdentityKind::Age),
            Some(_) => None,
        };
        match words.next() {
            None => {
                let lines = match &self.ident {
                    Some(i) => i.describe(),
                    None => vec![
                        "not signing: peers see you as unverified, and /call needs a key".into(),
                        "/identity age (or pgp) makes your key from a password, the same every time".into(),
                        "/identity new age (or pgp) makes one for this run, /identity file PATH reads one".into(),
                    ],
                };
                self.modal = Some(Modal::Info {
                    title: " Signing identity ".into(),
                    lines,
                });
            }
            Some("off" | "none") => self.use_identity(None),
            Some("new") => {
                let kind = kind_of(words.next()).ok_or("usage: /identity new age|pgp")?;
                self.use_identity(Some(Ident::made(kind)));
            }
            Some(k @ ("age" | "pgp")) => {
                let with_nick = words.next() != Some("nonick");
                self.prompt_key_password(kind_of(Some(k)).expect("age or pgp"), with_nick);
            }
            Some("file") => {
                let path = arg["file".len()..].trim();
                if path.is_empty() {
                    return Err("usage: /identity file PATH - an AGE key file, or an unencrypted armored PGP key".into());
                }
                let path = chat_core::net::files::typed_path_here(path);
                self.use_identity(Some(Ident::from_file(&path)?));
            }
            Some("copy") => {
                let i = self.ident.as_ref().ok_or("no signing key in use - /identity makes one")?;
                copy_to_clipboard(&i.public_text(&self.nick));
                self.say(match i.kind {
                    IdentityKind::Pgp => "PGP public key copied (others can gpg --import it)",
                    _ => "AGE recipient copied",
                });
            }
            Some(_) => {
                return Err("usage: /identity [age|pgp [nonick] | new age|pgp | file PATH | copy | off]".into());
            }
        }
        Ok(())
    }

    /// /verified: the signing keys verified, in every room; forget NICK lets one go.
    fn verified_command(&mut self, arg: &str) -> Result<(), String> {
        let trust = self.client.trust().clone();
        let mut t = trust.lock().map_err(|_| "the verified keys are unavailable")?;
        if let Some(who) = arg.strip_prefix("forget") {
            let skel = chat_core::protocol::text::nick_skeleton(who.trim().trim_start_matches('@'));
            if t.forget_nick(&skel) == 0 {
                return Err(format!("no verified key goes by {}", who.trim()));
            }
            drop(t);
            self.say(format!("{} is no longer verified - compare codes with them again", who.trim()));
            return Ok(());
        }
        let lines: Vec<String> = if t.verified().is_empty() {
            vec!["no verified keys yet: /verify NAME, once the code matches, verifies their key in every room".into()]
        } else {
            t.verified()
                .iter()
                .map(|e| {
                    format!(
                        "{} - {:?} key {}",
                        e.nick,
                        e.kind,
                        chat_core::protocol::hex::groups(&chat_core::protocol::crypto::fingerprint(&e.public))
                    )
                })
                .chain(std::iter::once(
                    "/verified forget NICK lets one go; /call NICK opens a room with them".into(),
                ))
                .collect()
        };
        drop(t);
        self.modal = Some(Modal::Info {
            title: " Verified keys ".into(),
            lines,
        });
        Ok(())
    }

    /// `/exportkey [FOLDER]`: the secret key, in a new file only you can read.
    fn export_command(&mut self, arg: &str) -> Result<(), String> {
        let i = self.ident.as_ref().ok_or("no signing key in use - /identity makes one")?;
        let dir = if arg.is_empty() {
            chat_core::net::files::home_dir().ok_or("which folder? /exportkey FOLDER")?
        } else {
            chat_core::net::files::typed_path_here(arg)
        };
        let path = crate::identity::export(i, &self.nick, &dir)?;
        self.say(format!(
            "your secret signing key is in {path}, readable by you alone - /identity file loads it"
        ));
        Ok(())
    }

    /// /call NICK: the room only your key and a verified one can work out, for today (UTC).
    fn call_command(&mut self, arg: &str) -> Result<(), String> {
        let who = arg.trim().trim_start_matches('@');
        if who.is_empty() {
            return Err("call whom? /call NICK, for a key /verified lists".into());
        }
        let ident = self
            .ident
            .clone()
            .ok_or("a call needs a signing identity of yours, which they've verified - /identity")?;
        let skel = chat_core::protocol::text::nick_skeleton(who);
        let found: Vec<_> = {
            let t = self.client.trust().lock().map_err(|_| "the verified keys are unavailable")?;
            t.verified()
                .iter()
                .filter(|e| chat_core::protocol::text::nick_skeleton(&e.nick) == skel)
                .map(|e| (e.public, e.nick.clone()))
                .collect()
        };
        let (public, nick) = match found.as_slice() {
            [] => return Err(format!("no verified key goes by {who} - /verified lists them")),
            [one] => one.clone(),
            _ => {
                return Err(format!(
                    "more than one verified key goes by {who} - /verified forget the one that's gone"
                ));
            }
        };
        if let Some(i) = self.rooms.iter().position(|r| r.call.as_ref().is_some_and(|c| c.0 == public)) {
            self.current = i;
            self.say(format!("the call with {nick} is open already"));
            return Ok(());
        }
        self.open_call(&ident, public, nick, chat_core::protocol::names::contact_day(unix_now()))
    }

    fn open_call(&mut self, ident: &Ident, public: [u8; 32], nick: String, day: u64) -> Result<(), String> {
        let (room, password) = chat_core::protocol::names::contact_room(&ident.kp, &public, day)
            .ok_or_else(|| format!("no room can be worked out with {nick}'s key"))?;
        // Only the verified key gets anything there, whatever else is set.
        let cfg = RoomConfig {
            room: Some(room),
            password: Some(password),
            invite: None,
            create: false,
            verify_required: true,
            ..self.base.clone()
        };
        self.open(cfg, format!("@{nick}"));
        let view = self.rooms.last_mut().expect("just opened");
        view.call = Some((public, nick.clone(), day));
        view.note(
            Level::Note,
            format!(
                "calling {nick}: a room only your signing key and theirs can work out, for today (UTC). They /call you \
                 too, and nothing goes to anyone there but the key you verified"
            ),
        );
        Ok(())
    }

    /// A call nobody's in moves to the new day's room as the day changes, so two who call either
    /// side of midnight (UTC), or with clocks a little apart, still meet.
    pub async fn calls_follow_the_day(&mut self) {
        let day = chat_core::protocol::names::contact_day(unix_now());
        let Some(ident) = self.ident.clone() else { return };
        let stale: Vec<usize> = (0..self.rooms.len())
            .filter(|&i| {
                let r = &self.rooms[i];
                r.call.as_ref().is_some_and(|c| c.2 != day) && r.peers.is_empty() && r.room().is_some()
            })
            .collect();
        for i in stale.into_iter().rev() {
            let r = self.rooms.remove(i);
            if let Some(room) = r.room() {
                room.leave().await;
            }
            let (public, nick, _) = r.call.expect("a call");
            let keep = self.current;
            if self.open_call(&ident, public, nick, day).is_ok() {
                let last = self.rooms.len() - 1;
                let moved = self.rooms.remove(last);
                self.rooms.insert(i, moved);
                self.current = keep.min(self.rooms.len() - 1);
            }
        }
    }

    /// The room :move went to takes the place of the one on screen.
    fn adopt_moved(&mut self, room: Room, events: RoomEvents) {
        let id = self.next_id;
        self.next_id += 1;
        let info = room.info().clone();
        let mut view = RoomView::joining(id, info.room.clone());
        let from = info.moved_from.clone().unwrap_or_default();
        view.note(
            Level::Note,
            format!(
                "moved here from {from}. {} - /invite shows this room's invite",
                if info.created {
                    "Those coming are asked now; anyone left behind isn't told where you went"
                } else {
                    "It opens once the others are here"
                }
            ),
        );
        view.info = Some(info);
        view.state = RoomState::Open(room);
        if self.rooms.is_empty() {
            self.rooms.push(view);
        } else {
            self.rooms[self.current] = view;
        }
        tokio::spawn(forward(id, events, self.tx.clone()));
    }

    /// The request to move in the room on screen, in its box: by itself (`fresh`), or again.
    fn show_move_ask(&mut self, fresh: bool) {
        let Some(a) = self.room().and_then(|r| r.move_ask.clone()) else {
            return;
        };
        let when = crate::text::hhmm(a.at);
        let what = if a.coming.is_empty() {
            format!("{} wants to move this room to a new one, just the two of you (at {when}).", a.from)
        } else {
            format!(
                "{} wants to move this room to a new one, and asks you along with {} (at {when}).",
                a.from,
                chat_core::protocol::names::list(&a.coming)
            )
        };
        self.move_shown = if fresh {
            Instant::now()
        } else {
            Instant::now() - Duration::from_secs(2)
        };
        self.modal = Some(Modal::Ask {
            title: "MOVE",
            paras: vec![
                what,
                "Yes takes you there, and leaves this room. No keeps you here, and you can't go later. Codes you compared \
                 here count there."
                    .into(),
            ],
            keys: "y go \u{b7} n stay \u{b7} esc later",
            then: Ask::MoveAsked(a.seq),
        });
    }

    /// Ctrl+N or /new: a new room's password first, a random one filled in.
    pub fn new_room(&mut self) {
        let mut input = Input::default();
        input.set(&chat_core::protocol::names::random_password());
        self.modal = Some(Modal::Prompt {
            kind: PromptKind::NewRoom,
            title: " NEW SESSION ".into(),
            hint: "A random password, filled in for you. Type to use your own instead. Blank still encrypts, but then \
                   the session's id alone lets anyone in."
                .into(),
            input,
        });
    }

    /// A new room, with this password (None: a random one).
    pub fn create_room(&mut self, password: Option<String>) {
        let cfg = RoomConfig {
            create: true,
            password,
            ..self.base.clone()
        };
        self.open(cfg, "new room".into());
    }

    /// Ctrl+J or /join: the rooms kept in the save, if there are any, otherwise a room's id.
    pub fn begin_rooms(&mut self) {
        if self.settings.rooms.is_empty() {
            return self.join_prompt("");
        }
        self.modal = Some(Modal::Rooms { sel: 0, forgetting: false });
    }

    /// Enter joins the room picked, s has it joined as chat starts (or not), d forgets it after
    /// asking; "another room" asks for an id.
    fn rooms_key(&mut self, sel: usize, forgetting: bool, k: KeyEvent) {
        use crate::settings_page::{ListKey, list_key};
        let n = self.settings.rooms.len();
        if forgetting {
            match k.code {
                KeyCode::Char('y' | 'Y') => {
                    let gone = self.settings.rooms.remove(sel);
                    let save = self.save.as_ref().map(|s| s.name().to_string()).unwrap_or_default();
                    self.rooms_saved(format!("{}: no longer kept in the save {save}", gone.label));
                    if self.settings.rooms.is_empty() {
                        return;
                    }
                    let sel = sel.min(self.settings.rooms.len() - 1);
                    self.modal = Some(Modal::Rooms { sel, forgetting: false });
                }
                KeyCode::Char('n' | 'N' | 'q') | KeyCode::Esc => self.modal = Some(Modal::Rooms { sel, forgetting: false }),
                _ => self.modal = Some(Modal::Rooms { sel, forgetting: true }),
            }
            return;
        }
        match (k.code, sel < n) {
            (KeyCode::Char('d'), true) => return self.modal = Some(Modal::Rooms { sel, forgetting: true }),
            (KeyCode::Char('s'), true) => {
                let r = &mut self.settings.rooms[sel];
                r.at_start = !r.at_start;
                let done = format!(
                    "{}: {}",
                    r.label,
                    if r.at_start {
                        "joined as chat starts"
                    } else {
                        "not joined as chat starts"
                    }
                );
                self.rooms_saved(done);
                return self.modal = Some(Modal::Rooms { sel, forgetting: false });
            }
            _ => {}
        }
        let sel = match list_key(&k) {
            ListKey::Choose | ListKey::Right if sel < n => {
                let r = &self.settings.rooms[sel];
                let line = format!("{} {}", r.id, r.password);
                return self.join(&line);
            }
            ListKey::Choose | ListKey::Right => return self.join_prompt(""),
            ListKey::Left | ListKey::Back | ListKey::Close => return,
            ListKey::Up => sel.saturating_sub(1),
            ListKey::Down => (sel + 1).min(n),
            ListKey::First => 0,
            ListKey::Last => n,
            _ => sel,
        };
        self.modal = Some(Modal::Rooms { sel, forgetting: false });
    }

    /// A change to the kept rooms, written to the save at once.
    fn rooms_saved(&mut self, done: String) {
        match self.write_settings() {
            Ok(()) => self.say(done),
            Err(_) => {
                let place = self
                    .save
                    .as_ref()
                    .and_then(|s| self.saves.as_ref().map(|v| v.shown_dir(s.name())))
                    .unwrap_or_default();
                self.fail(format!("couldn't write that to {place}/settings - it lasts until chat exits"));
            }
        }
    }

    /// An invite, or a room id followed by its password.
    pub fn join(&mut self, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        let mut cfg = self.base.clone();
        let label;
        if chat_core::protocol::names::is_invite(text) {
            match chat_core::protocol::names::parse_invite(text) {
                Ok((id, _)) => label = id,
                Err(e) => return self.fail(e.to_string()),
            }
            cfg.invite = Some(text.into());
        } else {
            let (id, pw) = text.split_once(' ').unwrap_or((text, ""));
            label = id.to_string();
            cfg.room = Some(id.into());
            cfg.password = Some(pw.trim().into());
        }
        if let Some(r) = self.rooms.iter().position(|r| r.label == label && r.room().is_some()) {
            self.current = r;
            return self.say(format!("already in {label}"));
        }
        self.open(cfg, label);
    }

    pub fn on_msg(&mut self, msg: Msg) {
        // A message can open a box (a save's news, a key made from its password); over a page, the
        // page is under it while it's handled, and comes back once the box closes.
        let page = matches!(msg, Msg::Save(_) | Msg::Identity(_)) && self.modal.as_ref().is_some_and(Modal::is_page);
        if page {
            self.behind = self.modal.take().map(Box::new);
        }
        self.handle_msg(msg);
        if page {
            self.back_to_page();
        }
    }

    fn handle_msg(&mut self, msg: Msg) {
        let joined = match &msg {
            Msg::Joined(id, Ok(_)) => Some(*id),
            _ => None,
        };
        let current = self.rooms.get(self.current).map(|r| r.id);
        match msg {
            Msg::Save(m) => self.on_save(m),
            Msg::Joined(id, result) => {
                let identity = self.base.identity.clone();
                let Some(r) = self.by_id(id) else { return };
                match result {
                    Ok((room, info)) => {
                        // The signing key may have changed while it opened.
                        room.set_identity(identity);
                        // A call keeps its name: who it's with.
                        if r.call.is_none() {
                            r.label = info.room.clone();
                        }
                        let invite = info.invite.clone().unwrap_or_default();
                        let how = match info.mode {
                            RouteMode::Tor => "through Tor: nobody learns your IP address, peers included",
                            RouteMode::Direct => "direct: faster, but peers see your IP address",
                        };
                        r.note(Level::Note, format!("this room goes {how}"));
                        if info.created {
                            r.note(
                                Level::Note,
                                format!(
                                    "room {} is ready. Share this invite with whoever you want here: {invite}",
                                    info.room
                                ),
                            );
                            r.note(
                                Level::Note,
                                "/invite copies it. Compare verify codes with each person who joins (/verify NAME).",
                            );
                        } else {
                            r.note(Level::Note, format!("joining {} - it opens once someone answers", info.room));
                        }
                        r.info = Some(info);
                        r.state = RoomState::Open(room);
                    }
                    Err(e) => {
                        r.note(Level::Warn, format!("couldn't open the room: {e}"));
                        r.state = RoomState::Failed(e);
                    }
                }
            }
            Msg::Closed(id) => {
                self.write_history(id, true);
                if let Some(r) = self.by_id(id) {
                    r.state = RoomState::Closed;
                }
                self.remember_open();
            }
            Msg::Identity(Ok(ident)) => self.use_identity(Some(ident)),
            Msg::Identity(Err(why)) => self.fail(why),
            Msg::Picture(id, num, result) => {
                let Some(r) = self.by_id(id) else { return };
                match result {
                    Ok((t, big)) => {
                        r.hidden.remove(&num);
                        r.pic_why.remove(&num);
                        r.pictures.insert(num, t);
                        r.picture_data.insert(num, big);
                    }
                    Err(why) => {
                        r.note(Level::Warn, format!("can't show file {num}: {why}"));
                        r.pic_why.insert(num, why);
                    }
                }
            }
            Msg::Room(id, event) => {
                let is_current = current == Some(id);
                let (nick, my_colour) = (self.nick.clone(), self.colour);
                // Locked, a notification shows no preview whatever the setting says.
                let notify_mode = self.settings.get("notify").to_string();
                let preview = if self.locked.is_some() {
                    "off".to_string()
                } else {
                    self.settings.get("preview").to_string()
                };
                let Some(r) = self.by_id(id) else { return };
                let mut bell = false;
                match event {
                    Event::Message(m) => {
                        // A direct message is for us, so it counts as a mention.
                        let mentioned = m.mention || m.direct;
                        let wanted = match notify_mode.as_str() {
                            "all" => true,
                            "mentions" => mentioned,
                            _ => false,
                        };
                        if !m.mine && wanted {
                            let (title, body) = crate::notify::compose(&preview, &m.name, m.body(), mentioned);
                            crate::notify::send(title, body);
                        }
                        if r.history.is_some() {
                            let (text, head) = crate::saved::history_text(&m, &nick, &r.peers);
                            let colour = m.colour.or(if m.mine { my_colour } else { None }).map(|c| c.0);
                            if let Some(h) = r.history.as_mut() {
                                h.add(m.at, colour, head, m.mention && !m.mine, &text);
                            }
                        }
                        if !m.mine {
                            if !is_current {
                                r.unread += 1;
                            }
                            if m.mention {
                                r.mentioned |= !is_current;
                                bell = true;
                            }
                        }
                        if r.scroll > 0 {
                            r.scroll += 1;
                        }
                        r.entries.push(Entry {
                            at: m.at.max(1),
                            kind: EntryKind::Msg(m),
                        });
                    }
                    Event::Delivery { own, delivery } => {
                        let s = r.sent.entry(own).or_default();
                        match delivery {
                            Delivery::Delivered { .. } => s.delivered += 1,
                            Delivery::Missed { name, .. } => s.missed.push(name),
                            Delivery::Settled => s.settled = true,
                        }
                    }
                    Event::PeerJoined(p) | Event::PeerChanged(p) => match r.peers.iter_mut().find(|q| q.id == p.id) {
                        Some(q) => *q = p,
                        None => r.peers.push(p),
                    },
                    Event::PeerLeft { id, .. } => r.peers.retain(|p| p.id != id),
                    Event::Timer { seconds, .. } => r.timer = seconds,
                    Event::Notice { level, text } => r.note(level, text),
                    Event::Log { text } => r.entries.push(Entry {
                        at: unix_now(),
                        kind: EntryKind::Log(text),
                    }),
                    Event::Net(n) => r.net = n,
                    Event::Files { list } => {
                        // A file someone offers: with notify all, as a message would be.
                        if notify_mode == "all" {
                            for f in list.iter().filter(|f| !f.mine && !r.files.iter().any(|o| o.num == f.num)) {
                                let (title, body) = crate::notify::compose(&preview, &f.from_name, "offered a file", false);
                                crate::notify::send(title, body);
                            }
                        }
                        r.files = list;
                    }
                    Event::MoveAsked { ask } => {
                        // Its box comes up by itself (on_tick), on the room's own screen.
                        bell |= ask.is_some();
                        r.move_ask = ask;
                    }
                    Event::Picture { .. } | Event::Opened => {}
                }
                if bell {
                    let _ = std::io::stdout().write_all(b"\x07").and_then(|_| std::io::stdout().flush());
                }
            }
        }
        if let Some(id) = joined {
            self.remember_open();
            self.start_history(id);
        }
    }

    /// Once a second: messages past the room's timer go, and so does an old status.
    pub fn on_tick(&mut self) {
        self.spinner = (self.spinner + 1) % SPINNER.len();
        // A request to move, in the room on screen, unless it was left for later.
        if self.modal.is_none()
            && self.locked.is_none()
            && let Some(r) = self.room()
            && let Some(a) = &r.move_ask
            && r.move_later != Some(a.seq)
        {
            self.show_move_ask(true);
        }
        if let Some((ok, msg)) = chat_core::net::update::poll() {
            self.update_proxy = None;
            self.console(ok, format!("update: {msg}"));
        }
        if self.clipboard_until.is_some_and(|t| Instant::now() >= t) {
            self.clipboard_until = None;
            if self.clipboard_native {
                crate::notify::clipboard_clear();
            } else {
                // The terminal can't say what's there now, so this can clear something copied since.
                // xterm empties it on a payload that isn't base64, others on an empty one.
                let mut out = std::io::stdout();
                let _ = out.write_all(b"\x1b]52;c;!\x07\x1b]52;c;\x07").and_then(|_| out.flush());
            }
        }
        if let Some(after) = self.settings.lock_after()
            && self.locked.is_none()
            && (self.save.is_some() || self.pin.is_some())
            && self.last_key.elapsed().as_secs() >= u64::from(after)
        {
            self.lock_now();
        }
        let now = unix_now();
        if self.last_history_write.elapsed().as_secs() >= 30 {
            self.last_history_write = Instant::now();
            let ids: Vec<usize> = self.rooms.iter().map(|r| r.id).collect();
            for id in ids {
                self.write_history(id, false);
            }
        }
        for r in &mut self.rooms {
            if r.timer > 0
                && let Some(h) = r.history.as_mut()
            {
                h.expire(r.timer, now);
            }
            if r.timer > 0 {
                r.entries
                    .retain(|e| !matches!(e.kind, EntryKind::Msg(_)) || now.saturating_sub(e.at) <= u64::from(r.timer));
            }
        }
        if self.status.as_ref().is_some_and(|(_, _, at)| at.elapsed() > Duration::from_secs(6)) {
            self.status = None;
        }
    }

    pub async fn on_terminal(&mut self, ev: TermEvent) {
        match ev {
            TermEvent::Key(k) if k.kind != KeyEventKind::Release => self.on_key(k).await,
            // A paste's letters would answer the QUIT box.
            TermEvent::Paste(_) | TermEvent::Mouse(_) if self.asking_quit => {}
            // Locked, only the passphrase box takes anything: what's under it is out of reach.
            TermEvent::Paste(text) if self.locked.is_some() => {
                if let Some(l) = self.locked.as_mut().filter(|l| !l.busy) {
                    text.replace(['\r', '\n'], "").chars().for_each(|c| l.input.insert(c));
                }
            }
            TermEvent::Mouse(_) if self.locked.is_some() => {}
            // The wheel scrolls what it's over: the console, or the chat.
            TermEvent::Mouse(m) if self.modal.is_none() => {
                let by: isize = match m.kind {
                    crossterm::event::MouseEventKind::ScrollUp => 1,
                    crossterm::event::MouseEventKind::ScrollDown => -1,
                    _ => return,
                };
                let at = ratatui::layout::Position::new(m.column, m.row);
                // Over a list in the sidebar that doesn't fit, it scrolls the list.
                let mut side = self.side.get();
                if let Some(k) = (0..2).find(|&k| side.at[k].is_some_and(|r| r.contains(at))) {
                    side.top[k] = side.top[k].saturating_add_signed(-by).min(side.most[k]);
                    return self.side.set(side);
                }
                let over = self.console_at.get().is_some_and(|r| r.contains(at));
                if let Some(r) = self.room_mut() {
                    if over {
                        r.console_scroll = r.console_scroll.saturating_add_signed(by);
                    } else {
                        r.scroll = r.scroll.saturating_add_signed(by);
                    }
                }
            }
            TermEvent::Paste(text) if matches!(self.modal, Some(Modal::Paste { .. })) => {
                // A key keeps its lines.
                if let Some(Modal::Paste { kind, text: mut buf }) = self.modal.take() {
                    let text = zeroize::Zeroizing::new(text);
                    for c in text.chars().filter(|c| *c != '\r') {
                        if buf.len() + c.len_utf8() <= crate::settings_page::PASTE_MAX {
                            buf.push(c);
                        }
                    }
                    self.pasted(kind, buf);
                }
            }
            TermEvent::Paste(text) => {
                // A paste goes in as text, its lines run together, and waits for Enter.
                let flat = text.replace(['\r', '\n'], " ");
                match &mut self.modal {
                    Some(Modal::Prompt { input, .. }) => flat.chars().for_each(|c| input.insert(c)),
                    Some(Modal::Settings(crate::settings_page::Page {
                        search: Some((input, sel)),
                        ..
                    })) => {
                        flat.chars().for_each(|c| input.insert(c));
                        *sel = 0;
                    }
                    None => flat.chars().for_each(|c| self.input.insert(c)),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    async fn on_key(&mut self, k: KeyEvent) {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        self.last_key = Instant::now();
        // The panic key works from anywhere, the lock screen too.
        if crate::lock::is_key(&k, self.settings.get("panickey")) {
            return self.panic();
        }
        if self.locked.is_some() {
            return self.lock_key(k);
        }
        if self.modal.is_none() && crate::lock::is_key(&k, self.settings.get("lockkey")) {
            return self.lock_now();
        }
        // Ctrl+C asks from anywhere, and a second one quits.
        if k.code == KeyCode::Char('c') && ctrl {
            if std::mem::replace(&mut self.asking_quit, true) {
                self.quit = true;
            }
            return;
        }
        // y quits, not q, which closes boxes elsewhere. Staying leaves what the box was over as it was.
        if self.asking_quit {
            match k.code {
                KeyCode::Char('y' | 'Y') => self.quit = true,
                KeyCode::Char('n' | 'N') | KeyCode::Esc => self.asking_quit = false,
                _ => {}
            }
            return;
        }
        if k.code == KeyCode::Esc
            && let Some(w) = &self.key_wait
        {
            w.cancel.store(true, std::sync::atomic::Ordering::Release);
            return;
        }
        if self.modal.is_some() {
            return self.modal_key(k).await;
        }
        // Keys for every mode.
        match k.code {
            KeyCode::Char('n') if ctrl => return self.new_room(),
            KeyCode::Char('s') if ctrl => return self.open_settings(None),
            KeyCode::Char('f') if ctrl => return self.begin_files(),
            KeyCode::Char('j') if ctrl => return self.begin_rooms(),
            KeyCode::Char('b') if ctrl => return self.show_sidebar = !self.show_sidebar,
            KeyCode::Char('o') if ctrl => return self.show_console = !self.show_console,
            KeyCode::Char('t') if ctrl => return self.show_chat = !self.show_chat,
            KeyCode::F(1) => return self.modal = Some(Modal::Help(0)),
            KeyCode::PageUp => return self.scroll(10),
            KeyCode::PageDown => return self.scroll(-10),
            _ => {}
        }
        match self.mode {
            crate::cmdline::Mode::Command => return self.command_key(k).await,
            crate::cmdline::Mode::Normal => {
                if self.normal_key(&k).await {
                    return;
                }
            }
            crate::cmdline::Mode::Insert => {
                if self.insert_key(&k) {
                    return;
                }
            }
        }
        match k.code {
            KeyCode::Tab => self.switch(1),
            KeyCode::BackTab => self.switch(-1),
            KeyCode::Up => self.scroll(1),
            KeyCode::Down => self.scroll(-1),
            KeyCode::Enter => self.submit().await,
            _ => {}
        }
    }

    /// INSERT types: '/' on an empty line opens the command line, Tab finishes a @nick, and Esc
    /// goes to NORMAL. False for a key it leaves to the screen.
    fn insert_key(&mut self, k: &KeyEvent) -> bool {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        match k.code {
            KeyCode::Char('/') if !ctrl && self.input.chars.is_empty() => self.enter_command('/'),
            KeyCode::Tab => return self.complete_mention(),
            KeyCode::Esc => {
                self.mode = crate::cmdline::Mode::Normal;
                self.input.cursor = self.input.cursor.min(self.input.chars.len().saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Down | KeyCode::Enter | KeyCode::BackTab => return false,
            _ => return self.input.edit(k),
        }
        true
    }

    /// NORMAL: vim's keys for the line (h l 0 $ x, i a I A to type), j and k to switch rooms, G back
    /// to the newest, ? the help, f the files, o the newest link, s c C to show or hide the sidebar,
    /// console and chat, and : or / for the command line. False for a key it leaves to the screen.
    async fn normal_key(&mut self, k: &KeyEvent) -> bool {
        use crate::cmdline::Mode;
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let len = self.input.chars.len();
        let last = len.saturating_sub(1);
        let cur = &mut self.input.cursor;
        match k.code {
            KeyCode::Char('u') if ctrl => self.scroll(10),
            KeyCode::Char('d') if ctrl => self.scroll(-10),
            _ if ctrl => return false,
            KeyCode::Char('h') | KeyCode::Left | KeyCode::Backspace => *cur = cur.saturating_sub(1),
            KeyCode::Char('l') | KeyCode::Right => *cur = (*cur + 1).min(last),
            KeyCode::Char('0') | KeyCode::Home => *cur = 0,
            KeyCode::Char('$') | KeyCode::End => *cur = last,
            KeyCode::Char('x') | KeyCode::Delete => {
                if *cur < len {
                    self.input.chars.remove(*cur);
                    self.input.cursor = self.input.cursor.min(self.input.chars.len().saturating_sub(1));
                }
            }
            KeyCode::Char('i') => self.mode = Mode::Insert,
            KeyCode::Char('a') => {
                *cur = (*cur + 1).min(len);
                self.mode = Mode::Insert;
            }
            KeyCode::Char('I') => {
                *cur = 0;
                self.mode = Mode::Insert;
            }
            KeyCode::Char('A') => {
                *cur = len;
                self.mode = Mode::Insert;
            }
            KeyCode::Char(p @ (':' | '/')) => self.enter_command(p),
            KeyCode::Char('j') => self.switch(1),
            KeyCode::Char('k') => self.switch(-1),
            KeyCode::Char('G') => {
                if let Some(r) = self.room_mut() {
                    r.scroll = 0;
                    r.console_scroll = 0;
                }
            }
            KeyCode::Char('?') => self.modal = Some(Modal::Help(0)),
            KeyCode::Char('f') => self.begin_files(),
            KeyCode::Char('o') => self.run("open").await,
            KeyCode::Char('c') => self.show_console = !self.show_console,
            KeyCode::Char('C') => self.show_chat = !self.show_chat,
            KeyCode::Char('s') => self.show_sidebar = !self.show_sidebar,
            KeyCode::Char(_) => {}
            _ => return false,
        }
        true
    }

    /// A room's id (its password comes next), or a whole invite, which has the password in it.
    fn join_prompt(&mut self, value: &str) {
        let mut input = Input::default();
        input.set(value.trim());
        self.modal = Some(Modal::Prompt {
            kind: PromptKind::JoinId,
            title: " JOIN SESSION ".into(),
            hint: "The id you were given, and its password comes next. Or a whole invite (chat:...), which has the \
                   password in it."
                .into(),
            input,
        });
    }

    fn join_id_typed(&mut self, text: &str) {
        let id = text.trim();
        if chat_core::protocol::names::is_invite(id) {
            return self.join(id);
        }
        self.modal = Some(Modal::Prompt {
            kind: PromptKind::JoinPassword(id.to_string()),
            title: " JOIN SESSION ".into(),
            hint: format!("The password for {id}, as you were given it."),
            input: Input::default(),
        });
    }

    async fn modal_key(&mut self, k: KeyEvent) {
        self.modal_key_inner(k).await;
        self.back_to_page();
    }

    async fn modal_key_inner(&mut self, k: KeyEvent) {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let Some(modal) = self.modal.take() else { return };
        match modal {
            Modal::Prompt {
                kind,
                title,
                hint,
                mut input,
            } => match k.code {
                KeyCode::Esc => match kind {
                    PromptKind::Nick => self.say(format!("you're {}", self.nick)),
                    PromptKind::Unlock(_) | PromptKind::Code => self.unlock_skipped(),
                    PromptKind::Install(_) => {
                        self.pending_factor = None;
                        self.say("not installed - nothing was written");
                    }
                    PromptKind::Uninstall(name) => self.say(format!("{name} is kept")),
                    PromptKind::KeyPin(Some(_)) => {
                        self.pending_pass = None;
                        self.say("started without the save: chat's defaults, and nothing you change is saved");
                        self.begin_start(false);
                    }
                    PromptKind::KeyPin(None) => self.say("no security key was registered"),
                    _ => {}
                },
                KeyCode::Enter => {
                    let text = input.text();
                    // A field that's refused stays open with what was typed, to fix or Esc.
                    if let Some(why) = self.refused(&kind, &text) {
                        self.fail(why);
                        self.modal = Some(Modal::Prompt { kind, title, hint, input });
                        return;
                    }
                    match kind {
                        PromptKind::Nick => self.set_nick(text.trim()).await,
                        PromptKind::NewRoom => self.create_room(Some(text.trim().to_string())),
                        PromptKind::JoinId => self.join_id_typed(&text),
                        PromptKind::JoinPassword(id) => self.join(&format!("{id} {}", text.trim())),
                        PromptKind::KeyPassword { kind, with_nick } => self.make_key(kind, &text, with_nick),
                        PromptKind::Unlock(name) => self.unlock(name, zeroize::Zeroizing::new(text)),
                        PromptKind::Code => self.check_code(text),
                        PromptKind::Install(crate::saved::Installing::Name) => self.install_name(&text),
                        PromptKind::Install(crate::saved::Installing::Pass(name)) => self.install_pass(name, &text),
                        PromptKind::Install(crate::saved::Installing::Again(name, first)) => self.install_again(name, first, &text),
                        PromptKind::Uninstall(name) => self.uninstall(name, &text),
                        PromptKind::SetPin => self.set_pin(&text),
                        PromptKind::Shadow(first) => self.shadow_pass(first, &text),
                        PromptKind::NewCode => self.new_code_typed(&text),
                        PromptKind::SetRow(name) => self.set_row(name, &text).await,
                        PromptKind::KeyPin(Some(name)) => self.key_open(name, Some(zeroize::Zeroizing::new(text))),
                        PromptKind::KeyPin(None) => self.register_key(Some(zeroize::Zeroizing::new(text))),
                        PromptKind::KeyPath(k) => self.key_path_typed(k, title, hint, input),
                    }
                }
                _ => {
                    input.edit(&k);
                    self.modal = Some(Modal::Prompt { kind, title, hint, input });
                }
            },
            Modal::Settings(page) => self.settings_key(page, k).await,
            Modal::Browser(b) => self.browser_key(b, k).await,
            Modal::Ask {
                then: Ask::File(what, num),
                ..
            } if matches!(k.code, KeyCode::Char('y' | 'Y')) => self.file_answer(what, num).await,
            Modal::Ask { then: Ask::File(..), .. } if matches!(k.code, KeyCode::Char('n' | 'N') | KeyCode::Esc) => {}
            Modal::Ask { then: Ask::Move, .. } => {
                if matches!(k.code, KeyCode::Char('y' | 'Y')) {
                    self.run("move yes").await;
                }
            }
            Modal::Ask {
                then: Ask::MoveAsked(seq),
                title,
                paras,
                keys,
            } => {
                // A request that came up by itself ignores keys for a moment.
                let keep = |s: &mut Self| {
                    s.modal = Some(Modal::Ask {
                        title,
                        paras,
                        keys,
                        then: Ask::MoveAsked(seq),
                    })
                };
                if self.move_shown.elapsed() < Duration::from_secs(1) {
                    return keep(self);
                }
                match k.code {
                    KeyCode::Char('y' | 'Y') => self.run("move yes").await,
                    KeyCode::Char('n' | 'N') => {
                        self.run("move no").await;
                        self.say("you stay in this room");
                    }
                    KeyCode::Char('q') | KeyCode::Esc => {
                        if let Some(r) = self.room_mut() {
                            r.move_later = Some(seq);
                        }
                        self.say("the request to move waits - /move shows it again");
                    }
                    _ => keep(self),
                }
            }
            Modal::Ask { title, paras, keys, then } => match k.code {
                KeyCode::Char('y' | 'Y') => self.answer(then, Some(true)),
                KeyCode::Char('n' | 'N') => self.answer(then, Some(false)),
                KeyCode::Esc => self.answer(then, None),
                _ => self.modal = Some(Modal::Ask { title, paras, keys, then }),
            },
            // Every key but Esc is the paste arriving.
            Modal::Paste { kind, mut text } => {
                let c = match k.code {
                    KeyCode::Esc => return,
                    KeyCode::Enter => Some('\n'),
                    KeyCode::Char(c) if !ctrl => Some(c),
                    KeyCode::Backspace => {
                        text.pop();
                        None
                    }
                    _ => None,
                };
                match c {
                    Some(c) if text.len() + c.len_utf8() <= crate::settings_page::PASTE_MAX => {
                        text.push(c);
                        self.pasted(kind, text);
                    }
                    _ => self.modal = Some(Modal::Paste { kind, text }),
                }
            }
            Modal::Files(num) => self.files_key(num, k).await,
            Modal::Picture(num) => self.picture_key(num, k).await,
            Modal::Rooms { sel, forgetting } => self.rooms_key(sel, forgetting, k),
            Modal::PickSave { names, sel } => self.pick_save_key(names, sel, k),
            Modal::Link { links, at } => match k.code {
                KeyCode::Char('j') | KeyCode::Down if at + 1 < links.len() => self.modal = Some(Modal::Link { links, at: at + 1 }),
                KeyCode::Char('k') | KeyCode::Up if at > 0 => self.modal = Some(Modal::Link { links, at: at - 1 }),
                KeyCode::Char('y') => {
                    crate::notify::open_link(chat_core::protocol::text::link_target(&links[at].0));
                    self.say("opened in your browser - it reaches the site directly, not through chat's Tor or relays");
                }
                KeyCode::Char('c') => {
                    self.copy_for_a_while(&chat_core::protocol::text::link_target(&links[at].0), false);
                    self.say("the link is copied");
                }
                KeyCode::Char('n') | KeyCode::Esc | KeyCode::Char('q') => {}
                _ => self.modal = Some(Modal::Link { links, at }),
            },
            Modal::Info { .. } | Modal::Qr { .. } if std::mem::take(&mut self.prompt_after_info) => self.ask_new_code(),
            Modal::Info { .. } | Modal::Qr { .. } => {}
            Modal::Verify { room, peer } => match k.code {
                KeyCode::Char('y' | 'Y') => self.verify(room, peer.id, true).await,
                KeyCode::Char('n' | 'N') => self.verify(room, peer.id, false).await,
                KeyCode::Esc | KeyCode::Char('q') => {}
                _ => self.modal = Some(Modal::Verify { room, peer }),
            },
            Modal::Help(sel) => self.help_key(sel, &k),
            Modal::Update => match k.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    if chat_core::net::update::view().running {
                        self.say("the update keeps running - /update shows it again");
                    }
                }
                _ => self.modal = Some(Modal::Update),
            },
        }
    }

    fn switch(&mut self, by: isize) {
        if self.rooms.is_empty() {
            return;
        }
        let n = self.rooms.len() as isize;
        self.current = ((self.current as isize + by).rem_euclid(n)) as usize;
        let r = &mut self.rooms[self.current];
        r.unread = 0;
        r.mentioned = false;
    }

    /// The chat scrolled back (by > 0) or forward by this many rows.
    fn scroll(&mut self, by: isize) {
        if let Some(r) = self.room_mut() {
            r.scroll = r.scroll.saturating_add_signed(by);
        }
    }

    /// Tab after "@bo" makes it "@bob ".
    fn complete_mention(&mut self) -> bool {
        let before: String = self.input.chars[..self.input.cursor].iter().collect();
        let Some(at) = before.rfind('@') else { return false };
        let partial = &before[at + 1..];
        if partial.contains(' ') {
            return false;
        }
        let Some(r) = self.room() else { return false };
        let Some(p) = r.peers.iter().find(|p| p.nick.to_lowercase().starts_with(&partial.to_lowercase())) else {
            return false;
        };
        let nick = p.nick.clone();
        let start = before[..at].chars().count() + 1;
        self.input
            .chars
            .splice(start..self.input.cursor, nick.chars().chain(std::iter::once(' ')));
        self.input.cursor = start + nick.chars().count() + 1;
        true
    }

    /// Enter on the line: a message. Commands go through the command line, so a line here that
    /// starts with '/' is text.
    async fn submit(&mut self) {
        let line = self.input.take();
        if line.trim().is_empty() {
            return;
        }
        self.send(&line).await;
    }

    pub(crate) fn open_room(&mut self) -> Result<(usize, Room), String> {
        match self.room() {
            Some(r) => match &r.state {
                RoomState::Open(room) => Ok((r.id, room.clone())),
                RoomState::Joining => Err("the room is still opening".into()),
                _ => Err("this room is closed - Ctrl+N starts a new one, Ctrl+J joins one".into()),
            },
            None => Err("start a room first: Ctrl+N makes one, Ctrl+J joins one".into()),
        }
    }

    /// The answer to a command that sent one of our messages: remembered for its ticks.
    fn sent(&mut self, id: usize, result: Result<Outcome, CommandError>) {
        match result {
            Ok(Outcome::Sent { own, to, held, .. }) => {
                if let Some(r) = self.by_id(id) {
                    let s = r.sent.entry(own).or_default();
                    s.to = to;
                    s.held = held;
                    r.scroll = 0;
                }
            }
            Ok(Outcome::Done | Outcome::Offered { .. } | Outcome::MovePlan(_)) => {}
            Err(e) => self.fail(e.to_string()),
        }
    }

    pub(crate) async fn send(&mut self, text: &str) {
        match self.open_room() {
            Ok((id, room)) => {
                let r = room.send(text).await;
                self.sent(id, r);
            }
            Err(e) => self.fail(e),
        }
    }

    pub(crate) async fn set_nick(&mut self, nick: &str) {
        if nick.is_empty() {
            return;
        }
        self.nick = chat_core::protocol::text::clean_nick(nick.as_bytes());
        for r in &self.rooms {
            if let Some(room) = r.room() {
                let _ = room.command(Command::SetNick { nick: self.nick.clone() }).await;
            }
        }
        let nick = self.nick.clone();
        self.setting_changed("nick", &nick);
        self.say(format!("you're {} now", self.nick));
        // A key made with the old nick stays that key: the password makes it with the new one.
        if let Some(Ident {
            origin: Origin::Password(Some(n)),
            kind,
            ..
        }) = &self.ident
            && *n != self.nick
        {
            let (n, kind) = (n.clone(), *kind);
            self.prompt_key_password(kind, true);
            self.fail(format!(
                "your key was made with the nick {n}: its password makes it again with {} (a new key, so peers compare \
                 codes again) - Esc keeps the old one",
                self.nick
            ));
        }
    }

    async fn verify(&mut self, id: usize, peer: PeerId, same: bool) {
        let Some(room) = self.rooms.iter().find(|r| r.id == id).and_then(|r| r.room().cloned()) else {
            return;
        };
        if let Err(e) = room.verify(peer, same).await {
            self.fail(e.to_string());
        }
    }

    /// A command line, without its "/".
    pub(crate) async fn run(&mut self, line: &str) {
        Box::pin(self.command(line)).await
    }

    async fn command(&mut self, line: &str) {
        let (name, arg) = line.split_once(' ').map_or((line, ""), |(n, a)| (n, a.trim()));
        let result: Result<(), String> = match name {
            "help" | "h" | "?" => {
                self.modal = Some(Modal::Help(0));
                Ok(())
            }
            "new" => {
                self.new_room();
                Ok(())
            }
            "join" | "j" => {
                if arg.is_empty() {
                    self.begin_rooms();
                } else if let Some(kept) = self.kept(arg) {
                    self.join(&kept);
                } else {
                    self.join(arg);
                }
                Ok(())
            }
            "lock" => {
                self.lock_now();
                Ok(())
            }
            "quitall" | "qa" | "qall" => {
                // Leaves every room, keeping none to reopen.
                self.settings.reopen.clear();
                self.autosave();
                self.quit_all = true;
                self.quit = true;
                Ok(())
            }
            "changelog" | "news" => {
                let lines = include_str!("../CHANGELOG.md").lines().map(String::from).collect();
                self.modal = Some(Modal::Info {
                    title: " Changelog ".into(),
                    lines,
                });
                Ok(())
            }
            "open" => self.open_command(arg),
            "update" => self.update_command().await,
            "copyid" => match self.room().and_then(|r| r.info.as_ref()).map(|i| i.room.clone()) {
                Some(id) => {
                    self.copy_for_a_while(&id, true);
                    self.say("the room's id is copied - it comes off the clipboard in 30 seconds");
                    Ok(())
                }
                None => Err("no room is open here".into()),
            },
            "install" => self.install_command(arg),
            "save" => self.save_command(),
            "uninstall" => self.uninstall_command(arg),
            "keep" => self.keep_command(arg),
            "set" => self.set_command(arg).await,
            "quit" | "q" | "exit" | "close" | "bd" | "bw" => {
                self.quit = true;
                Ok(())
            }
            "nick" | "name" => {
                if arg.is_empty() {
                    Err(format!("you're {} - /nick NAME changes it", self.nick))
                } else {
                    self.set_nick(arg).await;
                    Ok(())
                }
            }
            "route" => match arg {
                "tor" => {
                    self.base.route.mode = RouteMode::Tor;
                    self.setting_changed("routing", "tor");
                    self.say("rooms you open from now on go through Tor: private, a minute or two to connect");
                    Ok(())
                }
                "direct" => {
                    self.base.route.mode = RouteMode::Direct;
                    self.setting_changed("routing", "udp");
                    self.say("rooms you open from now on go direct: faster, but they show your IP address to peers");
                    Ok(())
                }
                _ => Err(format!(
                    "now {} - /route tor (private) or /route direct (faster, shows your IP to peers)",
                    route_name(self.base.route.mode)
                )),
            },
            "relays" => {
                self.base.route.nostr =
                    match arg {
                        "fallback" | "on" => NostrMode::Fallback,
                        "always" => NostrMode::Always,
                        "off" => NostrMode::Off,
                        _ => return self.fail(
                            "/relays fallback|always|off - the Nostr relays find members faster, and reach members on the other routing",
                        ),
                    };
                let row = if arg == "on" { "fallback" } else { arg };
                self.setting_changed("nostr", row);
                self.say("rooms you open from now on use that");
                Ok(())
            }
            "fast" | "limit" | "noise" | "downloads" => {
                let mut o = self.base.files.clone();
                match (name, arg) {
                    ("fast", "on") => o.fast = true,
                    ("fast", "off") => o.fast = false,
                    ("noise", "on") => o.noise = true,
                    ("noise", "off") => o.noise = false,
                    ("limit", a) if parse_size(a).is_some_and(|n| n > 0) => o.limit = parse_size(a).expect("checked"),
                    ("downloads", "") => o.dir = None,
                    ("downloads", d) => o.dir = Some(chat_core::net::files::typed_path_here(d)),
                    _ => {
                        let limit = if o.limit == 0 {
                            chat_core::protocol::files::FILE_CAP_DEFAULT
                        } else {
                            o.limit
                        };
                        let on = |b: bool| if b { "on" } else { "off" };
                        for line in [
                            format!(
                                "/fast on|off (now {}): slots every few milliseconds while a file goes - faster, but visible as a burst",
                                on(o.fast)
                            ),
                            format!(
                                "/limit SIZE (now {}): files bigger than that need \"anyway\"",
                                format_size_exact(limit)
                            ),
                            format!(
                                "/noise on|off (now {}): noise nobody can see in pictures you send, so no two copies match",
                                on(o.noise)
                            ),
                            format!(
                                "/downloads [FOLDER] (now {}): where files are saved",
                                o.dir.as_deref().unwrap_or("Downloads")
                            ),
                        ] {
                            self.say(line);
                        }
                        return;
                    }
                }
                self.base.files = o.clone();
                self.push_file_options().await;
                let on = |b: bool| if b { "on" } else { "off" };
                self.setting_changed("fastfiles", on(o.fast));
                self.setting_changed("noise", on(o.noise));
                if o.limit > 0 {
                    self.setting_changed("filelimit", &format_size_exact(o.limit));
                }
                self.say("files: set, here and in every room");
                Ok(())
            }
            "newtor" => {
                let rooms: Vec<Room> = self.rooms.iter().filter_map(|r| r.room().cloned()).collect();
                let mut n = 0;
                for room in rooms {
                    n += usize::from(room.newtor().await);
                }
                if n == 0 {
                    Err("no room goes through Tor - /route tor sends the next ones through it".into())
                } else {
                    self.say(match n {
                        1 => "new Tor circuits and onion address for 1 room".into(),
                        n => format!("new Tor circuits and onion addresses for {n} rooms"),
                    });
                    Ok(())
                }
            }
            // The lines are never echoed back: only how many there are and their transports.
            "bridges" => {
                let set = match arg {
                    "" => {
                        let (b, t) = self.client.bridges().await;
                        Ok(format!("bridges: {b} \u{b7} transport programs {t}"))
                    }
                    "none" | "off" => self.client.set_bridges("").await.map(|b| format!("bridges: {b}")),
                    lines => self
                        .client
                        .set_bridges(lines)
                        .await
                        .map(|b| format!("bridges: {b} - Tor reaches the Tor network only through them")),
                };
                set.map(|text| self.say(text)).map_err(|e| format!("bridges: {e}"))
            }
            "transports" => {
                let dir = (!matches!(arg, "" | "default")).then(|| std::path::PathBuf::from(arg));
                let set = self.client.set_transports(dir).await;
                set.map(|t| self.say(format!("transport programs {t}")))
                    .map_err(|e| format!("transport programs: {e}"))
            }
            "identity" | "sign" => self.identity_command(arg),
            "verified" => self.verified_command(arg),
            "call" => self.call_command(arg),
            "exportkey" if arg.is_empty() => {
                self.begin_export_browse(crate::browser::Back::Chat);
                Ok(())
            }
            "exportkey" => self.export_command(arg),
            "colour" | "color" => match Colour::parse(arg) {
                Some(c) => {
                    self.colour = Some(c);
                    self.setting_changed("colour", arg);
                    for r in &self.rooms {
                        if let Some(room) = r.room() {
                            let _ = room.command(Command::SetColour { colour: c }).await;
                        }
                    }
                    Ok(())
                }
                None => Err("a colour: red, orange, yellow, green, teal, cyan, blue, indigo, purple, pink, brown, gray, or #rrggbb".into()),
            },
            _ => self.room_command(name, arg).await,
        };
        if let Err(e) = result {
            self.fail(e);
        }
    }

    /// Commands for the room on screen.
    async fn room_command(&mut self, name: &str, arg: &str) -> Result<(), String> {
        let (id, room) = self.open_room()?;
        let view = self.room().expect("open");
        match name {
            "msg" | "dm" => {
                let (peer, text) = view.peer_and_text(arg)?;
                let r = room.dm(peer.id, &text).await;
                self.sent(id, r);
            }
            "reply" | "re" => {
                let (peer, text) = view.peer_and_text(arg)?;
                let mid = view
                    .entries
                    .iter()
                    .rev()
                    .find_map(|e| match &e.kind {
                        EntryKind::Msg(m) if m.from == peer.id && !m.direct => Some(m.mid.clone()),
                        _ => None,
                    })
                    .ok_or_else(|| format!("nothing from {} to reply to yet", peer.name))?;
                let r = room.reply(&mid, &text).await;
                self.sent(id, r);
            }
            // /verify NICK ok (or no) answers at once; /verify NICK shows the codes to compare.
            "verify" | "v" if arg.ends_with(" ok") || arg.ends_with(" no") => {
                let (who, answer) = arg.rsplit_once(' ').expect("ends with a word");
                let peer = view.find_peer(who.trim())?;
                if peer.code.is_none() {
                    return Err(format!("no code with {} yet - wait for the handshake to finish", peer.name));
                }
                self.verify(id, peer.id, answer == "ok").await;
            }
            "verify" | "v" => {
                let peer = view.find_peer(arg)?;
                if peer.code.is_none() {
                    return Err(format!("no code with {} yet - wait for the handshake to finish", peer.name));
                }
                self.modal = Some(Modal::Verify { room: id, peer });
            }
            "ignore" if arg.is_empty() => {
                let here: Vec<&str> = view.peers.iter().filter(|p| p.ignored).map(|p| p.name.as_str()).collect();
                let everywhere: Vec<String> = self
                    .client
                    .trust()
                    .lock()
                    .map(|t| t.ignored().iter().map(|e| e.nick.clone()).collect())
                    .unwrap_or_default();
                let mut lines = vec![if here.is_empty() {
                    "nobody online here is ignored - /ignore NICK hides what someone says".to_string()
                } else {
                    format!("ignored here: {}", here.join(", "))
                }];
                if !everywhere.is_empty() {
                    lines.push(format!("signing keys ignored in every room: {}", everywhere.join(", ")));
                }
                let r = self.room_mut().expect("open");
                lines.into_iter().for_each(|l| r.note(Level::Note, l));
            }
            "ignore" => {
                let (who, on) = match arg.strip_suffix(" off") {
                    Some(w) => (w, false),
                    None => (arg, true),
                };
                let peer = view.find_peer(who)?;
                room.command(Command::Ignore { peer: peer.id, on })
                    .await
                    .map_err(|e| e.to_string())?;
            }
            "invite" => {
                let invite = view.info.as_ref().and_then(|i| i.invite.clone()).ok_or("this room has no invite")?;
                self.copy_for_a_while(&invite, true);
                self.room_mut()
                    .expect("open")
                    .note(Level::Note, format!("invite (copied): {invite}"));
                // And as a QR code, for a phone to scan.
                if let Some(qr) = chat_core::protocol::qr::encode(&invite) {
                    self.modal = Some(Modal::Qr {
                        invite,
                        qr,
                        note: "copied - any key closes this".into(),
                    });
                }
            }
            "timer" => {
                let seconds = chat_core::protocol::names::parse_timer(arg)
                    .ok_or("usage: /timer 10m (or 2h, 1d - a minute to a week), or /timer off")?;
                room.command(Command::SetTimer { seconds }).await.map_err(|e| e.to_string())?;
            }
            "peers" | "who" => {
                let lines: Vec<String> = if view.peers.is_empty() {
                    vec!["nobody else is here yet".into()]
                } else {
                    view.peers
                        .iter()
                        .map(|p| {
                            format!(
                                "{} - code {}",
                                p.name,
                                p.code.as_ref().map_or("not yet".into(), |c| c.words.clone())
                            )
                        })
                        .collect()
                };
                let r = self.room_mut().expect("open");
                lines.into_iter().for_each(|l| r.note(Level::Note, l));
            }
            "net" => {
                room.command(Command::NetReport).await.map_err(|e| e.to_string())?;
            }
            "port" => {
                let want = match arg {
                    "" => None,
                    a => Some(
                        a.parse::<u16>()
                            .map_err(|_| format!("not a port: {a} - /port N (0 picks a free one)"))?,
                    ),
                };
                let got = room.port(want).await?;
                self.say(match want {
                    None => format!("UDP port {got} - /port N moves the room to another (0 picks a free one)"),
                    Some(_) => format!("now on UDP port {got}"),
                });
            }
            "history" => return self.history_command(arg),
            "send" | "offer" => {
                let (asis, path) = match arg.strip_prefix("asis ") {
                    _ if arg == "asis" => (true, ""),
                    Some(p) => (true, p.trim()),
                    None => (false, arg),
                };
                // Without a path, a browser to pick the file in.
                if path.is_empty() {
                    self.begin_send_browse(asis, crate::browser::Back::Chat);
                    return Ok(());
                }
                room.offer(path, asis).await.map_err(|e| e.to_string())?;
            }
            "files" => self.begin_files(),
            "saveto" => {
                let mut words = arg.split_whitespace();
                let num = words
                    .next()
                    .and_then(|w| w.parse::<u32>().ok())
                    .ok_or("usage: /saveto N [anyway] - N is the number in the offer")?;
                let anyway = words.next() == Some("anyway");
                let f = view
                    .files
                    .iter()
                    .find(|f| f.num == num)
                    .ok_or_else(|| format!("there's no file {num} - /files lists them"))?;
                if f.mine {
                    return Err(format!("file {num} is yours"));
                }
                self.begin_save_browse(num, anyway, crate::browser::Back::Chat);
            }
            "download" | "dl" | "save" => {
                // /download [N] [anyway] [FOLDER]: the newest not saved or coming without N.
                let mut rest = arg.trim_start();
                let first = rest.split_whitespace().next().unwrap_or("");
                let num = match first.parse::<u32>().ok() {
                    Some(n) => {
                        rest = rest[first.len()..].trim_start();
                        n
                    }
                    None => view
                        .files
                        .iter()
                        .filter(|f| {
                            !f.mine && f.saved.is_none() && !matches!(f.state, FileState::Fetching { .. } | FileState::Queued { .. })
                        })
                        .map(|f| f.num)
                        .max()
                        .ok_or("no file to download - /files lists what's been offered")?,
                };
                let anyway = rest == "anyway" || rest.starts_with("anyway ");
                if anyway {
                    rest = rest["anyway".len()..].trim_start();
                }
                let dir = (!rest.is_empty()).then_some(rest);
                room.fetch(num, false, anyway, dir).await.map_err(|e| e.to_string())?;
            }
            "show" => {
                let mut words = arg.split_whitespace();
                let num = words
                    .next()
                    .and_then(|w| w.parse::<u32>().ok())
                    .or_else(|| view.files.iter().filter(|f| f.image).map(|f| f.num).max())
                    .ok_or("usage: /show N - shows picture N here")?;
                let anyway = words.next() == Some("anyway");
                if view.pictures.contains_key(&num) {
                    self.room_mut().expect("open").hidden.remove(&num);
                } else {
                    room.fetch(num, true, anyway, None).await.map_err(|e| e.to_string())?;
                }
            }
            "hide" => {
                let num: u32 = arg.parse().map_err(|_| "usage: /hide N - hides picture N again")?;
                self.room_mut().expect("open").hidden.insert(num);
            }
            "move" => match arg {
                "yes" => {
                    if let Some((new_room, events)) = room.answer_move(true).await.map_err(|e| e.to_string())? {
                        self.adopt_moved(new_room, events);
                    }
                }
                "no" => {
                    room.answer_move(false).await.map_err(|e| e.to_string())?;
                }
                // With a request to move waiting, its box again.
                "" if view.move_ask.is_some() => self.show_move_ask(false),
                "" => {
                    let lines: Vec<String> = match &view.move_ask {
                        Some(_) => Vec::new(),
                        None => match room.command(Command::Move { answer: None }).await {
                            Ok(Outcome::MovePlan(p)) if p.coming.is_empty() && p.left.is_empty() => {
                                vec!["nobody else is here to move with".into()]
                            }
                            Ok(Outcome::MovePlan(p)) if p.coming.is_empty() => {
                                vec!["nobody can move with you yet - compare verify codes with them first (/verify NAME)".into()]
                            }
                            Ok(Outcome::MovePlan(p)) => {
                                let left = if p.left.is_empty() {
                                    "Everyone here is asked along, so this only gives the room a new id and password, as \
                                     after a leak."
                                        .to_string()
                                } else {
                                    format!(
                                        "Left behind: {}. Nothing tells them where you went: they keep this room, and \
                                         everything said in it so far.",
                                        chat_core::protocol::names::list(&p.left)
                                    )
                                };
                                self.modal = Some(Modal::Ask {
                                    title: "MOVE",
                                    paras: vec![
                                        format!("Move to a new room with {}?", chat_core::protocol::names::list(&p.coming)),
                                        left,
                                        "chat makes up the new room's id and password, and sends them only to those asked \
                                         along, over their encrypted sessions. Each is asked first, and comes if they say \
                                         yes. Codes you compared here count there."
                                            .into(),
                                    ],
                                    keys: "y move \u{b7} n cancel",
                                    then: Ask::Move,
                                });
                                Vec::new()
                            }
                            Ok(_) => Vec::new(),
                            Err(e) => return Err(e.to_string()),
                        },
                    };
                    let r = self.room_mut().expect("open");
                    lines.into_iter().for_each(|l| r.note(Level::Note, l));
                }
                _ => return Err("usage: /move, then /move yes or /move no".into()),
            },
            "cancel" => {
                let num: u32 = arg
                    .parse()
                    .map_err(|_| "usage: /cancel N - stops fetching file N, or stops offering one of yours")?;
                room.cancel(num).await.map_err(|e| e.to_string())?;
            }
            "leave" | "part" => {
                room.leave().await;
                let r = self.room_mut().expect("open");
                r.state = RoomState::Closed;
                let i = self.current;
                self.rooms.remove(i);
                self.current = self.current.min(self.rooms.len().saturating_sub(1));
                self.say("left the room");
            }
            other => return Err(format!("no command /{other} - /help lists them")),
        }
        Ok(())
    }

    /// The QUIT box: what quitting does to the rooms, then what would be lost.
    pub fn quit_paras(&self) -> Vec<String> {
        let open: Vec<&RoomView> = self.rooms.iter().filter(|r| r.room().is_some()).collect();
        let n = open.len();
        // As shutdown and remember_open keep them: calls find the day's room again instead.
        let kept = match &self.save {
            Some(_) if self.settings.on("reopen") => open.iter().filter(|r| r.call.is_none() && r.info.is_some()).count(),
            _ => 0,
        };
        let online: usize = open.iter().map(|r| r.peers.len()).sum();
        let what = if n == 0 {
            "No rooms are open.".to_string()
        } else if let (true, Some(save)) = (kept > 0, &self.save) {
            let which = if kept < n {
                format!("{kept} of its {n} rooms")
            } else if kept > 1 {
                format!("its {kept} rooms")
            } else {
                "its room".to_string()
            };
            format!(
                "Quitting closes chat but keeps {which} in the save {}: {} again as chat starts, and peers see you go \
                 offline until then.{} Keys are wiped from memory.",
                save.name(),
                if kept == 1 { "it opens" } else { "they open" },
                if kept < n { " Calls say bye." } else { "" }
            )
        } else {
            let which = if n == 1 { open[0].label.clone() } else { format!("{n} rooms") };
            let peers = match online {
                0 => "nobody else".to_string(),
                1 => "1 peer".to_string(),
                p => format!("{p} peers"),
            };
            format!(
                "Quitting leaves {which}, with {peers} online: {} {}, and its keys are wiped from memory.",
                if n == 1 { "it" } else { "each" },
                if online > 0 { "says bye, then closes" } else { "closes" }
            )
        };
        let mut paras = vec![what];
        let downloads = open
            .iter()
            .flat_map(|r| &r.files)
            .filter(|f| matches!(f.state, FileState::Fetching { .. } | FileState::Queued { .. }))
            .count();
        let mut lost = Vec::new();
        match downloads {
            0 => {}
            1 => lost.push("\u{2022} A file that's still downloading stops, and what's come of it is deleted.".to_string()),
            d => lost.push(format!(
                "\u{2022} {d} files that are still downloading stop, and what's come of them is deleted."
            )),
        }
        if chat_core::net::update::view().running {
            lost.push("\u{2022} An update is still running, and won't be installed.".into());
        }
        if !lost.is_empty() {
            paras.push(lost.join("\n"));
        }
        paras
    }

    /// Leaves every room, telling everyone, within a few seconds at most.
    pub async fn shutdown(&mut self) {
        if !self.panicked || self.settings.on("panichistory") {
            let ids: Vec<usize> = self.rooms.iter().map(|r| r.id).collect();
            for id in ids {
                self.write_history(id, true);
            }
        }
        let rooms: Vec<Room> = self.rooms.iter().filter_map(|r| r.room().cloned()).collect();
        if !self.panicked {
            self.keep_tor_state();
        }
        // Rooms opened again next time are gone offline from, not left.
        if self.settings.on("reopen") && !self.quit_all {
            if !self.panicked {
                self.remember_open();
            }
            for r in &rooms {
                let _ = r.command(Command::SetComingBack { on: true }).await;
            }
        }
        let leaving = futures_util::future::join_all(rooms.iter().map(|r| r.leave()));
        let _ = tokio::time::timeout(Duration::from_secs(3), leaving).await;
    }
}

pub fn route_name(m: RouteMode) -> &'static str {
    match m {
        RouteMode::Tor => "Tor",
        RouteMode::Direct => "direct",
    }
}

/// OSC 52: the terminal puts it on the clipboard, where it supports that (most do).
pub(crate) fn copy_to_clipboard(text: &str) {
    let seq = format!("\x1b]52;c;{}\x07", chat_core::protocol::base64::encode(text.as_bytes()));
    let mut out = std::io::stdout();
    let _ = out.write_all(seq.as_bytes()).and_then(|_| out.flush());
}

/// What /files says: each file, who offered it, and how it's going.
pub(crate) fn files_report(files: &[FileInfo]) -> Vec<String> {
    if files.is_empty() {
        return vec!["no files yet - /send PATH offers one".into()];
    }
    files
        .iter()
        .map(|f| {
            let desc = format!("{} ({}{})", f.name, format_size(f.size), if f.image { ", image" } else { "" });
            let state = match &f.state {
                _ if f.mine => match (&f.sending, f.sent_to.first()) {
                    (Some(s), _) => format!(
                        "sending to {}{}, {}%",
                        s.name,
                        if s.count > 1 { " and others" } else { "" },
                        s.permille / 10
                    ),
                    (None, Some(first)) => format!(
                        "sent to {first}{}{}",
                        if f.sent_count > 1 {
                            format!(" and {} others", f.sent_count - 1)
                        } else {
                            String::new()
                        },
                        if f.state == FileState::Withdrawn {
                            ", no longer offered"
                        } else {
                            ""
                        }
                    ),
                    _ if f.state == FileState::Withdrawn => "no longer offered".into(),
                    _ => "offered".into(),
                },
                FileState::Fetching { got, eta } => format!(
                    "fetching, {}% ({}), {}{}",
                    (got * 100).checked_div(f.size).unwrap_or(100),
                    format_size(*got),
                    match eta {
                        Eta::Seconds(s) => format!("{} left", format_duration(*s as f64)),
                        Eta::WaitingSender => "waiting for its sender".into(),
                        Eta::WaitingVerify => "waiting until verify codes are compared".into(),
                    },
                    if f.then_save {
                        ", saved too once it's here"
                    } else if f.then_show {
                        ", shown too once it's here"
                    } else {
                        ""
                    }
                ),
                FileState::Queued { after: Some(n) } => format!("queued, starts after file {n}"),
                FileState::Queued { after: None } => "queued, waiting for its sender".into(),
                _ if f.saved.is_some() => format!("saved to {}", f.saved.as_deref().unwrap_or_default()),
                _ if f.shown => format!("shown - /download {} saves it without fetching it again", f.num),
                FileState::Done => "shown".into(),
                FileState::Failed { why } => format!(
                    "failed{} - /{} {} tries again",
                    if why.is_empty() { String::new() } else { format!(" ({why})") },
                    if f.show { "show" } else { "download" },
                    f.num
                ),
                _ if f.image => format!("/show {n} or /download {n}", n = f.num),
                _ => format!("/download {}", f.num),
            };
            format!("file {} from {}: {desc} - {state}", f.num, f.from_name)
        })
        .collect()
}

/// A room's events to the UI, until it closes. Pictures are decoded here, off the UI's thread.
async fn forward(id: usize, mut events: RoomEvents, tx: mpsc::UnboundedSender<Msg>) {
    while let Some(e) = events.recv().await {
        let msg = match e {
            Event::Picture { num, data, .. } => {
                let t = tokio::task::spawn_blocking(move || {
                    use chat_core::protocol::picture::decode;
                    Ok((
                        decode(&data, PICTURE_W, PICTURE_H, [0, 0, 0])?,
                        decode(&data, PAGE_W, PAGE_H, [0, 0, 0])?,
                    ))
                })
                .await
                .unwrap_or_else(|_| Err("it couldn't be decoded".into()));
                Msg::Picture(id, num, t)
            }
            e => Msg::Room(id, e),
        };
        if tx.send(msg).is_err() {
            return;
        }
    }
    let _ = tx.send(Msg::Closed(id));
}
