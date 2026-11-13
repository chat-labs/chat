// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The input line's modes and the command line. INSERT types; NORMAL takes vim's keys for moving
//! about the line and the screen; COMMAND (/ on an empty line, or : or / in NORMAL) takes a
//! command, with a menu over it of what can go next: commands by name, settings and their values,
//! and what each command's arguments can be.

use crate::app::{App, Input};
use chat_core::net::settings::{self as st, PAGE};
use chat_core::{BuildState, CodeState, FileState};

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Insert,
    Normal,
    Command,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Insert => "INSERT",
            Mode::Normal => "NORMAL",
            Mode::Command => "COMMAND",
        }
    }
}

/// The command line while it's open.
#[derive(Default)]
pub struct CmdLine {
    pub input: Input,
    /// What opened it: ':' or '/'.
    pub prefix: char,
    /// Opened from INSERT, which it goes back to.
    from_insert: bool,
    /// Opened by '/' on an empty line: a line that can't be a command goes back to being text.
    as_text: bool,
    /// The menu's entry picked.
    pub sel: usize,
}

pub struct Command {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub args: &'static str,
    pub help: &'static str,
}

const fn c(name: &'static str, aliases: &'static [&'static str], args: &'static str, help: &'static str) -> Command {
    Command { name, aliases, args, help }
}

/// Every command, in the menu's order: the screen's, then the room's.
pub const COMMANDS: &[Command] = &[
    c("help", &["h", "?"], "", "list all commands and keybinds (F1)"),
    c("new", &[], "", "create a room (Ctrl+N)"),
    c("join", &["j"], "", "join a room by id, or one you kept (Ctrl+J)"),
    c(
        "keep",
        &[],
        "[LABEL | forget]",
        "keep this room in the open save, to join it again from Ctrl+J; forget lets it go",
    ),
    c(
        "call",
        &[],
        "NICK",
        "open the room only you and a verified key can work out; they /call you too, and what you send while they're away waits for them",
    ),
    c("quitall", &["qa", "qall"], "", "leave every room and quit, kept ones too"),
    c("lock", &[], "", "lock the screen until the save's passphrase, or a PIN, unlocks it"),
    c("set", &[], "[NAME [VALUE]]", "change a setting; alone, opens them all (Ctrl+S)"),
    c("copyid", &[], "", "copy this room's id to the clipboard"),
    c(
        "invite",
        &[],
        "",
        "copy this room's id and password as one invite, which Ctrl+J takes",
    ),
    c(
        "move",
        &[],
        "[yes|no]",
        "move to a new room with the peers whose codes you compared, leaving the rest behind",
    ),
    c(
        "newtor",
        &[],
        "",
        "new Tor circuits and onion addresses for every room that goes through Tor",
    ),
    c(
        "install",
        &[],
        "[NAME]",
        "save your settings and signing key on this computer (NAME: as a save of that name)",
    ),
    c(
        "save",
        &[],
        "",
        "save what's in use now to the open save, after asking (or /install it)",
    ),
    c("uninstall", &[], "[NAME]", "delete what /install saved (NAME: that save)"),
    c(
        "exportkey",
        &[],
        "",
        "write your signing key, unencrypted, to a new file in a folder you pick",
    ),
    c(
        "history",
        &[],
        "[forget [all]]",
        "whether this room's history is kept; forget deletes it (all: every room's)",
    ),
    c("changelog", &["news"], "", "show changelog"),
    c("update", &[], "", "install the latest release from GitHub"),
    c("files", &[], "", "the files offered here: show, save or stop them (Ctrl+F)"),
    c("show", &[], "N [anyway]", "show picture N in the chat, where it was offered"),
    c("hide", &[], "N", "tuck picture N away again"),
    c("saveto", &[], "N [anyway]", "pick a folder in a file browser and save file N there"),
    c(
        "open",
        &[],
        "[N | LINK]",
        "open a link from the chat in your browser, or copy it; N counts from the newest (o)",
    ),
    c("peers", &["who"], "", "who is online, with verify codes and builds"),
    c("verify", &["v"], "NICK [ok|no]", "compare a peer's verify code; ok once it matches"),
    c(
        "verified",
        &[],
        "[forget NICK]",
        "list the signing keys you verified, or remove one",
    ),
    c(
        "ignore",
        &[],
        "[NICK [off]]",
        "hide what a peer says, here and wherever they sign with that key; off shows it again",
    ),
    c(
        "msg",
        &["dm"],
        "NICK TEXT",
        "a direct message to one peer you're connected to; nobody else gets it",
    ),
    c("reply", &["re"], "NICK TEXT", "answer NICK's last message, quoting the start of it"),
    c(
        "timer",
        &[],
        "[off|10m|2h|1d]",
        "messages here go from every screen that keeps to it after this long; alone, says which",
    ),
    c("net", &[], "", "network report and diagnosis"),
    c("port", &[], "[N]", "show or change this room's udp port"),
    c(
        "send",
        &["offer"],
        "[asis] [PATH]",
        "offer a file; nobody gets it unless they fetch it, and a picture goes cleaned unless asis",
    ),
    c(
        "download",
        &["dl"],
        "[N] [anyway] [FOLDER]",
        "save file N (the newest if left out) in Downloads or FOLDER",
    ),
    c("cancel", &[], "N", "stop fetching or queueing file N, or stop offering yours"),
    c("leave", &["part"], "", "leave this room"),
    c("nick", &["name"], "NAME", "your name in every room (/set nick)"),
    c("colour", &["color"], "NAME|#RRGGBB", "your colour in every room (/set colour)"),
    c(
        "identity",
        &["sign"],
        "[age|pgp [nonick] | new age|pgp | file PATH | copy | off]",
        "your signing key (/set sign)",
    ),
    c(
        "route",
        &[],
        "[tor|direct]",
        "how rooms you open from now on reach peers (/set routing)",
    ),
    c("relays", &[], "[off|fallback|always]", "the Nostr relays (/set nostr)"),
    c("bridges", &[], "LINE; LINE", "Tor bridges, where Tor is blocked (/set bridges)"),
    c(
        "transports",
        &[],
        "FOLDER",
        "where the bridges' transport programs are (/set transports)",
    ),
    c("fast", &[], "[on|off]", "faster transfers, visible as a burst (/set fastfiles)"),
    c("limit", &[], "SIZE", "the size over which a download needs anyway (/set filelimit)"),
    c("noise", &[], "[on|off]", "noise in pictures sent cleaned (/set noise)"),
    c("downloads", &[], "FOLDER", "where downloads are saved"),
];

/// The command a word names: its name, or one of its aliases.
pub fn find(word: &str) -> Option<&'static Command> {
    COMMANDS.iter().find(|c| c.name == word || c.aliases.contains(&word))
}

/// Whether a command's name or alias starts with word (or, with whole, is word).
fn command_word(word: &str, whole: bool) -> bool {
    COMMANDS.iter().any(|c| {
        std::iter::once(c.name)
            .chain(c.aliases.iter().copied())
            .any(|n| if whole { n == word } else { n.starts_with(word) })
    })
}

/// What a command's arguments can be, in order, for the menu.
#[derive(Clone, Copy)]
enum Arg {
    Nick,
    Word,
    File,
    Path,
    Folder,
    Save,
    Trusted,
    Contact,
}

/// Enter fills it in only once some of it is typed.
const TYPED: u8 = 1;
/// TYPED, and it can be left out with the next one in its place, so that's listed too.
const SKIP: u8 = 2;
/// Enter never fills it in: it's typed in full or picked in the menu.
const PICK: u8 = 4;

const COMMAND_ARGS: &[(&str, &[(Arg, u8)])] = &[
    ("verify", &[(Arg::Nick, 0), (Arg::Word, TYPED)]),
    ("ignore", &[(Arg::Nick, 0), (Arg::Word, TYPED)]),
    ("msg", &[(Arg::Nick, 0), (Arg::Word, TYPED)]),
    ("reply", &[(Arg::Nick, 0), (Arg::Word, TYPED)]),
    ("verified", &[(Arg::Word, TYPED), (Arg::Trusted, PICK)]),
    ("send", &[(Arg::Word, SKIP), (Arg::Path, PICK)]),
    ("download", &[(Arg::File, SKIP), (Arg::Word, SKIP), (Arg::Folder, PICK)]),
    ("cancel", &[(Arg::File, TYPED)]),
    ("show", &[(Arg::File, 0), (Arg::Word, TYPED)]),
    ("hide", &[(Arg::File, 0)]),
    ("saveto", &[(Arg::File, 0), (Arg::Word, TYPED)]),
    ("install", &[(Arg::Save, TYPED)]),
    ("uninstall", &[(Arg::Save, TYPED)]),
    ("keep", &[(Arg::Word, TYPED)]),
    ("call", &[(Arg::Contact, 0)]),
];

const ARG_WORDS: &[(&str, &str, &str)] = &[
    ("verify", "ok", "their code is the same - what you send reaches them"),
    ("verify", "no", "their code differs - nothing you send reaches them"),
    ("verified", "forget", "remove a verified key"),
    ("ignore", "off", "show what they say again"),
    (
        "send",
        "asis",
        "as it is: a picture keeps what it holds about where, when and with what it was made",
    ),
    ("show", "anyway", "even if it's over your file size limit"),
    ("saveto", "anyway", "even if it's over your file size limit"),
    ("download", "anyway", "even if it's over your file size limit"),
    ("keep", "forget", "stop keeping this room in the save"),
];

/// An entry in the menu: the line it makes, what it shows (a name, the arguments it takes, and
/// help), the heading it's under, and whether Enter leaves it alone until it's picked.
#[derive(Default, Clone)]
pub struct Suggestion {
    pub line: String,
    pub name: String,
    pub args: String,
    pub help: String,
    pub group: &'static str,
    pub no_default: bool,
}

/// The most entries the menu lists.
const SUGGEST_MAX: usize = 64;

fn has_prefix_nocase(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() && s.is_char_boundary(prefix.len()) && s[..prefix.len()].eq_ignore_ascii_case(prefix)
}

impl App {
    /// The menu over the COMMAND line: commands by name; after "set ", the settings with their
    /// values now; after "set NAME ", the values it takes; after other commands, what their
    /// arguments can be.
    pub fn suggestions(&self, typed: &str) -> Vec<Suggestion> {
        let mut out = Vec::new();
        if let Some((word, rest)) = typed.split_once(' ')
            && let Some(cmd) = find(word)
            && let Some((_, args)) = COMMAND_ARGS.iter().find(|(n, _)| *n == cmd.name)
        {
            self.arg_suggest(cmd, typed, args, rest, &mut out);
            return out;
        }
        if let Some(key) = typed.strip_prefix("set ") {
            if let Some((name, v)) = key.split_once(' ') {
                let name = if name == "color" { "colour" } else { name };
                let Some(r) = PAGE.iter().find(|r| r.name == name) else {
                    return out;
                };
                let values: Vec<&str> = match r.name {
                    "sign" => vec!["off", "age", "pgp", "age-nonick", "pgp-nonick"],
                    n => st::steps(n).unwrap_or_default(),
                };
                let now = self.settings.get(r.name);
                for value in values.into_iter().filter(|x| x.starts_with(v)) {
                    out.push(Suggestion {
                        line: format!("set {} {value}", r.name),
                        name: value.into(),
                        help: format!("{}{}", r.label, if value == now { " \u{b7} now" } else { "" }),
                        group: "settings",
                        ..Default::default()
                    });
                }
                return out;
            }
            for r in PAGE.iter().filter(|r| r.name.starts_with(key)) {
                let takes = st::steps(r.name).is_some() || matches!(st::row_kind(r.name), st::RowKind::Text);
                out.push(Suggestion {
                    line: format!("set {}{}", r.name, if takes { " " } else { "" }),
                    name: format!("set {}", r.name),
                    args: r.values.into(),
                    help: format!("{} \u{b7} {}", r.label, self.settings.get(r.name)),
                    group: "settings",
                    ..Default::default()
                });
            }
            return out;
        }
        if typed.contains(' ') {
            return out;
        }
        for cmd in COMMANDS.iter().filter(|c| c.name.starts_with(typed)) {
            out.push(Suggestion {
                line: format!("{}{}", cmd.name, if cmd.args.is_empty() { "" } else { " " }),
                name: cmd.name.into(),
                args: cmd.args.into(),
                help: cmd.help.into(),
                group: "commands",
                ..Default::default()
            });
        }
        out.truncate(SUGGEST_MAX);
        out
    }

    /// The menu for `args[0]`, with rest typed for it: what it can be, then what can follow once
    /// rest holds a whole one, then (if it can be left out) what can come in its place.
    fn arg_suggest(&self, cmd: &Command, typed: &str, args: &[(Arg, u8)], rest: &str, out: &mut Vec<Suggestion>) {
        let Some(&(arg, flags)) = args.first() else { return };
        let after = if args.len() > 1 { " " } else { "" };
        let at = typed.len() - rest.len();
        let item = |text: &str, name: &str, help: String, group: &'static str| Suggestion {
            line: format!("{}{text}{after}", &typed[..at]),
            name: name.into(),
            help,
            group,
            ..Default::default()
        };
        let room = self.room();
        let before = out.len();
        match arg {
            Arg::Nick => {
                let mut peers: Vec<_> = room.map_or(Vec::new(), |r| {
                    r.peers.iter().filter(|p| has_prefix_nocase(&p.nick, rest)).collect()
                });
                // An exact match first, so Enter on "id" doesn't run it as "ida"; the rest by nick.
                peers.sort_by_key(|p| (p.nick.len() != rest.len(), p.nick.to_lowercase()));
                for p in peers {
                    let state = match (&p.identity, p.code_state) {
                        (None, _) => "unsigned",
                        (_, CodeState::Compare) => "code to compare",
                        (_, CodeState::Compared) => "code compared",
                        (_, CodeState::Differs) => "code differs",
                        (_, CodeState::KeyChanged) => "key changed",
                        (_, CodeState::Nothing) => "signed",
                    };
                    let modified = if p.build == BuildState::Modified {
                        " \u{b7} modified client"
                    } else {
                        ""
                    };
                    out.push(item(&p.nick, &p.name, format!("{state}{modified}"), "peers"));
                }
            }
            Arg::Word => {
                for (_, w, help) in ARG_WORDS.iter().filter(|(c, w, _)| *c == cmd.name && w.starts_with(rest)) {
                    out.push(item(w, w, help.to_string(), cmd.name_static()));
                }
            }
            Arg::File => {
                let mut files: Vec<_> = room.map_or(Vec::new(), |r| {
                    r.files
                        .iter()
                        .filter(|f| f.num.to_string().starts_with(rest))
                        .filter(|f| match cmd.name {
                            "show" => f.image && !(r.pictures.contains_key(&f.num) && !r.hidden.contains(&f.num)),
                            "hide" => r.pictures.contains_key(&f.num) && !r.hidden.contains(&f.num),
                            "cancel" if f.mine => true,
                            "cancel" => matches!(f.state, FileState::Fetching { .. } | FileState::Queued { .. }),
                            _ => !f.mine,
                        })
                        .collect()
                });
                // The one with the number typed first, then the newest.
                let exact: u32 = rest.parse().unwrap_or(0);
                files.sort_by_key(|f| (f.num != exact, std::cmp::Reverse(f.num)));
                for f in files {
                    let n = f.num.to_string();
                    let state = if f.mine {
                        " \u{b7} yours"
                    } else if matches!(f.state, FileState::Fetching { .. }) {
                        " \u{b7} fetching"
                    } else if matches!(f.state, FileState::Queued { .. }) {
                        " \u{b7} queued"
                    } else if f.saved.is_some() {
                        " \u{b7} saved"
                    } else {
                        ""
                    };
                    let help = format!("{} \u{b7} {}{state}", f.name, chat_core::protocol::files::format_size(f.size));
                    out.push(item(&n, &n, help, "files"));
                }
            }
            Arg::Path | Arg::Folder => {
                // The files and folders (or only folders) in the folder typed so far; hidden ones
                // once a '.' is typed.
                let (dir, base) = match rest.rfind('/') {
                    Some(i) => (&rest[..=i], &rest[i + 1..]),
                    None => ("", rest),
                };
                let path = match dir {
                    "" => ".".to_string(),
                    d => chat_core::net::files::typed_path_here(d),
                };
                let mut entries: Vec<(String, bool)> = std::fs::read_dir(path)
                    .map(|d| {
                        d.flatten()
                            .filter_map(|e| {
                                let name = e.file_name().into_string().ok()?;
                                let is_dir = std::fs::metadata(e.path()).is_ok_and(|m| m.is_dir());
                                Some((name, is_dir))
                            })
                            .filter(|(n, d)| {
                                !n.chars().any(char::is_control)
                                    && (!matches!(arg, Arg::Folder) || *d)
                                    && (!n.starts_with('.') || base.starts_with('.'))
                                    && n.starts_with(base)
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.to_lowercase().cmp(&b.0.to_lowercase())));
                let group = if matches!(arg, Arg::Folder) { "folders" } else { "your files" };
                for (name, is_dir) in entries.into_iter().take(SUGGEST_MAX) {
                    let shown = if is_dir { format!("{name}/") } else { name };
                    let mut s = item(&shown, &shown, if is_dir { "folder".into() } else { String::new() }, group);
                    s.line = format!("{}{dir}{shown}", &typed[..at]);
                    out.push(s);
                }
            }
            Arg::Save => {
                for s in self
                    .saves
                    .as_ref()
                    .map_or(Vec::new(), |v| v.list())
                    .into_iter()
                    .filter(|s| s.name.starts_with(rest))
                {
                    let open = if self.save.as_ref().is_some_and(|o| o.name() == s.name) {
                        " \u{b7} open"
                    } else {
                        ""
                    };
                    let when = s
                        .modified
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map_or(String::new(), |d| format!("saved {}", chat_core::net::history::stamp(d.as_secs())));
                    out.push(item(&s.name, &s.name, format!("{when}{open}"), "saves"));
                }
            }
            Arg::Trusted | Arg::Contact => {
                let verified = self.client.trust().lock().map(|t| t.verified().to_vec()).unwrap_or_default();
                let mut seen: Vec<&str> = Vec::new();
                for e in &verified {
                    if seen.contains(&e.nick.as_str()) || !has_prefix_nocase(&e.nick, rest) {
                        continue;
                    }
                    seen.push(&e.nick);
                    let keys = verified.iter().filter(|o| o.nick == e.nick).count();
                    out.push(item(
                        &e.nick,
                        &e.nick,
                        format!("{keys} verified key{}", if keys == 1 { "" } else { "s" }),
                        "verified",
                    ));
                }
                if matches!(arg, Arg::Trusted) && !verified.is_empty() && "all".starts_with(rest) {
                    out.push(item("all", "all", "every verified key".into(), "verified"));
                }
            }
        }
        if out.len() > before {
            let no_default = flags & PICK != 0 || (flags & (TYPED | SKIP) != 0 && rest.is_empty());
            out[before..].iter_mut().for_each(|s| s.no_default = no_default);
            out.truncate(SUGGEST_MAX);
            return;
        }
        if let Some(next) = self.arg_end(cmd, arg, rest) {
            self.arg_suggest(cmd, typed, &args[1..], next, out);
            if out.len() > before {
                return;
            }
        }
        if flags & SKIP != 0 {
            self.arg_suggest(cmd, typed, &args[1..], rest, out);
        }
    }

    /// Where the argument after a whole one of this kind at the start of rest begins, past its
    /// space. Nicks can have spaces, so it's after the longest one online there.
    fn arg_end<'a>(&self, cmd: &Command, arg: Arg, rest: &'a str) -> Option<&'a str> {
        let n = match arg {
            Arg::File => rest.bytes().take_while(u8::is_ascii_digit).count(),
            Arg::Word => ARG_WORDS
                .iter()
                .filter(|(c, w, _)| *c == cmd.name && rest.starts_with(w))
                .map(|(_, w, _)| w.len())
                .max()
                .unwrap_or(0),
            Arg::Nick => self.room().map_or(0, |r| {
                r.peers
                    .iter()
                    .filter(|p| has_prefix_nocase(rest, &p.nick) && rest.as_bytes().get(p.nick.len()) == Some(&b' '))
                    .map(|p| p.nick.len())
                    .max()
                    .unwrap_or(0)
            }),
            _ => 0,
        };
        (n > 0 && rest.as_bytes().get(n) == Some(&b' ')).then(|| &rest[n + 1..])
    }

    /// The menu's entry picked, if there's one.
    pub fn suggestion(&self) -> Option<Suggestion> {
        let list = self.suggestions(&self.cmdline.input.text());
        let sel = self.cmdline.sel.min(list.len().checked_sub(1)?);
        list.into_iter().nth(sel)
    }

    /// What Enter (or the faint rest of the line) would complete the line to.
    pub fn completion(&self) -> Option<Suggestion> {
        let typed = self.cmdline.input.text();
        let s = self.suggestion()?;
        (s.line.len() > typed.len() && s.line.starts_with(&typed) && (!s.no_default || self.cmdline.sel > 0)).then_some(s)
    }

    /// Opens the command line. A '/' line can only turn back into text if it started on an empty
    /// line, so a draft isn't changed.
    pub(crate) fn enter_command(&mut self, prefix: char) {
        self.cmdline = CmdLine {
            prefix,
            from_insert: self.mode == Mode::Insert,
            as_text: prefix == '/' && self.input.chars.is_empty(),
            ..Default::default()
        };
        self.mode = Mode::Command;
    }

    pub(crate) fn end_command(&mut self) {
        let back = self.cmdline.from_insert;
        self.cmdline = CmdLine::default();
        self.mode = if back { Mode::Insert } else { Mode::Normal };
        self.input.cursor = self.input.cursor.min(self.input.chars.len());
    }

    /// The command line as a message that starts with '/'.
    fn command_to_text(&mut self) {
        let text = format!("/{}", self.cmdline.input.text());
        self.cmdline = CmdLine::default();
        self.mode = Mode::Insert;
        self.input.set(&text);
    }

    /// Whether the COMMAND line could still be a command: its first word starts a command's name
    /// or alias, or, once a space follows it, is one.
    fn could_be_command(&self) -> bool {
        let text = self.cmdline.input.text();
        match text.split_once(' ') {
            Some((w, _)) => command_word(w, true),
            None => command_word(&text, false),
        }
    }

    /// COMMAND takes every key; Enter runs the line, or what the menu would complete it to.
    pub(crate) async fn command_key(&mut self, k: crossterm::event::KeyEvent) {
        use crossterm::event::{KeyCode, KeyModifiers};
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        let line = &mut self.cmdline;
        match k.code {
            // A second '/' straight after the first: a message that starts with '/'.
            KeyCode::Char('/') if !ctrl && line.input.chars.is_empty() && line.as_text => self.command_to_text(),
            KeyCode::Char(ch) if !ctrl => {
                line.input.chars.push(ch);
                line.input.cursor = line.input.chars.len();
                line.sel = 0;
                // Opened from typing, a line that can't be a command goes back to being text.
                if self.cmdline.as_text && !self.could_be_command() {
                    self.command_to_text();
                }
            }
            KeyCode::Tab => {
                if let Some(s) = self.suggestion() {
                    self.cmdline.input.set(&s.line);
                    self.cmdline.sel = 0;
                }
            }
            KeyCode::Up => line.sel = line.sel.saturating_sub(1),
            KeyCode::Down => {
                let n = self.suggestions(&self.cmdline.input.text()).len();
                if self.cmdline.sel + 1 < n {
                    self.cmdline.sel += 1;
                }
            }
            KeyCode::Backspace if line.input.chars.is_empty() => self.end_command(),
            KeyCode::Backspace => {
                line.input.chars.pop();
                line.input.cursor = line.input.chars.len();
                line.sel = 0;
            }
            KeyCode::Char('w' | 'u') if ctrl => {
                line.input.cursor = line.input.chars.len();
                line.input.edit(&k);
                line.sel = 0;
            }
            KeyCode::Esc => self.end_command(),
            KeyCode::Enter => {
                let mut cmd = self.cmdline.input.text();
                // Enter on a line the menu would complete runs what the menu has picked, so "se"
                // runs "set", as the menu shows.
                if (!cmd.is_empty() || self.cmdline.sel > 0)
                    && let Some(s) = self.completion()
                {
                    cmd = s.line;
                }
                // Completing an argument leaves a space for the next one, which "verify NICK " would
                // take as part of the nick.
                let cmd = cmd.trim_end().to_string();
                // Opened by typing '/', a line that turns out not to be a command is the start of a
                // message: it goes back in the input as text, for Enter to send.
                let word = cmd.split(' ').next().unwrap_or("");
                if self.cmdline.as_text && !cmd.is_empty() && !command_word(word, true) {
                    return self.command_to_text();
                }
                self.end_command();
                if !cmd.is_empty() {
                    self.run(&cmd).await;
                }
            }
            _ => {}
        }
    }
}

impl Command {
    fn name_static(&self) -> &'static str {
        self.name
    }
}

// ---- the help page: every key, then every command ----

/// The keys, by section, as the help page lists them: (section it starts, keys, what they do).
fn help_keys(lock: &str, panic: &str) -> Vec<(Option<&'static str>, String, &'static str)> {
    let rows: [(Option<&'static str>, &str, &'static str); 46] = [
        (Some("Rooms"), "ctrl+n", "start a new room"),
        (None, "ctrl+j", "join a room by its id and password, or one you kept (:keep)"),
        (None, "tab  shift+tab", "next / previous room"),
        (None, "ctrl+s", "settings"),
        (None, "ctrl+c", "quit, after asking - rooms leave, or go offline if kept"),
        (None, lock, "lock the screen, as :lock does (:set lockkey)"),
        (None, panic, "panic: clear the screen and quit at once (:set panickey)"),
        (Some("Screen"), "ctrl+b", "show or hide the sidebar"),
        (None, "ctrl+o", "show or hide the console"),
        (None, "ctrl+t", "show or hide the chat"),
        (None, "pgup  pgdn", "scroll the chat back / forward"),
        (None, "up  down", "scroll the chat by a row"),
        (None, "mouse wheel", "scroll what it's over: chat or console"),
        (None, "shift+drag", "select text with the mouse"),
        (None, "f1", "this page"),
        (Some("Typing"), "enter", "send"),
        (None, "/", "on an empty line: a command (what isn't one stays text)"),
        (None, "@nick  tab", "finish a nick"),
        (None, "ctrl+w  ctrl+u", "delete a word / back to the start"),
        (None, "esc", "NORMAL mode"),
        (Some("Normal mode"), "i  a  I  A", "type: at / after the cursor, at the start / end"),
        (None, "h  l  0  $  x", "move, to the start / end, delete"),
        (None, "j  k", "next / previous room"),
        (None, "ctrl+u  ctrl+d", "scroll the chat back / forward"),
        (None, "G", "back to the newest message and console line"),
        (None, "s  c  C", "show or hide the sidebar / console / chat"),
        (None, "f", "the files"),
        (None, "o", "open or copy the newest link in the chat (j k: older ones)"),
        (None, ":  /", "the command line"),
        (None, "?", "this page"),
        (Some("Files"), "ctrl+f", "the files offered here, and yours (f in NORMAL)"),
        (None, "enter  d", "download a file, in Downloads"),
        (None, "s", "save it in a folder you pick"),
        (None, "v", "show or hide a picture in the chat"),
        (None, "x", "stop fetching it, or stop offering yours"),
        (None, "n", "send a file"),
        (Some("Pages"), "j  k  g  G", "move, to the first / last"),
        (None, "h  l  enter", "change a value, go in, choose"),
        (None, "tab  shift+tab", "next / previous section (pgdn / pgup too)"),
        (None, "1 - 9", "the first to ninth section"),
        (None, "/", "in the settings: search them all"),
        (None, "esc  q", "back / close"),
        (Some("Command line"), "tab", "complete what the menu has picked"),
        (None, "up  down", "pick in the menu"),
        (None, "enter", "run it, or what the menu would complete it to"),
        (None, "esc", "back"),
    ];
    rows.into_iter().map(|(s, k, w)| (s, k.to_string(), w)).collect()
}

/// The help page's rows: the keys, then the commands. A command's row carries it, for Enter.
fn help_rows(app: &App) -> Vec<(Option<&'static str>, String, String, Option<&'static Command>)> {
    let mut rows: Vec<_> = help_keys(app.settings.get("lockkey"), app.settings.get("panickey"))
        .into_iter()
        .map(|(s, k, w)| (s, k, w.to_string(), None))
        .collect();
    for (i, cmd) in COMMANDS.iter().enumerate() {
        let label = format!(":{}{}{}", cmd.name, if cmd.args.is_empty() { "" } else { " " }, cmd.args);
        rows.push(((i == 0).then_some("Commands"), label, cmd.help.to_string(), Some(cmd)));
    }
    rows
}

impl App {
    /// The help page: every key, then every command.
    pub fn help_view(&self, sel: usize) -> crate::ui::PageView {
        use crate::ui::{PageRow, PageView, Value};
        let rows = help_rows(self);
        let sel = sel.min(rows.len() - 1);
        let nav: Vec<String> = rows.iter().filter_map(|r| r.0.map(String::from)).collect();
        let nav_sel = rows[..=sel].iter().filter(|r| r.0.is_some()).count().saturating_sub(1);
        let (_, _, what, cmd) = &rows[sel];
        // The row in full, since a narrow screen cuts it off in the list.
        let mut help = match what.chars().next() {
            Some(c) => format!("{}{}.", c.to_uppercase(), &what[c.len_utf8()..]),
            None => String::new(),
        };
        if let Some(c) = cmd {
            help.push_str(" Enter puts it on the command line.");
            if !c.aliases.is_empty() {
                let also: Vec<String> = c.aliases.iter().map(|a| format!(":{a}")).collect();
                help.push_str(&format!(" Also {}.", also.join(", ")));
            }
        }
        PageView {
            title: "Keys & commands".into(),
            nav,
            nav_sel,
            intro: None,
            side: None,
            rows: rows
                .iter()
                .map(|(s, k, w, _)| PageRow {
                    heading: *s,
                    prefix: None,
                    label: k.clone(),
                    value: Some(w.clone()),
                    kind: Value::Text,
                    swatch: None,
                    disabled: false,
                    permille: 0,
                })
                .collect(),
            selected: sel,
            help,
            usage: None,
            button: None,
            chip: Some("HELP"),
            keys: true,
            empty: None,
            hint: "enter use \u{b7} j/k move \u{b7} tab section \u{b7} esc close".into(),
        }
    }

    /// Enter on a command puts it on the command line; the list keys move, and Esc, q, F1 or ?
    /// close the page.
    pub(crate) fn help_key(&mut self, sel: usize, k: &crossterm::event::KeyEvent) {
        use crate::app::Modal;
        use crate::settings_page::{ListKey, list_key};
        use crossterm::event::KeyCode;
        let rows = help_rows(self);
        let n = rows.len();
        let starts: Vec<usize> = (0..n).filter(|&i| rows[i].0.is_some()).collect();
        let section = starts.iter().rposition(|&s| s <= sel).unwrap_or(0);
        if let KeyCode::Char(c @ '1'..='9') = k.code {
            let s = starts.get(c as usize - '1' as usize).copied().unwrap_or(sel);
            return self.modal = Some(Modal::Help(s));
        }
        let key = match k.code {
            KeyCode::F(1) | KeyCode::Char('?') => ListKey::Close,
            _ => list_key(k),
        };
        let sel = match key {
            ListKey::Choose | ListKey::Right => {
                if let Some(c) = rows[sel].3 {
                    let prefix = if self.mode == Mode::Normal { ':' } else { '/' };
                    self.enter_command(prefix);
                    self.cmdline
                        .input
                        .set(&format!("{}{}", c.name, if c.args.is_empty() { "" } else { " " }));
                    return;
                }
                sel
            }
            ListKey::Left | ListKey::Back | ListKey::Close => return,
            ListKey::NextSection => starts[(section + 1) % starts.len()],
            ListKey::PrevSection => starts[(section + starts.len() - 1) % starts.len()],
            ListKey::Up => sel.saturating_sub(1),
            ListKey::Down => (sel + 1).min(n - 1),
            ListKey::First => 0,
            ListKey::Last => n - 1,
            ListKey::None => sel,
        };
        self.modal = Some(Modal::Help(sel));
    }
}
