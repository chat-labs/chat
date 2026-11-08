// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The folder browser the key file, send, save and export pages use: what a folder lists, the keys
//! on its pages, and what they show. The folder shown is a tree of the folders above it, its
//! parent's entries go in a column beside it, and the left hand box says what the entry picked is.

use crate::app::{App, Input, Modal, PromptKind};
use crate::settings_page::{ListKey, Page, list_key};
use crate::ui::{PageRow, PageView, Side, Value};
use chat_core::IdentityKind;
use chat_core::net::files::home_dir;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The most entries a folder lists.
const MAX_ENTRIES: usize = 512;
/// A file bigger than this isn't read to see if it holds a key: no key file is that big.
const KEY_FILE_MAX: u64 = 65536;
/// The tree's columns per level, the columns kept for the names, and the most levels it shows.
const TREE_INDENT: usize = 3;
const TREE_NAME_ROOM: usize = 14;
const TREE_MAX_LEVELS: usize = 32;
/// Room kept under the tree for a few entries, so its top isn't scrolled away.
const ENTRIES_BELOW: usize = 3;
/// The rows the page takes besides the tree's.
const CHROME_ROWS: usize = 12;

#[derive(Clone, Copy)]
pub enum Purpose {
    /// A signing key file of this kind.
    Key(IdentityKind),
    /// A file to offer, cleaned unless asis.
    Send { asis: bool },
    /// The folder to save file `num` in.
    Save { num: u32, anyway: bool },
    /// The folder to write the signing key to.
    Export,
}

/// Where the browser goes back to.
pub enum Back {
    Chat,
    Files(u32),
    Page(Page),
}

struct Entry {
    name: String,
    os: OsString,
    is_dir: bool,
}

pub struct Browser {
    pub purpose: Purpose,
    pub back: Back,
    path: PathBuf,
    items: Vec<Entry>,
    selected: usize,
    /// The parent folder, its entries, and the folder shown among them: None at the root.
    parent: Option<(PathBuf, Vec<String>, Option<usize>)>,
    /// What the left hand box says about the entry picked.
    info: Vec<String>,
    /// The export's box while it's up: the file it would write.
    pub ask: Option<PathBuf>,
}

/// A folder's entries: folders first, then files, and in each the hidden ones (starting with '.')
/// last.
fn list(path: &Path) -> std::io::Result<Vec<Entry>> {
    let mut items = Vec::new();
    for e in std::fs::read_dir(path)?.flatten() {
        let os = e.file_name();
        let name = os.to_string_lossy().into_owned();
        // Names are drawn on the terminal, and one with control characters in it could steer it.
        if name.chars().any(char::is_control) {
            continue;
        }
        let is_dir = std::fs::metadata(e.path()).map_or_else(|_| e.file_type().is_ok_and(|t| t.is_dir()), |m| m.is_dir());
        items.push(Entry { name, os, is_dir });
        if items.len() >= MAX_ENTRIES {
            break;
        }
    }
    items.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then(a.name.starts_with('.').cmp(&b.name.starts_with('.')))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(items)
}

/// A path as shown: "~" for the home folder.
pub fn tilde(path: &Path) -> String {
    let shown = path.display().to_string();
    match home_dir() {
        Some(h) if shown == h => "~".into(),
        Some(h) => match shown.strip_prefix(&format!("{}/", h.trim_end_matches('/'))) {
            Some(rest) => format!("~/{rest}"),
            None => shown,
        },
        None => shown,
    }
}

/// s cut from the left to `room` columns, after an ellipsis: the end of a path says where it is.
fn tail_ell(s: &str, room: usize) -> String {
    let n = s.chars().count();
    if n <= room {
        return s.to_string();
    }
    let tail: String = s.chars().skip(n + 1 - room).collect();
    format!("\u{2026}{tail}")
}

/// What the left hand box says about an entry: its name, then what it is, its size (or for a
/// folder, how many entries it has), when it was changed and who can read it. For a key file, a
/// small file is also read to say whether it holds a secret key.
fn info(name: &str, path: &Path, key: Option<IdentityKind>) -> Vec<String> {
    let mut out = vec![name.to_string(), String::new()];
    let (Ok(link), meta) = (std::fs::symlink_metadata(path), std::fs::metadata(path)) else {
        out.push("can't be read".into());
        return out;
    };
    // A broken link: the link itself.
    let m = meta.unwrap_or(link.clone());
    let is_link = link.file_type().is_symlink();
    if m.is_dir() {
        out.push(if is_link { "link to a folder" } else { "folder" }.into());
        out.push(match std::fs::read_dir(path) {
            Ok(d) => match d.count() {
                1 => "1 entry".into(),
                n => format!("{n} entries"),
            },
            Err(_) => "can't be opened".into(),
        });
    } else {
        out.push(if is_link { "link to a file" } else { "file" }.into());
        out.push(chat_core::protocol::files::format_size(m.len()));
    }
    if let Some(t) = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()) {
        // "YYYY-MM-DD HH:MM" on two rows, to fit the box.
        let stamp = chat_core::net::history::stamp(t.as_secs());
        let (date, time) = stamp.split_once(' ').unwrap_or((&stamp, ""));
        out.extend([String::new(), "changed".into(), date.into(), time.into()]);
    }
    #[cfg(unix)]
    let mode = Some(std::os::unix::fs::PermissionsExt::mode(&m.permissions()) & 0o777);
    #[cfg(not(unix))]
    let mode: Option<u32> = None;
    if let Some(mode) = mode {
        let perm: String = "rwxrwxrwx"
            .chars()
            .enumerate()
            .map(|(i, c)| if mode & (0o400 >> i) != 0 { c } else { '-' })
            .collect();
        out.push(format!("{perm} {mode:03o}"));
    }
    if let (Some(kind), false) = (key, m.is_dir()) {
        out.push(String::new());
        // Only a regular file is read: a pipe or a device could block, or never end.
        let text = (m.is_file() && m.len() <= KEY_FILE_MAX)
            .then(|| std::fs::read(path).ok().map(zeroize::Zeroizing::new))
            .flatten();
        let found = text.as_ref().and_then(|t| {
            let t = String::from_utf8_lossy(t);
            if t.contains("AGE-SECRET-KEY-1") {
                Some(IdentityKind::Age)
            } else if t.contains(chat_core::protocol::crypto::pgp::PRIVATE_BEGIN) {
                Some(IdentityKind::Pgp)
            } else {
                None
            }
        });
        let name = |k: IdentityKind| if k == IdentityKind::Pgp { "PGP" } else { "AGE" };
        out.push(match (m.len() > KEY_FILE_MAX, &text, found) {
            (true, _, _) => "too big for a key".into(),
            (_, None, _) => "can't be read".into(),
            (_, _, None) => "no secret key".into(),
            (_, _, Some(f)) => format!("{} secret key", name(f)),
        });
        if found.is_some_and(|f| f != kind) {
            out.push(format!("but this is {}", name(kind)));
        }
        // Readable by more than its owner.
        if found.is_some() && mode.is_some_and(|m| m & 0o77 != 0) {
            out.extend(["not private:".into(), "chmod 600 it".into()]);
        }
    }
    out
}

impl Browser {
    /// Opens in the first of these folders that can be listed, or else the root.
    fn new(purpose: Purpose, back: Back, tries: impl IntoIterator<Item = PathBuf>) -> Box<Browser> {
        let mut b = Box::new(Browser {
            purpose,
            back,
            path: PathBuf::from("/"),
            items: Vec::new(),
            selected: 0,
            parent: None,
            info: Vec::new(),
            ask: None,
        });
        for p in tries.into_iter().chain([PathBuf::from("/")]) {
            if b.load(&p) {
                break;
            }
        }
        b
    }

    /// Shows a folder. One that can't be listed leaves the one shown.
    fn load(&mut self, path: &Path) -> bool {
        let Ok(items) = list(path) else { return false };
        self.path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        self.items = items;
        self.selected = 0;
        self.parent = self.path.parent().zip(self.path.file_name()).and_then(|(up, name)| {
            let items = list(up).ok()?;
            let name = name.to_string_lossy();
            let sel = items.iter().position(|e| e.is_dir && e.name == name);
            let names = items
                .into_iter()
                .map(|e| if e.is_dir { format!("{}/", e.name) } else { e.name })
                .collect();
            Some((up.to_path_buf(), names, sel))
        });
        self.settle();
        true
    }

    /// The entry picked has changed: what the left hand box says about it.
    fn settle(&mut self) {
        let key = match self.purpose {
            Purpose::Key(k) => Some(k),
            _ => None,
        };
        self.info = match self.items.get(self.selected) {
            Some(e) => info(&e.name, &self.path.join(&e.os), key),
            None => Vec::new(),
        };
    }

    fn select(&mut self, name: &str) {
        if let Some(i) = self.items.iter().position(|e| e.name == name) {
            self.selected = i;
            self.settle();
        }
    }

    /// Up to the parent folder, with the folder just left picked.
    fn up(&mut self) {
        let here = self.path.clone();
        if let (Some(up), Some(name)) = (here.parent(), here.file_name())
            && self.load(up)
        {
            self.select(&name.to_string_lossy());
        }
    }

    fn picked(&self) -> Option<(&Entry, PathBuf)> {
        self.items.get(self.selected).map(|e| (e, self.path.join(&e.os)))
    }

    /// The help when the entry picked is a folder, or there's none. None for a file.
    fn folder_help(&self) -> Option<String> {
        match self.items.get(self.selected) {
            None => Some("Nothing here. h goes up a folder.".into()),
            Some(e) if e.is_dir => Some(format!("Enter opens {}. h goes up a folder.", e.name)),
            Some(_) => None,
        }
    }

    /// The tree: the folder shown and the folders above it, one level a row, then its folders
    /// (drawn like rows that open a page) and files one level further in. As many levels get a
    /// row of their own as leave room for the names in `row_cols`; the levels above those are
    /// joined into the top row's path. Returns the rows, how many are levels, and what's here.
    fn tree(&self, row_cols: usize, list_rows: usize) -> (Vec<PageRow>, usize, String) {
        let shown = tilde(&self.path);
        let mut parts: Vec<&str> = shown.split('/').collect();
        if parts.len() > 1 && parts.last() == Some(&"") {
            parts.pop();
        }
        let n = parts.len();
        let mut levels = ((row_cols / 2).saturating_sub(TREE_NAME_ROOM) / TREE_INDENT)
            .clamp(1, TREE_MAX_LEVELS)
            .min(n);
        let below = self.items.len().min(ENTRIES_BELOW);
        if levels + below > list_rows {
            levels = list_rows.saturating_sub(below).max(1);
        }
        let joined = n - (levels - 1);
        let mut head = parts[..joined].join("/");
        if head.is_empty() || (joined == 1 && n > 1 && parts[0].is_empty()) {
            head = "/".into();
        }
        let room = (row_cols / 2).saturating_sub(3);
        if room > 8 && head.chars().count() > room {
            head = tail_ell(&head, room);
        }
        let row = |prefix: Option<String>, label: String, value: Option<String>| PageRow {
            heading: None,
            prefix,
            label,
            value,
            kind: Value::Link,
            swatch: None,
            disabled: false,
            permille: 0,
        };
        let mut rows = vec![row(None, head, None)];
        for i in 1..levels {
            let prefix = format!("{}\u{2514}\u{2500} ", " ".repeat((i - 1) * TREE_INDENT));
            rows.push(row(Some(prefix), parts[joined + i - 1].into(), None));
        }
        let pad = " ".repeat((levels - 1) * TREE_INDENT);
        let (mut folders, mut files) = (0, 0);
        for (i, e) in self.items.iter().enumerate() {
            let line = if i + 1 == self.items.len() { "\u{2514}" } else { "\u{251c}" };
            rows.push(row(
                Some(format!("{pad}{line}\u{2500} ")),
                e.name.clone(),
                e.is_dir.then(String::new),
            ));
            if e.is_dir { folders += 1 } else { files += 1 }
        }
        let plural = |n: usize, what: &str| format!("{n} {what}{}", if n == 1 { "" } else { "s" });
        let here = match (folders, files) {
            (0, 0) => "empty".into(),
            (d, 0) => plural(d, "folder"),
            (0, f) => plural(f, "file"),
            (d, f) => format!("{} \u{b7} {}", plural(d, "folder"), plural(f, "file")),
        };
        (rows, levels, here)
    }
}

impl App {
    /// Back where the browser came from.
    fn browser_back(&mut self, b: Box<Browser>) {
        match b.back {
            Back::Chat => self.modal = None,
            Back::Files(at) => self.modal = Some(Modal::Files(at)),
            Back::Page(p) => self.show_page(p),
        }
    }

    /// /set sign's "Pick a key file": opens in the folder of the key file in use, if there is one,
    /// on that file, and otherwise in the home folder.
    pub(crate) fn begin_key_browse(&mut self, kind: IdentityKind, p: Page) {
        let in_use = self.ident.as_ref().and_then(|i| match &i.origin {
            crate::identity::Origin::File(path) if i.kind == kind => Some(PathBuf::from(path)),
            _ => None,
        });
        let dir = in_use.as_ref().and_then(|f| f.parent()).map(Path::to_path_buf);
        let mut b = Browser::new(
            Purpose::Key(kind),
            Back::Page(p),
            dir.into_iter().chain(home_dir().map(PathBuf::from)),
        );
        if let Some(name) = in_use.as_ref().and_then(|f| f.file_name()) {
            b.select(&name.to_string_lossy());
        }
        self.modal = Some(Modal::Browser(b));
    }

    /// /send without a path: the file's picked here, starting where the last one came from.
    pub(crate) fn begin_send_browse(&mut self, asis: bool, back: Back) {
        let tries = self.send_dir.clone().into_iter().chain(home_dir().map(PathBuf::from));
        self.modal = Some(Modal::Browser(Browser::new(Purpose::Send { asis }, back, tries)));
    }

    /// /saveto N: the folder to save file N in is picked here, starting where the last one went, or
    /// in Downloads.
    pub(crate) fn begin_save_browse(&mut self, num: u32, anyway: bool, back: Back) {
        let tries = self
            .save_dir
            .clone()
            .into_iter()
            .chain(chat_core::net::files::downloads_dir())
            .chain(home_dir().map(PathBuf::from));
        self.modal = Some(Modal::Browser(Browser::new(Purpose::Save { num, anyway }, back, tries)));
    }

    /// Why the signing key in use can't be exported, if it can't.
    fn export_refusal(&self) -> Option<&'static str> {
        match &self.ident {
            None => Some("no signing key in use - /set sign picks or makes one"),
            Some(i) if i.export_name().is_none() => {
                Some("only a PGP key made here is exported - gpg --export-secret-keys gives one from a file or a paste")
            }
            Some(_) => None,
        }
    }

    /// /exportkey: the folder to write the signing key to is picked here, starting in Downloads.
    pub(crate) fn begin_export_browse(&mut self, back: Back) {
        if let Some(why) = self.export_refusal() {
            self.fail(why);
            if let Back::Page(p) = back {
                self.show_page(p);
            }
            return;
        }
        let tries = chat_core::net::files::downloads_dir()
            .into_iter()
            .chain(home_dir().map(PathBuf::from));
        self.modal = Some(Modal::Browser(Browser::new(Purpose::Export, back, tries)));
    }

    /// A key file read as the key of `kind`. Says why it isn't one if it isn't.
    pub(crate) fn load_key(&mut self, kind: IdentityKind, path: &str) -> bool {
        match crate::identity::Ident::from_file(path) {
            Ok(i) if i.kind == kind => {
                self.use_identity(Some(i));
                true
            }
            _ => {
                let shown: String = path.chars().take(80).collect();
                self.fail(match kind {
                    IdentityKind::Pgp => format!("{shown} can't be read, or isn't an unencrypted EdDSA/Ed25519 secret key"),
                    _ => format!("{shown} can't be read, or holds no AGE secret key"),
                });
                false
            }
        }
    }

    /// The key file's path typed: a path that isn't a key stays in the field to be fixed, and one
    /// that is goes back to the settings.
    pub(crate) fn key_path_typed(&mut self, kind: IdentityKind, title: String, hint: String, input: Input) {
        let text = input.text();
        let path = text.trim();
        if path.is_empty() {
            self.fail("type the key file's path - or Esc to go back");
        } else if self.load_key(kind, &chat_core::net::files::typed_path_here(path)) {
            let page = match self.behind.take().map(|m| *m) {
                Some(Modal::Settings(p)) => Some(p),
                Some(Modal::Browser(b)) => match b.back {
                    Back::Page(p) => Some(p),
                    _ => None,
                },
                _ => None,
            };
            if let Some(mut p) = page {
                p.pick = None;
                self.show_page(p);
            }
            return;
        }
        self.modal = Some(Modal::Prompt {
            kind: PromptKind::KeyPath(kind),
            title,
            hint,
            input,
        });
    }

    fn keep_browser(&mut self, b: Box<Browser>) {
        self.modal = Some(Modal::Browser(b));
    }

    /// Besides the list keys: ~ goes to the home folder; on the key file's page / types a path
    /// instead, starting with the file picked or the folder shown; and on the save and export
    /// pages s picks the folder shown.
    pub async fn browser_key(&mut self, mut b: Box<Browser>, k: KeyEvent) {
        if b.ask.is_some() {
            return self.export_ask_key(b, k);
        }
        let ch = match k.code {
            KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => Some(c),
            _ => None,
        };
        match (ch, b.purpose) {
            (Some('~'), _) => {
                if let Some(h) = home_dir() {
                    b.load(Path::new(&h));
                }
                return self.keep_browser(b);
            }
            (Some('/'), Purpose::Key(kind)) => {
                let start = match b.picked() {
                    Some((e, path)) if !e.is_dir => tilde(&path),
                    _ => format!("{}/", tilde(&b.path).trim_end_matches('/')),
                };
                let mut input = Input::default();
                input.set(&start);
                let (title, help) = crate::settings_page::key_path_box(kind);
                self.behind = Some(Box::new(Modal::Browser(b)));
                self.modal = Some(Modal::Prompt {
                    kind: PromptKind::KeyPath(kind),
                    title,
                    hint: help,
                    input,
                });
                return;
            }
            (Some('s'), Purpose::Save { num, anyway }) => {
                let dir = b.path.clone();
                self.browser_back(b);
                self.save_dir = Some(dir.clone());
                return self.save_into(num, anyway, &dir).await;
            }
            (Some('s'), Purpose::Export) => {
                let free = self.ident.as_ref().and_then(|i| crate::identity::export_path(i, &b.path));
                match free {
                    Some(f) => b.ask = Some(f),
                    None => self.fail(format!("{} has no free name for the key - pick another folder", tilde(&b.path))),
                }
                return self.keep_browser(b);
            }
            _ => {}
        }
        let last = b.items.len().saturating_sub(1);
        match list_key(&k) {
            ListKey::Left => b.up(),
            key @ (ListKey::Choose | ListKey::Right) => match b.picked() {
                Some((e, path)) if e.is_dir => {
                    b.load(&path);
                }
                Some((_, path)) => match b.purpose {
                    Purpose::Key(kind) => {
                        if self.load_key(kind, &path.to_string_lossy()) {
                            if let Back::Page(mut p) = b.back {
                                p.pick = None;
                                self.show_page(p);
                            }
                            return;
                        }
                    }
                    Purpose::Send { asis } if matches!(key, ListKey::Choose) => {
                        self.send_dir = Some(b.path.clone());
                        self.browser_back(b);
                        return self.offer_from_browser(&path, asis).await;
                    }
                    _ => {}
                },
                None => {}
            },
            ListKey::Back => return self.browser_back(b),
            ListKey::Close => {
                return match b.back {
                    Back::Page(mut p) if matches!(b.purpose, Purpose::Key(_)) => {
                        p.pick = None;
                        self.settings_done(p)
                    }
                    _ => self.browser_back(b),
                };
            }
            ListKey::Up => b.selected = b.selected.saturating_sub(1),
            ListKey::Down => b.selected = (b.selected + 1).min(last),
            ListKey::First => b.selected = 0,
            ListKey::Last => b.selected = last,
            _ => {}
        }
        b.settle();
        self.keep_browser(b);
    }

    /// y writes the key; n goes back to the browser.
    fn export_ask_key(&mut self, mut b: Box<Browser>, k: KeyEvent) {
        match k.code {
            KeyCode::Char('y' | 'Y') => {
                let Some(i) = self.ident.clone() else { return self.browser_back(b) };
                match crate::identity::export(&i, &self.nick, &b.path.to_string_lossy()) {
                    Ok(path) => {
                        let kind = if i.kind == IdentityKind::Pgp { "pgp" } else { "age" };
                        self.say(format!(
                            "your signing key is in {}, which only you can open - /set sign {kind}:PATH loads it elsewhere",
                            tilde(Path::new(&path))
                        ));
                        return self.browser_back(b);
                    }
                    Err(e) => {
                        self.fail(e);
                        b.ask = None;
                    }
                }
            }
            KeyCode::Char('n' | 'N') | KeyCode::Esc => b.ask = None,
            _ => {}
        }
        self.keep_browser(b);
    }

    async fn offer_from_browser(&mut self, path: &Path, asis: bool) {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let r = match self.open_room() {
            Ok((_, room)) => room
                .offer(&path.to_string_lossy(), asis)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(_) => Err(format!("no room to send {name} to")),
        };
        if let Err(e) = r {
            self.fail(e);
        }
    }

    async fn save_into(&mut self, num: u32, anyway: bool, dir: &Path) {
        let r = match self.open_room() {
            Ok((_, room)) => room
                .fetch(num, false, anyway, Some(&dir.to_string_lossy()))
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(_) => Err(format!("no room to save file {num} from")),
        };
        if let Err(e) = r {
            self.fail(e);
        }
    }

    /// The browser's page, laid out for this many columns and rows.
    pub fn browser_view(&self, b: &Browser, cols: u16, rows: u16) -> PageView {
        let (row_cols, side_w) = crate::ui::page_cols(cols);
        let side = b.parent.as_ref().filter(|_| side_w > 0).map(|(up, entries, sel)| Side {
            title: tail_ell(&tilde(up), side_w.saturating_sub(4).max(5)),
            entries: entries.clone(),
            sel: *sel,
        });
        let row_cols = row_cols.saturating_sub(if side.is_some() { side_w } else { 0 });
        let (rows_v, levels, here) = b.tree(row_cols, (rows as usize).saturating_sub(CHROME_ROWS));
        let picked = b.picked();
        let open_help = b.folder_help();
        let entry_name = picked.as_ref().map(|(e, _)| e.name.clone()).unwrap_or_default();
        let shown_dir = tilde(&b.path);
        let (title, help, usage, chip, hint): (String, String, Option<String>, Option<&'static str>, &str) = match b.purpose {
            Purpose::Key(kind) => {
                let (k, set) = if kind == IdentityKind::Pgp {
                    ("PGP", "pgp")
                } else {
                    ("AGE", "age")
                };
                let (help, usage) = match open_help {
                    Some(h) => (h, None),
                    None => (
                        format!(
                            "Enter uses {entry_name} as your {k} key. chat signs your handshakes with it, and only the secret key \
                             can make a signature. It stays in memory and isn't sent. /install saves this file's path, not the key."
                        ),
                        picked.as_ref().map(|(_, p)| format!("/set sign {set}:{}", tilde(p))),
                    ),
                };
                (
                    format!("Settings \u{203a} Profile \u{203a} Signing identity \u{203a} {k} key file"),
                    help,
                    usage,
                    None,
                    "enter open \u{b7} h up \u{b7} / type a path \u{b7} ~ home \u{b7} esc back \u{b7} q close",
                )
            }
            Purpose::Send { asis } => (
                "Send a file".into(),
                open_help
                    .unwrap_or_else(|| format!("Enter offers {entry_name} to everyone in this room. Nobody gets it unless they fetch it.")),
                None,
                Some(if asis { "SEND AS IS" } else { "SEND" }),
                "enter send \u{b7} h up \u{b7} ~ home \u{b7} j/k move \u{b7} esc close",
            ),
            Purpose::Save { num, .. } => {
                let what = self
                    .room()
                    .and_then(|r| r.files.iter().find(|f| f.num == num))
                    .map_or(format!("file {num}"), |f| {
                        format!("{} ({})", f.name, chat_core::protocol::files::format_size(f.size))
                    });
                let more = picked.as_ref().filter(|(e, _)| e.is_dir).and(open_help).map(|h| format!(" {h}"));
                (
                    format!("Save file {num}"),
                    format!("s saves {what} in {shown_dir}.{}", more.unwrap_or_default()),
                    None,
                    Some("SAVE"),
                    "s save here \u{b7} enter open \u{b7} h up \u{b7} ~ home \u{b7} j/k move \u{b7} esc close",
                )
            }
            Purpose::Export => {
                let name = self.ident.as_ref().and_then(|i| i.export_name()).unwrap_or_default();
                let more = picked.as_ref().filter(|(e, _)| e.is_dir).and(open_help).map(|h| format!(" {h}"));
                (
                    "Export signing key".into(),
                    format!(
                        "s writes your signing key to a new {name} in {shown_dir}, after asking.{}",
                        more.unwrap_or_default()
                    ),
                    None,
                    Some("EXPORT"),
                    "s write here \u{b7} enter open \u{b7} h up \u{b7} ~ home \u{b7} j/k move \u{b7} esc close",
                )
            }
        };
        PageView {
            title,
            nav: b.info.clone(),
            nav_sel: 0,
            intro: Some(here),
            side,
            selected: levels + b.selected,
            rows: rows_v,
            help,
            usage,
            button: None,
            chip,
            keys: false,
            empty: None,
            hint: hint.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_folders_first_and_hidden_last() {
        let dir = std::env::temp_dir().join(format!("chat-browser-{}", std::process::id()));
        for d in ["b", ".a", "A"] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        for f in ["z.txt", ".x", "c.txt"] {
            std::fs::write(dir.join(f), "").unwrap();
        }
        // Windows refuses control characters in file names, so there's nothing to hide there.
        if !cfg!(windows) {
            std::fs::write(dir.join("bad\u{1b}[2J"), "").unwrap();
        }
        let names: Vec<String> = list(&dir).unwrap().into_iter().map(|e| e.name).collect();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(names, ["A", "b", ".a", "c.txt", "z.txt", ".x"]);
        assert_eq!(tail_ell("/home/alice/keys", 8), "\u{2026}ce/keys");
    }
}
