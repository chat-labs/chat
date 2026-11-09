// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The settings page (Ctrl+S, or /set alone): a page for each section, with the sections listed on
//! the left and a last page after them (Done, or Start as chat starts) that has every row and the
//! button that leaves. A section's rows go under their groups' headings, and the picked row's help
//! and /set command go along the bottom. / searches every row, and the signing identity's row opens
//! a page of its own.

use crate::app::{App, Input, Modal, PromptKind};
use crate::browser::Back;
use crate::identity::Origin;
use crate::ui::{PageRow, PageView, Value};
use chat_core::IdentityKind;
use chat_core::net::settings::{self as st, PAGE, RowKind, SIGN_PICKS};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// The button's place, after every row.
pub const DONE: usize = PAGE.len();

/// Where the page is, kept while it's closed so it opens where it was.
#[derive(Clone)]
pub struct Page {
    /// The row picked, by its place in [`PAGE`], or [`DONE`].
    pub sel: usize,
    /// The page shown: a section's, or the last.
    pub page: usize,
    /// The row picked last on each section's page.
    rows: Vec<usize>,
    /// The search box while it's open: what's typed, and the match picked.
    pub search: Option<(Input, usize)>,
    /// The signing identity's page while it's open, on the choice picked.
    pub pick: Option<usize>,
    /// Why the device lock and a security key can't be used here, if they can't, and where the
    /// transport programs are: looked up as the page opens and after each change.
    device_why: Option<String>,
    /// The command that opens the TPM to this user, as root, where that's what's in the way.
    device_fix: Option<String>,
    key_why: Option<String>,
    transports: String,
}

impl Default for Page {
    fn default() -> Self {
        Page {
            sel: 0,
            page: 0,
            rows: vec![0; st::sections().len()],
            search: None,
            pick: None,
            device_why: None,
            device_fix: None,
            key_why: None,
            transports: String::new(),
        }
    }
}

/// The sections' pages and the last page.
fn n_pages() -> usize {
    st::sections().len() + 1
}

fn done_page() -> usize {
    st::sections().len()
}

fn select(p: &mut Page, sel: usize) {
    p.sel = sel;
    if sel >= DONE {
        p.page = done_page();
        return;
    }
    p.page = st::section_of(sel);
    p.rows[p.page] = sel;
}

/// What the list pages' keys do.
pub(crate) enum ListKey {
    Up,
    Down,
    First,
    Last,
    NextSection,
    PrevSection,
    Choose,
    Left,
    Right,
    Back,
    Close,
    None,
}

/// j/k or up/down move, g/G or Home/End go to the ends, Tab/Shift+Tab or PgDn/PgUp go to the next
/// or previous section, Enter or space chooses, h/l or left/right go sideways (Backspace too), Esc
/// goes back a level, and q or Ctrl+S closes the page.
pub(crate) fn list_key(k: &KeyEvent) -> ListKey {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    match k.code {
        KeyCode::Char('s') if ctrl => ListKey::Close,
        _ if ctrl => ListKey::None,
        KeyCode::Up | KeyCode::Char('k') => ListKey::Up,
        KeyCode::Down | KeyCode::Char('j') => ListKey::Down,
        KeyCode::Home | KeyCode::Char('g') => ListKey::First,
        KeyCode::End | KeyCode::Char('G') => ListKey::Last,
        KeyCode::Tab | KeyCode::PageDown => ListKey::NextSection,
        KeyCode::BackTab | KeyCode::PageUp => ListKey::PrevSection,
        KeyCode::Enter | KeyCode::Char(' ') => ListKey::Choose,
        KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => ListKey::Left,
        KeyCode::Right | KeyCode::Char('l') => ListKey::Right,
        KeyCode::Esc => ListKey::Back,
        KeyCode::Char('q') => ListKey::Close,
        _ => ListKey::None,
    }
}

const AGE_PATH_HELP: &str = "Type the path to your AGE key file, as age-keygen writes it. ~ is your home folder.";
const PGP_PATH_HELP: &str = "Type the path to your PGP key file: an unencrypted, armored EdDSA/Ed25519 secret key, as gpg \
                             --export-secret-keys --armor writes it from a key with no passphrase. ~ is your home folder.";
const KEY_WHY: &str = "Why the secret key: chat signs the handshake of every room you join, so peers can check it's you. \
                       Only the secret key can make a signature; the public key can only check one. The key is kept in \
                       memory and never sent: peers get your public key and the signatures.";
const KEY_FILE_SAVED: &str = "What /install keeps: this file's path, not the key. chat reads the file again each time it \
                              starts, so leave it where it is.";

const AGE_PASTE_HELP: &str = "Paste your AGE secret key now: the AGE-SECRET-KEY-1... line, or the whole file age-keygen \
                              wrote. It's read when its line ends (Enter, if the paste didn't end it).";
const PGP_PASTE_HELP: &str = "Paste your armored PGP private key now, BEGIN line to END line. It's read as soon as the END \
                              line arrives. It has to be an unencrypted EdDSA/Ed25519 key (gpg --export-secret-keys \
                              --armor, from a key with no passphrase).";
const KEY_PASTE_SAVED: &str = "What /install keeps: with no file to point to, the key itself, sealed with your passphrase. \
                               Until then it's only in memory. To keep it out of chat's files, save it to a file and \
                               pick that instead.";

/// The most a paste box takes: room for any key, kept in one buffer so it's never copied as it grows.
pub(crate) const PASTE_MAX: usize = 16 * 1024;

/// The paste box's title and help.
pub(crate) fn paste_box(kind: IdentityKind) -> (&'static str, [&'static str; 3]) {
    match kind {
        IdentityKind::Pgp => ("PASTE A PGP KEY", [PGP_PASTE_HELP, KEY_WHY, KEY_PASTE_SAVED]),
        _ => ("PASTE AN AGE KEY", [AGE_PASTE_HELP, KEY_WHY, KEY_PASTE_SAVED]),
    }
}

/// The key file path box's title and help.
pub(crate) fn key_path_box(kind: IdentityKind) -> (String, String) {
    let (title, help) = match kind {
        IdentityKind::Pgp => (" PGP KEY FILE ", PGP_PATH_HELP),
        _ => (" AGE KEY FILE ", AGE_PATH_HELP),
    };
    (title.into(), format!("{help} {KEY_WHY} {KEY_FILE_SAVED}"))
}

/// The colour's name in the palette, or #rrggbb.
fn colour_name(c: chat_core::Colour) -> String {
    chat_core::protocol::names::PALETTE
        .iter()
        .find(|(_, p)| *p == c)
        .map_or_else(|| format!("#{:02x}{:02x}{:02x}", c.0[0], c.0[1], c.0[2]), |(n, _)| n.to_string())
}

impl App {
    /// The signing key in use, and whether it was made here.
    fn key_in_use(&self) -> Option<(IdentityKind, bool)> {
        self.ident
            .as_ref()
            .map(|i| (i.kind, !matches!(i.origin, Origin::File(_) | Origin::Pasted)))
    }

    /// Why row i isn't on the page right now, or None if it is.
    fn row_hidden(&self, i: usize) -> Option<&'static str> {
        self.settings.hidden(PAGE[i].name, self.key_in_use())
    }

    pub(crate) fn row_shown(&self, i: usize) -> bool {
        self.row_hidden(i).is_none()
    }

    /// The rows that match a search, best first.
    pub fn search_found(&self, query: &str) -> Vec<usize> {
        let key = self.key_in_use();
        st::search(query, |name| self.settings.hidden(name, key).is_none())
    }

    fn factor_on(&self, f: u8) -> bool {
        self.save.as_ref().is_some_and(|s| s.factors() & f != 0)
    }

    /// A row that can't be used here: the device lock or a security key with nothing to work with.
    fn row_greyed(&self, p: &Page, name: &str) -> bool {
        use chat_core::protocol::crypto::passlock::{NEEDS_DEVICE, NEEDS_KEY};
        match name {
            "devicelock" => p.device_why.is_some() && !self.factor_on(NEEDS_DEVICE),
            "securitykey" => p.key_why.is_some() && !self.factor_on(NEEDS_KEY),
            _ => false,
        }
    }

    fn refresh(&self, p: &mut Page) {
        p.device_why = chat_core::net::device::lock::available().err();
        p.device_fix = chat_core::net::device::lock::fix();
        p.key_why = chat_core::net::seckey::usable().err();
        let mut b = chat_core::net::Bridges::default();
        let dir = self.settings.get("transports");
        let _ = b.set_transports((!dir.is_empty()).then(|| dir.into()));
        p.transports = b.describe_transports();
    }

    /// The signing identity, as its row shows it.
    fn sign_value(&self) -> String {
        let Some(i) = &self.ident else { return "off".into() };
        let kind = match i.kind {
            IdentityKind::Pgp => "pgp",
            IdentityKind::Age => "age",
            IdentityKind::Native => "native",
        };
        let from = match &i.origin {
            Origin::Password(None) => " from password, without nick".to_string(),
            Origin::Password(Some(n)) => format!(" from password and nick {n}"),
            _ => String::new(),
        };
        format!("{kind}{from}, fingerprint {}", i.fingerprint())
    }

    /// A row's value as the page shows it.
    fn row_value(&self, p: &Page, name: &str) -> String {
        use chat_core::protocol::crypto::passlock::{NEEDS_CODE, NEEDS_DEVICE, NEEDS_KEY};
        let on_off = |b: bool| if b { "on" } else { "off" }.to_string();
        let s = &self.settings;
        let pgp_here = matches!(self.key_in_use(), Some((IdentityKind::Pgp, true)));
        match name {
            "devicelock" => on_off(self.factor_on(NEEDS_DEVICE)),
            "securitykey" => on_off(self.factor_on(NEEDS_KEY)),
            "authenticator" => on_off(self.factor_on(NEEDS_CODE)),
            "destroy" => match self.save.as_ref().map_or(0, |s| s.destroy_limit()) {
                0 => "off".into(),
                n => n.to_string(),
            },
            "shadow" => on_off(self.save.as_ref().is_some_and(|s| s.has_shadow())),
            "relays" => {
                let r: Vec<&str> = s
                    .get(name)
                    .split_whitespace()
                    .map(|u| u.strip_prefix("wss://").unwrap_or(u))
                    .collect();
                if r.is_empty() { "none".into() } else { r.join(" ") }
            }
            "bridges" => {
                let mut b = chat_core::net::Bridges::default();
                match b.set_lines(s.get(name)) {
                    Ok(()) => b.describe(),
                    Err(_) => "none".into(),
                }
            }
            "transports" => p.transports.clone(),
            "filelimit" => chat_core::protocol::files::format_size(s.file_limit()),
            "torpath" if self.settings.get(name).is_empty() => "built in".into(),
            "torpassword" if self.tor_password.is_empty() => "not set (cookie or no login)".into(),
            "torpassword" => "set".into(),
            "nick" => self.nick.clone(),
            "colour" => self.colour.map_or("random".into(), colour_name),
            "sign" => self.sign_value(),
            "agerecipient" => match &self.ident {
                Some(i) if i.kind == IdentityKind::Age => i.kp.age_recipient().unwrap_or_default(),
                _ => "none".into(),
            },
            "pgpkey" => match &self.ident {
                Some(i) if pgp_here => {
                    chat_core::protocol::hex::encode(&chat_core::protocol::crypto::pgp::fingerprint(&i.kp.public, i.created))
                }
                _ => "none".into(),
            },
            "exportkey" => match self.key_in_use() {
                Some((IdentityKind::Age, _)) => "age-secret-key.txt".into(),
                Some((IdentityKind::Pgp, true)) => "pgp-secret-key.asc".into(),
                _ => "none".into(),
            },
            "port" => match s.get(name) {
                "0" => "0 (a free one)".into(),
                n => n.into(),
            },
            n => s.get(n).to_string(),
        }
    }

    /// A row's value in the form /set takes, for its edit box. Empty for a secret.
    fn row_text(&self, name: &str) -> String {
        match name {
            "nick" => self.nick.clone(),
            "colour" => self.colour.map(colour_name).unwrap_or_default(),
            "torpassword" => String::new(),
            n => self.settings.get(n).to_string(),
        }
    }

    /// How the page draws a row's value: a switch, a choice h/l steps through, a way into another
    /// page, or text.
    fn value_kind(&self, p: &Page, name: &str) -> Value {
        match st::row_kind(name) {
            RowKind::Toggle if self.row_value(p, name) == "on" => Value::On,
            RowKind::Toggle => Value::Off,
            RowKind::Choice => Value::Choice,
            RowKind::Action if matches!(name, "sign" | "shadow" | "exportkey") => Value::Link,
            RowKind::Secret => Value::Muted,
            _ => Value::Text,
        }
    }

    /// Section s's first listed row, or its last going back, or the button if it lists none.
    fn section_row(&self, s: usize, forward: bool) -> usize {
        let rows = st::section_begin(s)..st::section_begin(s + 1);
        let found = if forward {
            rows.clone().find(|&i| self.row_shown(i))
        } else {
            rows.rev().find(|&i| self.row_shown(i))
        };
        found.unwrap_or(DONE)
    }

    /// Section s, on the row picked there last if it's still listed, otherwise its first. The last
    /// page always opens on its button, so Tab then Enter leaves.
    fn go_section(&self, p: &mut Page, s: usize) {
        if s == done_page() {
            return select(p, DONE);
        }
        let mut i = p.rows[s];
        if i < st::section_begin(s) || i >= st::section_begin(s + 1) || !self.row_shown(i) {
            i = self.section_row(s, true);
        }
        p.page = s;
        select(p, i);
    }

    /// The last page's next listed row after sel, or before it for dir < 0.
    fn done_row(&self, sel: isize, dir: isize) -> Option<usize> {
        let mut i = sel + dir;
        while i >= 0 && (i as usize) < DONE {
            if self.row_shown(i as usize) {
                return Some(i as usize);
            }
            i += dir;
        }
        None
    }

    /// j/k go through the sections' listed rows in turn, then the last page's button and its rows.
    fn step(&self, p: &mut Page, dir: isize) {
        let (sel, s) = (p.sel, p.page);
        if s == done_page() {
            let i = if sel == DONE {
                if dir > 0 { self.done_row(-1, 1) } else { None }
            } else {
                self.done_row(sel as isize, dir)
            };
            match i {
                Some(i) => p.sel = i,
                None if sel == DONE && dir < 0 => {
                    let r = self.section_row(s - 1, false);
                    select(p, r);
                }
                None if dir < 0 => p.sel = DONE,
                None => {}
            }
            return;
        }
        let (a, b) = (st::section_begin(s) as isize, st::section_begin(s + 1) as isize);
        let mut i = sel as isize + dir;
        while i >= a && i < b {
            if self.row_shown(i as usize) {
                return select(p, i as usize);
            }
            i += dir;
        }
        if dir > 0 {
            select(p, self.section_row(s + 1, true));
        } else if s > 0 {
            select(p, self.section_row(s - 1, false));
        }
    }

    /// g and G: the page's first or last row, the last page's button being its first.
    fn go_end(&self, p: &mut Page, last: bool) {
        if p.page != done_page() {
            return select(p, self.section_row(p.page, !last));
        }
        p.sel = match self.done_row(DONE as isize, -1) {
            Some(i) if last => i,
            _ => DONE,
        };
    }

    /// Moves the pick off a row that stopped being listed: to the next one up in its section, or
    /// down. On the last page, back to the button.
    fn fix_sel(&self, p: &mut Page) {
        let sel = p.sel;
        if sel >= DONE || self.row_shown(sel) {
            return;
        }
        if p.page == done_page() {
            p.sel = DONE;
            return;
        }
        let s = st::section_of(sel);
        let found = (st::section_begin(s)..sel)
            .rev()
            .find(|&i| self.row_shown(i))
            .or_else(|| (sel + 1..st::section_begin(s + 1)).find(|&i| self.row_shown(i)));
        select(p, found.unwrap_or(DONE));
    }

    /// Tab and Shift+Tab: the next or previous section, round from the last to the first.
    fn section_step(&self, p: &mut Page, dir: isize) {
        let n = n_pages() as isize;
        self.go_section(p, ((p.page as isize + dir + n) % n) as usize);
    }

    /// Opens the page where it was left (a section's, not the last), or on a row, or says why the
    /// row isn't on it right now.
    pub fn open_settings(&mut self, name: Option<&str>) {
        self.behind = None;
        let mut p = self.settings_page.take().unwrap_or_default();
        self.refresh(&mut p);
        if p.page == done_page() {
            self.go_section(&mut p, 0);
        }
        self.fix_sel(&mut p);
        if let Some(i) = name.and_then(|n| PAGE.iter().position(|r| r.name == n)) {
            match self.row_hidden(i) {
                None => select(&mut p, i),
                Some(why) => self.fail(format!("{} isn't on the page right now: {why}", PAGE[i].label)),
            }
        }
        self.modal = Some(Modal::Settings(p));
    }

    /// As chat starts, once a save has opened or hasn't: the settings page, whose Start button
    /// starts chat, unless the save that opened has settings, which start it at once. Nothing goes
    /// on the network before that.
    pub(crate) fn begin_start(&mut self, had_settings: bool) {
        if self.start.is_none() {
            return;
        }
        if had_settings {
            return self.start_rooms();
        }
        self.onboarding = true;
        let mut p = Page::default();
        self.refresh(&mut p);
        self.fix_sel(&mut p);
        self.modal = Some(Modal::Settings(p));
    }

    /// The button, and Esc, q or Ctrl+S: back to the rooms, or as chat starts, starting it.
    pub(crate) fn settings_done(&mut self, p: Page) {
        self.settings_page = Some(p);
        self.behind = None;
        self.modal = None;
        if self.onboarding {
            self.onboarding = false;
            self.start_rooms();
        }
    }

    /// The settings page, looked over again.
    pub(crate) fn show_page(&mut self, mut p: Page) {
        self.refresh(&mut p);
        self.fix_sel(&mut p);
        self.modal = Some(Modal::Settings(p));
    }

    /// The page a box was opened from, again once the box has closed.
    pub(crate) fn back_to_page(&mut self) {
        if self.modal.is_none()
            && let Some(m) = self.behind.take()
        {
            match *m {
                Modal::Settings(p) => self.show_page(p),
                m => self.modal = Some(m),
            }
        }
    }

    fn keep(&mut self, p: Page) {
        self.modal = Some(Modal::Settings(p));
    }

    /// A command run from the page. One that opens a box of its own (a passphrase, a QR code)
    /// comes back to the page once the box closes.
    async fn page_command(&mut self, mut p: Page, cmd: &str) {
        self.modal = None;
        self.run(cmd).await;
        match self.modal {
            Some(Modal::Settings(_)) => {}
            Some(_) => self.behind = Some(Box::new(Modal::Settings(p))),
            None => {
                self.refresh(&mut p);
                self.fix_sel(&mut p);
                self.modal = Some(Modal::Settings(p));
            }
        }
    }

    /// h/l on a row with values to step through, the colour's palette among them.
    async fn step_value(&mut self, p: Page, name: &str, dir: isize) {
        let Some(steps) = st::steps(name) else { return self.keep(p) };
        let now = self.row_value(&p, name);
        let next = match steps.iter().position(|s| *s == now) {
            Some(i) => (i as isize + dir).rem_euclid(steps.len() as isize) as usize,
            None if name == "colour" => 0,
            None => return self.keep(p),
        };
        self.page_command(p, &format!("set {name} {}", steps[next])).await
    }

    /// A text row's edit box. A secret starts empty, and what's typed replaces it.
    pub(crate) fn begin_edit(&mut self, p: Page, name: &'static str) {
        let Some(r) = PAGE.iter().find(|r| r.name == name) else {
            return self.keep(p);
        };
        let mut input = Input::default();
        input.set(&self.row_text(name));
        self.behind = Some(Box::new(Modal::Settings(p)));
        self.modal = Some(Modal::Prompt {
            kind: PromptKind::SetRow(name),
            title: format!(" {} ", r.label.to_uppercase()),
            hint: r.help.into(),
            input,
        });
    }

    /// What the edit box typed: the row set from it, as /set NAME VALUE sets it.
    pub async fn set_row(&mut self, name: &'static str, value: &str) {
        if let Err(e) = self.set_value(name, value.trim()).await {
            self.fail(format!("{name}: {e}"));
        }
    }

    /// Left/right on a row changes its value; on the signing identity's row, right opens its page.
    /// On the last page, Enter or right on a row opens it on its section's page. / searches every
    /// section.
    pub async fn settings_key(&mut self, mut p: Page, k: KeyEvent) {
        if p.search.is_some() {
            return self.search_key(p, k);
        }
        if p.pick.is_some() {
            return self.pick_key(p, k).await;
        }
        if k.code == KeyCode::Char('/') {
            p.search = Some((Input::default(), 0));
            return self.keep(p);
        }
        if let KeyCode::Char(c @ '1'..='9') = k.code {
            let s = c as usize - '1' as usize;
            if s < n_pages() {
                self.go_section(&mut p, s);
            }
            return self.keep(p);
        }
        let sel = p.sel;
        let row = PAGE.get(sel);
        let name = row.map_or("", |r| r.name);
        let done = p.page == done_page();
        let steps = row.is_some() && !done && st::steps(name).is_some();
        let shadow = if self.save.as_ref().is_some_and(|s| s.has_shadow()) {
            "set shadow off"
        } else {
            "set shadow on"
        };
        match list_key(&k) {
            ListKey::Up => self.step(&mut p, -1),
            ListKey::Down => self.step(&mut p, 1),
            ListKey::First => self.go_end(&mut p, false),
            ListKey::Last => self.go_end(&mut p, true),
            ListKey::NextSection => self.section_step(&mut p, 1),
            ListKey::PrevSection => self.section_step(&mut p, -1),
            ListKey::Choose | ListKey::Right if !done && name == "devicelock" && self.row_greyed(&p, name) && p.device_fix.is_some() => {
                crate::app::copy_to_clipboard(p.device_fix.as_deref().unwrap_or_default());
                self.say("copied the command that opens the TPM to you: run it as root (after doas, sudo or the like), then log in again");
            }
            ListKey::Left if steps => return self.step_value(p, name, -1).await,
            ListKey::Right if done && row.is_some() => select(&mut p, sel),
            ListKey::Right if steps => return self.step_value(p, name, 1).await,
            ListKey::Right => match name {
                "sign" => p.pick = Some(self.sign_in_use()),
                "shadow" => return self.page_command(p, shadow).await,
                "exportkey" => return self.begin_export_browse(Back::Page(p)),
                _ => {}
            },
            ListKey::Choose => match row {
                None => return self.settings_done(p),
                Some(_) if done => select(&mut p, sel),
                Some(_) if steps && name != "colour" => return self.step_value(p, name, 1).await,
                Some(r) if matches!(st::row_kind(name), RowKind::Text | RowKind::Secret) => return self.begin_edit(p, r.name),
                Some(_) => match name {
                    "sign" => p.pick = Some(self.sign_in_use()),
                    "shadow" => return self.page_command(p, shadow).await,
                    "agerecipient" | "pgpkey" => return self.page_command(p, "identity copy").await,
                    "exportkey" => return self.begin_export_browse(Back::Page(p)),
                    _ => {}
                },
            },
            ListKey::Back | ListKey::Close => return self.settings_done(p),
            _ => {}
        }
        self.fix_sel(&mut p);
        self.keep(p);
    }

    /// Up/Down or Tab/Shift+Tab go through the matches, Enter opens the one picked on its
    /// section's page (or says why it isn't there), and Esc goes back.
    fn search_key(&mut self, mut p: Page, k: KeyEvent) {
        let Some((mut input, mut sel)) = p.search.take() else {
            return self.keep(p);
        };
        let found = self.search_found(&input.text());
        match k.code {
            KeyCode::Esc => {}
            KeyCode::Enter => {
                let Some(&i) = found.get(sel.min(found.len().saturating_sub(1))) else {
                    p.search = Some((input, sel));
                    return self.keep(p);
                };
                match self.row_hidden(i) {
                    None => select(&mut p, i),
                    Some(why) => self.fail(format!("{} isn't on the page right now: {why}", PAGE[i].label)),
                }
            }
            KeyCode::Up | KeyCode::BackTab => {
                sel = sel.saturating_sub(1);
                p.search = Some((input, sel));
            }
            KeyCode::Down | KeyCode::Tab => {
                if sel + 1 < found.len() {
                    sel += 1;
                }
                p.search = Some((input, sel));
            }
            _ => {
                let was = input.text();
                input.edit(&k);
                if input.text() != was {
                    sel = 0;
                }
                p.search = Some((input, sel));
            }
        }
        self.keep(p);
    }

    /// The signing identity's choice in use.
    fn sign_in_use(&self) -> usize {
        let Some(i) = &self.ident else { return 0 };
        let row = match i.origin {
            Origin::File(_) => 3,
            Origin::Pasted => 5,
            Origin::Password(None) => 2,
            _ => 1,
        };
        row + if i.kind == IdentityKind::Pgp { 5 } else { 0 }
    }

    async fn pick_key(&mut self, mut p: Page, k: KeyEvent) {
        let sel = p.pick.unwrap_or(0);
        let last = SIGN_PICKS.len() - 1;
        match list_key(&k) {
            ListKey::Choose | ListKey::Right => return self.sign_pick(p, sel).await,
            ListKey::Left | ListKey::Back => p.pick = None,
            ListKey::Close => {
                p.pick = None;
                return self.settings_done(p);
            }
            ListKey::Up => p.pick = Some(sel.saturating_sub(1)),
            ListKey::Down => p.pick = Some((sel + 1).min(last)),
            ListKey::First => p.pick = Some(0),
            ListKey::Last => p.pick = Some(last),
            _ => {}
        }
        self.keep(p);
    }

    /// A choice on the signing identity's page. Off goes back to the settings; a choice that asks
    /// for something comes back to this page after.
    async fn sign_pick(&mut self, mut p: Page, sel: usize) {
        let kind = if sel > 5 { IdentityKind::Pgp } else { IdentityKind::Age };
        let cmd = match sel {
            0 => "identity off",
            1 => "identity age",
            2 => "identity age nonick",
            6 => "identity pgp",
            7 => "identity pgp nonick",
            4 | 9 => {
                let mut input = Input::default();
                if let Some(i) = &self.ident
                    && let Origin::File(path) = &i.origin
                    && i.kind == kind
                {
                    input.set(&crate::browser::tilde(std::path::Path::new(path)));
                }
                let (title, hint) = key_path_box(kind);
                self.behind = Some(Box::new(Modal::Settings(p)));
                self.modal = Some(Modal::Prompt {
                    kind: PromptKind::KeyPath(kind),
                    title,
                    hint,
                    input,
                });
                return;
            }
            3 | 8 => return self.begin_key_browse(kind, p),
            _ => {
                self.behind = Some(Box::new(Modal::Settings(p)));
                self.modal = Some(Modal::Paste {
                    kind,
                    text: zeroize::Zeroizing::new(String::with_capacity(PASTE_MAX)),
                });
                return;
            }
        };
        self.modal = None;
        self.run(cmd).await;
        match self.modal {
            Some(_) => self.behind = Some(Box::new(Modal::Settings(p))),
            None => {
                p.pick = None;
                self.refresh(&mut p);
                self.modal = Some(Modal::Settings(p));
            }
        }
    }

    /// The paste box has more of the key. It's read once the key's line ends (AGE) or its END line
    /// arrives (PGP); one that isn't a key is let go, for another paste.
    pub(crate) fn pasted(&mut self, kind: IdentityKind, text: zeroize::Zeroizing<String>) {
        let whole = match kind {
            IdentityKind::Pgp => text.trim_end().ends_with(chat_core::protocol::crypto::pgp::PRIVATE_END),
            _ => text.ends_with('\n') && text.contains("AGE-SECRET-KEY-1"),
        };
        if !whole {
            self.modal = Some(Modal::Paste { kind, text });
            return;
        }
        match crate::identity::Ident::from_text(&text, kind) {
            Some(i) => self.use_identity(Some(i)),
            None => {
                self.fail(match kind {
                    IdentityKind::Pgp => "that isn't an unencrypted EdDSA/Ed25519 secret key - paste another, or Esc",
                    _ => "that isn't an AGE secret key - paste another, or Esc",
                });
                self.modal = Some(Modal::Paste {
                    kind,
                    text: zeroize::Zeroizing::new(String::with_capacity(PASTE_MAX)),
                });
            }
        }
    }

    /// The page's sections, and the last page after them, as the list on the left names them.
    fn nav(&self) -> Vec<String> {
        let mut v: Vec<String> = st::sections().into_iter().map(String::from).collect();
        v.push(if self.onboarding { "Start" } else { "Done" }.into());
        v
    }

    /// What the keys do on the row picked, its main action first.
    fn settings_hint(&self, p: &Page) -> String {
        let act = match PAGE.get(p.sel).map(|r| r.name) {
            None if self.onboarding => Some("enter start"),
            None => Some("enter done"),
            Some(_) if p.page == done_page() => Some("enter open"),
            Some("colour") => Some("h/l step \u{b7} enter type one"),
            Some(n) if matches!(st::row_kind(n), RowKind::Text | RowKind::Secret) => Some("enter edit"),
            Some("sign") => Some("enter choose"),
            Some("shadow") => Some("enter set"),
            Some("agerecipient" | "pgpkey") => Some("enter copy"),
            Some("exportkey") => Some("enter export"),
            Some("devicelock") if self.row_greyed(p, "devicelock") && p.device_fix.is_some() => Some("enter copy the fix"),
            Some(n) if self.row_greyed(p, n) => None,
            Some(_) => Some("h/l change"),
        };
        format!(
            "{}j/k move \u{b7} tab/1-{} section \u{b7} / search \u{b7} esc {}",
            act.map_or(String::new(), |a| format!("{a} \u{b7} ")),
            n_pages(),
            if self.onboarding { "start" } else { "done" }
        )
    }

    /// The page as it's drawn: a section's rows, or on the last page every row under its section.
    pub fn settings_view(&self, p: &Page) -> PageView {
        let done = p.page == done_page();
        let (begin, end) = if done {
            (0, PAGE.len())
        } else {
            (st::section_begin(p.page), st::section_begin(p.page + 1))
        };
        let mut rows = Vec::new();
        let mut selected = usize::MAX;
        let mut heading = None;
        for (i, r) in PAGE.iter().enumerate().take(end).skip(begin) {
            // A heading goes on the first listed row under it.
            if let Some(h) = if done { r.section } else { r.group } {
                heading = Some(h);
            }
            if !self.row_shown(i) {
                continue;
            }
            if i == p.sel {
                selected = rows.len();
            }
            let greyed = self.row_greyed(p, r.name);
            let value = if greyed {
                "can't be used here".into()
            } else {
                self.row_value(p, r.name)
            };
            // h/l don't change anything on the last page, so no row shows the arrows that say they do.
            let kind = match self.value_kind(p, r.name) {
                Value::Choice | Value::Link if done => Value::Text,
                k => k,
            };
            rows.push(PageRow {
                heading: heading.take(),
                prefix: None,
                label: if done { r.label.into() } else { st::short_label(i) },
                value: Some(value),
                kind,
                swatch: if r.name == "colour" { self.colour } else { None },
                disabled: greyed,
                permille: 0,
            });
        }
        if p.sel == DONE {
            selected = rows.len();
        }
        let installed = self.save.is_some();
        let autosave = self.settings.on("autosave");
        let (help, usage) = match PAGE.get(p.sel) {
            None => {
                let help = if self.onboarding {
                    let rest = if installed && autosave {
                        ", and what you change is saved where /install put it."
                    } else if installed {
                        ", and with autosave off, lasts until chat exits unless you /save."
                    } else if self.saves.as_ref().is_some_and(|s| !s.list().is_empty()) {
                        " and isn't saved: what /install saved stays sealed until /install opens it."
                    } else {
                        " and lasts until chat exits. It's only written to disk if you /install."
                    };
                    format!("Go on to your rooms: Ctrl+N creates one, Ctrl+J joins one. Everything here applies at once{rest}")
                } else {
                    let rest = if !installed {
                        "."
                    } else if autosave {
                        ", and is saved."
                    } else {
                        ". Autosave is off: /save saves it."
                    };
                    format!("Back to your rooms. Everything here already applies{rest}")
                };
                (help, Some("ctrl+s or /set brings this page back".to_string()))
            }
            Some(r) => {
                let greyed = self.row_greyed(p, r.name);
                let help = match r.name {
                    "securitykey" if greyed => format!(
                        "Can't be used here: {}. A security key's secret is only given after a touch, and chat needs a \
                         way to ask it for one.",
                        p.key_why.as_deref().unwrap_or_default()
                    ),
                    "devicelock" if greyed => format!(
                        "Can't be used here: {}. The device lock makes the save unlock only on this device, by sealing \
                         a secret with something the device keeps to itself: its TPM, on Linux through systemd's \
                         credential service or /dev/tpmrm0. Without that, there's nothing to seal it with.{}",
                        p.device_why.as_deref().unwrap_or_default(),
                        p.device_fix.as_deref().map_or(String::new(), |c| format!(
                            " Enter copies the command that opens it to you. Run it as root in a terminal, after doas, \
                             sudo or whichever you use (chat's sandbox keeps it from getting root itself), then log in \
                             again: {c}"
                        ))
                    ),
                    _ if greyed => format!("Not in this build yet. {}", r.help),
                    "agerecipient" if matches!(self.key_in_use(), Some((IdentityKind::Age, _))) => {
                        format!("{}: {}", self.row_value(p, r.name), r.help)
                    }
                    _ => r.help.to_string(),
                };
                let usage = if !r.values.is_empty() && !greyed {
                    Some(format!("/set {} {}", r.name, r.values))
                } else if st::row_kind(r.name) == RowKind::Secret {
                    Some(format!("/set {}", r.name))
                } else if r.name == "exportkey" {
                    Some("/exportkey".into())
                } else {
                    None
                };
                (help, usage)
            }
        };
        let nav = self.nav();
        PageView {
            title: format!("Settings \u{203a} {}", nav[p.page]),
            nav_sel: p.page,
            nav,
            intro: self.onboarding.then(|| {
                "chat is an end-to-end encrypted chat with no server. Check how it reaches peers, then press Start \
                 chatting. Nothing goes on the network before that."
                    .into()
            }),
            side: None,
            rows,
            selected,
            help,
            usage,
            button: done.then_some(if self.onboarding { "Start chatting" } else { "Done" }),
            chip: None,
            keys: false,
            empty: None,
            hint: self.settings_hint(p),
        }
    }

    /// The signing identity's page: its choices under AGE and PGP, the one in use marked.
    pub fn pick_view(&self, p: &Page) -> PageView {
        let sel = p.pick.unwrap_or(0);
        let in_use = self.sign_in_use();
        let rows = SIGN_PICKS
            .iter()
            .enumerate()
            .map(|(i, s)| PageRow {
                heading: s.section,
                prefix: None,
                label: s.label.into(),
                value: (i == in_use).then(|| "in use".into()),
                kind: if i == in_use { Value::On } else { Value::Text },
                swatch: None,
                disabled: false,
                permille: 0,
            })
            .collect();
        let sign = PAGE.iter().position(|r| r.name == "sign").unwrap_or(0);
        PageView {
            title: "Settings \u{203a} Profile \u{203a} Signing identity".into(),
            nav: self.nav(),
            nav_sel: st::section_of(sign),
            intro: None,
            side: None,
            rows,
            selected: sel,
            help: format!("{} Now: {}.", SIGN_PICKS[sel].help, self.sign_value()),
            usage: SIGN_PICKS[sel].set.map(|s| format!("/set sign {s}")),
            button: None,
            chip: None,
            keys: false,
            empty: None,
            hint: "enter choose \u{b7} j/k move \u{b7} esc back \u{b7} q close".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_the_sections_then_the_last_page() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let app = App::new(Default::default(), Some("alice".into()), tx);
        let name = |p: &Page| PAGE.get(p.sel).map_or("button", |r| r.name);
        let mut p = Page::default();
        // Tor routing leaves the UDP rows out, so down from Routing is Tor's first row.
        app.step(&mut p, 1);
        assert_eq!(name(&p), "torlaunch");
        // Up from a section's first row is the last listed row of the one before.
        app.go_section(&mut p, 1);
        assert_eq!(name(&p), "nick");
        app.step(&mut p, -1);
        assert_eq!((p.page, name(&p)), (0, "net"));
        // Down from the last section's last row is the last page, on its button.
        app.go_section(&mut p, 3);
        app.go_end(&mut p, true);
        app.step(&mut p, 1);
        assert_eq!((p.page, name(&p)), (done_page(), "button"));
        app.step(&mut p, 1);
        assert_eq!((p.page, name(&p)), (done_page(), "routing"));
        // Tab goes round to the first section, on the row picked there last.
        app.section_step(&mut p, 1);
        assert_eq!((p.page, name(&p)), (0, "net"));
    }
}
