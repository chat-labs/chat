// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The files page (Ctrl+F, f in NORMAL, /files): what's offered to you, then yours, newest first,
//! with what each is doing, its details on the left, and what Enter does with it. A picture opens
//! on a page of its own, decoded to fit the screen.

use crate::app::{App, Ask, Modal, RoomView};
use crate::browser::{Back, tilde};
use crate::settings_page::{ListKey, list_key};
use crate::ui::{PageRow, PageView, Value};
use chat_core::protocol::files::{format_duration, format_size};
use chat_core::{Eta, FileInfo, FileState};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// What a file is, as the page sorts it out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    Mine,
    Coming,
    Queued,
    Failed,
    Saved,
    /// Shown, or kept in memory.
    Here,
    /// A picture that can't be shown.
    Broken,
    /// Not fetched, and over the size limit.
    Over,
    New,
}

/// What a y/n box over the files page or the picture asks.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FileAsk {
    View,
    Show,
    Fetch,
    Retry,
    SaveTo,
    Stop,
    Unoffer,
}

fn state(r: &RoomView, f: &FileInfo, limit: u64) -> St {
    match &f.state {
        _ if f.mine => St::Mine,
        FileState::Fetching { .. } => St::Coming,
        FileState::Queued { .. } => St::Queued,
        FileState::Failed { .. } => St::Failed,
        _ if f.saved.is_some() => St::Saved,
        _ if f.shown || r.pictures.contains_key(&f.num) => St::Here,
        _ if r.pic_why.contains_key(&f.num) => St::Broken,
        _ if f.size > limit => St::Over,
        _ => St::New,
    }
}

/// The room's files in the page's order: those offered to you, then yours, newest first.
pub fn files_list(r: &RoomView) -> Vec<&FileInfo> {
    let mut l: Vec<&FileInfo> = r.files.iter().collect();
    l.sort_by_key(|f| (f.mine, std::cmp::Reverse(f.num)));
    l
}

/// How far a fetch has got, as a share and as words.
fn progress(f: &FileInfo) -> (u32, String) {
    match &f.state {
        FileState::Fetching { got, eta } => {
            let pm = (got * 1000).checked_div(f.size).unwrap_or(0).min(1000) as u32;
            let left = match eta {
                Eta::Seconds(s) => format!("{} left", format_duration(*s as f64)),
                Eta::WaitingSender => "waiting for the sender to come back".into(),
                Eta::WaitingVerify => "waiting: compare codes with the sender".into(),
            };
            (pm, format!("{}% \u{b7} {left}", pm / 10))
        }
        FileState::Queued { after: Some(n) } => (0, format!("queued after file {n}")),
        FileState::Queued { after: None } => (0, "queued until the sender is back".into()),
        _ => (0, String::new()),
    }
}

impl App {
    fn file_limit(&self) -> u64 {
        self.settings.file_limit()
    }

    /// Fetching f now would take it past the size limit: it's over, and there's no copy here.
    fn needs_anyway(&self, r: &RoomView, f: &FileInfo) -> bool {
        !f.mine
            && f.size > self.file_limit()
            && !f.shown
            && f.saved.is_none()
            && !matches!(f.state, FileState::Fetching { .. } | FileState::Queued { .. })
            && !r.pictures.contains_key(&f.num)
    }

    /// The files page, on the newest file.
    pub fn begin_files(&mut self) {
        let Some(r) = self.room().filter(|r| r.room().is_some()) else {
            return self.fail("no room open - ctrl+n starts one, ctrl+j joins one");
        };
        let newest = r.files.iter().map(|f| f.num).max().unwrap_or(0);
        self.modal = Some(Modal::Files(newest));
    }

    fn value(&self, r: &RoomView, f: &FileInfo) -> (Value, String, u32) {
        let sz = format_size(f.size);
        match state(r, f, self.file_limit()) {
            St::Mine => match (&f.sending, &f.state) {
                (Some(s), _) => (
                    Value::Progress,
                    format!(
                        "{}% \u{b7} sending to {}{}",
                        s.permille / 10,
                        s.name,
                        if s.count > 1 { " and others" } else { "" }
                    ),
                    s.permille,
                ),
                (None, _) if !f.sent_to.is_empty() => (Value::On, format!("sent to {}", f.sent_to.join(", ")), 0),
                (None, FileState::Withdrawn) => (Value::Muted, "no longer offered".into(), 0),
                _ => (Value::Text, format!("offered \u{b7} {sz}"), 0),
            },
            St::Coming | St::Queued => {
                let (pm, text) = progress(f);
                (Value::Progress, text, pm)
            }
            St::Failed => match &f.state {
                FileState::Failed { why } => (Value::Bad, why.clone(), 0),
                _ => (Value::Bad, "it didn't finish".into(), 0),
            },
            St::Saved => (Value::On, format!("saved \u{b7} {sz}"), 0),
            St::Here => {
                let shown = r.pictures.contains_key(&f.num) && !r.hidden.contains(&f.num);
                (
                    Value::On,
                    format!("{} \u{b7} {sz}", if shown { "shown" } else { "here, hidden" }),
                    0,
                )
            }
            St::Broken => (Value::Bad, "can't be shown".into(), 0),
            St::Over => (Value::Off, format!("{sz} \u{b7} over your size limit"), 0),
            St::New => (Value::Off, format!("{} \u{b7} {sz}", if f.image { "picture" } else { "file" }), 0),
        }
    }

    /// The left hand box: the file's name, what it is, who from, when, and what it's doing.
    fn details(&self, r: &RoomView, f: &FileInfo) -> Vec<String> {
        let sz = format_size(f.size);
        let mut out = vec![
            f.name.clone(),
            String::new(),
            format!("{} \u{b7} {sz}", if f.image { "picture" } else { "file" }),
            if f.mine { "yours".into() } else { format!("from {}", f.from_name) },
            format!("file {}, at {}", f.num, crate::text::hhmm(f.at)),
            String::new(),
        ];
        match state(r, f, self.file_limit()) {
            St::Mine => {
                out.push(match (&f.sending, &f.state) {
                    (Some(s), _) => format!("sending to {}: {}%", s.name, s.permille / 10),
                    (None, FileState::Withdrawn) => "no longer offered".into(),
                    _ => "offered to everyone here".into(),
                });
                if !f.sent_to.is_empty() {
                    out.push(format!("sent to {}", f.sent_to.join(", ")));
                }
            }
            St::Coming | St::Queued => out.extend(progress(f).1.split(" \u{b7} ").map(String::from)),
            St::Failed => out.push(match &f.state {
                FileState::Failed { why } => format!("failed: {why}"),
                _ => "failed: it didn't finish".into(),
            }),
            St::Saved => {
                let shown = tilde(std::path::Path::new(f.saved.as_deref().unwrap_or_default()));
                let (dir, name) = shown.rsplit_once('/').unwrap_or(("", &shown));
                out.extend([
                    "saved in".to_string(),
                    if dir.is_empty() { "/".into() } else { dir.into() },
                    format!("as {name}"),
                ]);
            }
            St::Here => {
                let shown = r.pictures.contains_key(&f.num) && !r.hidden.contains(&f.num);
                out.push(if shown { "shown in the chat" } else { "here, hidden in the chat" }.into());
                out.push("only in memory".into());
            }
            St::Broken => out.push(format!("can't be shown: {}", r.pic_why.get(&f.num).cloned().unwrap_or_default())),
            St::Over => out.push(format!("not fetched, and over your {} limit", format_size(self.file_limit()))),
            St::New => out.push("not fetched yet".into()),
        }
        out
    }

    /// What Enter does with f, for the bar, or None for nothing.
    fn enter_word(&self, r: &RoomView, f: &FileInfo) -> Option<&'static str> {
        let st = state(r, f, self.file_limit());
        if f.image && st != St::Broken {
            return Some(if matches!(st, St::New | St::Over | St::Failed) {
                "show"
            } else {
                "view"
            });
        }
        match st {
            St::New | St::Over => Some("download"),
            St::Failed => Some("retry"),
            _ => None,
        }
    }

    /// The help along the bottom, and the command that does what Enter does.
    fn file_help(&self, r: &RoomView, f: &FileInfo) -> (String, Option<String>) {
        let save = "d saves it in Downloads, s in a folder you pick.";
        let n = f.num;
        match state(r, f, self.file_limit()) {
            St::Mine if matches!(f.state, FileState::Withdrawn) => {
                ("Yours, and no longer offered. /send offers it again, as a new file.".into(), None)
            }
            St::Mine => (
                format!(
                    "Yours, offered to everyone here{}.{} x stops offering it.",
                    if self.settings.get("verify") == "required" {
                        " whose verify code you've compared"
                    } else {
                        ""
                    },
                    if f.image { " Enter shows it big." } else { "" }
                ),
                Some(format!("/cancel {n}")),
            ),
            st @ (St::Coming | St::Queued) => (
                format!(
                    "{}{} x stops it.",
                    if st == St::Queued {
                        "Queued: one file comes from each sender at a time."
                    } else {
                        "On its way."
                    },
                    if f.image {
                        " Enter shows how far it's got, then the picture."
                    } else {
                        ""
                    }
                ),
                Some(format!("/cancel {n}")),
            ),
            St::Failed => {
                let why = match &f.state {
                    FileState::Failed { why } => why.clone(),
                    _ => "it stopped".into(),
                };
                (
                    format!("Failed: {why}. Enter tries again. {save}"),
                    Some(format!("/{} {n}", if f.image { "show" } else { "download" })),
                )
            }
            St::Saved => (
                format!(
                    "Saved as {}.{} y copies where it is, s saves a copy in another folder.",
                    tilde(std::path::Path::new(f.saved.as_deref().unwrap_or_default())),
                    if f.image { " Enter shows it big, v in the chat." } else { "" }
                ),
                Some(format!("/saveto {n}")),
            ),
            St::Here => (
                format!("Enter shows it big, v shows or hides it in the chat. It's only in memory: {save}"),
                Some(format!("/download {n}")),
            ),
            St::Broken => (
                format!(
                    "chat can't show it ({}). d saves it in Downloads, to open with something else.",
                    r.pic_why.get(&n).cloned().unwrap_or_default()
                ),
                Some(format!("/download {n}")),
            ),
            st => {
                let over = if st == St::Over {
                    " It's over your file size limit, so chat asks first."
                } else {
                    ""
                };
                let help = if f.image {
                    format!(
                        "{} offers it. Enter fetches it and shows it big, and in the chat under the offer. {save}{over}",
                        f.from_name
                    )
                } else {
                    format!(
                        "{} offers it. Enter saves it in Downloads, s in a folder you pick. Nothing is fetched until you ask.{over}",
                        f.from_name
                    )
                };
                let cmd = format!(
                    "/{} {n}{}",
                    if f.image { "show" } else { "download" },
                    if over.is_empty() { "" } else { " anyway" }
                );
                (help, Some(cmd))
            }
        }
    }

    /// The files page as it's drawn.
    pub fn files_view(&self, num: u32) -> PageView {
        let Some(r) = self.room() else {
            return PageView::empty("Files", "No room open\nctrl+n starts one, ctrl+j joins one");
        };
        let l = files_list(r);
        let sel = l.iter().position(|f| f.num == num).unwrap_or(0);
        let digits = l.iter().map(|f| f.num.to_string().len()).max().unwrap_or(1);
        let rows: Vec<PageRow> = l
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let (kind, value, permille) = self.value(r, f);
                let heading = (i == 0 || l[i - 1].mine != f.mine).then_some(if f.mine { "Yours" } else { "Offered to you" });
                PageRow {
                    heading,
                    prefix: Some(format!("{:>digits$}  ", f.num)),
                    label: f.name.clone(),
                    value: Some(value),
                    kind,
                    swatch: None,
                    disabled: false,
                    permille,
                }
            })
            .collect();
        let theirs = l.iter().filter(|f| !f.mine).count();
        let coming = l
            .iter()
            .filter(|f| matches!(f.state, FileState::Fetching { .. } | FileState::Queued { .. }))
            .count();
        let mut parts = Vec::new();
        if theirs > 0 {
            parts.push(format!("{theirs} offered to you"));
        }
        if coming > 0 {
            parts.push(format!("{coming} on the way"));
        }
        if l.len() > theirs {
            parts.push(format!("{} yours", l.len() - theirs));
        }
        let (nav, help, usage, hint) = match l.get(sel) {
            Some(f) => {
                let (help, usage) = self.file_help(r, f);
                (self.details(r, f), help, usage, self.files_hint(r, f))
            }
            None => (Vec::new(), String::new(), None, "n send a file \u{b7} esc close".into()),
        };
        PageView {
            title: format!("{} \u{203a} Files", r.label),
            nav,
            nav_sel: 0,
            intro: Some(parts.join(" \u{b7} ")),
            side: None,
            rows,
            selected: sel,
            help,
            usage,
            button: None,
            chip: Some("FILES"),
            keys: false,
            empty: Some(
                "Nothing's been offered here yet\nWhat peers offer shows up here, and nothing is fetched until you ask.\nn sends a file of yours, or /send PATH"
                    .into(),
            ),
            hint,
        }
    }

    fn files_hint(&self, r: &RoomView, f: &FileInfo) -> String {
        let enter = self.enter_word(r, f);
        let st = state(r, f, self.file_limit());
        let mut parts: Vec<String> = Vec::new();
        if let Some(e) = enter {
            parts.push(format!("enter {e}"));
        }
        if f.saved.is_some() {
            parts.push("y copy path".into());
        }
        if !f.mine && enter != Some("download") {
            parts.push("d download".into());
        }
        if !f.mine {
            parts.push("s save in".into());
        }
        if (f.mine && !matches!(f.state, FileState::Withdrawn)) || matches!(st, St::Coming | St::Queued) {
            parts.push("x stop".into());
        }
        parts.push("n send".into());
        parts.push("esc close".into());
        parts.join(" \u{b7} ")
    }

    /// A box that asks before a file action, over the page it's asked from.
    fn file_ask(&mut self, what: FileAsk, num: u32, from: Modal) {
        let Some(f) = self.room().and_then(|r| r.files.iter().find(|f| f.num == num)).cloned() else {
            return;
        };
        let (title, keys, text) = match what {
            FileAsk::Stop => {
                let got = match f.state {
                    FileState::Fetching { got, .. } => got,
                    _ => 0,
                };
                (
                    "STOP",
                    "y stop \u{b7} n keep it coming",
                    format!(
                        "Stop fetching {}? The {} that's come so far is thrown away, and fetching it again starts from the beginning.",
                        f.name,
                        format_size(got)
                    ),
                )
            }
            FileAsk::Unoffer => (
                "STOP",
                "y stop offering \u{b7} n keep offering",
                format!(
                    "Stop offering {}? Nobody can fetch it after this, and anyone fetching it now stops. /send offers it again, as a new file.",
                    f.name
                ),
            ),
            _ => (
                "OVER YOUR LIMIT",
                "y fetch it \u{b7} n cancel",
                format!(
                    "{} is {}, over your {} file size limit. Fetch it anyway{}?",
                    f.name,
                    format_size(f.size),
                    format_size(self.file_limit()),
                    match what {
                        FileAsk::SaveTo => ", into a folder you pick",
                        FileAsk::View | FileAsk::Show => ", to show it",
                        _ => "",
                    }
                ),
            ),
        };
        self.behind = Some(Box::new(from));
        self.modal = Some(Modal::Ask {
            title,
            paras: vec![text],
            keys,
            then: Ask::File(what, num),
        });
    }

    /// y on a file's box.
    pub(crate) async fn file_answer(&mut self, what: FileAsk, num: u32) {
        let back = self.behind.take().map(|m| *m);
        match what {
            FileAsk::SaveTo => {
                let to = match back {
                    Some(Modal::Picture(n)) => Back::Files(n),
                    _ => Back::Files(num),
                };
                return self.begin_save_browse(num, true, to);
            }
            FileAsk::Stop | FileAsk::Unoffer => self.run(&format!("cancel {num}")).await,
            FileAsk::Fetch | FileAsk::Retry => self.run(&format!("download {num} anyway")).await,
            FileAsk::Show => self.run(&format!("show {num} anyway")).await,
            FileAsk::View => {
                self.run(&format!("show {num} anyway")).await;
                if self.modal.is_none() {
                    self.modal = Some(Modal::Picture(num));
                }
                return;
            }
        }
        if self.modal.is_none() {
            self.modal = back;
        }
    }

    /// The keys the files page and the picture share: d downloads, s saves in a folder picked, v
    /// shows or hides a picture in the chat, x stops it, y copies where it was saved.
    async fn file_action(&mut self, ch: char, num: u32, from: Modal) -> bool {
        let Some(r) = self.room() else { return false };
        let Some(f) = r.files.iter().find(|f| f.num == num).cloned() else {
            return false;
        };
        let needs_anyway = self.needs_anyway(r, &f);
        let shown_here = r.pictures.contains_key(&num);
        match ch {
            'd' | 's' if f.mine => self.fail(format!("file {num} is yours")),
            'd' if needs_anyway => self.file_ask(FileAsk::Fetch, num, from),
            'd' => self.run(&format!("download {num}")).await,
            's' if needs_anyway => self.file_ask(FileAsk::SaveTo, num, from),
            's' => {
                let to = Back::Files(num);
                self.begin_save_browse(num, false, to);
                return true;
            }
            'v' if !f.image => self.fail(format!("only pictures are shown in the chat - d saves {}", f.name)),
            'v' if shown_here => {
                let hidden = self.room().is_some_and(|r| r.hidden.contains(&num));
                self.run(&format!("{} {num}", if hidden { "show" } else { "hide" })).await;
                self.say(if hidden {
                    format!("file {num} is shown in the chat")
                } else {
                    format!("file {num} is hidden in the chat - v shows it again")
                });
            }
            'v' if needs_anyway => self.file_ask(FileAsk::Show, num, from),
            'v' => self.run(&format!("show {num}")).await,
            'x' if f.mine && !matches!(f.state, FileState::Withdrawn) => self.file_ask(FileAsk::Unoffer, num, from),
            'x' if f.mine => self.fail(format!("file {num} isn't offered any more")),
            'x' if matches!(f.state, FileState::Fetching { .. }) => self.file_ask(FileAsk::Stop, num, from),
            'x' if matches!(f.state, FileState::Queued { .. }) => self.run(&format!("cancel {num}")).await,
            'x' => self.fail(format!("file {num} isn't on its way - there's nothing to stop")),
            'y' => match &f.saved {
                Some(p) => {
                    crate::app::copy_to_clipboard(p);
                    self.say(format!("copied {} to the clipboard (OSC 52)", tilde(std::path::Path::new(p))));
                }
                None if f.mine => self.fail(format!("file {num} is yours, not a copy chat saved")),
                None => self.fail(format!("file {num} isn't saved - d saves it")),
            },
            _ => return false,
        }
        true
    }

    /// Enter: a picture opens on a page of its own, fetched first if it isn't here. A file is
    /// saved in Downloads.
    async fn file_open(&mut self, num: u32) {
        let Some(r) = self.room() else { return };
        let Some(f) = r.files.iter().find(|f| f.num == num).cloned() else {
            return;
        };
        let st = state(r, &f, self.file_limit());
        let needs_anyway = self.needs_anyway(r, &f);
        if f.image && st != St::Broken {
            if matches!(st, St::New | St::Over | St::Failed) {
                if needs_anyway {
                    return self.file_ask(FileAsk::View, num, Modal::Files(num));
                }
                self.run(&format!("show {num}")).await;
            }
            self.modal = Some(Modal::Picture(num));
            return;
        }
        match st {
            St::Mine => self.say(format!("file {num} is yours - x stops offering it")),
            St::Broken => self.say("chat can't show it - d saves it"),
            St::Coming => self.say(format!("file {num} is on its way - x stops it")),
            St::Queued => self.say(format!("file {num} is queued - x takes it off the queue")),
            St::Saved => self.say(format!(
                "saved as {} - y copies where it is",
                tilde(std::path::Path::new(f.saved.as_deref().unwrap_or_default()))
            )),
            St::Failed if needs_anyway => return self.file_ask(FileAsk::Retry, num, Modal::Files(num)),
            St::Over => return self.file_ask(FileAsk::Fetch, num, Modal::Files(num)),
            _ => self.run(&format!("download {num}")).await,
        }
        if self.modal.is_none() {
            self.modal = Some(Modal::Files(num));
        }
    }

    pub(crate) async fn files_key(&mut self, num: u32, k: KeyEvent) {
        let Some(r) = self.room() else { return };
        let l: Vec<(u32, bool)> = files_list(r).iter().map(|f| (f.num, f.mine)).collect();
        let sel = l.iter().position(|(n, _)| *n == num).unwrap_or(0);
        let cur = l.get(sel).map(|(n, _)| *n);
        if let KeyCode::Char(ch) = k.code
            && !k.modifiers.contains(KeyModifiers::CONTROL)
        {
            if ch == 'n' {
                return self.begin_send_browse(false, Back::Files(num));
            }
            if let Some(n) = cur
                && self.file_action(ch, n, Modal::Files(n)).await
            {
                if self.modal.is_none() {
                    self.modal = Some(Modal::Files(n));
                }
                return;
            }
        }
        let num = match list_key(&k) {
            ListKey::Choose | ListKey::Right => {
                if let Some(n) = cur {
                    self.file_open(n).await;
                }
                return;
            }
            ListKey::Left | ListKey::Back | ListKey::Close => return,
            // To the other section: theirs and yours.
            ListKey::NextSection | ListKey::PrevSection => {
                let mine = l.get(sel).is_some_and(|(_, m)| *m);
                l.iter().find(|(_, m)| *m != mine).map_or(num, |(n, _)| *n)
            }
            ListKey::Up => l.get(sel.saturating_sub(1)).map_or(num, |(n, _)| *n),
            ListKey::Down => l.get((sel + 1).min(l.len().saturating_sub(1))).map_or(num, |(n, _)| *n),
            ListKey::First => l.first().map_or(num, |(n, _)| *n),
            ListKey::Last => l.last().map_or(num, |(n, _)| *n),
            ListKey::None => num,
        };
        self.modal = Some(Modal::Files(num));
    }

    /// The picture page: j and k go to the next and previous picture in the files page's order.
    pub(crate) async fn picture_key(&mut self, num: u32, k: KeyEvent) {
        let Some(r) = self.room() else { return };
        let pics: Vec<u32> = files_list(r).iter().filter(|f| f.image).map(|f| f.num).collect();
        let at = pics.iter().position(|n| *n == num);
        if let KeyCode::Char(ch) = k.code
            && !k.modifiers.contains(KeyModifiers::CONTROL)
            && self.file_action(ch, num, Modal::Picture(num)).await
        {
            if self.modal.is_none() {
                self.modal = Some(Modal::Picture(num));
            }
            return;
        }
        let next = match list_key(&k) {
            ListKey::Down => at.and_then(|i| pics.get(i + 1)).copied().unwrap_or(num),
            ListKey::Up => at.and_then(|i| i.checked_sub(1)).and_then(|i| pics.get(i)).copied().unwrap_or(num),
            ListKey::First => pics.first().copied().unwrap_or(num),
            ListKey::Last => pics.last().copied().unwrap_or(num),
            ListKey::Choose | ListKey::Right => {
                self.view_fetch(num).await;
                num
            }
            ListKey::Left | ListKey::Back => return self.modal = Some(Modal::Files(num)),
            ListKey::Close => return,
            _ => num,
        };
        if self.modal.is_none() {
            self.modal = Some(Modal::Picture(next));
        }
    }

    async fn view_fetch(&mut self, num: u32) {
        let Some(r) = self.room() else { return };
        let Some(f) = r.files.iter().find(|f| f.num == num).cloned() else {
            return;
        };
        if r.picture_data.contains_key(&num) {
            return;
        }
        match state(r, &f, self.file_limit()) {
            St::Coming | St::Queued => self.say("on its way - it's shown here once it's come"),
            St::Mine => self.say("it can't be shown - it's changed since you offered it, or isn't offered any more"),
            St::Broken => self.say("chat can't show it - d saves it"),
            _ if self.needs_anyway(r, &f) => self.file_ask(FileAsk::Show, num, Modal::Picture(num)),
            _ => self.run(&format!("show {num}")).await,
        }
    }

    pub fn picture_hint(&self, num: u32) -> String {
        let Some(r) = self.room() else { return "esc back".into() };
        let Some(f) = r.files.iter().find(|f| f.num == num) else {
            return "esc back".into();
        };
        let st = state(r, f, self.file_limit());
        let fetch = !r.picture_data.contains_key(&num) && !matches!(st, St::Mine | St::Coming | St::Queued | St::Broken);
        format!(
            "{}j/k next/previous \u{b7} {}v in chat \u{b7} esc back",
            if fetch { "enter fetch \u{b7} " } else { "" },
            if f.mine {
                "x stop offering \u{b7} "
            } else {
                "d download \u{b7} s save in \u{b7} "
            }
        )
    }

    /// What the picture page says when there's no picture to show, or its caption when there is.
    pub fn picture_text(&self, num: u32) -> (String, String, Option<(u32, String)>) {
        let Some(r) = self.room() else {
            return (
                String::new(),
                "That picture isn't here any more\nesc goes back to the files".into(),
                None,
            );
        };
        let Some(f) = r.files.iter().find(|f| f.num == num) else {
            return (
                format!("{} \u{203a} Files", r.label),
                "That picture isn't here any more\nesc goes back to the files".into(),
                None,
            );
        };
        let title = format!("{} \u{203a} Files \u{203a} {}", r.label, f.name);
        let pics: Vec<u32> = files_list(r).iter().filter(|x| x.image).map(|x| x.num).collect();
        let of = match pics.iter().position(|n| *n == num) {
            Some(i) if pics.len() > 1 => format!(" \u{b7} {} of {}", i + 1, pics.len()),
            _ => String::new(),
        };
        let sz = format_size(f.size);
        let from = if f.mine {
            "yours".to_string()
        } else {
            format!("from {}", f.from_name)
        };
        let caption = format!("{} \u{b7} {sz} \u{b7} {from}{of}", f.name);
        let note = match state(r, f, self.file_limit()) {
            _ if r.picture_data.contains_key(&num) || r.pictures.contains_key(&num) => caption.clone(),
            St::Coming | St::Queued => {
                let (pm, text) = progress(f);
                let text = text.split_once(" \u{b7} ").map_or(text.clone(), |(_, rest)| rest.to_string());
                return (title, format!("On its way\n{sz} from {}", f.from_name), Some((pm, text)));
            }
            St::Failed => format!(
                "It didn't finish\n{}\nenter tries again",
                match &f.state {
                    FileState::Failed { why } => why.clone(),
                    _ => "it stopped".into(),
                }
            ),
            St::Over => format!("Not fetched yet\n{sz}, over your file size limit\nenter fetches it, after asking"),
            St::New => format!(
                "Not fetched yet\n{sz} from {}\nenter fetches it \u{b7} d saves it in Downloads",
                f.from_name
            ),
            St::Mine => "It can't be shown\nit's changed since you offered it, or it isn't offered any more".into(),
            St::Broken => format!(
                "chat can't show this picture\n{}\nd saves it, to open with something else",
                r.pic_why.get(&num).cloned().unwrap_or_default()
            ),
            _ => "It isn't here any more\nthe copy shown was dropped from memory, or the saved one has changed\nenter fetches it again"
                .into(),
        };
        (title, note, None)
    }
}
