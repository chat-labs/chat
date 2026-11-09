// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Drawing: the sidebar (rooms, people), the messages, the input line, the hint bar, and dialogs.

use crate::app::{App, EntryKind, Input, Modal, PromptKind, RoomState, RoomView, SPINNER};
use crate::text::{hhmm, width, wrap};
use chat_core::{CodeState, Colour, FileState, Level, RouteMode};
use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, Paragraph, Widget};

/// The terminal's background, once it has said what it is: 0, or 1 << 24 and its RGB.
static BACKGROUND: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// What the terminal says its background is, when it starts and each time its theme changes.
pub fn set_background(c: [u8; 3]) {
    let v = 1 << 24 | u32::from(c[0]) << 16 | u32::from(c[1]) << 8 | u32::from(c[2]);
    BACKGROUND.store(v, std::sync::atomic::Ordering::Relaxed);
}

fn background() -> Option<[u8; 3]> {
    let v = BACKGROUND.load(std::sync::atomic::Ordering::Relaxed);
    (v != 0).then_some([(v >> 16) as u8, (v >> 8) as u8, v as u8])
}

/// Relative luminance, using a gamma of 2 to approximate sRGB's curve.
fn lum(c: [u8; 3]) -> f64 {
    let [r, g, b] = c.map(|v| v as f64 / 255.0);
    0.2126 * r * r + 0.7152 * g * g + 0.0722 * b * b
}

fn contrast(a: [u8; 3], b: [u8; 3]) -> f64 {
    let (la, lb) = (lum(a) + 0.05, lum(b) + 0.05);
    if la > lb { la / lb } else { lb / la }
}

fn is_dark(c: [u8; 3]) -> bool {
    lum(c) < 0.25
}

/// A person's colour, moved toward the terminal's foreground until it's readable on the
/// background: yellow on a light theme gets darker, indigo on a dark one lighter. Readable is
/// WCAG's contrast for large text, reached in at most 12 steps of a fifth of the way each.
fn readable(mut c: [u8; 3]) -> [u8; 3] {
    let Some(bg) = background() else { return c };
    let toward: i32 = if is_dark(bg) { 255 } else { 0 };
    for _ in 0..12 {
        if contrast(c, bg) >= 3.0 {
            break;
        }
        c = c.map(|v| (v as i32 + (toward - v as i32) / 5) as u8);
    }
    c
}

fn rgb(c: Colour) -> Color {
    let [r, g, b] = readable(c.0);
    Color::Rgb(r, g, b)
}

/// The picked row's background: a little lighter than a dark background, or darker than a light
/// one. None until the terminal has said what its background is.
fn sel_bg() -> Option<Color> {
    let bg = background()?;
    let s = bg.map(|v| if is_dark(bg) { v + (255 - v) / 9 } else { v - v / 16 });
    Some(Color::Rgb(s[0], s[1], s[2]))
}

/// What the bottom row says: where you are (the chip, in the tone of what the keys do there), and
/// what the keys do. The lock screen's is anonymous: it doesn't say who you are.
struct Bar {
    chip: String,
    tone: Color,
    hint: String,
    anonymous: bool,
}

impl Bar {
    /// A page's, or a box's: in the pages' and prompts' colour.
    fn page(chip: &str, hint: &str) -> Bar {
        Bar {
            chip: chip.into(),
            tone: Color::Magenta,
            hint: hint.into(),
            anonymous: false,
        }
    }
}

/// Everything is drawn in the terminal's own colours: its foreground and background, faint text
/// for what's secondary (box borders among it), and its palette for accents. So the UI matches the
/// terminal's theme, whatever it is. Peers' colours are the only exception (see readable()).
pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let [frame, bar_area] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(area);
    // Locked: nothing says whose chat it is, or which save.
    if let Some(lock) = &app.locked {
        f.render_widget(Clear, frame);
        let d = lock_dialog(app, lock);
        let cursor = draw_dialog(f, frame, &d);
        let bar = Bar {
            anonymous: true,
            ..Bar::page("LOCKED", &d.keys)
        };
        draw_status(f, app, bar_area, &bar);
        if let Some(c) = cursor {
            f.set_cursor_position(c);
        }
        return;
    }
    // A page, or the chat; then the box over it, if one is open.
    let page = match &app.modal {
        Some(m) if m.is_page() => Some(m),
        Some(_) => app.behind.as_deref().filter(|m| m.is_page()),
        None => None,
    };
    let over = app.modal.as_ref().is_some_and(|m| !m.is_page()) || app.key_wait.is_some() || app.asking_quit;
    let (mut bar, mut cursor) = match page {
        Some(m) => draw_page_modal(f, app, m, frame),
        None => draw_chat(f, app, frame, over),
    };
    if let Some(m) = app.modal.as_ref().filter(|m| !m.is_page()) {
        let (d, chip) = modal_dialog(app, m);
        cursor = match m {
            Modal::Update => draw_update(f, frame),
            _ => draw_dialog(f, frame, &d),
        };
        // Over a page, the bar still says which.
        bar = Bar::page(if page.is_some() { &bar.chip } else { chip }, &d.keys);
    }
    // A security key being waited for: what to do with it, over everything.
    if let Some(w) = &app.key_wait {
        use chat_core::net::seckey::Wait;
        let stage = w.stage.load(std::sync::atomic::Ordering::Acquire);
        let text = match (stage, &app.key_save) {
            (Wait::LOOKING, None) => "Plug in your security key.".to_string(),
            (Wait::LOOKING, Some(s)) => format!("Plug in the security key the save {s} was locked with."),
            (Wait::TOUCH, None) => format!(
                "Touch your security key now ({} of 2): it's blinking.",
                w.touches.load(std::sync::atomic::Ordering::Acquire) + 1
            ),
            (Wait::TOUCH, Some(s)) => format!("Touch your security key now, to open {s}: it's blinking."),
            _ => "Asking the security key...".into(),
        };
        let d = Dialog {
            title: "SECURITY KEY".into(),
            text: paras(&[text]),
            keys: "esc cancel".into(),
            ..Dialog::default()
        };
        draw_dialog(f, frame, &d);
        cursor = None;
        let chip = match (&app.key_save, page) {
            (Some(_), _) => "UNLOCK",
            (None, Some(_)) => &bar.chip,
            (None, None) => "SETTINGS",
        };
        bar = Bar::page(chip, &d.keys);
    }
    if app.asking_quit {
        let d = Dialog {
            title: "QUIT".into(),
            text: paras(&app.quit_paras()),
            keys: "ctrl+c/y quit \u{b7} n stay".into(),
            ..Dialog::default()
        };
        draw_dialog(f, frame, &d);
        cursor = None;
        bar = Bar::page("QUIT", &d.keys);
    }
    draw_status(f, app, bar_area, &bar);
    if let Some(c) = cursor {
        f.set_cursor_position(c);
    }
}

/// The chat screen, as one frame: the sidebar's right side is the chat's left, and the chat's
/// bottom edge is the input box's top. `over`: a box is open over it, so the input box doesn't
/// take the keys, and its border is faint.
fn draw_chat(f: &mut Frame, app: &App, frame: Rect, over: bool) -> (Bar, Option<(u16, u16)>) {
    let boxed = frame.height + 1 >= BOXED_ROWS && frame.width >= BOXED_COLS;
    let sbw = if boxed && app.show_sidebar {
        chat_left_width(frame.width)
    } else {
        0
    };
    if sbw > 0 {
        draw_sidebar(f, app, Rect { width: sbw, ..frame });
    }
    let x = sbw.saturating_sub(1);
    let col = Rect {
        x: frame.x + x,
        width: frame.width - x,
        ..frame
    };
    let input_h = if boxed { 3 } else { 1 };
    let input = Rect {
        y: col.bottom().saturating_sub(input_h),
        height: input_h.min(col.height),
        ..col
    };
    let main = Rect {
        height: (col.height + u16::from(boxed)).saturating_sub(input_h),
        ..col
    };
    draw_main(f, app, main, boxed, sbw > 0);
    let cursor = draw_input(f, app, input, main, boxed, sbw > 0, over);
    let bar = Bar {
        chip: app.mode.name().to_string(),
        tone: tone(app),
        hint: chat_hint(app),
        anonymous: false,
    };
    (bar, (!over).then_some(cursor).flatten())
}

fn spinner(app: &App) -> char {
    SPINNER[app.spinner]
}

/// The left hand box's title: "◆ chat", and the version at its right.
fn brand(w: u16) -> (Vec<Span<'static>>, Vec<Span<'static>>) {
    let right = vec![Span::styled(format!("v{}", env!("CARGO_PKG_VERSION")), faint())];
    let room = title_room(w as usize, spans_width(&right));
    (vec![Span::styled(ell("\u{25c6} chat", room), accent_bold())], right)
}

/// A list with more entries than rows scrolls, with a row saying how many are above and one saying
/// how many are below while there are any, given LIST_ROWS_MIN rows for them.
const LIST_ROWS_MIN: usize = 3;

#[derive(Clone, Copy, Default)]
struct ListView {
    top: usize,
    shown: usize,
    above: bool,
    below: bool,
    most: usize,
}

fn list_view(n: usize, rows: usize, top: usize) -> ListView {
    let mut v = ListView {
        shown: n.min(rows),
        ..Default::default()
    };
    if n <= rows || rows == 0 {
        return v;
    }
    let marks = rows >= LIST_ROWS_MIN;
    v.most = if marks { n - rows + 1 } else { n - rows };
    v.top = top.min(v.most);
    v.above = marks && v.top > 0;
    v.shown = rows - usize::from(v.above);
    if marks && v.top + v.shown < n {
        v.below = true;
        v.shown -= 1;
    }
    v
}

/// Scrolled so entry sel is in view.
fn list_view_at(n: usize, rows: usize, top: usize, sel: Option<usize>) -> ListView {
    let mut v = list_view(n, rows, top);
    let Some(sel) = sel.filter(|s| *s < n) else { return v };
    if sel < v.top {
        v = list_view(n, rows, sel);
    }
    while sel >= v.top + v.shown && v.top < v.most {
        v = list_view(n, rows, v.top + 1);
    }
    v
}

/// Each list's rows: either gets all it needs while that leaves the other half, otherwise they
/// share them evenly.
fn split_rows(rows: usize, a: usize, b: usize) -> (usize, usize) {
    let half = rows / 2;
    if a + b <= rows {
        (a, b)
    } else if a <= rows - half {
        (a, rows - a)
    } else if b <= half {
        (rows - b, b)
    } else {
        (rows - half, half)
    }
}

fn list_cramped(rows: usize, n: usize) -> bool {
    rows < n && rows < LIST_ROWS_MIN
}

/// What applies to a peer: its glyph, the words for it, and its style.
type Mark = (&'static str, &'static str, Style);

/// Who it is or its verify state, most urgent first (codes that differ, a key that isn't the one
/// verified for the nick, a bad signature, a code still to compare), then a history kept, a
/// modified client and an ignored one.
fn peer_marks(p: &chat_core::PeerInfo) -> Vec<Mark> {
    use chat_core::{BuildState, SignatureState};
    let red = Style::default().fg(Color::Red).add_modifier(Modifier::BOLD);
    let yellow = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
    let green = Style::default().fg(Color::Green);
    let sig = p.identity.as_ref().map(|i| i.signature);
    let mut m = vec![match (p.code_state, sig) {
        (CodeState::Differs, _) => ("\u{2717}", "codes differ", red),
        (CodeState::KeyChanged, _) => ("\u{2717}", "key changed", red),
        (_, Some(SignatureState::Failed)) => ("\u{2717}", "bad signature", red),
        (CodeState::Compare, _) => ("?", "compare code", yellow),
        (CodeState::Compared, _) => ("\u{2713}", "code compared", green),
        (_, Some(SignatureState::Verified)) => ("\u{2713}", "verified", green),
        _ => ("?", "unverified", faint()),
    }];
    if p.keeps_history {
        m.push(("h", "keeps history", yellow));
    }
    if p.build == BuildState::Modified {
        m.push(("!", "modified client", red));
    }
    if p.ignored {
        m.push(("i", "ignored", faint()));
    }
    m
}

fn mark_cols(m: &Mark, word: bool) -> usize {
    width(m.0) + if word { 1 + width(m.1) } else { 0 }
}

/// The rows under a peer that spell out its marks, `room` columns wide: marks share a row while
/// they fit. Each row is the marks on it.
fn mark_rows(marks: &[Mark], room: usize) -> Vec<Vec<Mark>> {
    let mut rows: Vec<Vec<Mark>> = Vec::new();
    let mut used = 0;
    for m in marks {
        let c = mark_cols(m, true);
        match rows.last_mut() {
            Some(row) if used + 2 + c <= room => {
                row.push(*m);
                used += 2 + c;
            }
            _ => {
                rows.push(vec![*m]);
                used = c;
            }
        }
    }
    rows
}

/// The marks are indented under the nick, past the dot before it.
const MARK_INDENT: usize = 2;

/// One peer in the sidebar: its nick and the id added to tell a lookalike apart, its colour, and
/// what applies to it.
struct SideRow {
    nick: String,
    tag: String,
    colour: Colour,
    you: bool,
    marks: Vec<Mark>,
}

/// A peer's nick, and unless its marks are spelled out under it, the marks after it: in words while
/// they fit, then as symbols, the verify state last. The nick is cut to make room for them.
fn peer_spans(p: &SideRow, spelled: bool, cw: usize) -> Vec<Span<'static>> {
    let marks: &[Mark] = if spelled { &[] } else { &p.marks };
    let n = marks.len();
    let tag_w = width(&p.tag);
    let room = cw.saturating_sub(2 + tag_w + 1);
    let want = width(&p.nick).min(6);
    let mut word = vec![true; n];
    let mut right: usize = n.saturating_sub(1) + marks.iter().map(|m| mark_cols(m, true)).sum::<usize>();
    // From the second mark round to the first, so the verify state keeps its word longest.
    let mut i = 1;
    while i <= n && room.saturating_sub(right) < want {
        let k = i % n;
        right -= mark_cols(&marks[k], true) - mark_cols(&marks[k], false);
        word[k] = false;
        i += 1;
    }
    let colour = Style::default().fg(rgb(p.colour));
    let mut spans = vec![Span::styled("\u{25cf} ", colour)];
    let nick_room = cw.saturating_sub(2 + tag_w + right + 1).max(1);
    spans.push(Span::styled(
        ell(&p.nick, nick_room),
        if p.you { colour.add_modifier(Modifier::BOLD) } else { colour },
    ));
    spans.push(Span::styled(p.tag.clone(), faint()));
    let used = spans_width(&spans);
    spans.push(Span::raw(" ".repeat(cw.saturating_sub(right).saturating_sub(used))));
    for i in 1..=n {
        let k = i % n;
        if i > 1 {
            spans.push(Span::raw(" "));
        }
        let (g, w, st) = marks[k];
        spans.push(Span::styled(if word[k] { format!("{g} {w}") } else { g.to_string() }, st));
    }
    spans
}

/// Where the sidebar's lists are scrolled to (the rooms', then the people's), how far they can go,
/// the room on screen and the rows the rooms had, and where the lists were drawn, for the wheel.
#[derive(Clone, Copy, Default)]
pub struct SideState {
    pub top: [usize; 2],
    pub most: [usize; 2],
    sel: Option<usize>,
    rows: usize,
    pub at: [Option<Rect>; 2],
}

/// The rows the sidebar draws.
enum SideLine {
    Blank,
    HeadRooms,
    NoRooms,
    Room(usize),
    HeadPeers,
    Peer(usize),
    PeerMarks(usize, usize),
    HeadNet,
    Net(usize),
    Above(usize),
    Below(usize),
}

/// The sidebar: the rooms, the people in the one on screen with what applies to each, and how it
/// reaches them. Lists that don't fit scroll, the mouse wheel over them too.
fn draw_sidebar(f: &mut Frame, app: &App, area: Rect) {
    let buf = f.buffer_mut();
    let (title, right) = brand(area.width);
    page_box(buf, area, faint(), false, title, right);
    let h = area.height.saturating_sub(2) as usize;
    let iw = area.width.saturating_sub(2);
    let cw = (iw as usize).saturating_sub(2);

    let r = app.room();
    let mut peers: Vec<SideRow> = Vec::new();
    if let Some(r) = r.filter(|r| r.room().is_some()) {
        peers.push(SideRow {
            nick: app.nick.clone(),
            tag: String::new(),
            colour: app.colour.unwrap_or(Colour([0x88, 0x88, 0x88])),
            you: true,
            marks: [("\u{25c6}", "you", faint())]
                .into_iter()
                .chain(r.history.is_some().then_some((
                    "h",
                    "keeps history",
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )))
                .collect(),
        });
        for p in &r.peers {
            // Nicks can't contain '#', so one here is the id added to tell lookalikes apart, never cut off.
            let (nick, tag) = match p.name.find('#') {
                Some(i) => (p.name[..i].to_string(), p.name[i..].to_string()),
                None => (p.name.clone(), String::new()),
            };
            peers.push(SideRow {
                nick,
                tag,
                colour: p.colour,
                you: false,
                marks: peer_marks(p),
            });
        }
    }
    let net: Vec<(&str, String)> = match r.filter(|r| r.room().is_some()) {
        None => Vec::new(),
        Some(r) => {
            let n = &r.net;
            let mut kv = Vec::new();
            if n.mode == RouteMode::Tor {
                kv.push(("route", "tor".to_string()));
                kv.push(("tor", if n.tor_ready { "connected" } else { "connecting" }.into()));
                kv.push(("onion", if n.onion_up { "published" } else { "waiting" }.into()));
            } else {
                kv.push(("route", format!("udp/{}", r.info.as_ref().map_or(0, |i| i.port))));
                kv.push((
                    "portmap",
                    match n.portmap {
                        None => "off",
                        Some(true) => "mapped",
                        Some(false) => "not yet",
                    }
                    .into(),
                ));
            }
            kv.push((
                "relays",
                match &n.relays {
                    None => "off".into(),
                    Some(rs) if !rs.used => "not needed".into(),
                    Some(rs) => format!("{}/{} up", rs.up, rs.total),
                },
            ));
            if n.mode != RouteMode::Tor {
                match n.dht {
                    Some(d) => {
                        kv.push(("dht", if d { "connected" } else { "connecting" }.into()));
                        kv.push(("found", format!("{} peers", n.dht_found)));
                    }
                    None => kv.push(("dht", "off".into())),
                }
            }
            kv.push(("cands", n.candidates.to_string()));
            kv.push(("pending", n.pending.to_string()));
            kv.push(("rx", format!("{} packets", n.rx)));
            kv
        }
    };

    // Each peer's marks are spelled out on rows under it while every peer's fit above the network.
    let under: usize = peers
        .iter()
        .map(|p| mark_rows(&p.marks, cw.saturating_sub(MARK_INDENT)).len())
        .sum();
    let n_rooms = app.rooms.len();
    let s_need = n_rooms.max(1);
    let p_head = if peers.is_empty() { 0 } else { 2 };
    let mut net_rows = if net.is_empty() { 0 } else { 2 + net.len() };
    let spelled = 1 + s_need + 2 + peers.len() + under + net_rows <= h;
    // Too many rooms or peers to fit, and they scroll. Rather than lists too short for that, the
    // network goes.
    let (mut s_rows, mut p_rows) = split_rows(h.saturating_sub(1 + p_head + net_rows), s_need, peers.len());
    if net_rows > 0 && (list_cramped(s_rows, s_need) || list_cramped(p_rows, peers.len())) {
        net_rows = 0;
        (s_rows, p_rows) = split_rows(h.saturating_sub(1 + p_head), s_need, peers.len());
    }
    // The rooms follow the one on screen as it changes, and when they get more rows or fewer.
    let mut st = app.side.get();
    let sel = (!app.rooms.is_empty()).then_some(app.current);
    if st.sel != sel {
        st.sel = sel;
        st.top[1] = 0;
        st.rows = usize::MAX;
    }
    if s_rows != st.rows {
        st.rows = s_rows;
        st.top[0] = list_view_at(n_rooms, s_rows, st.top[0], sel).top;
    }
    let sv = list_view(n_rooms, s_rows, st.top[0]);
    let pv = list_view(peers.len(), p_rows, st.top[1]);
    st.top = [sv.top, pv.top];
    st.most = [sv.most, pv.most];
    st.at = [None, None];

    let mut rows: Vec<SideLine> = vec![SideLine::HeadRooms];
    if n_rooms == 0 {
        rows.push(SideLine::NoRooms);
    }
    if sv.above {
        rows.push(SideLine::Above(sv.top));
    }
    rows.extend((sv.top..sv.top + sv.shown).map(SideLine::Room));
    if sv.below {
        rows.push(SideLine::Below(n_rooms - sv.top - sv.shown));
    }
    if sv.most > 0 {
        st.at[0] = Some(Rect::new(area.x, area.y + 1, area.width, rows.len() as u16));
    }
    if !peers.is_empty() {
        rows.push(SideLine::Blank);
        let head = rows.len();
        rows.push(SideLine::HeadPeers);
        if pv.above {
            rows.push(SideLine::Above(pv.top));
        }
        for (i, p) in peers.iter().enumerate().skip(pv.top).take(pv.shown) {
            rows.push(SideLine::Peer(i));
            if spelled {
                let n = mark_rows(&p.marks, cw.saturating_sub(MARK_INDENT)).len();
                rows.extend((0..n).map(|j| SideLine::PeerMarks(i, j)));
            }
        }
        if pv.below {
            rows.push(SideLine::Below(peers.len() - pv.top - pv.shown));
        }
        if pv.most > 0 {
            st.at[1] = Some(Rect::new(area.x, area.y + 1 + head as u16, area.width, (rows.len() - head) as u16));
        }
    }
    if net_rows > 0 {
        // At the bottom when there's room, otherwise straight after the rest.
        let start = h.saturating_sub(net.len() + 1).max(rows.len() + 1);
        while rows.len() < start {
            rows.push(SideLine::Blank);
        }
        rows.push(SideLine::HeadNet);
        rows.extend((0..net.len()).map(SideLine::Net));
    }
    app.side.set(st);

    let lw = net.iter().map(|(l, _)| width(l)).max().unwrap_or(0);
    let heading = |t: &str, count: Option<usize>| {
        let mut s = vec![Span::styled(t.to_string(), faint())];
        if let Some(c) = count {
            let c = c.to_string();
            s.push(Span::raw(" ".repeat(cw.saturating_sub(width(t) + c.len()))));
            s.push(Span::styled(c, faint()));
        }
        s
    };
    for (i, row) in rows.iter().take(h).enumerate() {
        let y = area.y + 1 + i as u16;
        let x = area.x + 1;
        let spans = match row {
            SideLine::Blank => continue,
            SideLine::HeadRooms => heading("SESSIONS", (n_rooms > 0).then_some(n_rooms)),
            SideLine::NoRooms => vec![Span::styled("none yet \u{b7} ctrl+n", faint())],
            SideLine::HeadPeers => heading("PEERS", Some(peers.len())),
            SideLine::HeadNet => heading("NETWORK", None),
            SideLine::Above(n) => vec![Span::styled(format!("\u{2191} {n} more"), faint())],
            SideLine::Below(n) => vec![Span::styled(format!("\u{2193} {n} more"), faint())],
            SideLine::Net(k) => vec![
                Span::styled(net[*k].0.to_string(), faint()),
                Span::raw(" ".repeat(lw + 2 - width(net[*k].0))),
                Span::raw(ell(&net[*k].1, cw.saturating_sub(lw + 2))),
            ],
            SideLine::Peer(k) => peer_spans(&peers[*k], spelled, cw),
            SideLine::PeerMarks(k, j) => {
                let mr = mark_rows(&peers[*k].marks, cw.saturating_sub(MARK_INDENT));
                let mut s = vec![Span::raw(" ".repeat(MARK_INDENT))];
                for (n, (g, w, st)) in mr[*j].iter().enumerate() {
                    if n > 0 {
                        s.push(Span::raw("  "));
                    }
                    s.push(Span::styled(format!("{g} {w}"), *st));
                }
                s
            }
            SideLine::Room(k) => {
                let v = &app.rooms[*k];
                let on = *k == app.current;
                let online = v.peers.len() + 1;
                let badge = (!on && v.unread > 0).then(|| {
                    format!(
                        " {}{}{} ",
                        if v.mentioned { "@" } else { "" },
                        v.unread.min(99),
                        if v.unread > 99 { "+" } else { "" }
                    )
                });
                let (glyph, gs) = state_mark(v);
                let count = online.to_string();
                let right = 2 + count.len() + badge.as_ref().map_or(0, |b| b.len() + 1);
                let style = if on {
                    accent_bold()
                } else if badge.is_some() {
                    bold()
                } else {
                    Style::default()
                };
                let mut s = vec![pointer(on), Span::styled(ell(&v.label, cw.saturating_sub(2 + right + 1)), style)];
                s.push(Span::raw(" ".repeat(cw.saturating_sub(right + spans_width(&s)))));
                if let Some(b) = badge {
                    let tone = if v.mentioned { Color::Yellow } else { Color::Magenta };
                    s.push(Span::styled(
                        b,
                        Style::default().fg(tone).add_modifier(Modifier::BOLD | Modifier::REVERSED),
                    ));
                    s.push(Span::raw(" "));
                }
                s.push(Span::styled(glyph, gs));
                s.push(Span::styled(format!(" {count}"), faint()));
                if on {
                    picked_line(buf, x, y, iw, s);
                    continue;
                }
                s
            }
        };
        inner_line(buf, x, y, iw, spans);
    }
}

/// The lines one entry takes, wrapped to the width.
fn entry_lines(app: &App, r: &RoomView, e: &crate::app::Entry, w: usize) -> Vec<Line<'static>> {
    let time = (hhmm(e.at) + " ", faint());
    match &e.kind {
        EntryKind::Msg(m) => {
            let colour = m.colour.map_or(Color::Reset, rgb);
            let name_style = Style::default().fg(colour).add_modifier(Modifier::BOLD);
            let mut pieces = vec![time];
            if m.mention && !m.mine {
                pieces.push(("▌".into(), Style::default().fg(Color::Yellow)));
            }
            let peer_name = |id| {
                r.peers
                    .iter()
                    .find(|p| Some(p.id) == id)
                    .map_or_else(|| "someone".to_string(), |p| p.name.clone())
            };
            let who = match (m.direct, m.mine) {
                (true, true) => format!("you → {}", peer_name(m.peer)),
                (true, false) => format!("{} → you", m.name),
                (false, true) => app.nick.clone(),
                (false, false) if m.relayed => format!("{} (via {})", m.name, peer_name(m.peer)),
                (false, false) => m.name.clone(),
            };
            pieces.push((
                who,
                if m.direct {
                    name_style.add_modifier(Modifier::ITALIC)
                } else {
                    name_style
                },
            ));
            pieces.push((": ".into(), faint()));
            let (quote, body) = m.text.split_at(m.quote_len.min(m.text.len()));
            if !quote.is_empty() {
                pieces.push((quote.to_string(), faint().add_modifier(Modifier::ITALIC)));
            }
            // Its links underlined.
            let mut at = 0;
            for (a, n) in chat_core::protocol::text::links(body) {
                pieces.push((body[at..a].to_string(), Style::default()));
                pieces.push((body[a..a + n].to_string(), Style::default().add_modifier(Modifier::UNDERLINED)));
                at = a + n;
            }
            pieces.push((body[at..].to_string(), Style::default()));
            if let Some(own) = m.own {
                pieces.push(delivery_mark(r, own));
            }
            if let Some(num) = m.file {
                pieces.push(file_hint(r, num, m.mine));
            }
            let mut lines = wrap(&pieces, w, 6);
            if let Some(num) = m.file
                && !r.hidden.contains(&num)
                && let Some(t) = r.pictures.get(&num)
            {
                lines.extend(picture_lines(t, w.saturating_sub(8), PICTURE_ROWS));
                lines.push(Line::styled(format!("        /hide {num} hides it"), faint()));
            }
            lines
        }
        EntryKind::Note(Level::Warn, text) => console_line(
            app,
            r,
            time,
            "! ",
            text,
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            w,
        ),
        EntryKind::Note(Level::Note, text) => console_line(app, r, time, "\u{b7} ", text, faint(), w),
        EntryKind::Log(text) => console_line(app, r, time, "net: ", text, faint().add_modifier(Modifier::ITALIC), w),
    }
}

/// A line of chat's own text, highlighted: its prose in `base`, and what chat-core marks in it
/// brought out of the faint. Where it comes from is in the accent, and so are commands, as keys
/// are; what went right is green, what's under way yellow and what went wrong red; addresses are
/// blue, numbers and ids cyan, and a verify code, paths and invites in the terminal's own colour.
/// The room, you and peers are named in bold, people in their colours. A line that starts with
/// "warning:" is yellow.
fn console_line(app: &App, r: &RoomView, time: (String, Style), lead: &str, text: &str, base: Style, w: usize) -> Vec<Line<'static>> {
    use chat_core::protocol::text::{Mark, console_marks};
    let names: Vec<&str> = [r.label.as_str(), app.nick.as_str()]
        .into_iter()
        .chain(r.peers.iter().map(|p| p.name.as_str()))
        .collect();
    let marks = console_marks(text, &names);
    let base = match marks.first() {
        Some((_, _, Mark::Warning)) => Style::default().fg(Color::Yellow),
        _ => base,
    };
    let fg = |c: Color| Style::default().fg(c);
    let mut pieces = vec![time, (lead.to_string(), base)];
    let mut at = 0;
    for (a, n, m) in marks {
        let st = match m {
            Mark::Source => accent(),
            Mark::Command => accent_bold(),
            Mark::Warning => fg(Color::Yellow).add_modifier(Modifier::BOLD),
            Mark::Good => fg(Color::Green),
            Mark::Busy => fg(Color::Yellow),
            Mark::Bad => fg(Color::Red).add_modifier(Modifier::BOLD),
            Mark::Address => fg(Color::Blue),
            Mark::Number => fg(Color::Cyan),
            Mark::Code | Mark::Invite => bold(),
            Mark::Path => Style::default(),
            Mark::Name(0) => bold(),
            Mark::Name(1) => fg(app.colour.map_or(Color::Reset, rgb)).add_modifier(Modifier::BOLD),
            Mark::Name(i) => fg(r.peers.get(i - 2).map_or(Color::Reset, |p| rgb(p.colour))).add_modifier(Modifier::BOLD),
        };
        pieces.push((text[at..a].to_string(), base));
        pieces.push((text[a..a + n].to_string(), base.patch(st.remove_modifier(Modifier::DIM))));
        at = a + n;
    }
    pieces.push((text[at..].to_string(), base));
    wrap(&pieces, w, 8)
}

/// The most rows a picture takes in the messages.
const PICTURE_ROWS: usize = 20;

/// After an offer: what can be done with it, or how it's going.
fn file_hint(r: &RoomView, num: u32, mine: bool) -> (String, Style) {
    let Some(f) = r.file(num) else {
        return (String::new(), faint());
    };
    let text = match &f.state {
        _ if mine => match &f.sending {
            Some(s) => format!(" · sending to {}, {}%", s.name, s.permille / 10),
            None if !f.sent_to.is_empty() => format!(" · sent to {}", f.sent_to.join(", ")),
            None => String::new(),
        },
        FileState::Fetching { got, .. } => format!(" · {}%", (got * 100).checked_div(f.size).unwrap_or(100)),
        FileState::Queued { .. } => " · queued".into(),
        FileState::Failed { why } => format!(" · failed: {why}"),
        _ if f.saved.is_some() => format!(" · saved to {}", f.saved.as_deref().unwrap_or_default()),
        _ if r.pictures.contains_key(&num) && r.hidden.contains(&num) => format!(" · /show {num}"),
        _ if r.pictures.contains_key(&num) => format!(" · /download {num} saves it"),
        _ if f.image => format!(" · /show {num} to see it, /download {num} to save it"),
        _ => format!(" · /download {num} saves it"),
    };
    (text, faint())
}

/// A picture in half-block characters: each cell is two pixels, the top in its colour and the
/// bottom in its background, scaled down (never up) to fit `cols` by `rows`.
fn picture_lines(t: &chat_core::protocol::picture::Thumb, cols: usize, rows: usize) -> Vec<Line<'static>> {
    if t.w == 0 || t.h == 0 || cols == 0 {
        return Vec::new();
    }
    let s = (cols as f64 / f64::from(t.w)).min(2.0 * rows as f64 / f64::from(t.h)).min(1.0);
    let (tw, th) = (((f64::from(t.w) * s) as usize).max(1), ((f64::from(t.h) * s) as usize).max(1));
    let px = |x: usize, y: usize| {
        let sx = (x * t.w as usize / tw).min(t.w as usize - 1);
        let sy = (y * t.h as usize / th).min(t.h as usize - 1);
        let i = 3 * (sy * t.w as usize + sx);
        Color::Rgb(t.rgb[i], t.rgb[i + 1], t.rgb[i + 2])
    };
    (0..th.div_ceil(2))
        .map(|row| {
            let mut spans = vec![Span::raw("        ")];
            spans.extend((0..tw).map(|x| {
                let top = px(x, 2 * row);
                let style = if 2 * row + 1 < th {
                    Style::default().fg(top).bg(px(x, 2 * row + 1))
                } else {
                    Style::default().fg(top)
                };
                Span::styled("\u{2580}", style)
            }));
            Line::from(spans)
        })
        .collect()
}

/// What became of one of our messages: still going, everyone has it, held, or missed.
fn delivery_mark(r: &RoomView, own: u64) -> (String, Style) {
    let Some(s) = r.sent.get(&own) else {
        return (" ·".into(), faint());
    };
    if !s.missed.is_empty() {
        return (
            format!(" ✗ not delivered to {}", s.missed.join(", ")),
            Style::default().fg(Color::Red),
        );
    }
    if s.to == 0 && s.held > 0 {
        return (" ⏸ held until you compare codes".into(), Style::default().fg(Color::Yellow));
    }
    if s.to == 0 {
        return (" · nobody else here".into(), faint());
    }
    if s.settled {
        return (" ✓".into(), Style::default().fg(Color::Green));
    }
    if s.delivered > 0 {
        return (" ✓".into(), faint());
    }
    (" ·".into(), faint())
}

/// Where `n` rows start to sit a little above the middle of `nrows` rows from `first`.
fn center_top(first: u16, nrows: usize, n: usize) -> u16 {
    first + (nrows.saturating_sub(n) / 2).saturating_sub(nrows / 10) as u16
}

/// Lines centred across `w` columns from `x`, a little above the middle of `nrows` rows: the first
/// bold and the rest faint, except a line that's just `emph` (the room's id, to share), highlighted.
fn draw_center(buf: &mut Buffer, x: u16, top: u16, w: u16, nrows: usize, text: &str, emph: Option<&str>) {
    let lines: Vec<&str> = text.split('\n').collect();
    let first = center_top(top, nrows, lines.len());
    for (i, l) in lines.iter().enumerate() {
        let y = first + i as u16;
        if y >= top + nrows as u16 {
            break;
        }
        let style = if i == 0 {
            bold()
        } else if emph == Some(*l) {
            accent_bold()
        } else {
            faint()
        };
        let l = ell(l, w as usize);
        let pad = (w as usize).saturating_sub(width(&l)) / 2;
        buf.set_line(x + pad as u16, y, &Line::styled(l, style), w);
    }
}

/// No room yet: what chat is, and the keys that start one.
fn draw_welcome(buf: &mut Buffer, x: u16, top: u16, w: u16, nrows: usize) {
    const KEYS: [(&str, &str); 4] = [
        ("ctrl+n", "start a new session"),
        ("ctrl+j", "join a session"),
        ("ctrl+s", "settings"),
        ("/help", "keys and commands"),
    ];
    // The keys in a column, and what they do in one about as wide as the longest.
    const KEY_COLS: usize = 9;
    const DOES_COLS: usize = 20;
    let first = center_top(top, nrows, 2 + KEYS.len());
    let end = top + nrows as u16;
    let brand = "\u{25c6} chat";
    if first < end {
        let pad = (w as usize).saturating_sub(width(brand)) / 2;
        buf.set_line(x + pad as u16, first, &Line::styled(brand, accent_bold()), w);
    }
    let left = (w as usize).saturating_sub(KEY_COLS + DOES_COLS) / 2;
    for (i, (key, does)) in KEYS.iter().enumerate() {
        let y = first + 2 + i as u16;
        if y >= end {
            break;
        }
        let spans = vec![
            Span::raw(" ".repeat(left)),
            Span::styled(format!("{key:KEY_COLS$}"), accent_bold()),
            Span::raw(*does),
        ];
        buf.set_line(x, y, &Line::from(spans), w);
    }
}

/// What the chat shows while a room has no messages: how it's getting on, and what to do next.
fn empty_text(r: &RoomView) -> Option<String> {
    let RoomState::Open(_) = &r.state else {
        return matches!(r.state, RoomState::Joining).then(|| "Starting the session\nDeriving its keys - this takes a moment.".to_string());
    };
    Some(if !r.net.ready {
        format!(
            "Connecting to {}\nThe chat opens once someone in the session answers.\nFinding them can take a minute{}.",
            r.label,
            if r.net.mode == RouteMode::Tor { " over Tor" } else { "" }
        )
    } else if r.peers.is_empty() {
        format!(
            "No one else is here yet\nTo invite peers, share the session id and its password.\n\n{}\n/invite copies both, as one invite",
            r.label
        )
    } else {
        "No messages yet\nSay hello - it's end-to-end encrypted.".into()
    })
}

/// A page and anything that goes over it, and what the bar says there.
fn draw_page_modal(f: &mut Frame, app: &App, m: &Modal, area: Rect) -> (Bar, Option<(u16, u16)>) {
    let full = f.area();
    match m {
        Modal::Settings(p) => {
            let v = if p.pick.is_some() { app.pick_view(p) } else { app.settings_view(p) };
            let bar = draw_page(f, &v, area);
            match &p.search {
                Some((input, sel)) => {
                    let d = search_dialog(app, input, *sel);
                    let cursor = draw_dialog(f, area, &d);
                    (Bar::page(&bar.chip, &d.keys), cursor)
                }
                None => (bar, None),
            }
        }
        Modal::Browser(b) => {
            let bar = draw_page(f, &app.browser_view(b, full.width, full.height), area);
            match &b.ask {
                Some(path) => {
                    let d = export_dialog(app, path);
                    draw_dialog(f, area, &d);
                    (Bar::page("EXPORT", &d.keys), None)
                }
                None => (bar, None),
            }
        }
        Modal::Files(num) => (draw_page(f, &app.files_view(*num), area), None),
        Modal::Picture(num) => (draw_picture(f, app, *num, area), None),
        Modal::Help(sel) => (draw_page(f, &app.help_view(*sel), area), None),
        _ => (Bar::page("", ""), None),
    }
}

/// A box as it's drawn, and the bar's chip while it's open over the chat.
fn modal_dialog(app: &App, m: &Modal) -> (Dialog, &'static str) {
    match m {
        Modal::Prompt { kind, title, hint, input } => prompt_dialog(app, kind, title, hint, input),
        Modal::Verify { peer, .. } => {
            let code = peer.code.clone().unwrap_or(chat_core::VerifyCode {
                words: "-".into(),
                hex: "-".into(),
            });
            let mut text = paras(&[format!(
                "Compare this code with {} over another channel you trust (in person, a call):",
                peer.name
            )]);
            text.push(Para::Blank);
            // Two groups of four words a line, as they're read out.
            let groups: Vec<&str> = code.words.split(" \u{b7} ").collect();
            for pair in groups.chunks(2) {
                text.push(Para::Text(vec![(format!("  {}", pair.join("   ")), bold())]));
            }
            text.push(Para::Text(vec![(format!("  {}", code.hex), faint())]));
            text.push(Para::Blank);
            text.push(Para::Text(vec![(
                "If anyone sat between you, the codes on your two screens would differ.".into(),
                Style::default(),
            )]));
            let d = Dialog {
                title: "VERIFY".into(),
                text,
                keys: "y they match \u{b7} n they differ \u{b7} esc later".into(),
                ..Dialog::default()
            };
            (d, "VERIFY")
        }
        Modal::Ask { title, paras: p, keys, .. } => {
            let d = Dialog {
                title: (*title).into(),
                text: paras(p),
                keys: (*keys).into(),
                ..Dialog::default()
            };
            // A box that asks is about what its title says first: MOVE, INSTALL...
            let title: &'static str = title;
            (d, title.split(" \u{b7} ").next().unwrap_or(title))
        }
        Modal::Paste { kind, text } => {
            let (title, p) = crate::settings_page::paste_box(*kind);
            let status = if text.is_empty() {
                "waiting for the paste".to_string()
            } else {
                format!("{} bytes so far", text.len())
            };
            let d = Dialog {
                title: title.into(),
                text: paras(&p.map(String::from)),
                status: Some(status),
                keys: "esc back".into(),
                ..Dialog::default()
            };
            (d, "SETTINGS")
        }
        Modal::Rooms { sel, forgetting } => (rooms_dialog(app, *sel, *forgetting), "JOIN"),
        Modal::PickSave { names, sel } => {
            let (esc, skip) = if app.start.is_some() {
                ("Esc starts without any", "esc skip")
            } else {
                ("Esc cancels", "esc cancel")
            };
            let d = Dialog {
                title: "UNLOCK".into(),
                text: paras(&[format!("Your saves. Enter opens one; {esc}.")]),
                items: names.iter().map(|n| (n.clone(), String::new())).collect(),
                sel: Some(*sel),
                keys: format!("enter open \u{b7} {skip}"),
                ..Dialog::default()
            };
            (d, "UNLOCK")
        }
        Modal::Link { links, at } => {
            let (link, who, when) = &links[*at];
            let target = chat_core::protocol::text::link_target(link);
            let from = if when.is_empty() {
                format!("typed by {who}")
            } else {
                format!("from {who} at {when}")
            };
            let more = links.len() > 1;
            let d = Dialog {
                title: if more {
                    format!("OPEN LINK \u{b7} {} OF {}", at + 1, links.len())
                } else {
                    "OPEN LINK".into()
                },
                text: vec![
                    Para::Text(vec![(target, Style::default())]),
                    Para::Text(vec![(from, faint())]),
                    Para::Blank,
                    Para::Text(vec![(
                        "Your browser fetches it directly, not through chat's Tor or relays: the site sees your IP \
                         address, and when you opened it."
                            .into(),
                        Style::default(),
                    )]),
                ],
                keys: if more {
                    "y open \u{b7} c copy \u{b7} j/k older/newer \u{b7} n cancel"
                } else {
                    "y open \u{b7} c copy \u{b7} n cancel"
                }
                .into(),
                ..Dialog::default()
            };
            (d, "LINK")
        }
        Modal::Qr { invite, qr, note } => {
            // Two modules a cell, top and bottom, with the light border a scanner needs.
            const QUIET: usize = 4;
            let side = qr.size + 2 * QUIET;
            let dark = |x: usize, y: usize| {
                (QUIET..QUIET + qr.size).contains(&x) && (QUIET..QUIET + qr.size).contains(&y) && qr.dark(x - QUIET, y - QUIET)
            };
            let colour = |d: bool| if d { Color::Black } else { Color::White };
            let mut text: Vec<Para> = (0..side.div_ceil(2))
                .map(|row| {
                    let spans: Vec<Span> = (0..side)
                        .map(|x| {
                            let bottom = 2 * row + 1 < side && dark(x, 2 * row + 1);
                            Span::styled("\u{2580}", Style::default().fg(colour(dark(x, 2 * row))).bg(colour(bottom)))
                        })
                        .collect();
                    Para::Art(Line::from(spans))
                })
                .collect();
            text.push(Para::Blank);
            text.push(Para::Text(vec![(invite.clone(), Style::default())]));
            let d = Dialog {
                title: "INVITE".into(),
                text,
                note: Some(note.clone()),
                keys: "esc close".into(),
                ..Dialog::default()
            };
            (d, "INVITE")
        }
        Modal::Info { title, lines } => {
            let d = Dialog {
                title: title.trim().to_uppercase(),
                text: lines.iter().map(|l| Para::Text(vec![(l.clone(), Style::default())])).collect(),
                keys: "esc close".into(),
                ..Dialog::default()
            };
            (d, "INFO")
        }
        Modal::Update => {
            let running = chat_core::net::update::view().running;
            let d = Dialog {
                keys: if running { "esc hide" } else { "enter close" }.into(),
                ..Dialog::default()
            };
            (d, "UPDATE")
        }
        Modal::Settings(_) | Modal::Browser(_) | Modal::Files(_) | Modal::Picture(_) | Modal::Help(_) => (Dialog::default(), ""),
    }
}

/// A field's box. Its help goes under the field when it's a line about what to type (a room's id,
/// a setting), and above it when it's more to read first.
fn prompt_dialog(app: &App, kind: &PromptKind, title: &str, hint: &str, input: &Input) -> (Dialog, &'static str) {
    use crate::saved::Installing;
    let text = input.text();
    // An invite holds the password.
    let mask = kind.secret() || matches!(kind, PromptKind::JoinId) && chat_core::protocol::names::is_invite(&text);
    let pgp = |k: &chat_core::IdentityKind| *k == chat_core::IdentityKind::Pgp;
    let skip = if app.start.is_some() { "esc skip" } else { "esc cancel" };
    let (placeholder, keys, chip): (String, String, &'static str) = match kind {
        PromptKind::Nick => ("your name".into(), "enter save \u{b7} esc cancel".into(), "NICK"),
        PromptKind::NewRoom => ("password".into(), "enter create \u{b7} esc cancel".into(), "NEW"),
        PromptKind::JoinId => ("session id, or an invite".into(), "enter next \u{b7} esc cancel".into(), "JOIN"),
        PromptKind::JoinPassword(_) => ("password".into(), "enter join \u{b7} esc cancel".into(), "JOIN"),
        PromptKind::Unlock(_) => ("passphrase".into(), format!("enter open \u{b7} {skip}"), "UNLOCK"),
        PromptKind::Code => ("6-digit code".into(), format!("enter open \u{b7} {skip}"), "UNLOCK"),
        PromptKind::KeyPin(Some(_)) => ("PIN".into(), "enter send \u{b7} esc cancel".into(), "UNLOCK"),
        PromptKind::KeyPin(None) => ("PIN".into(), "enter send \u{b7} esc cancel".into(), "SETTINGS"),
        PromptKind::Install(Installing::Name) => (String::new(), "enter next \u{b7} esc cancel".into(), "INSTALL"),
        PromptKind::Install(Installing::Pass(_)) => ("passphrase".into(), "enter next \u{b7} esc cancel".into(), "INSTALL"),
        PromptKind::Install(Installing::Again(..)) => ("the same passphrase".into(), "enter install \u{b7} esc cancel".into(), "INSTALL"),
        PromptKind::Uninstall(_) => ("yes".into(), "enter delete \u{b7} esc cancel".into(), "UNINSTALL"),
        PromptKind::SetPin => ("PIN".into(), "enter lock \u{b7} esc cancel".into(), "LOCK"),
        PromptKind::Shadow(None) => ("shadow passphrase".into(), "enter next \u{b7} esc cancel".into(), "SETTINGS"),
        PromptKind::Shadow(Some(_)) => ("the same passphrase".into(), "enter set \u{b7} esc cancel".into(), "SETTINGS"),
        PromptKind::NewCode => ("6-digit code".into(), "enter turn on \u{b7} esc cancel".into(), "SETTINGS"),
        PromptKind::SetRow(name) => (
            chat_core::net::settings::PAGE
                .iter()
                .find(|r| r.name == *name)
                .map_or("", |r| r.values)
                .into(),
            "enter save \u{b7} esc cancel".into(),
            "SETTINGS",
        ),
        PromptKind::KeyPath(k) => (
            if pgp(k) { "~/key.asc" } else { "~/.config/age/key.txt" }.into(),
            "enter use this key \u{b7} esc back".into(),
            "SETTINGS",
        ),
        PromptKind::KeyPassword { .. } => ("password".into(), "enter make the key \u{b7} esc back".into(), "SETTINGS"),
    };
    let below = matches!(
        kind,
        PromptKind::NewRoom | PromptKind::JoinId | PromptKind::JoinPassword(_) | PromptKind::SetRow(_)
    );
    let d = Dialog {
        title: title.trim().to_uppercase(),
        text: if below || hint.is_empty() {
            Vec::new()
        } else {
            paras(&[hint.to_string()])
        },
        field: Some(Field::of(input, mask, placeholder)),
        note: below.then(|| hint.to_string()).filter(|h| !h.is_empty()),
        keys,
        ..Dialog::default()
    };
    (d, chip)
}

/// The lock screen's box: the passphrase or PIN, as dots, or that it's being checked.
fn lock_dialog(app: &App, lock: &crate::lock::Lock) -> Dialog {
    let pass = app.save.is_some() || lock.busy && app.pin.is_none();
    let mut d = Dialog {
        title: "LOCKED".into(),
        keys: "enter unlock".into(),
        ..Dialog::default()
    };
    if lock.busy {
        d.status = Some("checking\u{2026}".into());
    } else {
        d.field = Some(Field::of(&lock.input, true, if pass { "passphrase" } else { "PIN" }.into()));
    }
    d
}

// ---- the chat screen: the console over the chat, the input box, and the bottom row ----

/// The sidebar is the left hand box, if the chat keeps CHAT_COLS_MIN.
const CHAT_COLS_MIN: u16 = 44;
/// The console over the chat takes a quarter of the box, within these, and leaves the chat
/// CHAT_ROWS_MIN.
const CONSOLE_ROWS_MIN: usize = 3;
const CONSOLE_ROWS_MAX: usize = 8;
const CHAT_ROWS_MIN: usize = 4;
const MENU_ROWS: usize = 8;

fn chat_left_width(cols: u16) -> u16 {
    let w = (cols / 4).clamp(LEFT_MIN, LEFT_MAX);
    if cols.saturating_sub(w) < CHAT_COLS_MIN { 0 } else { w }
}

/// The colour of the mode's chip and its input box: INSERT green, NORMAL blue, COMMAND yellow.
fn tone(app: &App) -> Color {
    match app.mode {
        crate::cmdline::Mode::Insert => Color::Green,
        crate::cmdline::Mode::Normal => Color::Blue,
        crate::cmdline::Mode::Command => Color::Yellow,
    }
}

/// The last `n` rows of these lines, `skip` rows up from the newest, drawn from `top`.
fn draw_rows(buf: &mut Buffer, x: u16, top: u16, w: u16, n: usize, lines: &[Line<'static>], skip: usize) {
    draw_rows_linked(buf, x, top, w, n, lines, skip, &[], None);
}

/// A message's link targets, by the spans of its wrapped lines that are its underlined links: a
/// link broken across lines has a span on each.
fn link_spans(lines: &[Line<'static>], targets: &[(usize, String)]) -> Vec<Vec<(usize, String)>> {
    let mut out = Vec::new();
    let (mut k, mut got) = (0, 0);
    for l in lines {
        let mut row = Vec::new();
        for (i, s) in l.spans.iter().enumerate() {
            if !s.style.add_modifier.contains(Modifier::UNDERLINED) {
                continue;
            }
            let Some((len, target)) = targets.get(k) else { break };
            row.push((i, target.clone()));
            got += s.content.chars().count();
            if got >= *len {
                (k, got) = (k + 1, 0);
            }
        }
        out.push(row);
    }
    out
}

/// draw_rows, noting where each link lands, for OSC 8 to make it something to click.
#[allow(clippy::too_many_arguments)]
fn draw_rows_linked(
    buf: &mut Buffer,
    x: u16,
    top: u16,
    w: u16,
    n: usize,
    lines: &[Line<'static>],
    skip: usize,
    links: &[Vec<(usize, String)>],
    seen: Option<&std::cell::RefCell<Vec<(Rect, String)>>>,
) {
    let end = lines.len().saturating_sub(skip);
    let first = end.saturating_sub(n);
    // Too few to fill the pane: they sit at its bottom, newest last.
    let pad = n.saturating_sub(end - first);
    for (i, l) in lines[first..end].iter().enumerate() {
        let y = top + (pad + i) as u16;
        let mut spans = vec![Span::raw(" ")];
        spans.extend(l.spans.iter().cloned());
        buf.set_line(x, y, &Line::from(spans), w);
        if let (Some(seen), Some(row)) = (seen, links.get(first + i)) {
            for (si, target) in row {
                let before: usize = 1 + l.spans[..*si].iter().map(|s| width(&s.content)).sum::<usize>();
                let sw = width(&l.spans[*si].content);
                // Only while the whole of it is on screen.
                if before + sw <= w as usize {
                    seen.borrow_mut()
                        .push((Rect::new(x + before as u16, y, sw as u16, 1), target.clone()));
                }
            }
        }
    }
}

/// The console above the chat, sharing an edge, in one box. Either one fills it if shown alone.
/// The console has the notes; the chat has the messages, and the warnings too, since the console
/// can be hidden.
fn draw_main(f: &mut Frame, app: &App, m: Rect, boxed: bool, joined: bool) {
    let r = app.room();
    let w = (m.width as usize).saturating_sub(4);
    let (mut console, mut chat) = (Vec::new(), Vec::new());
    let mut chat_links: Vec<Vec<(usize, String)>> = Vec::new();
    app.links.borrow_mut().clear();
    let entries = r.map_or(&[][..], |r| &r.entries[r.entries.len().saturating_sub(400)..]);
    for e in entries {
        let r = r.expect("entries come from a room");
        match &e.kind {
            EntryKind::Msg(m) => {
                let lines = entry_lines(app, r, e, w);
                let body = m.body();
                let targets: Vec<(usize, String)> = chat_core::protocol::text::links(body)
                    .into_iter()
                    .map(|(a, n)| {
                        (
                            body[a..a + n].chars().count(),
                            chat_core::protocol::text::link_target(&body[a..a + n]),
                        )
                    })
                    .collect();
                let mut row_links = link_spans(&lines, &targets);
                // A picture's rows under it have none.
                row_links.resize(lines.len(), Vec::new());
                chat_links.extend(row_links);
                chat.extend(lines);
            }
            EntryKind::Note(Level::Warn, _) => {
                let lines = entry_lines(app, r, e, w);
                chat_links.extend(lines.iter().map(|_| Vec::new()));
                chat.extend(lines.iter().cloned());
                console.extend(lines);
            }
            _ => console.extend(entry_lines(app, r, e, w)),
        }
    }
    // Without a room there's no console: the welcome fills the box.
    let (mut show_con, show_chat) = (app.show_console && r.is_some(), app.show_chat || r.is_none());
    let (scroll, console_scroll) = r.map_or((0, 0), |r| (r.scroll, r.console_scroll));
    // The chat pane: the welcome, how a room with no messages yet is getting on, or the messages.
    let pane = |buf: &mut Buffer, x: u16, top: u16, iw: u16, rows: usize| match r {
        None => draw_welcome(buf, x + 1, top, iw.saturating_sub(2), rows),
        Some(r) if chat.is_empty() => {
            if let Some(t) = empty_text(r) {
                draw_center(buf, x + 1, top, iw.saturating_sub(2), rows, &t, Some(&r.label));
            }
        }
        Some(_) => {
            let skip = scroll.min(chat.len().saturating_sub(rows));
            draw_rows_linked(buf, x, top, iw, rows, &chat, skip, &chat_links, Some(&app.links));
        }
    };
    let hidden = |buf: &mut Buffer, x: u16, top: u16, iw: u16, rows: usize| {
        draw_center(
            buf,
            x + 1,
            top,
            iw.saturating_sub(2),
            rows,
            "Chat and console are hidden\nctrl+t shows the chat \u{b7} ctrl+o the console",
            None,
        );
    };
    let buf = f.buffer_mut();
    if !boxed {
        if show_chat {
            pane(buf, m.x, m.y, m.width, m.height as usize);
        } else if show_con {
            draw_rows(buf, m.x, m.y, m.width, m.height as usize, &console, console_scroll);
        } else {
            hidden(buf, m.x, m.y, m.width, m.height as usize);
        }
        return;
    }
    let inner = (m.height as usize).saturating_sub(2);
    let mut con_h = 0;
    if show_con && show_chat {
        con_h = (inner / 4).clamp(CONSOLE_ROWS_MIN, CONSOLE_ROWS_MAX);
        if inner < con_h + 1 + CHAT_ROWS_MIN {
            con_h = inner.saturating_sub(1 + CHAT_ROWS_MIN);
        }
        show_con = con_h > 0;
    }
    let con_rows = if show_chat { con_h } else { inner };
    app.console_at
        .set(show_con.then(|| Rect::new(m.x, m.y, m.width, con_rows as u16 + 1)));
    let kskip = console_scroll.min(console.len().saturating_sub(con_rows));
    let bs = faint();
    let clock = vec![Span::styled(hhmm(crate::text::unix_now()), faint())];
    let title = chat_title(app, m.width as usize, spans_width(&clock), joined);
    let corner = if joined { "\u{252c}" } else { "\u{256d}" };
    if show_con {
        let mut ktitle = vec![Span::styled("console", faint())];
        if kskip > 0 {
            ktitle.push(Span::styled(" \u{b7} ", faint()));
            ktitle.push(Span::styled(format!("\u{2193} {kskip} newer"), accent_bold()));
        }
        let right = if show_chat { Vec::new() } else { clock.clone() };
        edge(buf, m.x, m.y, m.width, [corner, "\u{256e}"], bs, ktitle, right);
    } else if show_chat {
        edge(buf, m.x, m.y, m.width, [corner, "\u{256e}"], bs, title.clone(), clock.clone());
    } else {
        edge(
            buf,
            m.x,
            m.y,
            m.width,
            [corner, "\u{256e}"],
            bs,
            vec![Span::styled("hidden", faint())],
            clock.clone(),
        );
    }
    for y in m.y + 1..m.y + m.height.saturating_sub(1) {
        box_side(buf, m.x, y, bs);
        box_side(buf, m.x + m.width - 1, y, bs);
    }
    let mut row = m.y + 1;
    let iw = m.width.saturating_sub(2);
    if show_con {
        draw_rows(buf, m.x + 1, row, iw, con_rows, &console, kskip);
        row += con_rows as u16;
        if show_chat {
            edge(buf, m.x, row, m.width, ["\u{251c}", "\u{2524}"], bs, title, clock);
            row += 1;
        }
    }
    let rest = (m.y + m.height.saturating_sub(1)).saturating_sub(row) as usize;
    if show_chat {
        pane(buf, m.x + 1, row, iw, rest);
    } else if !show_con {
        hidden(buf, m.x + 1, row, iw, rest);
    }
}

/// The chat's title: the room's state and name, unread messages in other rooms while the sidebar is
/// hidden, and how it's getting on; or "welcome" with no room. Cut to the name when it doesn't fit.
fn chat_title(app: &App, w: usize, right: usize, sidebar: bool) -> Vec<Span<'static>> {
    let Some(r) = app.room() else {
        return vec![Span::styled("welcome", bold())];
    };
    let (glyph, gs) = state_mark(r);
    let mut title = vec![Span::styled(glyph, gs), Span::raw(" "), Span::styled(r.label.clone(), bold())];
    let elsewhere: usize = app
        .rooms
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != app.current)
        .map(|(_, v)| v.unread)
        .sum();
    if !sidebar && elsewhere > 0 {
        let mentioned = app.rooms.iter().enumerate().any(|(i, v)| i != app.current && v.mentioned);
        title.push(Span::styled(" \u{b7} ", faint()));
        title.push(Span::styled(
            format!("{}{elsewhere} new elsewhere", if mentioned { "@" } else { "" }),
            if mentioned {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                accent_bold()
            },
        ));
    }
    title.push(Span::styled(format!(" \u{b7} {}", r.status_line(spinner(app))), faint()));
    if r.timer > 0 {
        title.push(Span::styled(
            format!(" \u{b7} messages go after {}", chat_core::protocol::names::format_timer(r.timer)),
            faint(),
        ));
    }
    let room = title_room(w, right);
    if spans_width(&title) > room {
        title = vec![Span::styled(ell(&r.label, room), bold())];
    }
    title
}

/// A room's state: a ring while it starts (or once it's gone), dotted while it connects, a dot once
/// it's live.
fn state_mark(r: &RoomView) -> (&'static str, Style) {
    match &r.state {
        RoomState::Open(_) if r.net.ready => ("\u{25cf}", Style::default().fg(Color::Green)),
        RoomState::Open(_) => ("\u{25cc}", Style::default().fg(Color::Yellow)),
        _ => ("\u{25cb}", faint()),
    }
}

/// The rest of the @nick being typed, if a peer here has it: Tab finishes it.
fn mention_rest(app: &App) -> Option<String> {
    let input = &app.input;
    if input.cursor != input.chars.len() {
        return None;
    }
    let before: String = input.chars.iter().collect();
    let at = before.rfind('@')?;
    let typed = &before[at + 1..];
    if typed.is_empty() || typed.contains(' ') || (at > 0 && !before[..at].ends_with(' ')) {
        return None;
    }
    let p = app
        .room()?
        .peers
        .iter()
        .find(|p| p.nick.to_lowercase().starts_with(&typed.to_lowercase()))?;
    (p.nick.chars().count() > typed.chars().count()).then(|| p.nick.chars().skip(typed.chars().count()).collect())
}

/// The suggestions for the COMMAND line, at the bottom of the box above the input box.
fn draw_menu(buf: &mut Buffer, app: &App, input: Rect, over: Rect, bs: Style) {
    let list = app.suggestions(&app.cmdline.input.text());
    let count = list.len();
    let vis = count.min(MENU_ROWS).min((over.height as usize).saturating_sub(3));
    if vis == 0 {
        return;
    }
    let sel = app.cmdline.sel.min(count - 1);
    let first = (sel + 1).saturating_sub(vis);
    let top = input.y - vis as u16 - 1;
    let pos = vec![Span::styled(format!("{}/{count}", sel + 1), faint())];
    edge(
        buf,
        input.x,
        top,
        input.width,
        ["\u{251c}", "\u{2524}"],
        bs,
        vec![Span::styled(list[sel].group, faint())],
        pos,
    );
    let mut nw = list[first..first + vis]
        .iter()
        .map(|s| width(&s.name) + if s.args.is_empty() { 0 } else { 1 + width(&s.args) })
        .max()
        .unwrap_or(0);
    nw = nw.min((input.width as usize).saturating_sub(6) / 2);
    let iw = input.width.saturating_sub(2);
    for i in 0..vis {
        let y = top + 1 + i as u16;
        buf.set_style(Rect::new(input.x + 1, y, iw, 1), Style::reset());
        buf.set_string(input.x + 1, y, " ".repeat(iw as usize), Style::default());
        box_side(buf, input.x, y, bs);
        box_side(buf, input.x + input.width - 1, y, bs);
        let s = &list[first + i];
        let on = first + i == sel;
        let mut spans = vec![pointer(on), Span::styled(s.name.clone(), if on { accent_bold() } else { bold() })];
        if !s.args.is_empty() {
            spans.push(Span::styled(format!(" {}", s.args), faint()));
        }
        let used = 2 + spans_width(&spans[1..]);
        spans.push(Span::raw(if used < 2 + nw + 3 {
            " ".repeat(2 + nw + 3 - used)
        } else {
            "  ".into()
        }));
        let room = (iw as usize).saturating_sub(2 + spans_width(&spans[1..]) + 1);
        spans.push(Span::styled(ell(&s.help, room), if on { Style::default() } else { faint() }));
        let draw = if on { picked_line } else { inner_line };
        draw(buf, input.x + 1, y, iw, spans);
    }
}

/// The input box: the line in the mode's colour, or the command line with the menu over it. Its
/// top edge is the chat's bottom, and says how many newer messages are below the chat. Under a box
/// its border is faint, since the box takes the keys. Returns where the cursor goes.
#[allow(clippy::too_many_arguments)]
fn draw_input(f: &mut Frame, app: &App, r: Rect, over: Rect, boxed: bool, joined: bool, covered: bool) -> Option<(u16, u16)> {
    let tone = tone(app);
    let bs = if covered { faint() } else { Style::default().fg(tone) };
    let command = app.mode == crate::cmdline::Mode::Command;
    let buf = f.buffer_mut();
    let (row, left, iw) = if boxed {
        if command {
            draw_menu(buf, app, r, over, bs);
        }
        let scroll = app.room().map_or(0, |v| v.scroll);
        let more = if app.show_chat && scroll > 0 {
            vec![Span::styled(format!("\u{2193} {scroll} newer \u{b7} pgdn"), accent_bold())]
        } else {
            Vec::new()
        };
        edge(buf, r.x, r.y, r.width, ["\u{251c}", "\u{2524}"], bs, Vec::new(), more);
        box_side(buf, r.x, r.y + 1, bs);
        box_side(buf, r.x + r.width - 1, r.y + 1, bs);
        let len = app.input.chars.len();
        let max = chat_core::protocol::session::MAX_TEXT;
        let count = if len > 0 && !command {
            vec![Span::styled(
                format!("{len}/{max}"),
                if len > max {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                } else {
                    faint()
                },
            )]
        } else {
            Vec::new()
        };
        let bl = if joined { "\u{2534}" } else { "\u{2570}" };
        edge(buf, r.x, r.y + 2, r.width, [bl, "\u{256f}"], bs, Vec::new(), count);
        (r.y + 1, r.x + 1, r.width.saturating_sub(2))
    } else {
        (r.y, r.x, r.width)
    };
    let room = (iw as usize).saturating_sub(4);
    let mut spans = vec![Span::styled("\u{276f} ", Style::default().fg(tone).add_modifier(Modifier::BOLD))];
    let cursor_col;
    if command {
        spans.push(Span::styled(app.cmdline.prefix.to_string(), accent_bold()));
        let typed = app.cmdline.input.text();
        // A line wider than the box shows its end, where it's typed.
        let shown: String = {
            let n = typed.chars().count();
            if n + 1 > room {
                typed.chars().skip(n + 2 - room).collect()
            } else {
                typed.clone()
            }
        };
        if shown.len() < typed.len() {
            spans.push(Span::styled("\u{2026}", faint()));
        }
        cursor_col = spans_width(&spans) + width(&shown);
        spans.push(Span::raw(shown.clone()));
        if shown == typed
            && let Some(s) = app.completion()
        {
            spans.push(Span::styled(s.line[typed.len()..].to_string(), faint()));
        }
    } else if app.input.chars.is_empty() {
        let placeholder = match (app.mode, app.room()) {
            (crate::cmdline::Mode::Normal, _) => "i to type \u{b7} : for a command".to_string(),
            (_, None) => "No room yet \u{b7} ctrl+n starts one, ctrl+j joins one, / for commands".into(),
            (_, Some(v)) => match &v.state {
                RoomState::Joining => format!("Starting {}\u{2026}", v.label),
                _ if v.peers.is_empty() => format!("Waiting for someone in {} to answer\u{2026}", v.label),
                _ => format!("Message {}", v.label),
            },
        };
        cursor_col = spans_width(&spans);
        spans.push(Span::styled(ell(&placeholder, room), faint()));
    } else {
        // Scrolled so the cursor stays in view.
        let before: String = app.input.chars[..app.input.cursor].iter().collect();
        let mut skip = 0;
        while width(&before.chars().skip(skip).collect::<String>()) > room.saturating_sub(1) {
            skip += 1;
        }
        let shown: String = app.input.chars.iter().skip(skip).collect();
        cursor_col = spans_width(&spans) + width(&before.chars().skip(skip).collect::<String>());
        spans.push(Span::raw(shown));
        if app.mode == crate::cmdline::Mode::Insert
            && let Some(rest) = mention_rest(app)
        {
            spans.push(Span::styled(rest, faint()));
        }
    }
    inner_line(buf, left, row, iw, spans);
    Some((left + 1 + (cursor_col as u16).min(iw.saturating_sub(2)), row))
}

/// What the keys do on the chat screen, most useful first: the last is the way to the help.
fn chat_hint(app: &App) -> String {
    use crate::cmdline::Mode;
    match (app.mode, app.room().filter(|r| r.room().is_some())) {
        (Mode::Command, _) => "enter run \u{b7} tab complete \u{b7} \u{2191}\u{2193} choose \u{b7} esc back".to_string(),
        (_, None) => "ctrl+n new \u{b7} ctrl+j join \u{b7} / commands \u{b7} ctrl+s settings".into(),
        (Mode::Normal, Some(_)) => "i type \u{b7} : command \u{b7} f files \u{b7} j/k session \u{b7} pgup/pgdn scroll \u{b7} ? help".into(),
        (Mode::Insert, Some(r)) => format!(
            "enter send \u{b7} / commands{}{} \u{b7} esc normal \u{b7} f1 help",
            if app.rooms.len() > 1 { " \u{b7} tab next session" } else { "" },
            if r.files.is_empty() { "" } else { " \u{b7} ctrl+f files" }
        ),
    }
}

/// The bottom row, on every screen: the chip, whether you sign and as what, your nick, the last
/// message, and as many of the hints as fit, the last (the way out, or to the help) always.
fn draw_status(f: &mut Frame, app: &App, area: Rect, bar: &Bar) {
    let mut spans = vec![
        Span::styled(
            format!(" {} ", bar.chip),
            Style::default().fg(bar.tone).add_modifier(Modifier::BOLD | Modifier::REVERSED),
        ),
        Span::raw(" "),
    ];
    let message = if bar.anonymous {
        app.locked.as_ref().and_then(|l| l.why.clone()).map(|w| (w, true))
    } else {
        match &app.ident {
            None => spans.push(Span::styled("\u{25cb} unsigned", Style::default().fg(Color::Yellow))),
            Some(i) => {
                spans.push(Span::styled("\u{2713} signed ", Style::default().fg(Color::Green)));
                spans.push(Span::styled(
                    match i.kind {
                        chat_core::IdentityKind::Age => "age",
                        chat_core::IdentityKind::Pgp => "pgp",
                        chat_core::IdentityKind::Native => "native",
                    },
                    faint(),
                ));
            }
        }
        if !app.nick.is_empty() {
            spans.push(Span::styled("  ", faint()));
            spans.push(Span::styled(
                app.nick.clone(),
                Style::default()
                    .fg(app.colour.map_or(Color::Reset, rgb))
                    .add_modifier(Modifier::BOLD),
            ));
        }
        app.status.as_ref().map(|(t, bad, _)| (t.clone(), *bad))
    };
    if let Some((text, bad)) = message {
        spans.push(Span::styled("  \u{203a} ", faint()));
        spans.push(Span::styled(
            text,
            if bad {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                bold()
            },
        ));
    }
    // As many of the hints as fit, from the first; the last stays whatever the width.
    let parts: Vec<&str> = bar.hint.split(" \u{b7} ").filter(|p| !p.is_empty()).collect();
    let used = spans_width(&spans) + 3;
    let cols = area.width as usize;
    let last = parts.last().copied().unwrap_or_default();
    let mut fit: Vec<&str> = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        let mut trial = fit.clone();
        trial.push(p);
        let w = width(&trial.join(" \u{b7} ")) + if i + 1 < parts.len() { 3 + width(last) } else { 0 };
        if used + w > cols {
            break;
        }
        fit.push(p);
    }
    if fit.len() < parts.len() && used + width(&fit.join(" \u{b7} ")) + 3 + width(last) <= cols {
        fit.push(last);
    }
    if !fit.is_empty() {
        let text = fit.join(" \u{b7} ");
        let pad = cols.saturating_sub(spans_width(&spans) + width(&text) + 1);
        spans.push(Span::raw(" ".repeat(pad)));
        spans.extend(hint_spans(&text));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// A picture on a page of its own: in the middle, scaled to fit, with its caption under it; or
/// what's become of it, with a progress bar while it comes.
fn draw_picture(f: &mut Frame, app: &App, num: u32, main: Rect) -> Bar {
    f.render_widget(Clear, main);
    let (title, note, progress) = app.picture_text(num);
    let buf = f.buffer_mut();
    let right = vec![Span::styled(hhmm(crate::text::unix_now()), faint())];
    let t = crumb_title(&title, title_room(main.width as usize, spans_width(&right)));
    page_box(buf, main, accent(), false, t, right);
    let (top, ih, left, iw) = (main.y + 1, main.height.saturating_sub(2), main.x + 1, main.width.saturating_sub(2));
    // A blank row and the caption under the picture.
    let area_h = ih.saturating_sub(2) as usize;
    let thumb = app.room().and_then(|r| r.picture_data.get(&num).or_else(|| r.pictures.get(&num)));
    match thumb {
        Some(th) => {
            let lines = picture_lines(th, (iw as usize).saturating_sub(2), area_h);
            let first = top + (area_h.saturating_sub(lines.len()) / 2) as u16;
            for (k, l) in lines.into_iter().enumerate().take(area_h) {
                let spans: Vec<Span> = l.spans.into_iter().skip(1).collect();
                let pad = (iw as usize).saturating_sub(spans.len()) / 2;
                buf.set_line(left + pad as u16, first + k as u16, &Line::from(spans), iw);
            }
            let cap = ell(&note, iw as usize);
            let pad = (iw as usize).saturating_sub(width(&cap)) / 2;
            buf.set_line(left + pad as u16, top + ih - 1, &Line::styled(cap, faint()), iw);
        }
        None => {
            let rows = note.split('\n').count() + if progress.is_some() { 3 } else { 0 };
            let start = top + (area_h.saturating_sub(rows) / 2) as u16;
            draw_centred(buf, start, left, iw, note.split('\n').count(), &note);
            if let Some((pm, text)) = progress {
                let y = start + note.split('\n').count() as u16 + 1;
                let bw = (iw as usize).saturating_sub(8).min(40);
                let mut spans = bar_spans(pm, bw);
                spans.push(Span::styled(format!(" {}%", pm / 10), bold()));
                let pad = (iw as usize).saturating_sub(spans_width(&spans)) / 2;
                buf.set_line(left + pad as u16, y, &Line::from(spans), iw);
                let pad = (iw as usize).saturating_sub(width(&text)) / 2;
                buf.set_line(left + pad as u16, y + 1, &Line::styled(text, faint()), iw);
            }
        }
    }
    Bar::page("PICTURE", &app.picture_hint(num))
}

// ---- list pages: settings, and the signing identity's page under it ----

/// How a page row's value is drawn: as it is, as a switch, as a choice h/l steps through, as a way
/// into another page, or dim.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Value {
    Text,
    On,
    Off,
    Choice,
    Link,
    Muted,
    /// After a progress bar, `permille` of it lit.
    Progress,
    /// After a red cross.
    Bad,
}

pub struct PageRow {
    /// Starts a new section under this heading.
    pub heading: Option<&'static str>,
    /// Drawn faint before the label: a tree's lines.
    pub prefix: Option<String>,
    pub label: String,
    /// In a column after the label.
    pub value: Option<String>,
    pub kind: Value,
    /// A sample of this colour before the value.
    pub swatch: Option<Colour>,
    /// Can't be used here: label and value faint, and the help says why.
    pub disabled: bool,
    /// [`Value::Progress`]'s bar, in thousandths.
    pub permille: u32,
}

/// A list page: rows grouped under headings with one picked, the button before them if there is
/// one (picked when `selected` is past the last row), and the picked row's help and usage at the
/// bottom. `nav` lists the sections on the left, `nav_sel` highlighted, and `title` goes in the
/// page's border, showing where the page is.
pub struct PageView {
    pub title: String,
    pub nav: Vec<String>,
    pub nav_sel: usize,
    pub intro: Option<String>,
    /// A list in a column left of the rows, inside the page: a browser's parent folder. It's left
    /// out where the page is too narrow for it.
    pub side: Option<Side>,
    pub rows: Vec<PageRow>,
    pub selected: usize,
    pub help: String,
    pub usage: Option<String>,
    pub button: Option<&'static str>,
    /// What the bar says the page is for, before the keys.
    pub chip: Option<&'static str>,
    /// The labels are keys, drawn as keys are.
    pub keys: bool,
    /// Shown in the middle while there are no rows: lines split by '\n', the first bold.
    pub empty: Option<String>,
    /// What the keys do, for the bar.
    pub hint: String,
}

impl PageView {
    /// A page with nothing on it but a note.
    pub fn empty(title: &str, note: &str) -> PageView {
        PageView {
            title: title.into(),
            nav: Vec::new(),
            nav_sel: 0,
            intro: None,
            side: None,
            rows: Vec::new(),
            selected: 0,
            help: String::new(),
            usage: None,
            button: None,
            chip: None,
            keys: false,
            empty: Some(note.into()),
            hint: "esc back".into(),
        }
    }
}

pub struct Side {
    pub title: String,
    pub entries: Vec<String>,
    pub sel: Option<usize>,
}

fn faint() -> Style {
    Style::default().add_modifier(Modifier::DIM)
}

fn accent() -> Style {
    Style::default().fg(Color::Magenta)
}

fn accent_bold() -> Style {
    accent().add_modifier(Modifier::BOLD)
}

fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

/// A screen this small has no boxes, and the left hand box takes a quarter of the screen, within
/// these, unless what's right of it would get narrower than the page needs.
const BOXED_ROWS: u16 = 10;
const BOXED_COLS: u16 = 40;
const LEFT_MIN: u16 = 24;
const LEFT_MAX: u16 = 32;
const PAGE_COLS_MIN: u16 = 56;
const HELP_ROWS: usize = 5;
const INTRO_ROWS: usize = 3;
const EDGE_ENDS: usize = 4;
const TITLE_PAD: usize = 2;

fn left_width(cols: u16) -> u16 {
    let w = (cols / 4).clamp(LEFT_MIN, LEFT_MAX);
    if cols.saturating_sub(w) < PAGE_COLS_MIN { 0 } else { w }
}

/// The side column takes a third of the rows' width, within these, if the rows keep ROWS_COLS_MIN.
const SIDE_MIN: usize = 20;
const SIDE_MAX: usize = 36;
const ROWS_COLS_MIN: usize = 60;

/// The side column's width for rows `iw` columns wide, its rule included, or 0 if it doesn't fit.
fn side_width(iw: usize) -> usize {
    let w = (iw / 3).clamp(SIDE_MIN, SIDE_MAX);
    if iw.saturating_sub(w) >= ROWS_COLS_MIN { w } else { 0 }
}

/// The columns a page's rows get at this width, and its side column's (0 if it doesn't fit).
pub fn page_cols(cols: u16) -> (usize, usize) {
    let navw = left_width(cols) as usize;
    let iw = (cols as usize).saturating_sub(navw.max(1) + 1);
    (iw.saturating_sub(4), side_width(iw))
}

/// The text cut to `room` columns, ending in an ellipsis if it was longer.
fn ell(s: &str, room: usize) -> String {
    if width(s) <= room {
        return s.to_string();
    }
    let mut out = String::new();
    let mut used = 0;
    for c in s.chars() {
        let w = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
        if used + w + 1 > room {
            break;
        }
        out.push(c);
        used += w;
    }
    if room > 0 {
        out.push('\u{2026}');
    }
    out
}

fn spans_width(spans: &[Span]) -> usize {
    spans.iter().map(|s| width(&s.content)).sum()
}

/// The room a box's title has next to its right hand title.
fn title_room(w: usize, right_cols: usize) -> usize {
    w.saturating_sub(EDGE_ENDS + TITLE_PAD + if right_cols > 0 { right_cols + TITLE_PAD } else { 0 })
}

/// A box's side at (x, y). Like an edge, it's drawn in its own style alone, whatever box was drawn
/// there before: a side two boxes share is the second's.
fn box_side(buf: &mut Buffer, x: u16, y: u16, bs: Style) {
    buf.set_style(Rect::new(x, y, 1, 1), Style::reset());
    buf.set_string(x, y, "\u{2502}", bs);
}

/// A box's top or bottom edge, or a junction across it: lc, a rule with title near its left end
/// and right near its right end, then rc.
#[allow(clippy::too_many_arguments)]
fn edge(buf: &mut Buffer, x: u16, y: u16, w: u16, ends: [&str; 2], bs: Style, title: Vec<Span<'static>>, right: Vec<Span<'static>>) {
    let w = w as usize;
    if w < EDGE_ENDS {
        return;
    }
    let mut tc = if title.is_empty() { 0 } else { spans_width(&title) + TITLE_PAD };
    let mut rc = if right.is_empty() { 0 } else { spans_width(&right) + TITLE_PAD };
    if EDGE_ENDS + tc + rc > w {
        rc = 0;
    }
    if EDGE_ENDS + tc > w {
        tc = 0;
    }
    let mut spans = vec![Span::styled(format!("{}\u{2500}", ends[0]), bs)];
    if tc > 0 {
        spans.push(Span::styled(" ", bs));
        spans.extend(title);
        spans.push(Span::styled(" ", bs));
    }
    spans.push(Span::styled("\u{2500}".repeat(w - EDGE_ENDS - tc - rc), bs));
    if rc > 0 {
        spans.push(Span::styled(" ", bs));
        spans.extend(right);
        spans.push(Span::styled(" ", bs));
    }
    spans.push(Span::styled(format!("\u{2500}{}", ends[1]), bs));
    buf.set_style(Rect::new(x, y, w as u16, 1), Style::reset());
    buf.set_line(x, y, &Line::from(spans), w as u16);
}

/// A box. One that isn't at the screen's left edge shares its left side with the box before it,
/// so its corners there join the frame's top and bottom edges.
fn page_box(buf: &mut Buffer, r: Rect, bs: Style, joined: bool, title: Vec<Span<'static>>, right: Vec<Span<'static>>) {
    if r.height < 2 {
        return;
    }
    let (tl, bl) = if joined {
        ("\u{252c}", "\u{2534}")
    } else {
        ("\u{256d}", "\u{2570}")
    };
    edge(buf, r.x, r.y, r.width, [tl, "\u{256e}"], bs, title, right);
    for y in r.y + 1..r.y + r.height - 1 {
        box_side(buf, r.x, y, bs);
        box_side(buf, r.x + r.width - 1, y, bs);
    }
    edge(buf, r.x, r.y + r.height - 1, r.width, [bl, "\u{256f}"], bs, Vec::new(), Vec::new());
}

fn pointer(on: bool) -> Span<'static> {
    if on {
        Span::styled("\u{276f} ", accent_bold())
    } else {
        Span::raw("  ")
    }
}

/// The first of n entries to show in `shown` rows: the one that puts sel in the middle, when they
/// don't all fit.
fn centred_first(n: usize, shown: usize, sel: usize) -> usize {
    if n <= shown {
        return 0;
    }
    sel.saturating_sub(shown / 2).min(n - shown)
}

/// A row inside a box: a space, then the spans.
fn inner_line(buf: &mut Buffer, x: u16, y: u16, w: u16, mut spans: Vec<Span<'static>>) {
    spans.insert(0, Span::raw(" "));
    buf.set_line(x, y, &Line::from(spans), w);
}

/// A row inside a box that's picked: shaded across the box, where the terminal's background is known.
fn picked_line(buf: &mut Buffer, x: u16, y: u16, w: u16, spans: Vec<Span<'static>>) {
    inner_line(buf, x, y, w, spans);
    if let Some(bg) = sel_bg() {
        buf.set_style(Rect::new(x, y, w, 1), Style::default().bg(bg));
    }
}

fn draw_nav(buf: &mut Buffer, r: Rect, v: &PageView) {
    let right = vec![Span::styled(format!("v{}", env!("CARGO_PKG_VERSION")), faint())];
    let room = title_room(r.width as usize, spans_width(&right));
    page_box(
        buf,
        r,
        faint(),
        false,
        vec![Span::styled(ell("\u{25c6} chat", room), accent_bold())],
        right,
    );
    let rows = r.height.saturating_sub(2) as usize;
    let top = centred_first(v.nav.len(), rows.saturating_sub(1), v.nav_sel);
    let room = (r.width as usize).saturating_sub(6);
    // A blank row above the first.
    for i in 1..rows {
        let k = i - 1 + top;
        let Some(name) = v.nav.get(k) else { break };
        if name.is_empty() {
            continue;
        }
        let on = k == v.nav_sel;
        let style = if on { accent_bold() } else { faint() };
        let draw = if on { picked_line } else { inner_line };
        draw(
            buf,
            r.x + 1,
            r.y + 1 + i as u16,
            r.width - 2,
            vec![pointer(on), Span::styled(ell(name, room), style)],
        );
    }
}

/// A row's value after its label: as a switch, a choice, a way in, or text, in `room` columns.
fn value_spans(r: &PageRow, on: bool, mut room: usize) -> Vec<Span<'static>> {
    let mut out = Vec::new();
    if let Some(c) = r.swatch {
        // A colour sample, as it is.
        out.push(Span::styled(
            "\u{2588}\u{2588} ",
            Style::default().fg(Color::Rgb(c.0[0], c.0[1], c.0[2])),
        ));
        room = room.saturating_sub(3);
    }
    let v = r.value.as_deref().unwrap_or_default();
    if r.disabled {
        out.push(Span::styled(ell(v, room), faint()));
        return out;
    }
    match r.kind {
        Value::On => {
            out.push(Span::styled("\u{25cf} ", Style::default().fg(Color::Green)));
            out.push(Span::raw(ell(v, room.saturating_sub(2))));
        }
        Value::Off => {
            out.push(Span::styled("\u{25cb} ", faint()));
            out.push(Span::styled(ell(v, room.saturating_sub(2)), faint()));
        }
        Value::Choice if on => {
            out.push(Span::styled("\u{2039} ", faint()));
            out.push(Span::styled(ell(v, room.saturating_sub(4)), bold()));
            out.push(Span::styled(" \u{203a}", faint()));
        }
        Value::Link => {
            out.push(Span::raw(ell(v, room.saturating_sub(2))));
            out.push(Span::styled(" \u{203a}", faint()));
        }
        Value::Muted => out.push(Span::styled(ell(v, room), faint())),
        Value::Progress => {
            let bw = if room >= 30 {
                10
            } else if room >= 18 {
                6
            } else {
                0
            };
            if bw > 0 {
                out.extend(bar_spans(r.permille, bw));
                out.push(Span::raw(" "));
            }
            out.push(Span::raw(ell(v, room.saturating_sub(bw + usize::from(bw > 0)))));
        }
        Value::Bad => {
            out.push(Span::styled("\u{2717} ", Style::default().fg(Color::Red)));
            out.push(Span::raw(ell(v, room.saturating_sub(2))));
        }
        Value::Choice | Value::Text => out.push(Span::raw(ell(v, room))),
    }
    out
}

/// A progress bar `w` columns wide, `permille` of it lit.
fn bar_spans(permille: u32, w: usize) -> Vec<Span<'static>> {
    let lit = (permille.min(1000) as usize * w) / 1000;
    vec![
        Span::styled("\u{2501}".repeat(lit), accent()),
        Span::styled("\u{2500}".repeat(w - lit), faint()),
    ]
}

/// Lines in the middle of `nrows` rows from `top`: the first bold, the rest faint.
fn draw_centred(buf: &mut Buffer, top: u16, left: u16, iw: u16, nrows: usize, text: &str) {
    let tw = (iw as usize).saturating_sub(6);
    let mut lines: Vec<(String, bool)> = Vec::new();
    for (i, l) in text.split('\n').enumerate() {
        lines.extend(wrap_plain(l, tw).into_iter().map(|p| (p, i == 0)));
    }
    let first = top + (nrows.saturating_sub(lines.len()) / 2) as u16;
    for (k, (l, bold_line)) in lines.iter().enumerate().take(nrows) {
        let pad = (iw as usize).saturating_sub(width(l)) / 2;
        let style = if *bold_line { bold() } else { faint() };
        buf.set_line(left + pad as u16, first + k as u16, &Line::styled(l.clone(), style), iw);
    }
}

/// The rows under their headings, with the button before them, in `nrows` rows from `top`,
/// scrolled so the picked row shows with its heading and as much of the rest of its section as
/// fits in `view` rows (the room left with the help at its longest, so the rows don't move as it
/// changes).
#[allow(clippy::too_many_arguments)]
fn draw_list(buf: &mut Buffer, top: u16, left: u16, iw: u16, view: usize, nrows: usize, v: &PageView) {
    enum L {
        Blank,
        Heading(usize),
        Row(usize),
        Button,
    }
    let mut lines = Vec::new();
    let (mut sel_line, mut head_line, mut end_line, mut head) = (None::<usize>, 0, None::<usize>, None::<usize>);
    let button_on = v.button.is_some() && v.selected == v.rows.len();
    if v.button.is_some() {
        if button_on {
            (sel_line, end_line) = (Some(0), Some(0));
        }
        lines.push(L::Button);
        lines.push(L::Blank);
    }
    for (i, r) in v.rows.iter().enumerate() {
        if r.heading.is_some() {
            if sel_line.is_some() && end_line.is_none() {
                end_line = Some(lines.len() - 1);
            }
            if i > 0 {
                lines.push(L::Blank);
            }
            head = Some(lines.len());
            lines.push(L::Heading(i));
        }
        // Rows before the first heading count as under one at the top.
        if i == v.selected {
            sel_line = Some(lines.len());
            head_line = head.unwrap_or(0);
        }
        lines.push(L::Row(i));
    }
    let end_line = end_line.unwrap_or(lines.len().saturating_sub(1)) as isize;
    let mut scroll = 0isize;
    if let Some(sl) = sel_line {
        let (sl, hl, view) = (sl as isize, head_line as isize, view as isize);
        scroll = (end_line - view + 1).max(sl - view + 1);
        if scroll > hl {
            scroll = hl.max(sl - view + 1);
        }
    }
    let scroll = scroll.max(0) as usize;

    let cw = (iw as usize).saturating_sub(2);
    let any_value = v.rows.iter().any(|r| r.value.is_some());
    let mut lw = v
        .rows
        .iter()
        .map(|r| width(&r.label) + r.prefix.as_deref().map_or(0, width))
        .max()
        .unwrap_or(0)
        + 3;
    if !any_value || lw > cw.saturating_sub(2) / 2 {
        lw = if any_value {
            cw.saturating_sub(2) / 2
        } else {
            cw.saturating_sub(2)
        };
    }
    for row in 0..nrows {
        let y = top + row as u16;
        match lines.get(scroll + row) {
            None | Some(L::Blank) => {}
            Some(L::Button) => {
                let label = format!(" {} ", v.button.unwrap_or_default());
                let spans = if button_on {
                    vec![pointer(true), Span::styled(label, accent_bold().add_modifier(Modifier::REVERSED))]
                } else {
                    vec![
                        Span::raw("  "),
                        Span::styled("[", faint()),
                        Span::styled(label, bold()),
                        Span::styled("]", faint()),
                    ]
                };
                inner_line(buf, left, y, iw, spans);
            }
            Some(L::Heading(i)) => {
                inner_line(
                    buf,
                    left,
                    y,
                    iw,
                    vec![Span::styled(v.rows[*i].heading.unwrap_or_default(), accent_bold())],
                );
            }
            Some(L::Row(i)) => {
                let r = &v.rows[*i];
                let on = *i == v.selected;
                let style = if r.disabled {
                    faint()
                } else if on {
                    accent_bold()
                } else if v.keys {
                    accent()
                } else {
                    Style::default()
                };
                let pc = r.prefix.as_deref().map_or(0, width);
                let label = ell(
                    &r.label,
                    (if r.value.is_some() { lw.saturating_sub(2) } else { lw }).saturating_sub(pc),
                );
                let used = 2 + pc + width(&label);
                let mut spans = vec![pointer(on)];
                if let Some(pre) = &r.prefix {
                    spans.push(Span::styled(pre.clone(), faint()));
                }
                spans.push(Span::styled(label, style));
                if r.value.is_some() {
                    spans.push(Span::raw(" ".repeat((2 + lw).saturating_sub(used))));
                    spans.extend(value_spans(r, on, cw.saturating_sub(2 + lw)));
                }
                let draw = if on { picked_line } else { inner_line };
                draw(buf, left, y, iw, spans);
            }
        }
    }
}

/// The side column: its title, a blank row, then its entries, scrolled so the one picked is in the
/// middle when they don't all fit, with a rule on its right.
fn draw_side(buf: &mut Buffer, top: u16, left: u16, w: u16, nrows: usize, side: &Side) {
    let first = centred_first(side.entries.len(), nrows.saturating_sub(2), side.sel.unwrap_or(0));
    let room = (w as usize).saturating_sub(3);
    for i in 0..nrows {
        let y = top + i as u16;
        let spans = match i {
            0 => vec![Span::styled(ell(&side.title, room), faint())],
            1 => Vec::new(),
            _ => match side.entries.get(first + i - 2) {
                Some(e) => {
                    let on = side.sel == Some(first + i - 2);
                    vec![
                        pointer(on),
                        Span::styled(ell(e, room.saturating_sub(2)), if on { accent_bold() } else { faint() }),
                    ]
                }
                None => Vec::new(),
            },
        };
        inner_line(buf, left, y, w - 1, spans);
        box_side(buf, left + w - 1, y, faint());
    }
}

/// The export's box over its browser: what's written where, and what that means.
fn export_dialog(app: &App, path: &std::path::Path) -> Dialog {
    let shown = crate::browser::tilde(path);
    let age = app.ident.as_ref().is_none_or(|i| i.kind != chat_core::IdentityKind::Pgp);
    let text = [
        format!("This writes your signing key, unencrypted, to {shown}, a new file only you can open."),
        "Anyone who reads it can sign as you, and peers who verified you would take them for you. Deleting it later \
         isn't erasing: the disk, its snapshots and its backups can keep traces."
            .to_string(),
        format!(
            "It's the same key, with the same fingerprint: /set sign {}:PATH loads it on another device, and {} takes it too.",
            if age { "age" } else { "pgp" },
            if age { "age -d -i" } else { "gpg --import" }
        ),
    ];
    Dialog {
        title: "EXPORT SIGNING KEY".into(),
        text: paras(&text),
        keys: "y write \u{b7} n back".into(),
        ..Dialog::default()
    }
}

/// The rooms kept in the save, by label, and "another room" last; or forgetting one, asked.
fn rooms_dialog(app: &App, sel: usize, forgetting: bool) -> Dialog {
    let rooms = &app.settings.rooms;
    if forgetting && let Some(r) = rooms.get(sel) {
        return Dialog {
            title: "JOIN SESSION".into(),
            text: paras(&[format!("Forget {}? Its id and password go from the save.", r.label)]),
            keys: "y forget \u{b7} n keep".into(),
            ..Dialog::default()
        };
    }
    Dialog {
        title: "JOIN SESSION".into(),
        text: paras(&["The rooms kept in the save, by label. Enter joins one.".to_string()]),
        items: rooms
            .iter()
            .map(|r| (r.label.clone(), if r.at_start { "joined at start" } else { "" }.to_string()))
            .chain(std::iter::once(("another room...".to_string(), "type its id".to_string())))
            .collect(),
        sel: Some(sel),
        keys: if sel < rooms.len() {
            "enter join \u{b7} s at start \u{b7} d forget \u{b7} esc close"
        } else {
            "enter type an id \u{b7} esc close"
        }
        .into(),
        ..Dialog::default()
    }
}

/// A paragraph in a box: text wrapped to the box (a line starting with "• " hangs under its text),
/// a blank row, or a picture's row, centred as it is.
enum Para {
    Blank,
    Text(Vec<(String, Style)>),
    Art(Line<'static>),
}

/// Paragraphs of plain text with a blank row between them, each of their lines on its own.
fn paras(texts: &[String]) -> Vec<Para> {
    let mut out = Vec::new();
    for (i, t) in texts.iter().enumerate() {
        if i > 0 {
            out.push(Para::Blank);
        }
        out.extend(t.split('\n').map(|l| Para::Text(vec![(l.to_string(), Style::default())])));
    }
    out
}

/// A paragraph's rows, `w` columns wide. A list item's bullet is in the accent, and the rows after
/// its first line up under its text.
fn para_rows(pieces: &[(String, Style)], w: usize) -> Vec<Line<'static>> {
    match pieces.first().and_then(|(t, s)| t.strip_prefix("\u{2022} ").map(|rest| (rest, *s))) {
        Some((rest, s)) => {
            let mut p = vec![("\u{2022} ".to_string(), accent()), (rest.to_string(), s)];
            p.extend(pieces[1..].iter().cloned());
            wrap(&p, w, 2)
        }
        None => wrap(pieces, w, 0),
    }
}

/// A field in a box: what's typed (as dots, if it's secret), where the cursor is, and what it
/// takes while it's empty.
struct Field {
    text: Vec<char>,
    cursor: usize,
    placeholder: String,
}

impl Field {
    fn of(input: &Input, mask: bool, placeholder: String) -> Field {
        Field {
            text: if mask {
                vec!['\u{2022}'; input.chars.len()]
            } else {
                input.chars.clone()
            },
            cursor: input.cursor.min(input.chars.len()),
            placeholder,
        }
    }
}

/// A question, a field or a list, in a box over the middle of the screen: its title on the top
/// edge and its keys on the bottom one, then its text, the list with the one picked marked, the
/// field (or `status`, while there's nothing to type), and a note under them.
#[derive(Default)]
struct Dialog {
    title: String,
    text: Vec<Para>,
    /// Each with its detail, faint on its right.
    items: Vec<(String, String)>,
    sel: Option<usize>,
    field: Option<Field>,
    status: Option<String>,
    note: Option<String>,
    keys: String,
}

const DIALOG_MAX_W: u16 = 76;
const CONSOLE_DIALOG_MAX_W: u16 = 100;
/// The backdrop around a box: columns either side, and a row above and below while there's room.
const DIALOG_MX: u16 = 2;
const DIALOG_NOTE_ROWS: usize = 6;

/// A box's width, at most `max`: its backdrop stays inside the frame's sides, so the frame is
/// whole on a narrow screen too.
fn dialog_fit(cols: u16, max: u16) -> u16 {
    cols.saturating_sub(2 + 2 * DIALOG_MX).min(max)
}

fn dialog_rows(text: usize, list: usize, field: bool, note: usize) -> usize {
    let part = |n: usize| if n > 0 { n + 1 } else { 0 };
    1 + part(text) + part(list) + if field { 2 } else { 0 } + part(note)
}

/// A box's backdrop (a margin around it, shaded like the picked row) and its frame, the title on
/// the top edge and the keys on the bottom one, `inner` rows high and `bw` wide, in the middle of
/// `area`. Returns the rect inside its sides.
fn dialog_frame(buf: &mut Buffer, area: Rect, bw: u16, inner: u16, my: u16, title: &str, keys: &str) -> Rect {
    let bh = (inner + 2).min(area.height);
    let (oh, ow) = ((bh + 2 * my).min(area.height), (bw + 2 * DIALOG_MX).min(area.width));
    let outer = Rect::new(area.x + (area.width - ow) / 2, area.y + (area.height - oh) / 2, ow, oh);
    Clear.render(outer, buf);
    let b = Rect::new(outer.x + (ow - bw.min(ow)) / 2, outer.y + (oh - bh) / 2, bw.min(ow), bh);
    let bs = accent();
    let title = vec![Span::styled(ell(title, title_room(b.width as usize, 0)), accent_bold())];
    edge(buf, b.x, b.y, b.width, ["\u{256d}", "\u{256e}"], bs, title, Vec::new());
    for y in b.y + 1..b.bottom().saturating_sub(1) {
        box_side(buf, b.x, y, bs);
        box_side(buf, b.right() - 1, y, bs);
    }
    edge(
        buf,
        b.x,
        b.bottom() - 1,
        b.width,
        ["\u{2570}", "\u{256f}"],
        bs,
        Vec::new(),
        hint_spans(keys),
    );
    // The shade goes on last: the frame's edges start from no style at all.
    if let Some(bg) = sel_bg() {
        buf.set_style(outer, Style::default().bg(bg));
    }
    Rect::new(b.x + 1, b.y + 1, b.width.saturating_sub(2), bh.saturating_sub(2))
}

/// Draws a box over `area` (the screen above the bottom row). What doesn't fit is cut from the end
/// of the text, then from the note, then from the list; the field always shows. Returns where the
/// cursor goes, if it has a field.
fn draw_dialog(f: &mut Frame, area: Rect, d: &Dialog) -> Option<(u16, u16)> {
    let bw = dialog_fit(area.width, DIALOG_MAX_W);
    if bw < 10 || area.height < 3 {
        return None;
    }
    let tw = (bw as usize).saturating_sub(6);
    let mut text: Vec<(Line<'static>, bool)> = Vec::new();
    for p in &d.text {
        match p {
            Para::Blank => text.push((Line::default(), false)),
            Para::Text(pieces) => text.extend(para_rows(pieces, tw).into_iter().map(|l| (l, false))),
            Para::Art(l) => text.push((l.clone(), true)),
        }
    }
    let note: Vec<String> = d.note.as_deref().map_or(Vec::new(), |n| wrap_plain(n, tw));
    let field = d.field.is_some() || d.status.is_some();
    let (mut tn, mut nn, mut ln) = (text.len(), note.len().min(DIALOG_NOTE_ROWS), d.items.len());
    let avail = area.height as usize;
    let my = if dialog_rows(tn, ln, field, nn) + 4 > avail { 0 } else { 1 };
    while dialog_rows(tn, ln, field, nn) + 2 > avail && (tn > 0 || nn > 0 || ln > 1) {
        if tn > 0 {
            tn -= 1;
        } else if nn > 0 {
            nn -= 1;
        } else {
            ln -= 1;
        }
    }
    let inner = dialog_rows(tn, ln, field, nn).min(avail.saturating_sub(2)).max(1) as u16;
    let r = dialog_frame(f.buffer_mut(), area, bw, inner, my, &d.title, &d.keys);
    let buf = f.buffer_mut();
    // Everything starts a column in from the box's padding.
    let (x, cw, end) = (r.x + 2, r.width.saturating_sub(4), r.bottom());
    let mut y = r.y + 1;
    let put = |buf: &mut Buffer, y: u16, line: &Line, at: u16| {
        if y < end {
            buf.set_line(at, y, line, cw);
        }
    };
    for (l, art) in text.iter().take(tn) {
        if !art {
            put(buf, y, l, x);
        } else if y < end {
            buf.set_line(r.x + r.width.saturating_sub(l.width() as u16) / 2, y, l, r.width);
        }
        y += 1;
    }
    if tn > 0 {
        y += 1;
    }
    if ln > 0 {
        let first = match d.sel {
            Some(s) if s >= ln => s + 1 - ln,
            _ => 0,
        };
        for (i, (name, detail)) in d.items.iter().enumerate().skip(first).take(ln) {
            let on = d.sel == Some(i);
            let (nw, dw) = (width(name), width(detail));
            // The detail is left out unless the whole name fits beside it.
            let dw = if 2 + nw + 3 + dw > cw as usize { 0 } else { dw };
            let room = (cw as usize).saturating_sub(2 + if dw > 0 { dw + 3 } else { 1 });
            let mut spans = vec![pointer(on), Span::styled(ell(name, room), if on { accent_bold() } else { bold() })];
            if dw > 0 {
                spans.push(Span::raw(" ".repeat((cw as usize).saturating_sub(spans_width(&spans) + dw))));
                spans.push(Span::styled(detail.clone(), faint()));
            }
            put(buf, y, &Line::from(spans), x);
            y += 1;
        }
        y += 1;
    }
    let mut cursor = None;
    if let Some(fl) = &d.field {
        // Scrolled so the text before the cursor fits, with a column for the cursor itself.
        let room = (cw as usize).saturating_sub(2);
        let mut spans = vec![Span::styled("\u{203a} ", accent_bold())];
        let before = |from: usize| fl.text[from..fl.cursor].iter().collect::<String>();
        let mut skip = 0;
        while skip < fl.cursor && width(&before(skip)) > room.saturating_sub(1) {
            skip += 1;
        }
        if fl.text.is_empty() {
            spans.push(Span::styled(ell(&fl.placeholder, room), faint()));
        } else {
            spans.push(Span::raw(ell(&fl.text[skip..].iter().collect::<String>(), room)));
        }
        put(buf, y, &Line::from(spans), x);
        if y < end {
            cursor = Some((x + 2 + width(&before(skip)) as u16, y));
        }
        y += 2;
    } else if let Some(s) = &d.status {
        put(buf, y, &Line::styled(ell(s, cw as usize), faint()), x);
        y += 2;
    }
    for l in note.iter().take(nn) {
        put(buf, y, &Line::styled(l.clone(), faint()), x);
        y += 1;
    }
    cursor
}

/// /update's box, wider than the rest: its console in a frame of its own with the last lines that
/// fit, then a progress bar as wide as the console with the percentage on its right, then the
/// current step. The console loses rows on a short screen; the rest always shows.
fn draw_update(f: &mut Frame, area: Rect) -> Option<(u16, u16)> {
    use chat_core::net::update::LineKind;
    /// A blank, the console's edges, a blank, the bar, a blank, the step and a blank.
    const FIXED: usize = 8;
    let v = chat_core::net::update::view();
    let bw = dialog_fit(area.width, CONSOLE_DIALOG_MAX_W);
    let avail = area.height as usize;
    let mut con = 12;
    let my = if con + FIXED + 4 > avail { 0 } else { 1 };
    if con + FIXED + 2 > avail {
        con = avail.saturating_sub(FIXED + 2).max(1);
    }
    let keys = if v.running { "esc hide" } else { "enter close" };
    let r = dialog_frame(f.buffer_mut(), area, bw, (con + FIXED) as u16, my, "UPDATE", keys);
    let buf = f.buffer_mut();
    let (x, cw) = (r.x + 2, r.width.saturating_sub(4));
    let mut y = r.y + 1;
    let console = Rect::new(x, y, cw, con as u16 + 2);
    page_box(buf, console, faint(), false, Vec::new(), Vec::new());
    let first = v.log.len().saturating_sub(con);
    for (i, (kind, line)) in v.log[first..].iter().enumerate() {
        let style = match kind {
            LineKind::Detail => faint(),
            LineKind::Info => Style::default(),
            LineKind::Good => Style::default().fg(Color::Green),
            LineKind::Bad => Style::default().fg(Color::Red),
        };
        let room = cw.saturating_sub(4);
        buf.set_line(x + 2, y + 1 + i as u16, &Line::styled(ell(line, usize::from(room)), style), room);
    }
    y += con as u16 + 3;
    let pm = v.permille.min(1000);
    let mut right = match v.amount.as_str() {
        "" => format!("{:3}%", pm / 10),
        a => format!("{:3}%  {a}", pm / 10),
    };
    if usize::from(cw).saturating_sub(width(&right) + 1) < 8 {
        right = format!("{:3}%", pm / 10);
    }
    let mut bar = bar_spans(pm, usize::from(cw).saturating_sub(width(&right) + 1));
    bar.push(Span::raw(" "));
    bar.push(Span::styled(right, bold()));
    buf.set_line(x, y, &Line::from(bar), cw);
    y += 2;
    let st = if v.running {
        accent_bold()
    } else if v.ok {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    };
    let step = vec![
        Span::styled("\u{203a} ", st),
        Span::styled(ell(&v.step, usize::from(cw.saturating_sub(2))), st),
    ];
    buf.set_line(x, y, &Line::from(step), cw);
    None
}

/// Plain text wrapped to `w` columns.
fn wrap_plain(text: &str, w: usize) -> Vec<String> {
    wrap(&[(text.to_string(), Style::default())], w, 0)
        .into_iter()
        .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>())
        .collect()
}

/// "key action \u{b7} key action": each key in the accent, what it does faint.
fn hint_spans(hint: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (i, item) in hint.split(" \u{b7} ").enumerate() {
        if i > 0 {
            spans.push(Span::styled(" \u{b7} ", faint()));
        }
        let (key, what) = item.split_once(' ').unwrap_or((item, ""));
        spans.push(Span::styled(key.to_string(), accent()));
        if !what.is_empty() {
            spans.push(Span::styled(format!(" {what}"), faint()));
        }
    }
    spans
}

/// "a \u{203a} b \u{203a} c": the path to a page faint, and the page itself bold; just the page when
/// that's all that fits in `room`.
fn crumb_title(title: &str, room: usize) -> Vec<Span<'static>> {
    let parts: Vec<&str> = title.split(" \u{203a} ").collect();
    let mut t = Vec::new();
    for (i, part) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        t.push(Span::styled(part.to_string(), if last { bold() } else { faint() }));
        if !last {
            t.push(Span::styled(" \u{203a} ", faint()));
        }
    }
    if spans_width(&t) > room {
        t = vec![Span::styled(ell(parts.last().copied().unwrap_or_default(), room), bold())];
    }
    t
}

/// A list page over the whole screen: the sections on the left, the page beside them sharing its
/// edge, and the bar along the bottom.
fn draw_page(f: &mut Frame, v: &PageView, main: Rect) -> Bar {
    f.render_widget(Clear, main);
    let boxed = main.height + 1 >= BOXED_ROWS && main.width >= BOXED_COLS;
    // A page that gives the list on the left keeps its column while the list is empty.
    let navw = if boxed { left_width(main.width) } else { 0 };
    let buf = f.buffer_mut();
    if navw > 0 {
        draw_nav(buf, Rect { width: navw, ..main }, v);
    }
    let x = navw.saturating_sub(1);
    let r = Rect {
        x: main.x + x,
        width: main.width - x,
        ..main
    };
    let bs = accent();
    let (top, ih, left, iw) = if boxed {
        (r.y + 1, r.height.saturating_sub(2), r.x + 1, r.width.saturating_sub(2))
    } else {
        (r.y, r.height, r.x, r.width)
    };
    let cw = (iw as usize).saturating_sub(2);
    if boxed {
        let right = vec![Span::styled(hhmm(crate::text::unix_now()), faint())];
        let title = crumb_title(&v.title, title_room(r.width as usize, spans_width(&right)));
        page_box(buf, r, bs, navw > 0, title, right);
    }

    // Over the bottom of the rows, below an edge titled with the picked row: its help and usage.
    // Above the rows, the intro. The rows come first when there's no room for all of it.
    let help = if boxed && !v.help.is_empty() {
        wrap_plain(&v.help, cw)
    } else {
        Vec::new()
    };
    let intro: Vec<String> = match &v.intro {
        Some(t) if boxed => wrap_plain(t, cw).into_iter().take(INTRO_ROWS).collect(),
        _ => Vec::new(),
    };
    let mut il = intro.len();
    let mut ul = usize::from(boxed && v.usage.is_some());
    let btn = if v.button.is_some() { 2 } else { 0 };
    let (mut hmax, mut umax) = if boxed { (HELP_ROWS, 1) } else { (0, 0) };
    let ih = ih as isize;
    let (mut list, mut view);
    loop {
        list = ih - if il > 0 { il as isize + 1 } else { 0 };
        view = list - if hmax + umax > 0 { (hmax + umax + 1) as isize } else { 0 };
        if view >= 4 + btn || (il == 0 && hmax + umax == 0) {
            break;
        }
        if il > 0 {
            il = 0;
        } else if hmax > 2 {
            hmax = 2;
        } else {
            (hmax, umax) = (0, 0);
        }
    }
    let hl = help.len().min(hmax);
    if umax == 0 {
        ul = 0;
    }
    let view = view.max(1) as usize;
    let end = top + ih.max(0) as u16;
    let mut row = top;
    for line in intro.iter().take(il) {
        inner_line(buf, left, row, iw, vec![Span::styled(line.clone(), faint())]);
        row += 1;
    }
    if il > 0 && row < end {
        row += 1;
    }
    let list = (list.max(0) as usize).min((end - row) as usize);
    let shown = list.saturating_sub(if hl + ul > 0 { hl + ul + 1 } else { 0 });
    let sidew = match &v.side {
        Some(side) => {
            let w = side_width(iw as usize) as u16;
            if w > 0 {
                draw_side(buf, row, left, w, shown, side);
            }
            w
        }
        None => 0,
    };
    match &v.empty {
        Some(e) if v.rows.is_empty() && v.button.is_none() => draw_centred(buf, row, left + sidew, iw - sidew, shown, e),
        _ => draw_list(buf, row, left + sidew, iw - sidew, view, shown, v),
    }
    row += shown as u16;
    if hl + ul > 0 && row < end {
        let what = v.rows.get(v.selected).map(|r| r.label.as_str()).or(v.button).unwrap_or_default();
        let about = if what.is_empty() {
            Vec::new()
        } else {
            vec![Span::styled(ell(what, title_room(r.width as usize, 0)), faint())]
        };
        edge(buf, r.x, row, r.width, ["\u{251c}", "\u{2524}"], bs, about, Vec::new());
        row += 1;
        for (i, piece) in help.iter().take(hl).enumerate() {
            if row >= end {
                break;
            }
            // Help that goes on past its last row says so.
            let mut piece = piece.clone();
            if help.len() > hl && (i + 1 == hl || row + 1 == end) {
                piece.push('\u{2026}');
            }
            inner_line(buf, left, row, iw, vec![Span::raw(ell(&piece, cw))]);
            row += 1;
        }
        if ul > 0 && row < end {
            inner_line(
                buf,
                left,
                row,
                iw,
                vec![Span::styled(v.usage.clone().unwrap_or_default(), accent())],
            );
        }
    }
    Bar::page(v.chip.unwrap_or("SETTINGS"), &v.hint)
}

const SEARCH_ROWS: usize = 8;

/// The settings' search box: the matches above the field, SEARCH_ROWS at a time so the box keeps
/// its height as they change, each with its place on the page.
fn search_dialog(app: &App, input: &Input, sel: usize) -> Dialog {
    use chat_core::net::settings::{self as st, PAGE};
    let found = app.search_found(&input.text());
    let sel = sel.min(found.len().saturating_sub(1));
    let first = (sel + 1).saturating_sub(SEARCH_ROWS);
    let mut items: Vec<(String, String)> = (first..first + SEARCH_ROWS)
        .map(|k| match found.get(k) {
            Some(&i) => (
                PAGE[i].label.to_string(),
                format!("{}{}", st::place(i), if app.row_shown(i) { "" } else { " (hidden)" }),
            ),
            None => (String::new(), String::new()),
        })
        .collect();
    if found.is_empty() {
        items[0].0 = "No setting matches".into();
    }
    Dialog {
        title: "SEARCH SETTINGS".into(),
        items,
        sel: (!found.is_empty()).then(|| sel - first),
        field: Some(Field::of(
            input,
            false,
            "a setting's name or /set name, or a word in its help".into(),
        )),
        keys: if found.is_empty() {
            "esc back"
        } else {
            "enter open \u{b7} up/down move \u{b7} esc back"
        }
        .into(),
        ..Dialog::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_box_keeps_its_field_and_keys_when_its_text_is_cut() {
        let d = Dialog {
            title: "JOIN SESSION".into(),
            text: paras(&["word ".repeat(200)]),
            field: Some(Field {
                text: Vec::new(),
                cursor: 0,
                placeholder: "password".into(),
            }),
            note: Some("The password for a-room, as you were given it.".into()),
            keys: "enter join \u{b7} esc cancel".into(),
            ..Dialog::default()
        };
        let (w, h) = (70, 14);
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
        let mut cursor = None;
        t.draw(|f| cursor = draw_dialog(f, f.area(), &d)).unwrap();
        let rows: Vec<String> = (0..h)
            .map(|y| (0..w).map(|x| t.backend().buffer()[(x, y)].symbol().to_string()).collect())
            .collect();
        assert!(rows.iter().any(|r| r.contains("\u{256d}\u{2500} JOIN SESSION \u{2500}")));
        assert!(rows.iter().any(|r| r.contains("enter join \u{b7} esc cancel \u{2500}\u{256f}")));
        // The text gives way; the field and the cursor at its start stay.
        let (cx, cy) = cursor.expect("the field takes the cursor");
        assert!(rows[cy as usize].contains("\u{203a} password"));
        assert_eq!(rows[cy as usize].chars().nth(cx as usize), Some('p'));
    }

    #[test]
    fn makes_colours_readable() {
        assert!(contrast([0xf5, 0xd9, 0x0a], [255, 255, 255]) < 3.0);
        set_background([255, 255, 255]);
        assert!(contrast(readable([0xf5, 0xd9, 0x0a]), [255, 255, 255]) >= 3.0);
    }

    #[test]
    fn sidebar_lists_scroll_with_their_more_rows() {
        // All fit: no rows saying more.
        let v = list_view(3, 5, 0);
        assert_eq!((v.top, v.shown, v.above, v.below, v.most), (0, 3, false, false, 0));
        // Ten in five rows from the top: four shown, then "6 more" below.
        let v = list_view(10, 5, 0);
        assert_eq!((v.shown, v.above, v.below, v.most), (4, false, true, 6));
        // Scrolled to the bottom: "more" above, the last four shown.
        let v = list_view(10, 5, 99);
        assert_eq!((v.top, v.shown, v.above, v.below), (6, 4, true, false));
        // Kept on the one picked.
        let v = list_view_at(10, 5, 0, Some(7));
        assert!(v.top <= 7 && 7 < v.top + v.shown);
        assert_eq!(split_rows(10, 3, 4), (3, 4));
        assert_eq!(split_rows(10, 2, 20), (2, 8));
        assert_eq!(split_rows(10, 20, 20), (5, 5));
    }

    #[test]
    fn links_follow_their_spans_across_lines() {
        let u = Style::default().add_modifier(Modifier::UNDERLINED);
        let lines = vec![
            Line::from(vec![Span::raw("see "), Span::styled("example.com/a", u), Span::raw(" and ")]),
            Line::from(vec![Span::styled("https://exam", u)]),
            Line::from(vec![Span::styled("ple.org", u), Span::raw(" ok")]),
        ];
        let targets = vec![(13, "https://example.com/a".to_string()), (19, "https://example.org".to_string())];
        let got = link_spans(&lines, &targets);
        assert_eq!(got[0], vec![(1, "https://example.com/a".to_string())]);
        assert_eq!(got[1], vec![(0, "https://example.org".to_string())]);
        assert_eq!(got[2], vec![(0, "https://example.org".to_string())]);
    }
}
