// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Drawing: the sidebar (rooms, people), the messages, the input line, the hint bar, and dialogs.

use crate::app::{App, EntryKind, Modal, PromptKind, RoomState, RoomView, SPINNER};
use crate::text::{hhmm, width, wrap};
use chat_core::{CodeState, Colour, FileState, Level, RouteMode};
use ratatui::Frame;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};

/// The terminal's background, once it has said what it is.
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

fn dim() -> Style {
    Style::default().fg(Color::DarkGray)
}

fn block(title: impl Into<Line<'static>>) -> Block<'static> {
    Block::bordered().border_type(BorderType::Rounded).border_style(dim()).title(title)
}

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    // Locked, nothing but the box for the passphrase is drawn.
    if let Some(lock) = &app.locked {
        let r = centered(area, 60, 7);
        let what = if app.save.is_some() || lock.busy && app.pin.is_none() {
            "the save's passphrase"
        } else {
            "your PIN"
        };
        let lines = vec![
            Line::raw(format!(" Locked. Type {what}, then Enter.")),
            Line::raw(""),
            Line::raw(format!(" {}", "\u{2022}".repeat(lock.input.text().chars().count()))),
            Line::styled(
                format!(
                    " {}",
                    if lock.busy {
                        "checking..."
                    } else {
                        lock.why.as_deref().unwrap_or("")
                    }
                ),
                Style::default().fg(Color::Red),
            ),
        ];
        f.render_widget(Paragraph::new(lines).block(block(" chat ")), r);
        return;
    }
    // One frame: the sidebar's right side is the chat's left, and the chat's bottom edge is the
    // input box's top. The bottom row says what's going on.
    let [frame, bar] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(area);
    let boxed = area.height >= BOXED_ROWS && area.width >= BOXED_COLS;
    let sbw = if boxed && app.show_sidebar {
        chat_left_width(area.width)
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
    draw_input(f, app, input, main, boxed, sbw > 0);
    draw_status(f, app, bar);
    // A box opened from a page goes over the page.
    if let Some(m) = &app.behind
        && !matches!(app.modal, Some(Modal::Settings(_) | Modal::Browser(_)) | None)
    {
        draw_modal(f, app, m, area);
    }
    if let Some(m) = &app.modal {
        draw_modal(f, app, m, area);
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
        draw_dialog(f, area, "SECURITY KEY", &[text], None, "esc cancel");
    }
    if app.asking_quit {
        draw_dialog(f, area, "QUIT", &app.quit_paras(), None, "ctrl+c/y quit \u{b7} n stay");
    }
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
                let (glyph, gs) = match &v.state {
                    RoomState::Open(_) if v.net.ready => ("\u{25cf}", Style::default().fg(Color::Green)),
                    RoomState::Open(_) => ("\u{25cc}", Style::default().fg(Color::Yellow)),
                    _ => ("\u{25cb}", faint()),
                };
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
    let time = (hhmm(e.at) + " ", dim());
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
            pieces.push((": ".into(), dim()));
            let (quote, body) = m.text.split_at(m.quote_len.min(m.text.len()));
            if !quote.is_empty() {
                pieces.push((quote.to_string(), dim().add_modifier(Modifier::ITALIC)));
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
                lines.push(Line::styled(format!("        /hide {num} hides it"), dim()));
            }
            lines
        }
        EntryKind::Note(Level::Warn, text) => wrap(
            &[
                time,
                (format!("! {text}"), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            ],
            w,
            8,
        ),
        EntryKind::Note(Level::Note, text) => wrap(&[time, (format!("· {text}"), dim())], w, 8),
        EntryKind::Log(text) => wrap(&[time, (format!("net: {text}"), dim().add_modifier(Modifier::ITALIC))], w, 8),
    }
}

/// The most rows a picture takes in the messages.
const PICTURE_ROWS: usize = 20;

/// After an offer: what can be done with it, or how it's going.
fn file_hint(r: &RoomView, num: u32, mine: bool) -> (String, Style) {
    let Some(f) = r.file(num) else {
        return (String::new(), dim());
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
    (text, Style::default().fg(Color::Cyan))
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
    let Some(s) = r.sent.get(&own) else { return (" ·".into(), dim()) };
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
        return (" · nobody else here".into(), dim());
    }
    if s.settled {
        return (" ✓".into(), Style::default().fg(Color::Green));
    }
    if s.delivered > 0 {
        return (" ✓".into(), dim());
    }
    (" ·".into(), dim())
}

fn welcome(app: &App) -> Vec<Line<'static>> {
    let key = |k: &str| Span::styled(k.to_string(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    vec![
        Line::raw(""),
        Line::styled("  chat", Style::default().add_modifier(Modifier::BOLD)),
        Line::styled("  end-to-end encrypted rooms, with no server and no accounts", dim()),
        Line::raw(""),
        Line::from(vec![
            Span::raw("  "),
            key("Ctrl+N"),
            Span::raw("  start a new room, and share its invite"),
        ]),
        Line::from(vec![Span::raw("  "), key("Ctrl+J"), Span::raw("  join a room with an invite")]),
        Line::from(vec![Span::raw("  "), key("F1    "), Span::raw("  every key and command")]),
        Line::raw(""),
        Line::from(vec![
            Span::styled("  rooms go ", dim()),
            Span::styled(
                match app.base.route.mode {
                    RouteMode::Tor => "through Tor: nobody learns your IP address, peers included",
                    RouteMode::Direct => "direct: faster, but peers see your IP address",
                },
                Style::default(),
            ),
        ]),
        Line::styled(
            match app.base.route.mode {
                RouteMode::Tor => "  /route direct is faster, but shows your IP address to peers",
                RouteMode::Direct => "  /route tor hides your IP address, and takes a minute or two to connect",
            },
            dim(),
        ),
        Line::styled("  the Nostr relays (on unless /relays off) find members faster", dim()),
    ]
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width.saturating_sub(2));
    let h = h.min(area.height.saturating_sub(2));
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

fn draw_modal(f: &mut Frame, app: &App, m: &Modal, area: Rect) {
    let key = |k: &str| Span::styled(k.to_string(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));
    match m {
        Modal::Prompt { kind, title, hint, input } => {
            let w = 72.min(area.width.saturating_sub(2));
            let mut lines = wrap(&[(hint.clone(), dim())], w.saturating_sub(2) as usize, 0);
            let hint_rows = lines.len() as u16;
            let r = centered(area, w, hint_rows + 6);
            f.render_widget(Clear, r);
            let text = input.text();
            // An invite holds the password.
            let shown = if kind.secret() || matches!(kind, PromptKind::JoinId) && chat_core::protocol::names::is_invite(&text) {
                "\u{2022}".repeat(text.chars().count())
            } else {
                text
            };
            // An empty field says what it takes.
            let placeholder = match kind {
                PromptKind::SetRow(name) if shown.is_empty() => chat_core::net::settings::PAGE
                    .iter()
                    .find(|r| r.name == *name)
                    .map_or("", |r| r.values),
                PromptKind::KeyPath(chat_core::IdentityKind::Pgp) if shown.is_empty() => "~/key.asc",
                PromptKind::KeyPath(_) if shown.is_empty() => "~/.config/age/key.txt",
                _ => "",
            };
            lines.extend([
                Line::raw(""),
                Line::from(vec![
                    Span::styled("› ", dim()),
                    Span::raw(shown.clone()),
                    Span::styled(placeholder, dim()),
                ]),
                Line::raw(""),
                Line::from(vec![
                    key("Enter"),
                    Span::styled(" ok   ", dim()),
                    key("Esc"),
                    Span::styled(" cancel", dim()),
                ]),
            ]);
            f.render_widget(Paragraph::new(lines).block(block(title.clone())), r);
            if !app.asking_quit {
                f.set_cursor_position((r.x + 3 + width(&shown) as u16, r.y + 2 + hint_rows));
            }
        }
        Modal::Verify { peer, .. } => {
            let r = centered(area, 72, 13);
            f.render_widget(Clear, r);
            let code = peer.code.clone().unwrap_or(chat_core::VerifyCode {
                words: "-".into(),
                hex: "-".into(),
            });
            // Two groups of four words a line, as they're read out.
            let groups: Vec<&str> = code.words.split(" \u{b7} ").collect();
            let bold = Style::default().add_modifier(Modifier::BOLD);
            let mut lines = vec![
                Line::raw(format!(
                    "Compare this code with {} over another channel you trust (in person, a call):",
                    peer.name
                )),
                Line::raw(""),
            ];
            for pair in groups.chunks(2) {
                lines.push(Line::styled(format!("    {}", pair.join("   ")), bold));
            }
            lines.extend([
                Line::styled(format!("    {}", code.hex), dim()),
                Line::raw(""),
                Line::styled("If anyone sat between you, the codes on your two screens would differ.", dim()),
                Line::raw(""),
                Line::from(vec![
                    key("y"),
                    Span::raw(" they match   "),
                    key("n"),
                    Span::raw(" they differ   "),
                    key("Esc"),
                    Span::styled(" later", dim()),
                ]),
            ]);
            f.render_widget(
                Paragraph::new(lines)
                    .wrap(Wrap { trim: false })
                    .block(block(format!(" Verify {} ", peer.name))),
                r,
            );
        }
        Modal::Settings(page) => draw_settings(f, app, page, area),
        Modal::Ask { title, paras, keys, .. } => draw_dialog(f, area, title, paras, None, keys),
        Modal::Paste { kind, text } => {
            let (title, paras) = crate::settings_page::paste_box(*kind);
            let status = if text.is_empty() {
                "waiting for the paste".to_string()
            } else {
                format!("{} bytes so far", text.len())
            };
            draw_dialog(f, area, title, &paras.map(String::from), Some(&status), "esc back");
        }
        Modal::Browser(b) => {
            draw_page(f, app, &app.browser_view(b, area.width, area.height), area);
            if let Some(path) = &b.ask {
                draw_export_ask(f, app, path, area);
            }
        }
        Modal::Files(num) => draw_page(f, app, &app.files_view(*num), area),
        Modal::Picture(num) => draw_picture(f, app, *num, area),
        Modal::Rooms { sel, forgetting } => draw_rooms(f, app, *sel, *forgetting, area),
        Modal::Link { links, at } => {
            let (link, who, when) = &links[*at];
            let target = chat_core::protocol::text::link_target(link);
            let from = if when.is_empty() {
                format!("typed by {who}")
            } else {
                format!("from {who} at {when}")
            };
            let lines = vec![
                Line::raw(format!(" {target}")),
                Line::styled(format!(" {from} \u{b7} {} of {}", at + 1, links.len()), dim()),
                Line::raw(""),
                Line::raw(" Your browser fetches it directly, not through chat's Tor or relays: the site sees"),
                Line::raw(" your IP address, and when you opened it."),
                Line::raw(""),
                Line::styled(" y open \u{b7} c copy \u{b7} j/k older/newer \u{b7} n or Esc close", dim()),
            ];
            let r = centered(area, 86, 9);
            f.render_widget(Clear, r);
            f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }).block(block(" Open a link ")), r);
        }
        Modal::Qr { invite, qr, note } => {
            // Two modules a cell, top and bottom, with the light border a scanner needs.
            const QUIET: usize = 4;
            let side = qr.size + 2 * QUIET;
            let dark = |x: usize, y: usize| {
                (QUIET..QUIET + qr.size).contains(&x) && (QUIET..QUIET + qr.size).contains(&y) && qr.dark(x - QUIET, y - QUIET)
            };
            let colour = |d: bool| if d { Color::Black } else { Color::White };
            let mut lines: Vec<Line> = (0..side.div_ceil(2))
                .map(|row| {
                    let spans: Vec<Span> = (0..side)
                        .map(|x| {
                            let bottom = 2 * row + 1 < side && dark(x, 2 * row + 1);
                            Span::styled("\u{2580}", Style::default().fg(colour(dark(x, 2 * row))).bg(colour(bottom)))
                        })
                        .collect();
                    Line::from(spans).centered()
                })
                .collect();
            lines.push(Line::raw(""));
            lines.push(Line::raw(invite.clone()).centered());
            lines.push(Line::styled(note.clone(), dim()).centered());
            let w = (side.max(invite.len()) + 4).min(area.width as usize) as u16;
            let r = centered(area, w, (lines.len() as u16 + 2).min(area.height));
            f.render_widget(Clear, r);
            f.render_widget(Paragraph::new(lines).block(block(" Invite ")), r);
        }
        Modal::Info { title, lines } => {
            let w = area.width.saturating_sub(4).min(90);
            let mut body: Vec<Line> = Vec::new();
            for l in lines {
                body.extend(wrap(&[(l.clone(), Style::default())], w.saturating_sub(4) as usize, 0));
            }
            body.push(Line::raw(""));
            body.push(Line::styled(" Any key closes this.", dim()));
            let r = centered(area, w, (body.len() as u16 + 2).min(area.height));
            f.render_widget(Clear, r);
            f.render_widget(Paragraph::new(body).block(block(title.clone())), r);
        }
        Modal::Help(sel) => draw_page(f, app, &app.help_view(*sel), area),
        Modal::Update => draw_update(f, area),
    }
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
    let Some(r) = app.room() else {
        f.render_widget(Paragraph::new(welcome(app)).block(block(" chat ")).wrap(Wrap { trim: false }), m);
        return;
    };
    let w = (m.width as usize).saturating_sub(4);
    let (mut console, mut chat) = (Vec::new(), Vec::new());
    let mut chat_links: Vec<Vec<(usize, String)>> = Vec::new();
    app.links.borrow_mut().clear();
    let start = r.entries.len().saturating_sub(400);
    for e in &r.entries[start..] {
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
    let (mut show_con, show_chat) = (app.show_console, app.show_chat);
    let buf = f.buffer_mut();
    if !boxed {
        let lines = if show_chat { &chat } else { &console };
        draw_rows(
            buf,
            m.x,
            m.y,
            m.width,
            m.height as usize,
            lines,
            if show_chat { r.scroll } else { r.console_scroll },
        );
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
    let kskip = r.console_scroll.min(console.len().saturating_sub(con_rows));
    let bs = faint();
    let clock = vec![Span::styled(hhmm(crate::text::unix_now()), faint())];
    let mut title = vec![
        Span::styled(r.label.clone(), bold()),
        Span::styled(format!(" \u{b7} {}", r.status_line(spinner(app))), faint()),
    ];
    if r.timer > 0 {
        title.push(Span::styled(
            format!(" \u{b7} messages go after {}", chat_core::protocol::names::format_timer(r.timer)),
            faint(),
        ));
    }
    let room = title_room(m.width as usize, spans_width(&clock));
    if spans_width(&title) > room {
        title = vec![Span::styled(ell(&r.label, room), bold())];
    }
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
        buf.set_string(m.x, y, "\u{2502}", bs);
        buf.set_string(m.x + m.width - 1, y, "\u{2502}", bs);
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
        let skip = r.scroll.min(chat.len().saturating_sub(rest));
        draw_rows_linked(buf, m.x + 1, row, iw, rest, &chat, skip, &chat_links, Some(&app.links));
    } else if !show_con {
        let lines = [
            Line::styled("Chat and console are hidden", bold()),
            Line::from(vec![
                Span::styled("ctrl+t", accent()),
                Span::styled(" shows the chat \u{b7} ", faint()),
                Span::styled("ctrl+o", accent()),
                Span::styled(" the console", faint()),
            ]),
        ];
        let top = row + (rest as u16).saturating_sub(2) / 2;
        for (i, l) in lines.into_iter().enumerate() {
            let lw = spans_width(&l.spans) as u16;
            buf.set_line(m.x + 1 + iw.saturating_sub(lw) / 2, top + i as u16, &l, iw);
        }
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
        buf.set_string(input.x, y, "\u{2502}", bs);
        buf.set_string(input.x + input.width - 1, y, "\u{2502}", bs);
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
/// top edge is the chat's bottom, and says how many newer messages are below the chat.
fn draw_input(f: &mut Frame, app: &App, r: Rect, over: Rect, boxed: bool, joined: bool) {
    let tone = tone(app);
    let bs = Style::default().fg(tone);
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
        buf.set_string(r.x, r.y + 1, "\u{2502}", bs);
        buf.set_string(r.x + r.width - 1, r.y + 1, "\u{2502}", bs);
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
    if app.modal.is_none() && !app.asking_quit {
        f.set_cursor_position((left + 1 + (cursor_col as u16).min(iw.saturating_sub(2)), row));
    }
}

/// The bottom row: the mode's chip, whether you sign and as what, your nick, the last message,
/// and as many of the hints as fit, the last (the way out, or to the help) always.
fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    use crate::cmdline::Mode;
    let mut spans = vec![
        Span::styled(
            format!(" {} ", app.mode.name()),
            Style::default().fg(tone(app)).add_modifier(Modifier::BOLD | Modifier::REVERSED),
        ),
        Span::raw(" "),
    ];
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
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        app.nick.clone(),
        Style::default()
            .fg(app.colour.map_or(Color::Reset, rgb))
            .add_modifier(Modifier::BOLD),
    ));
    if let Some((text, bad, _)) = &app.status {
        spans.push(Span::styled("  \u{203a} ", faint()));
        spans.push(Span::styled(
            text.clone(),
            if *bad {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                bold()
            },
        ));
    }
    let room = app.room().filter(|r| r.room().is_some());
    let hint = match (app.mode, room) {
        (Mode::Command, _) => "enter run \u{b7} tab complete \u{b7} \u{2191}\u{2193} choose \u{b7} esc back".to_string(),
        (_, None) => "ctrl+n new \u{b7} ctrl+j join \u{b7} / commands \u{b7} ctrl+s settings".into(),
        (Mode::Normal, Some(_)) => "i type \u{b7} : command \u{b7} f files \u{b7} j/k session \u{b7} pgup/pgdn scroll \u{b7} ? help".into(),
        (Mode::Insert, Some(r)) => format!(
            "enter send \u{b7} / commands{}{} \u{b7} esc normal \u{b7} f1 help",
            if app.rooms.len() > 1 { " \u{b7} tab next session" } else { "" },
            if r.files.is_empty() { "" } else { " \u{b7} ctrl+f files" }
        ),
    };
    // As many of the hints as fit, from the first; the last stays whatever the width.
    let parts: Vec<&str> = hint.split(" \u{b7} ").collect();
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
        spans.extend(hint_line(None, &text).spans.into_iter().skip(1));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// A picture on a page of its own: in the middle, scaled to fit, with its caption under it; or
/// what's become of it, with a progress bar while it comes.
fn draw_picture(f: &mut Frame, app: &App, num: u32, area: Rect) {
    f.render_widget(Clear, area);
    let [main, bar] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(area);
    let (title, note, progress) = app.picture_text(num);
    let status = match &app.status {
        Some((text, bad, _)) => Line::styled(
            format!(" {text}"),
            if *bad {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Cyan)
            },
        ),
        None => hint_line(Some("PICTURE"), &app.picture_hint(num)),
    };
    f.render_widget(Paragraph::new(status), bar);
    let buf = f.buffer_mut();
    let right = vec![Span::styled(hhmm(crate::text::unix_now()), faint())];
    let room = title_room(main.width as usize, spans_width(&right));
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
    page_box(buf, main, Style::default().fg(Color::Magenta), false, t, right);
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
}

/// The settings page, or the signing identity's page under it, with the search box over it while
/// it's open.
fn draw_settings(f: &mut Frame, app: &App, p: &crate::settings_page::Page, area: Rect) {
    let v = if p.pick.is_some() { app.pick_view(p) } else { app.settings_view(p) };
    draw_page(f, app, &v, area);
    if let Some((input, sel)) = &p.search {
        draw_search(f, app, input, *sel, area);
    }
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
        buf.set_string(r.x, y, "\u{2502}", bs);
        buf.set_string(r.x + r.width - 1, y, "\u{2502}", bs);
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
        buf.set_string(left + w - 1, y, "\u{2502}", faint());
    }
}

/// The export's box over its browser: what's written where, and what that means.
fn draw_export_ask(f: &mut Frame, app: &App, path: &std::path::Path, area: Rect) {
    let shown = crate::browser::tilde(path);
    let age = app.ident.as_ref().is_none_or(|i| i.kind != chat_core::IdentityKind::Pgp);
    let paras = [
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
    draw_dialog(f, area, "EXPORT SIGNING KEY", &paras, None, "y write \u{b7} n back");
}

/// The rooms kept in the save, by label, and "another room" last; or forgetting one, asked.
fn draw_rooms(f: &mut Frame, app: &App, sel: usize, forgetting: bool, area: Rect) {
    let rooms = &app.settings.rooms;
    if forgetting && let Some(r) = rooms.get(sel) {
        let text = format!("Forget {}? Its id and password go from the save.", r.label);
        return draw_dialog(f, area, "JOIN SESSION", &[text], None, "y forget \u{b7} n keep");
    }
    let w = 72.min(area.width.saturating_sub(2));
    let items: Vec<(String, &str)> = rooms
        .iter()
        .map(|r| (r.label.clone(), if r.at_start { "joined at start" } else { "" }))
        .chain(std::iter::once(("another room...".to_string(), "type its id")))
        .collect();
    let keys = if sel < rooms.len() {
        "enter join \u{b7} s at start \u{b7} d forget \u{b7} esc close"
    } else {
        "enter type an id \u{b7} esc close"
    };
    let r = centered(area, w, items.len() as u16 + 6);
    f.render_widget(Clear, r);
    let buf = f.buffer_mut();
    page_box(
        buf,
        r,
        Style::default().fg(Color::Magenta),
        false,
        vec![Span::styled("JOIN SESSION", bold())],
        Vec::new(),
    );
    let iw = r.width.saturating_sub(2);
    inner_line(
        buf,
        r.x + 1,
        r.y + 1,
        iw,
        vec![Span::raw("The rooms kept in the save, by label. Enter joins one.")],
    );
    let lw = items.iter().map(|(l, _)| width(l)).max().unwrap_or(0) + 3;
    for (i, (label, detail)) in items.iter().enumerate() {
        let on = i == sel;
        let mut spans = vec![
            pointer(on),
            Span::styled(label.clone(), if on { accent_bold() } else { Style::default() }),
        ];
        spans.push(Span::raw(" ".repeat(lw.saturating_sub(width(label)))));
        spans.push(Span::styled(detail.to_string(), faint()));
        let draw = if on { picked_line } else { inner_line };
        draw(buf, r.x + 1, r.y + 3 + i as u16, iw, spans);
    }
    buf.set_line(r.x + 1, r.y + 4 + items.len() as u16, &hint_line(None, keys), iw);
}

/// A box of paragraphs over a page: its title in the border, a status line under them if there's
/// one, and its keys.
fn draw_dialog(f: &mut Frame, area: Rect, title: &str, paras: &[String], status: Option<&str>, keys: &str) {
    let w = 72.min(area.width.saturating_sub(2));
    let mut lines = Vec::new();
    for (i, p) in paras.iter().enumerate() {
        if i > 0 {
            lines.push(Line::raw(""));
        }
        // Each line of a paragraph wraps on its own, a bullet's under its text.
        for line in p.split('\n') {
            let indent = if line.starts_with('\u{2022}') { 2 } else { 0 };
            lines.extend(wrap(&[(line.to_string(), Style::default())], w.saturating_sub(4) as usize, indent));
        }
    }
    if let Some(s) = status {
        lines.push(Line::raw(""));
        lines.push(Line::styled(s.to_string(), accent()));
    }
    lines.push(Line::raw(""));
    lines.push(hint_line(None, keys));
    let r = centered(area, w, lines.len() as u16 + 2);
    f.render_widget(Clear, r);
    let buf = f.buffer_mut();
    page_box(
        buf,
        r,
        Style::default().fg(Color::Magenta),
        false,
        vec![Span::styled(title.to_string(), bold())],
        Vec::new(),
    );
    for (i, l) in lines.into_iter().enumerate() {
        let y = r.y + 1 + i as u16;
        if y + 1 >= r.y + r.height {
            break;
        }
        let mut spans = vec![Span::raw(" ")];
        spans.extend(l.spans);
        buf.set_line(r.x + 1, y, &Line::from(spans), r.width.saturating_sub(2));
    }
}

/// /update's box: its console in a frame of its own with the last lines that fit, a progress bar
/// with the percentage on its right, the current step, and the keys. The console loses rows on a
/// short screen; the rest always shows.
fn draw_update(f: &mut Frame, area: Rect) {
    use chat_core::net::update::LineKind;
    /// A blank, the console's edges, a blank, the bar, a blank, the step, a blank, the keys, and
    /// the box's edges.
    const FIXED: u16 = 11;
    let v = chat_core::net::update::view();
    let con = 12u16.min(area.height.saturating_sub(FIXED + 2)).max(1);
    let r = centered(area, area.width.saturating_sub(6).min(100), con + FIXED);
    f.render_widget(Clear, r);
    let buf = f.buffer_mut();
    let title = vec![Span::styled("UPDATE", bold())];
    page_box(buf, r, Style::default().fg(Color::Magenta), false, title, Vec::new());
    let (x, iw) = (r.x + 1, r.width.saturating_sub(2));
    let cw = iw.saturating_sub(4);
    let mut y = r.y + 2;
    page_box(buf, Rect::new(x + 2, y, cw, con + 2), faint(), false, Vec::new(), Vec::new());
    let first = v.log.len().saturating_sub(usize::from(con));
    for (i, (kind, line)) in v.log[first..].iter().enumerate() {
        let style = match kind {
            LineKind::Detail => faint(),
            LineKind::Info => Style::default(),
            LineKind::Good => Style::default().fg(Color::Green),
            LineKind::Bad => Style::default().fg(Color::Red),
        };
        let room = cw.saturating_sub(2);
        buf.set_line(x + 3, y + 1 + i as u16, &Line::styled(ell(line, usize::from(room)), style), room);
    }
    y += con + 3;
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
    buf.set_line(x + 2, y, &Line::from(bar), cw);
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
    buf.set_line(x + 2, y, &Line::from(step), cw);
    let keys = if v.running { "esc hide" } else { "enter close" };
    buf.set_line(x, y + 2, &hint_line(None, keys), iw);
}

/// Plain text wrapped to `w` columns.
fn wrap_plain(text: &str, w: usize) -> Vec<String> {
    wrap(&[(text.to_string(), Style::default())], w, 0)
        .into_iter()
        .map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect::<String>())
        .collect()
}

/// What the keys do, along the bottom: each key in the accent, what it does faint.
fn hint_line(chip: Option<&str>, hint: &str) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    if let Some(c) = chip {
        spans.push(Span::styled(format!(" {c} "), accent_bold().add_modifier(Modifier::REVERSED)));
        spans.push(Span::raw(" "));
    }
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
    Line::from(spans)
}

/// A list page over the whole screen: the sections on the left, the page beside them sharing its
/// edge, and the bar along the bottom.
fn draw_page(f: &mut Frame, app: &App, v: &PageView, area: Rect) {
    f.render_widget(Clear, area);
    let [main, bar] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(area);
    let boxed = area.height >= BOXED_ROWS && area.width >= BOXED_COLS;
    // A page that gives the list on the left keeps its column while the list is empty.
    let navw = if boxed { left_width(main.width) } else { 0 };
    let bar_line = match &app.status {
        Some((text, true, _)) => Line::styled(format!(" {text}"), Style::default().fg(Color::Red)),
        Some((text, false, _)) => Line::styled(format!(" {text}"), Style::default().fg(Color::Cyan)),
        None => hint_line(v.chip, &v.hint),
    };
    f.render_widget(Paragraph::new(bar_line), bar);
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
    let bs = Style::default().fg(Color::Magenta);
    let (top, ih, left, iw) = if boxed {
        (r.y + 1, r.height.saturating_sub(2), r.x + 1, r.width.saturating_sub(2))
    } else {
        (r.y, r.height, r.x, r.width)
    };
    let cw = (iw as usize).saturating_sub(2);
    if boxed {
        let right = vec![Span::styled(hhmm(crate::text::unix_now()), faint())];
        let room = title_room(r.width as usize, spans_width(&right));
        let parts: Vec<&str> = v.title.split(" \u{203a} ").collect();
        let mut title = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            let last = i + 1 == parts.len();
            title.push(Span::styled(part.to_string(), if last { bold() } else { faint() }));
            if !last {
                title.push(Span::styled(" \u{203a} ", faint()));
            }
        }
        if spans_width(&title) > room {
            title = vec![Span::styled(ell(parts.last().copied().unwrap_or_default(), room), bold())];
        }
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
}

const SEARCH_ROWS: usize = 8;

/// The settings' search box: the matches above the field, SEARCH_ROWS at a time so the box keeps
/// its height as they change, each with its place on the page.
fn draw_search(f: &mut Frame, app: &App, input: &crate::app::Input, sel: usize, area: Rect) {
    use chat_core::net::settings::{self as st, PAGE};
    let query = input.text();
    let found = app.search_found(&query);
    let r = centered(area, 76, SEARCH_ROWS as u16 + 7);
    f.render_widget(Clear, r);
    let buf = f.buffer_mut();
    page_box(
        buf,
        r,
        Style::default().fg(Color::Magenta),
        false,
        vec![Span::styled("SEARCH SETTINGS", bold())],
        Vec::new(),
    );
    let (left, iw) = (r.x + 1, r.width.saturating_sub(2));
    let sel = sel.min(found.len().saturating_sub(1));
    let first = (sel + 1).saturating_sub(SEARCH_ROWS);
    let half = (iw as usize).saturating_sub(4) / 2;
    for k in 0..SEARCH_ROWS {
        let y = r.y + 2 + k as u16;
        let Some(&i) = found.get(first + k) else {
            if found.is_empty() && k == 0 {
                inner_line(buf, left, y, iw, vec![Span::raw("  "), Span::styled("No setting matches", faint())]);
            }
            continue;
        };
        let on = first + k == sel;
        let hidden = if app.row_shown(i) { "" } else { " (hidden)" };
        let label = ell(PAGE[i].label, half);
        let pad = " ".repeat(half + 1 - width(&label));
        inner_line(
            buf,
            left,
            y,
            iw,
            vec![
                pointer(on),
                Span::styled(label, if on { accent_bold() } else { Style::default() }),
                Span::raw(pad),
                Span::styled(ell(&format!("{}{hidden}", st::place(i)), half), faint()),
            ],
        );
    }
    let field = r.y + 3 + SEARCH_ROWS as u16;
    let shown = if query.is_empty() {
        Span::styled("a setting's name or /set name, or a word in its help", faint())
    } else {
        Span::raw(query.clone())
    };
    inner_line(buf, left, field, iw, vec![Span::styled("\u{203a} ", faint()), shown]);
    let keys = if found.is_empty() {
        "esc back"
    } else {
        "enter open \u{b7} up/down move \u{b7} esc back"
    };
    buf.set_line(left, field + 2, &hint_line(None, keys), iw);
    let cursor: String = input.chars[..input.cursor].iter().collect();
    if !app.asking_quit {
        f.set_cursor_position((left + 3 + width(&cursor) as u16, field));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
