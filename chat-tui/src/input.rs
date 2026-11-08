// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Keys as the terminal sends them, read from stdin on a thread of their own and decoded here, so
//! the terminal's own reports come through too: its background colour (OSC 11), and that its theme
//! changed (mode 2031), which asks for the colour again. Keys go on as crossterm's events.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub enum Input {
    Event(Event),
    /// The terminal's background colour.
    Background([u8; 3]),
    /// The terminal switched to a dark or a light theme.
    ThemeChanged,
    /// A bracketed paste starts, or ends.
    PasteStart,
    PasteEnd,
}

/// Asks for the background colour, and to be told when the theme changes.
pub const THEME_WATCH: &[u8] = b"\x1b]11;?\x1b\\\x1b[?2031h";
pub const THEME_QUERY: &[u8] = b"\x1b]11;?\x1b\\";
pub const THEME_UNWATCH: &[u8] = b"\x1b[?2031l";

const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;
/// A sequence cut off at the end of a read waits this long for its rest; an Esc on its own waits
/// too, then it's the key.
const CUT_WAIT: Duration = Duration::from_millis(25);
/// The most of a read's end that can be a sequence still coming.
const CUT_MAX: usize = 32;
/// A paste that hasn't ended after this long has.
const PASTE_GAP_MAX: Duration = Duration::from_secs(2);

/// "11;rgb:RRRR/GGGG/BBBB" (1 to 4 hex digits each), the terminal's background colour.
pub fn parse_background(s: &[u8]) -> Option<[u8; 3]> {
    let rest = s.strip_prefix(b"11;rgb:")?;
    let mut c = [0u8; 3];
    let mut i = 0;
    for (k, v) in c.iter_mut().enumerate() {
        if k > 0 {
            if rest.get(i) != Some(&b'/') {
                return None;
            }
            i += 1;
        }
        let digits = rest[i..].iter().take_while(|b| b.is_ascii_hexdigit()).count();
        if digits == 0 || digits > 4 {
            return None;
        }
        let n = u32::from_str_radix(std::str::from_utf8(&rest[i..i + digits]).ok()?, 16).ok()?;
        *v = (n * 255 / ((1 << (4 * digits)) - 1)) as u8;
        i += digits;
    }
    Some(c)
}

/// How many bytes at the end of `buf` are a sequence that may still be coming: an Esc, or a CSI
/// or SS3 without its final byte. 0 if none.
fn cut(buf: &[u8]) -> usize {
    let low = buf.len().saturating_sub(CUT_MAX);
    let Some(p) = buf[low..].iter().rposition(|b| *b == ESC).map(|p| p + low) else {
        return 0;
    };
    let n = buf.len() - p;
    match buf.get(p + 1) {
        None => n,
        Some(b'O') => {
            if n == 2 {
                n
            } else {
                0
            }
        }
        Some(b'[') if buf.get(p + 2) == Some(&b'M') => {
            if n < 6 {
                n
            } else {
                0
            }
        }
        Some(b'[') => {
            if buf[p + 2..].iter().all(|b| (b' '..=b'?').contains(b)) {
                n
            } else {
                0
            }
        }
        // An OSC runs until BEL or ST.
        Some(b']') => {
            if buf[p..].contains(&BEL) {
                0
            } else {
                n
            }
        }
        Some(_) => 0,
    }
}

/// A modifier parameter, the second ("1;5" before the final byte; "5" alone is a key's number):
/// Shift, Alt, Ctrl.
fn modifiers(params: &[u8]) -> KeyModifiers {
    let n: u8 = params
        .split(|b| *b == b';')
        .nth(1)
        .and_then(|m| std::str::from_utf8(m).ok())
        .and_then(|m| m.parse().ok())
        .unwrap_or(1);
    let m = n.saturating_sub(1);
    let mut k = KeyModifiers::NONE;
    if m & 1 != 0 {
        k |= KeyModifiers::SHIFT;
    }
    if m & 2 != 0 {
        k |= KeyModifiers::ALT;
    }
    if m & 4 != 0 {
        k |= KeyModifiers::CONTROL;
    }
    k
}

fn key(code: KeyCode, m: KeyModifiers) -> Option<Input> {
    Some(Input::Event(Event::Key(KeyEvent::new(code, m))))
}

/// One key (or report) from the start of `buf`: what it is (None for one nothing uses), and how
/// many bytes it took.
pub fn decode(buf: &[u8]) -> (Option<Input>, usize) {
    let none = KeyModifiers::NONE;
    let Some(&b0) = buf.first() else { return (None, 0) };
    if b0 == ESC {
        if buf.len() == 1 {
            return (key(KeyCode::Esc, none), 1);
        }
        // An OSC is the terminal answering a query, consumed in full up to BEL or ST.
        if buf[1] == b']' {
            let mut k = 2;
            while k < buf.len() && buf[k] != BEL && !(buf[k] == ESC && buf.get(k + 1) == Some(&b'\\')) {
                k += 1;
            }
            let report = (k < buf.len())
                .then(|| parse_background(&buf[2..k]))
                .flatten()
                .map(Input::Background);
            let used = if k >= buf.len() {
                buf.len()
            } else if buf[k] == BEL {
                k + 1
            } else {
                k + 2
            };
            return (report, used);
        }
        if buf.len() >= 3 && buf[1] == b'[' {
            // Parameter and intermediate bytes run up to a final byte from '@' to '~'.
            let mut k = 2;
            while k < buf.len() && (b' '..=b'?').contains(&buf[k]) {
                k += 1;
            }
            if buf[2] == b'M' {
                // A mouse report without mode 1006: its numbers as bytes, each 32 over.
                if buf.len() < 6 {
                    return (None, buf.len());
                }
                return (
                    mouse(
                        u32::from(buf[3]).saturating_sub(32),
                        u16::from(buf[4].saturating_sub(32)),
                        u16::from(buf[5].saturating_sub(32)),
                    ),
                    6,
                );
            }
            if k >= buf.len() || !(b'@'..=b'~').contains(&buf[k]) {
                return (None, 1);
            }
            let params = &buf[2..k];
            let m = modifiers(params);
            let code = match buf[k] {
                b'A' => Some(KeyCode::Up),
                b'B' => Some(KeyCode::Down),
                b'C' => Some(KeyCode::Right),
                b'D' => Some(KeyCode::Left),
                b'H' => Some(KeyCode::Home),
                b'F' => Some(KeyCode::End),
                b'Z' => return (key(KeyCode::BackTab, KeyModifiers::SHIFT), k + 1),
                b'P' => Some(KeyCode::F(1)),
                b'Q' => Some(KeyCode::F(2)),
                b'R' => Some(KeyCode::F(3)),
                b'S' => Some(KeyCode::F(4)),
                b'~' => {
                    let n = params.split(|b| *b == b';').next().and_then(|n| std::str::from_utf8(n).ok());
                    match n {
                        Some("1" | "7") => Some(KeyCode::Home),
                        Some("2") => Some(KeyCode::Insert),
                        Some("3") => Some(KeyCode::Delete),
                        Some("4" | "8") => Some(KeyCode::End),
                        Some("5") => Some(KeyCode::PageUp),
                        Some("6") => Some(KeyCode::PageDown),
                        Some("200") => return (Some(Input::PasteStart), k + 1),
                        Some("201") => return (Some(Input::PasteEnd), k + 1),
                        Some(f) => f.parse::<u8>().ok().and_then(|f| match f {
                            11..=15 => Some(KeyCode::F(f - 10)),
                            17..=21 => Some(KeyCode::F(f - 11)),
                            23 | 24 => Some(KeyCode::F(f - 12)),
                            _ => None,
                        }),
                        None => None,
                    }
                }
                // "?997;1n" or "?997;2n": the terminal switched to a dark or a light theme.
                b'n' if params.starts_with(b"?997;") => return (Some(Input::ThemeChanged), k + 1),
                // "<b;col;row", then M for a press or m for a release: a mouse report.
                b'M' if params.first() == Some(&b'<') => {
                    let v: Vec<u32> = params[1..]
                        .split(|b| *b == b';')
                        .filter_map(|n| std::str::from_utf8(n).ok()?.parse().ok())
                        .collect();
                    return match v[..] {
                        [b, c, r] => (mouse(b, c.min(u16::MAX as u32) as u16, r.min(u16::MAX as u32) as u16), k + 1),
                        _ => (None, k + 1),
                    };
                }
                _ => None,
            };
            return (code.and_then(|c| key(c, m)), k + 1);
        }
        if buf.len() >= 3 && buf[1] == b'O' {
            let code = match buf[2] {
                b'A' => Some(KeyCode::Up),
                b'B' => Some(KeyCode::Down),
                b'C' => Some(KeyCode::Right),
                b'D' => Some(KeyCode::Left),
                b'H' => Some(KeyCode::Home),
                b'F' => Some(KeyCode::End),
                b'P' => Some(KeyCode::F(1)),
                b'Q' => Some(KeyCode::F(2)),
                b'R' => Some(KeyCode::F(3)),
                b'S' => Some(KeyCode::F(4)),
                _ => None,
            };
            return (code.and_then(|c| key(c, none)), 3);
        }
        // Esc and the next key arrived in one read (a fast ':' after Esc): the Esc on its own,
        // like vim.
        return (
            if matches!(buf[1], b'[' | b'O') {
                None
            } else {
                key(KeyCode::Esc, none)
            },
            1,
        );
    }
    let ctrl = KeyModifiers::CONTROL;
    let simple = match b0 {
        b'\r' => key(KeyCode::Enter, none),
        b'\t' => key(KeyCode::Tab, none),
        0x7f | 0x08 => key(KeyCode::Backspace, none),
        0x1c => key(KeyCode::Char('\\'), ctrl),
        0x01..=0x1a => key(KeyCode::Char((b0 - 1 + b'a') as char), ctrl),
        0x00..=0x1f => return (None, 1),
        _ => {
            // Only complete, valid characters: a stray byte (a C1 control too) is dropped.
            let len = match b0 {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                0x20..=0x7e => 1,
                _ => return (None, 1),
            };
            return match buf
                .get(..len)
                .and_then(|c| std::str::from_utf8(c).ok())
                .and_then(|s| s.chars().next())
            {
                Some(c) if !c.is_control() => (key(KeyCode::Char(c), none), len),
                _ => (None, 1),
            };
        }
    };
    (simple, 1)
}

/// A mouse report: only the wheel (64 up, 65 down, with Shift, Alt and Ctrl added as 4, 8, 16).
fn mouse(b: u32, col: u16, row: u16) -> Option<Input> {
    let kind = match b & !28 {
        64 => MouseEventKind::ScrollUp,
        65 => MouseEventKind::ScrollDown,
        _ => return None,
    };
    Some(Input::Event(Event::Mouse(MouseEvent {
        kind,
        column: col.saturating_sub(1),
        row: row.saturating_sub(1),
        modifiers: KeyModifiers::NONE,
    })))
}

/// What came on stdin within `wait` ms (-1: however long it takes), and whether the window was
/// resized; None if nothing came, Err once it has ended.
#[cfg(unix)]
fn read_some(wait: i32) -> Result<Option<(Vec<u8>, bool)>, ()> {
    let mut fd = libc::pollfd {
        fd: 0,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll and read only use the struct and the buffer they're given.
    let ready = unsafe { libc::poll(&mut fd, 1, wait) };
    if ready < 0 {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            Ok(None)
        } else {
            Err(())
        };
    }
    if ready == 0 {
        return Ok(None);
    }
    let mut chunk = [0u8; 512];
    let n = unsafe { libc::read(0, chunk.as_mut_ptr().cast(), chunk.len()) };
    if n <= 0 {
        return Err(());
    }
    Ok(Some((chunk[..n as usize].to_vec(), false)))
}

/// The console's key events, as the characters they type: with [`vt_input`] on, the terminal's
/// sequences come as characters too, for [`decode`] to read as on Unix.
#[cfg(windows)]
fn read_some(wait: i32) -> Result<Option<(Vec<u8>, bool)>, ()> {
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Console::*;
    use windows_sys::Win32::System::Threading::{INFINITE, WaitForSingleObject};
    const BATCH: usize = 64;
    // SAFETY: the console's own handle; ReadConsoleInputW writes at most BATCH records.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        match WaitForSingleObject(h, if wait < 0 { INFINITE } else { wait as u32 }) {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => return Ok(None),
            _ => return Err(()),
        }
        let mut recs: [INPUT_RECORD; BATCH] = std::mem::zeroed();
        let mut got = 0u32;
        if ReadConsoleInputW(h, recs.as_mut_ptr(), BATCH as u32, &mut got) == 0 {
            return Err(());
        }
        let (mut units, mut resized) = (Vec::new(), false);
        for r in &recs[..got as usize] {
            match u32::from(r.EventType) {
                KEY_EVENT => {
                    let k = r.Event.KeyEvent;
                    let ch = k.uChar.UnicodeChar;
                    if k.bKeyDown != 0 && ch != 0 {
                        units.extend(std::iter::repeat_n(ch, usize::from(k.wRepeatCount.max(1))));
                    }
                }
                WINDOW_BUFFER_SIZE_EVENT => resized = true,
                _ => {}
            }
        }
        Ok(Some((String::from_utf16_lossy(&units).into_bytes(), resized)))
    }
}

/// The console sends what's typed, the mouse and the terminal's reports as the sequences a Unix
/// terminal would, rather than as its own events. Called once the screen is up (raw mode).
#[cfg(windows)]
pub fn vt_input() {
    use windows_sys::Win32::System::Console::*;
    // SAFETY: the console's own handle, and its mode.
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut m = 0;
        if GetConsoleMode(h, &mut m) != 0 {
            SetConsoleMode(h, (m & !ENABLE_MOUSE_INPUT) | ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_WINDOW_INPUT);
        }
    }
}

fn send_paste(tx: &mpsc::UnboundedSender<Input>, text: &[u8]) -> bool {
    let text = String::from_utf8_lossy(text).replace("\r\n", "\n").replace('\r', "\n");
    tx.send(Input::Event(Event::Paste(text))).is_ok()
}

/// Reads stdin on a thread of its own until it ends, sending what it decodes. A paste (between
/// its brackets) goes as one Event::Paste.
pub fn start() -> mpsc::UnboundedReceiver<Input> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let mut held: Vec<u8> = Vec::new();
        let mut paste: Option<(Vec<u8>, Instant)> = None;
        loop {
            // A sequence cut off waits a moment for its rest; then what's held is decoded as it is.
            let wait = if held.is_empty() { -1 } else { CUT_WAIT.as_millis() as i32 };
            let mut buf = std::mem::take(&mut held);
            let got = match read_some(wait) {
                Err(()) => return,
                Ok(None) => false,
                Ok(Some((bytes, resized))) => {
                    if resized
                        && let Ok((w, h)) = crossterm::terminal::size()
                        && tx.send(Input::Event(Event::Resize(w, h))).is_err()
                    {
                        return;
                    }
                    buf.extend_from_slice(&bytes);
                    true
                }
            };
            let keep = if got { cut(&buf) } else { 0 };
            held = buf.split_off(buf.len() - keep);
            let mut at = 0;
            while at < buf.len() {
                let (what, used) = decode(&buf[at..]);
                let raw = &buf[at..at + used.max(1)];
                at += used.max(1);
                match (what, &mut paste) {
                    (Some(Input::PasteStart), _) => paste = Some((Vec::new(), Instant::now())),
                    (Some(Input::PasteEnd), p @ Some(_)) => {
                        let (text, _) = p.take().expect("pasting");
                        if !send_paste(&tx, &text) {
                            return;
                        }
                    }
                    (Some(Input::PasteEnd), None) => {}
                    (_, Some((text, at_time))) => {
                        text.extend_from_slice(raw);
                        *at_time = Instant::now();
                    }
                    (Some(i), None) => {
                        if tx.send(i).is_err() {
                            return;
                        }
                    }
                    (None, None) => {}
                }
            }
            // A paste whose end never came: what came of it goes as it is.
            if paste.as_ref().is_some_and(|(_, t)| t.elapsed() > PASTE_GAP_MAX)
                && let Some((text, _)) = paste.take()
                && !send_paste(&tx, &text)
            {
                return;
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(buf: &[u8]) -> (Option<(KeyCode, KeyModifiers)>, usize) {
        let (i, n) = decode(buf);
        let k = match i {
            Some(Input::Event(Event::Key(k))) => Some((k.code, k.modifiers)),
            _ => None,
        };
        (k, n)
    }

    #[test]
    fn decodes_keys_and_reports() {
        let none = KeyModifiers::NONE;
        assert_eq!(code(b"\x1b[A"), (Some((KeyCode::Up, none)), 3));
        assert_eq!(code(b"\x1b[1;5C"), (Some((KeyCode::Right, KeyModifiers::CONTROL)), 6));
        assert_eq!(code(b"\x1b[5~x"), (Some((KeyCode::PageUp, none)), 4));
        assert_eq!(code(b"\x1b[5;5~"), (Some((KeyCode::PageUp, KeyModifiers::CONTROL)), 6));
        assert_eq!(code(b"\x1b[11~"), (Some((KeyCode::F(1), none)), 5));
        assert_eq!(code(b"\x1b[24~"), (Some((KeyCode::F(12), none)), 5));
        assert_eq!(code(b"\x1bOP"), (Some((KeyCode::F(1), none)), 3));
        assert_eq!(code(b"\x1b:"), (Some((KeyCode::Esc, none)), 1));
        assert_eq!(code(b"\x0e"), (Some((KeyCode::Char('n'), KeyModifiers::CONTROL)), 1));
        assert_eq!(code(b"\x1c"), (Some((KeyCode::Char('\\'), KeyModifiers::CONTROL)), 1));
        assert_eq!(code("é".as_bytes()), (Some((KeyCode::Char('é'), none)), 2));
        assert!(matches!(decode(b"\x1b[?997;1n"), (Some(Input::ThemeChanged), 9)));
        assert!(matches!(
            decode(b"\x1b]11;rgb:ffff/8080/0000\x1b\\"),
            (Some(Input::Background([255, 128, 0])), 25)
        ));
        assert!(matches!(
            decode(b"\x1b]11;rgb:1e/1e/1e\x07"),
            (Some(Input::Background([30, 30, 30])), 18)
        ));
        assert!(matches!(
            decode(b"\x1b[<65;10;5M"),
            (
                Some(Input::Event(Event::Mouse(MouseEvent {
                    kind: MouseEventKind::ScrollDown,
                    column: 9,
                    row: 4,
                    ..
                }))),
                11
            )
        ));
        // A device attributes answer is consumed and nothing comes of it.
        assert!(matches!(decode(b"\x1b[?62;22c"), (None, 9)));
        // What's cut off at the end of a read waits for its rest.
        assert_eq!(
            (cut(b"ab\x1b"), cut(b"ab\x1b[1;"), cut(b"\x1b[A"), cut(b"x\x1b]11;rgb:")),
            (1, 4, 0, 9)
        );
    }
}
