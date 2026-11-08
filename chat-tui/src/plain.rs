// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! --simple: a line-by-line UI, for terminals that can't do the full screen and for scripts. It
//! runs the same App as the full screen, without drawing it: lines go out as `[HH:MM] ...`, and
//! lines come in on stdin, one starting with : (or /) a command and anything else a message.

use crate::app::{App, EntryKind, Modal, Msg};
use crate::text::hhmm;
use chat_core::net::saves::{Save, SaveError, Saves, Unlocked};
use chat_core::protocol::crypto::passlock::{NEEDS_CODE, NEEDS_DEVICE, NEEDS_KEY};
use chat_core::{Level, RouteMode};
use std::io::{IsTerminal, Write};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

/// Ctrl+C quits when it's pressed again within this.
const CTRL_C_AGAIN: Duration = Duration::from_secs(3);

/// A line typed after a prompt; hidden, it isn't echoed. None at the end of input.
fn read_line(prompt: &str, hidden: bool) -> Option<String> {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    #[cfg(unix)]
    let restore = hidden.then(|| {
        // SAFETY: tcgetattr and tcsetattr only use the struct they're given.
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(0, &mut t) } != 0 {
            return None;
        }
        let was = t;
        t.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) };
        Some(was)
    });
    #[cfg(windows)]
    let restore = hidden.then(|| {
        use windows_sys::Win32::System::Console::*;
        // SAFETY: the console's own handle, and its mode.
        unsafe {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            let mut was = 0;
            (GetConsoleMode(h, &mut was) != 0 && SetConsoleMode(h, was & !ENABLE_ECHO_INPUT) != 0).then_some(was)
        }
    });
    let mut line = String::new();
    let got = std::io::stdin().read_line(&mut line);
    #[cfg(unix)]
    if let Some(Some(was)) = restore {
        // SAFETY: as above.
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &was) };
        println!();
    }
    #[cfg(windows)]
    if let Some(Some(was)) = restore {
        use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode};
        // SAFETY: as above.
        unsafe { SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), was) };
        println!();
    }
    match got {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end_matches(['\r', '\n']).to_string()),
    }
}

/// What a save opened in the terminal came to.
pub enum Opened {
    /// There's no save to open.
    None,
    /// There's one, and it stays sealed.
    Sealed,
    Open(Box<Save>),
}

/// Tries before giving up: a security key's PIN, an authenticator code, picking a save, and the
/// passphrase.
const PIN_TRIES: usize = 4;
const CODE_TRIES: usize = 5;
const PICK_TRIES: usize = 3;
const PASS_TRIES: usize = 3;

/// A save opened before anything else (--update): the one --save names, or the only one. Its
/// passphrase comes from CHAT_INSTALL_PASSWORD, which with several saves and no --save opens the
/// first that needs no security key or code, otherwise it's typed, with the save to open picked
/// first; a security key is waited for, and a code typed, here.
pub fn open_save(saves: &Saves, name: Option<&str>) -> Opened {
    let list = saves.list();
    let tty = std::io::stdin().is_terminal();
    let to_pick = list.len() > 1 && name.is_none();
    let mut current = match name {
        Some(n) if list.iter().any(|s| s.name == n) => n.to_string(),
        Some(_) => return Opened::None,
        None if list.len() == 1 => list[0].name.clone(),
        None if list.is_empty() => return Opened::None,
        None => String::new(),
    };
    let more = NEEDS_KEY | NEEDS_CODE;
    if let Ok(pass) = std::env::var("CHAT_INSTALL_PASSWORD").map(Zeroizing::new) {
        if !to_pick {
            if let Ok(save) = open_one(saves, &current, &pass, true) {
                return Opened::Open(Box::new(save));
            }
        } else {
            // Saves it doesn't fit aren't counted towards self-destruct, and no decoy opens.
            for s in list.iter().filter(|s| s.factors & more == 0) {
                match open_one(saves, &s.name, &pass, false) {
                    Ok(save) => return Opened::Open(Box::new(save)),
                    Err(SaveError::Wrong | SaveError::Device(_)) => {}
                    Err(_) => break,
                }
            }
        }
    }
    if to_pick {
        match tty.then(|| pick(&list)).flatten() {
            Some(n) => current = n,
            None => return Opened::Sealed,
        }
    }
    for _ in 0..if tty { PASS_TRIES } else { 0 } {
        let what = if list.len() > 1 {
            format!("the save {current}")
        } else {
            "what /install saved".to_string()
        };
        let Some(pass) = read_line(&format!("passphrase for {what} (blank: start without it): "), true).map(Zeroizing::new) else {
            break;
        };
        if pass.is_empty() {
            break;
        }
        match open_one(saves, &current, &pass, true) {
            Ok(save) => return Opened::Open(Box::new(save)),
            Err(e) => {
                eprintln!("chat: the save didn't open: {e}");
                if !matches!(e, SaveError::Wrong) {
                    break;
                }
            }
        }
    }
    Opened::Sealed
}

/// The saves, numbered, then a number or name typed in. None for none.
fn pick(list: &[chat_core::net::saves::SaveInfo]) -> Option<String> {
    println!(
        "chat: /install made {} saves here, each sealed with its own passphrase:",
        list.len()
    );
    for (i, s) in list.iter().enumerate() {
        let holds = match (s.settings, s.key) {
            (true, true) => "settings and key",
            (true, false) => "settings",
            _ => "key",
        };
        let needs: String = [
            (NEEDS_DEVICE, " \u{b7} this device only"),
            (NEEDS_KEY, " \u{b7} security key"),
            (NEEDS_CODE, " \u{b7} code"),
        ]
        .iter()
        .filter(|(f, _)| s.factors & f != 0)
        .map(|(_, t)| *t)
        .collect();
        println!("  {:2}  {:<16}  {holds}{needs}", i + 1, s.name);
    }
    for _ in 0..PICK_TRIES {
        let line = read_line("which one to open (number or name, blank: none): ", false)?;
        let line = line.trim();
        if line.is_empty() {
            return None;
        }
        let num: Option<usize> = line.parse().ok();
        if let Some(s) = list.iter().enumerate().find(|(i, s)| num == Some(i + 1) || s.name == line) {
            return Some(s.1.name.clone());
        }
        eprintln!("chat: there's no save {line}");
    }
    None
}

/// One save opened: its security key first if it needs one, then the passphrase, then its code.
/// `act`: as [`Saves::unlock`] takes it.
fn open_one(saves: &Saves, name: &str, pass: &str, act: bool) -> Result<Save, SaveError> {
    let needs_key = saves.list().iter().any(|s| s.name == name && s.factors & NEEDS_KEY != 0);
    let key = if needs_key {
        Some(key_in_terminal(saves, name).ok_or(SaveError::Key)?)
    } else {
        None
    };
    match saves.unlock(name, pass, act, key.as_deref())? {
        Unlocked::Open(save) => Ok(save),
        Unlocked::Code(mut pending) => {
            for _ in 0..if std::io::stdin().is_terminal() { CODE_TRIES } else { 0 } {
                let code = read_line("the code your authenticator app shows: ", false).unwrap_or_default();
                if code.trim().is_empty() {
                    break;
                }
                match pending.check(code.trim()) {
                    Ok(save) => return Ok(save),
                    Err((p, e)) => {
                        eprintln!("chat: {e}");
                        pending = *p;
                    }
                }
            }
            Err(SaveError::Failed("it needs the code your authenticator app shows".into()))
        }
    }
}

/// The save's security key's secret: plugged in, touched, and its PIN typed where it asks.
fn key_in_terminal(saves: &Saves, name: &str) -> Option<Zeroizing<[u8; 32]>> {
    use chat_core::net::seckey::Wait;
    use std::sync::atomic::Ordering;
    let mut pin: Option<Zeroizing<String>> = None;
    let mut last = String::new();
    for _ in 0..PIN_TRIES {
        let wait = std::sync::Arc::new(Wait::default());
        let (s, n, w, p) = (saves.clone(), name.to_string(), wait.clone(), pin.take());
        let job = std::thread::spawn(move || s.key_secret(&n, p.as_deref().map(String::as_str), &w));
        let mut said = None;
        while !job.is_finished() {
            let stage = wait.stage.load(Ordering::Acquire);
            if said != Some(stage) && stage != Wait::BUSY {
                eprintln!(
                    "chat: {}",
                    if stage == Wait::LOOKING {
                        "plug in the save's security key"
                    } else {
                        "touch your security key (it's blinking)"
                    }
                );
                said = Some(stage);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        match job.join() {
            Ok(Ok(secret)) => return Some(secret),
            Ok(Err(SaveError::KeyPin(why))) if std::io::stdin().is_terminal() => {
                eprintln!("chat: {why}");
                let p = read_line("security key PIN: ", true).filter(|p| !p.is_empty())?;
                pin = Some(Zeroizing::new(p));
                last = why;
            }
            Ok(Err(e)) => {
                eprintln!("chat: the security key: {e}");
                return None;
            }
            Err(_) => return None,
        }
    }
    eprintln!("chat: the security key: {last}");
    None
}

/// What --simple asks as it starts: the room (blank starts a new one) and its password, and how
/// rooms reach peers if nothing chose it.
pub fn ask_start(app: &mut App, route_chosen: bool) -> Option<()> {
    let tty = std::io::stdin().is_terminal();
    let Some((new, joins, _)) = app.start.take() else { return Some(()) };
    let (mut new, mut joins) = (new, joins);
    if !new && joins.is_empty() {
        let id = if tty {
            read_line("room id or invite (blank = start a new one): ", false)?
        } else {
            String::new()
        };
        let id = id.trim().to_string();
        if id.is_empty() || id.starts_with("chat:") {
            new = id.is_empty();
            joins.extend((!id.is_empty()).then_some(id));
        } else {
            let pass = match std::env::var("CHAT_PASSWORD") {
                Ok(p) => p,
                Err(_) if tty => read_line("password: ", true)?,
                Err(_) => String::new(),
            };
            joins.push(format!("{id} {pass}"));
        }
    }
    if !route_chosen && tty {
        println!("how should chat reach people?");
        println!(
            "  [1] Tor (recommended): onion services, which hide your IP address from peers and everyone else. Connecting takes longer"
        );
        println!(
            "  [2] UDP: straight to peers, found through the BitTorrent DHT (IPv4 and IPv6), your LAN and a router port mapping. Peers see your IP address"
        );
        println!(
            "either way, public Nostr relays carry the traffic, encrypted and padded, when the route can't, and UDP and Tor members meet there (--nostr off turns them off)"
        );
        let pick = read_line("routing [1/2, Enter = 1]: ", false)?;
        let mode = if pick.trim() == "2" { "udp" } else { "tor" };
        let _ = app.settings.set("routing", mode);
        app.base.route.mode = if mode == "udp" { RouteMode::Direct } else { RouteMode::Tor };
    }
    app.start = Some((new, joins, false));
    Some(())
}

/// A picture, two pixel rows a line of half blocks.
fn print_picture(t: &chat_core::protocol::picture::Thumb, num: u32) {
    let (w, h) = (t.w as usize, t.h as usize);
    let px = |x: usize, y: usize| &t.rgb[(y * w + x) * 3..(y * w + x) * 3 + 3];
    for y in (0..h).step_by(2) {
        let mut line = String::from("  ");
        for x in 0..w {
            let a = px(x, y);
            if y + 1 < h {
                let b = px(x, y + 1);
                line.push_str(&format!(
                    "\x1b[38;2;{};{};{};48;2;{};{};{}m\u{2580}",
                    a[0], a[1], a[2], b[0], b[1], b[2]
                ));
            } else {
                line.push_str(&format!("\x1b[0;38;2;{};{};{}m\u{2580}", a[0], a[1], a[2]));
            }
        }
        println!("{line}\x1b[0m");
    }
    println!("* file {num} ({}x{})", t.src_w, t.src_h);
}

/// What's been printed of each room, and of the rest.
#[derive(Default)]
struct Printed {
    entries: std::collections::HashMap<usize, usize>,
    pictures: std::collections::HashSet<(usize, u32)>,
    status: Option<String>,
    banner: std::collections::HashSet<usize>,
}

/// Prints what's new since the last time: each room's lines, a picture asked for, the bar's
/// message, and a box something opened, which this UI can't show, as text.
fn print_new(app: &mut App, p: &mut Printed) {
    let ansi = std::io::stdout().is_terminal();
    for r in &app.rooms {
        if let Some(info) = &r.info
            && p.banner.insert(r.id)
        {
            let route = match info.mode {
                RouteMode::Tor => "over Tor only".to_string(),
                RouteMode::Direct => format!("udp/{}, routing: direct", info.port),
            };
            println!(
                "room '{}', you are {} (peer {}). encrypted, {route}. :quit or EOF to stop.",
                info.room,
                info.nick,
                info.me.short()
            );
        }
        let from = p.entries.entry(r.id).or_insert(0);
        for e in &r.entries[(*from).min(r.entries.len())..] {
            let time = hhmm(e.at);
            match &e.kind {
                EntryKind::Msg(m) => {
                    let head = if m.direct && !m.mine {
                        format!("{} (\u{2192} you)", m.name)
                    } else {
                        m.name.clone()
                    };
                    let text = format!("{head}: {}", m.body());
                    match (ansi, m.mention && !m.mine, m.colour) {
                        (true, true, _) => println!("[{time}] \x1b[1m\x1b[48;2;110;70;10m{text}\x1b[0m"),
                        (true, false, Some(c)) => {
                            println!("[{time}] \x1b[38;2;{};{};{}m{head}\x1b[0m: {}", c.0[0], c.0[1], c.0[2], m.body())
                        }
                        _ => println!("[{time}] {text}"),
                    }
                }
                EntryKind::Note(Level::Warn, t) if ansi => println!("[{time}] \x1b[1;33m* {t}\x1b[0m"),
                EntryKind::Note(_, t) | EntryKind::Log(t) => println!("[{time}] * {t}"),
            }
        }
        *from = r.entries.len();
        for (num, t) in &r.pictures {
            if p.pictures.insert((r.id, *num)) {
                if ansi {
                    print_picture(t, *num);
                } else {
                    println!("* file {num} came, but showing a picture needs a terminal with colour - :download {num} saves it");
                }
            }
        }
    }
    let status = app.status.as_ref().map(|(t, _, _)| t.clone());
    if status != p.status {
        if let Some(t) = &status {
            println!("* {t}");
        }
        p.status = status;
    }
    match app.modal.take() {
        Some(Modal::Info { lines, .. }) => lines.iter().for_each(|l| println!("* {l}")),
        Some(Modal::Verify { peer, .. }) => match &peer.code {
            Some(c) => println!(
                "* {}'s verify code: {} - if theirs is the same, :verify {} ok, otherwise :verify {} no",
                peer.name, c.words, peer.nick, peer.nick
            ),
            None => println!("* no code with {} yet", peer.name),
        },
        Some(Modal::Qr { invite, note, .. }) => println!("* {invite}\n* {note}"),
        Some(Modal::Prompt { title, hint, .. }) => println!("* {}: {hint}", title.trim()),
        Some(Modal::Help(_)) => {
            for c in crate::cmdline::COMMANDS {
                println!(":{}{}{} - {}", c.name, if c.args.is_empty() { "" } else { " " }, c.args, c.help);
            }
        }
        Some(Modal::Files(_)) => {
            let lines = app.room().map(|r| crate::app::files_report(&r.files)).unwrap_or_default();
            if lines.is_empty() {
                println!("* no files offered here yet - :send PATH offers one");
            }
            lines.iter().for_each(|l| println!("* {l}"));
        }
        Some(_) | None => {}
    }
    let _ = std::io::stdout().flush();
}

/// Runs --simple until the input ends, :quit leaves, or Ctrl+C is pressed twice.
pub async fn run(mut app: App, mut rx: mpsc::UnboundedReceiver<Msg>) -> std::io::Result<()> {
    let mut printed = Printed::default();
    app.start_rooms();
    print_new(&mut app, &mut printed);
    // Lines from stdin, read off the runtime's threads.
    let (ltx, mut lines) = mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lines() {
            let Ok(line) = line else { break };
            if ltx.send(line).is_err() {
                break;
            }
        }
    });
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut ctrl_c_at: Option<Instant> = None;
    loop {
        tokio::select! {
            line = lines.recv() => {
                let Some(line) = line else { break };
                let line = line.trim_end();
                match line.strip_prefix(':').or_else(|| line.strip_prefix('/')) {
                    Some("changelog" | "news") => print!("{}", include_str!("../CHANGELOG.md")),
                    Some(cmd) => app.run(cmd.trim()).await,
                    None if line.is_empty() => {}
                    None => app.send(line).await,
                }
            }
            Some(m) = rx.recv() => {
                app.on_msg(m);
                while let Ok(m) = rx.try_recv() {
                    app.on_msg(m);
                }
            }
            _ = tick.tick() => app.on_tick(),
            _ = tokio::signal::ctrl_c() => {
                if ctrl_c_at.is_some_and(|t| t.elapsed() < CTRL_C_AGAIN) {
                    break;
                }
                ctrl_c_at = Some(Instant::now());
                println!("* Ctrl+C again to quit");
            }
        }
        print_new(&mut app, &mut printed);
        if app.quit || (app.rooms.is_empty() && app.start.is_none()) {
            break;
        }
    }
    app.shutdown().await;
    let _ = std::io::stdout().flush();
    Ok(())
}
