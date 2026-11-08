// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! chat in the terminal, built on chat-core.

mod app;
mod browser;
mod cmdline;
mod files_page;
mod identity;
mod input;
mod lock;
mod notify;
mod plain;
mod saved;
mod settings_page;
mod text;
mod ui;

use chat_core::net::update;
use chat_core::{NostrMode, RoomConfig, Route, RouteMode};
use std::time::Duration;
use tokio::sync::mpsc;

const USAGE: &str = "usage: chat [--nick NAME] [--colour NAME|#HEX] [--identity age|pgp[-nonick|:KEYFILE]]
            [--simple | --json] [--save NAME] [--new] [--join INVITE]
            [--routing udp|tor] [--nodht] [--noipv6] [--nolan] [--noportmap]
            [--nostr off|fallback|always] [--relay wss://HOST ...] [--tor-dir DIR]
            [--verify-required] [--file-limit SIZE] [--fast-files]
            [--session ID --port UDP_PORT --peer HOST:PORT ...]
       chat --update [--betas] | --version

--direct is --routing udp, and --no-dht, --no-lan, --no-portmap and --relays are the same as
--nodht, --nolan, --noportmap and --nostr. --simple prints plain \"[HH:MM] ...\" lines for one
room and reads lines from stdin, a line starting with : a command; it's used whenever stdout
isn't a terminal. --json serves one room as JSON Lines, for another program to drive.
--update installs the latest release from GitHub and exits, without opening chat: through Tor
if the save (opened with CHAT_INSTALL_PASSWORD, or its passphrase typed) or --routing chose Tor.
--betas lets it and /update install betas too, the test builds of the next release.

Rooms go through Tor by default: nobody learns your IP address, peers included, and the Nostr
relays (through Tor too) find members faster. --direct is faster still, but every peer sees your
IP address. Inside chat, F1 lists every key and command.";

struct Args {
    nosandbox: bool,
    update: bool,
    simple: bool,
    json: bool,
    /// --identity: a signing key made or read as chat starts.
    identity: Option<String>,
    /// --session: a room to join at start.
    session: Option<String>,
    nick: Option<String>,
    new: bool,
    join: Vec<String>,
    base: RoomConfig,
    tor_dir: Option<std::path::PathBuf>,
    save: Option<String>,
    /// The options that are settings too: they win over a save's for this run, and aren't saved.
    overrides: Vec<(&'static str, String)>,
}

fn args() -> Result<Args, String> {
    let mut a = Args {
        nosandbox: false,
        update: false,
        simple: false,
        json: false,
        identity: None,
        session: None,
        nick: None,
        new: false,
        join: Vec::new(),
        base: RoomConfig::default(),
        tor_dir: None,
        save: None,
        overrides: Vec::new(),
    };
    a.base.route = Route::default();
    let mut relays = Vec::new();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match arg.as_str() {
            "--nick" => {
                let n = value("--nick")?;
                a.overrides.push(("nick", n.clone()));
                a.nick = Some(n);
            }
            "--save" => a.save = Some(value("--save")?),
            "--simple" => a.simple = true,
            "--json" => a.json = true,
            "--colour" | "--color" => {
                let c = value("--colour")?;
                let colour = chat_core::Colour::parse(&c).ok_or_else(|| format!("--colour takes a colour name or #RRGGBB, not {c}"))?;
                a.base.colour = Some(colour);
                a.overrides.push(("colour", c));
            }
            "--identity" => a.identity = Some(value("--identity")?),
            "--session" => a.session = Some(value("--session")?),
            "--routing" => match value("--routing")?.as_str() {
                "udp" => {
                    a.base.route.mode = RouteMode::Direct;
                    a.overrides.push(("routing", "udp".into()));
                }
                "tor" => {
                    a.base.route.mode = RouteMode::Tor;
                    a.overrides.push(("routing", "tor".into()));
                }
                other => return Err(format!("--routing takes udp or tor, not {other}")),
            },
            "--noipv6" => {
                a.base.route.ipv6 = false;
                a.overrides.push(("dht6", "off".into()));
            }
            "--file-limit" => {
                let v = value("--file-limit")?;
                chat_core::protocol::files::parse_size(&v).ok_or("--file-limit takes a size: 8M, 500K, 1G")?;
                a.overrides.push(("filelimit", v));
            }
            "--fast-files" => a.overrides.push(("fastfiles", "on".into())),
            // Settings too: kept for this run, like the rest.
            "--tor-launch" => a.overrides.push(("torlaunch", value("--tor-launch")?)),
            "--tor-path" => a.overrides.push(("torpath", value("--tor-path")?)),
            "--tor-socks" => a.overrides.push(("torsocks", value("--tor-socks")?)),
            "--tor-control" => a.overrides.push(("torcontrol", value("--tor-control")?)),
            "--betas" => a.overrides.push(("betas", "on".into())),
            "--nosandbox" => {
                a.nosandbox = true;
                a.overrides.push(("sandbox", "off".into()));
            }
            "--update" => a.update = true,
            "--new" => a.new = true,
            "--join" => a.join.push(value("--join")?),
            "--direct" => {
                a.base.route.mode = RouteMode::Direct;
                a.overrides.push(("routing", "udp".into()));
            }
            "--tor" => {
                a.base.route.mode = RouteMode::Tor;
                a.overrides.push(("routing", "tor".into()));
            }
            "--relays" | "--nostr" => {
                a.base.route.nostr = match value("--relays")?.as_str() {
                    "fallback" => NostrMode::Fallback,
                    "always" => NostrMode::Always,
                    "off" => NostrMode::Off,
                    other => return Err(format!("--relays takes fallback, always or off, not {other}")),
                };
                let row = match a.base.route.nostr {
                    NostrMode::Fallback => "fallback",
                    NostrMode::Always => "always",
                    NostrMode::Off => "off",
                };
                a.overrides.push(("nostr", row.into()));
            }
            "--relay" => relays.push(value("--relay")?),
            "--verify-required" => {
                a.base.verify_required = true;
                a.overrides.push(("verify", "required".into()));
            }
            "--verify-optional" => {
                a.base.verify_required = false;
                a.overrides.push(("verify", "optional".into()));
            }
            "--tor-dir" => a.tor_dir = Some(value("--tor-dir")?.into()),
            "--port" => {
                a.base.route.port = value("--port")?.parse().map_err(|_| "--port takes a number")?;
                a.overrides.push(("port", a.base.route.port.to_string()));
            }
            "--peer" => a.base.route.peers.push(value("--peer")?),
            "--no-dht" | "--nodht" => {
                a.base.route.dht = false;
                a.overrides.push(("dht", "off".into()));
            }
            "--no-lan" | "--nolan" => {
                a.base.route.lan = false;
                a.overrides.push(("lan", "off".into()));
            }
            "--no-portmap" | "--noportmap" => {
                a.base.route.portmap = false;
                a.overrides.push(("portmap", "off".into()));
            }
            "--version" | "-V" => {
                println!("chat-tui {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown option {other}\n\n{USAGE}")),
        }
    }
    if !relays.is_empty() {
        a.overrides.push(("relays", relays.join(" ")));
        a.base.route.relays = relays;
    }
    Ok(a)
}

/// A cell as drawn, and where.
type Placed = (u16, u16, ratatui::buffer::Cell);

/// What the sandbox put up, for the settings page and the notes.
pub static SANDBOX: std::sync::OnceLock<chat_core::net::sandbox::Sandbox> = std::sync::OnceLock::new();

/// What handles secrets allocates where it can't be swapped out.
#[global_allocator]
static ALLOC: chat_core::net::memlock::LockedAlloc = chat_core::net::memlock::LockedAlloc;

fn main() -> std::io::Result<()> {
    chat_core::harden_process();
    let mut argv = std::env::args().skip(1);
    if argv.next().as_deref() == Some(update::HELPER_ARG)
        && argv.next().is_none()
        && let Some(code) = update::helper()
    {
        std::process::exit(code);
    }
    update::cleanup_stale();
    // This thread runs the UI, which holds passphrases, keys and the conversation.
    chat_core::net::memlock::lock_this_thread();
    let args = match args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("chat: {e}");
            std::process::exit(2);
        }
    };
    // Before the sandbox, which would keep it from replacing chat.
    if args.update {
        std::process::exit(run_update(&args));
    }
    // --json has no save to wait for. The other modes put it up once a save's settings are known
    // (App::sandbox_up).
    if args.json && !args.nosandbox {
        let run = chat_core::net::Bridges::default().programs();
        let write: Vec<_> = args.tor_dir.iter().cloned().collect();
        let _ = SANDBOX.set(chat_core::net::sandbox::up(&run, &write));
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(args))
}

/// --update: what chat exits with. By the routing the save or --routing chose: through Tor, a
/// running tor or chat's own as rooms would use; otherwise direct.
fn run_update(args: &Args) -> i32 {
    use chat_core::net::settings::Settings;
    // What /install saved may route the download through Tor, so it isn't skipped silently.
    let (mut s, mut route_chosen, mut sealed) = (Settings::default(), false, false);
    match chat_core::net::saves::Saves::new().map_or(plain::Opened::None, |saves| plain::open_save(&saves, args.save.as_deref())) {
        plain::Opened::Open(save) => {
            if let Ok(text) = save.settings() {
                route_chosen = Settings::toml_sets(&text, "routing");
                s = Settings::from_toml(&text).0;
            }
        }
        plain::Opened::Sealed => sealed = true,
        plain::Opened::None => {}
    }
    for (name, value) in &args.overrides {
        let _ = s.set(name, value);
        route_chosen |= *name == "routing";
    }
    if sealed && !route_chosen {
        eprintln!(
            "chat: not updating - what /install saved stays sealed, and with it the routing to download by: \
             CHAT_INSTALL_PASSWORD opens it, or --routing chooses one"
        );
        return 1;
    }
    let (betas, over_tor) = (s.on("betas"), route_chosen && s.get("routing") == "tor");
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("chat: {e}");
            return 1;
        }
    };
    let result = runtime.block_on(async {
        let mut proxy = None;
        if over_tor {
            /// How long a tor gets to reach the Tor network.
            const TOR_WAIT: Duration = Duration::from_secs(120);
            let mut client = chat_core::Client::new();
            if let Some(dir) = &args.tor_dir {
                client = client.with_tor_dir(dir.clone());
            }
            client.set_tor_use(s.tor_use(""));
            let transports = s.get("transports");
            let _ = client.set_transports((!transports.is_empty()).then(|| transports.into())).await;
            client.set_bridges(s.get("bridges")).await?;
            let tor = client.tor().await.map_err(|e| e.to_string())?;
            let until = tokio::time::Instant::now() + TOR_WAIT;
            while !tor.ready() && tokio::time::Instant::now() < until {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if !tor.ready() {
                return Err("no tor to download through - not updating".to_string());
            }
            proxy = Some(update::tor_proxy(tor).await.map_err(|e| e.to_string())?);
        }
        println!(
            "chat: checking GitHub for a newer release{} (v{} here){}...",
            if betas { " or beta" } else { "" },
            update::VERSION,
            if over_tor { " through Tor" } else { "" }
        );
        let addr = proxy.as_ref().map(|p| p.addr.clone());
        tokio::task::spawn_blocking(move || update::run(betas, addr.as_deref()))
            .await
            .map_err(|e| e.to_string())
    });
    match result {
        Ok((true, msg)) => {
            println!("chat: {msg}");
            0
        }
        Ok((false, msg)) | Err(msg) => {
            eprintln!("chat: {msg}");
            1
        }
    }
}

async fn async_main(args: Args) -> std::io::Result<()> {
    if args.json {
        chat_core::json::serve().await;
        return Ok(());
    }
    // Without a terminal to draw on, the line-by-line UI.
    use std::io::IsTerminal;
    if args.simple || !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        let (app, rx) = start(args, true);
        return plain::run(app, rx).await;
    }
    let mut terminal = ratatui::init();
    // Read as a terminal's sequences on every platform (input.rs), so Windows' console sends them too.
    #[cfg(windows)]
    input::vt_input();
    // The terminal's background, and word each time its theme changes; pastes, and the mouse.
    write_sequences(&[input::THEME_WATCH, &ansi(crossterm::event::EnableMouseCapture)]);
    crossterm::execute!(std::io::stdout(), crossterm::event::EnableBracketedPaste)?;
    let result = run(&mut terminal, args).await;
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableBracketedPaste);
    write_sequences(&[&ansi(crossterm::event::DisableMouseCapture), input::THEME_UNWATCH]);
    ratatui::restore();
    notify::shutdown();
    result
}

/// A command as the escape sequence a terminal reads, which crossterm on Windows would do through
/// the console's own calls instead.
fn ansi(c: impl crossterm::Command) -> Vec<u8> {
    let mut s = String::new();
    let _ = c.write_ansi(&mut s);
    s.into_bytes()
}

fn write_sequences(seqs: &[&[u8]]) {
    use std::io::Write;
    let mut out = std::io::stdout();
    let _ = seqs.iter().try_for_each(|s| out.write_all(s)).and_then(|()| out.flush());
}

/// The App, set up from the command line: for the full screen, it opens the save next; for
/// --simple, it asks what to join instead, and opens no save.
fn start(args: Args, simple: bool) -> (app::App, mpsc::UnboundedReceiver<app::Msg>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let ask_nick = args.nick.is_none() && !simple;
    let route_chosen = args.overrides.iter().any(|(n, _)| *n == "routing");
    let mut app = app::App::new(args.base, args.nick, tx);
    if let Some(dir) = args.tor_dir {
        app.client = chat_core::Client::new().with_tor_dir(dir.clone());
        app.tor_dir = Some(dir);
    }
    for (name, value) in &args.overrides {
        let _ = app.settings.set(name, value);
    }
    app.overrides = args.overrides;
    app.apply_settings();
    let mut joins = args.join;
    // --session ID: its password from CHAT_PASSWORD, or typed in the join box.
    if let Some(id) = args.session {
        match std::env::var("CHAT_PASSWORD") {
            Ok(p) => joins.push(format!("{id} {p}")),
            Err(_) if simple => joins.push(id),
            Err(_) => app.pending_join = Some(format!("{id} ")),
        }
    }
    app.start = Some((args.new, joins, ask_nick));
    app.identity_at_start = args.identity;
    if simple {
        app.saves = None;
        if plain::ask_start(&mut app, route_chosen).is_none() {
            std::process::exit(0);
        }
    }
    (app, rx)
}

async fn run(terminal: &mut ratatui::DefaultTerminal, args: Args) -> std::io::Result<()> {
    let save = args.save.clone();
    let (mut app, mut rx) = start(args, false);
    app.open_at_start(save);
    // Keys, and the terminal's reports, read and decoded here. On Windows a resize comes with them.
    let mut keys = input::start();
    #[cfg(unix)]
    let mut resized = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        let done = terminal.draw(|f| ui::draw(f, &app))?;
        // The chat's links, while nothing covers it: drawn again inside OSC 8, so a terminal that
        // takes it opens the link on a click.
        let linked: Vec<(String, Vec<Placed>)> = if app.modal.is_none() && app.locked.is_none() {
            app.links
                .borrow()
                .iter()
                .filter(|(_, t)| !t.chars().any(char::is_control))
                .map(|(r, t)| {
                    (
                        t.clone(),
                        (r.x..r.right()).map(|x| (x, r.y, done.buffer[(x, r.y)].clone())).collect(),
                    )
                })
                .collect()
        } else {
            Vec::new()
        };
        if !linked.is_empty() {
            use ratatui::backend::Backend;
            use std::io::Write;
            let b = terminal.backend_mut();
            let _ = write!(b, "\x1b7");
            for (target, cells) in &linked {
                let _ = write!(b, "\x1b]8;;{target}\x1b\\");
                let _ = b.draw(cells.iter().map(|(x, y, c)| (*x, *y, c)));
                let _ = write!(b, "\x1b]8;;\x1b\\");
            }
            let _ = write!(b, "\x1b8");
            let _ = Backend::flush(b);
        }
        let key = async {
            match keys.recv().await {
                Some(input::Input::Event(ev)) => Some(ev),
                Some(input::Input::Background(c)) => {
                    ui::set_background(c);
                    None
                }
                Some(input::Input::ThemeChanged) => {
                    use std::io::Write;
                    let _ = std::io::stdout()
                        .write_all(input::THEME_QUERY)
                        .and_then(|()| std::io::stdout().flush());
                    None
                }
                Some(_) => None,
                // stdin closed: the terminal is gone.
                None => Some(crossterm::event::Event::Key(crossterm::event::KeyEvent::new(
                    crossterm::event::KeyCode::Char('c'),
                    crossterm::event::KeyModifiers::CONTROL,
                ))),
            }
        };
        #[cfg(unix)]
        let resize = resized.recv();
        #[cfg(not(unix))]
        let resize = std::future::pending::<Option<()>>();
        tokio::select! {
            ev = key => {
                if let Some(ev) = ev {
                    app.on_terminal(ev).await;
                }
            }
            _ = resize => {}
            Some(m) = rx.recv() => {
                app.on_msg(m);
                while let Ok(m) = rx.try_recv() {
                    app.on_msg(m);
                }
            }
            _ = tick.tick() => {
                app.on_tick();
                app.calls_follow_the_day().await;
            }
        }
        if app.quit {
            break;
        }
    }
    if app.panicked {
        // The screen and the terminal's scrollback cleared at once.
        use std::io::Write;
        terminal.clear()?;
        let _ = std::io::stdout()
            .write_all(b"\x1b[2J\x1b[3J\x1b[H")
            .and_then(|()| std::io::stdout().flush());
    } else {
        app.status = Some(("leaving...".into(), false, std::time::Instant::now()));
        terminal.draw(|f| ui::draw(f, &app))?;
    }
    app.shutdown().await;
    Ok(())
}
