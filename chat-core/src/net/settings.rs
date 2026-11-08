// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The settings every interface shares, as rows of text in the form a `set NAME VALUE` command takes
//! them, and as a save keeps them: TOML, inside its sealed settings file. Only rows that differ from
//! their defaults are saved, so a later version's new default still reaches you; `routing` is
//! always saved, so the file means the same wherever it's read. The kept rooms (`[rooms]`), the
//! sessions to reopen (`[open]`) and the ignored keys (`[ignored]`) go in the same file.

use crate::net::{Bridges, Route};
use crate::protocol::api::{NetLog, NostrMode, RouteMode};
use crate::protocol::crypto::identity::IdentityKind;
use crate::protocol::files::{format_size_exact, parse_size};
use crate::protocol::trust::{TrustEntry, kind_from_name, kind_name};
use crate::protocol::{hex, names, text};

/// The TOML table a row is saved in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    Network,
    Profile,
    Chat,
}

impl Table {
    fn name(self) -> &'static str {
        match self {
            Table::Network => "network",
            Table::Profile => "profile",
            Table::Chat => "chat",
        }
    }
}

/// What values a row takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// "on" or "off" (true or false in TOML).
    Toggle,
    /// One of these.
    Choice(&'static [&'static str]),
    /// Text, checked by the row (a port, a size, relays, bridges, a nick, a colour...).
    Text,
    /// Not a setting a save keeps: a secret, an action, or how the save itself is locked.
    NotSaved,
}

pub struct Def {
    pub name: &'static str,
    pub table: Table,
    pub kind: Kind,
    pub default: &'static str,
}

const fn row(name: &'static str, table: Table, kind: Kind, default: &'static str) -> Def {
    Def {
        name,
        table,
        kind,
        default,
    }
}

const ON: &str = "on";
const OFF: &str = "off";
use Kind::{Choice, NotSaved, Text, Toggle};
use Table::{Chat, Network, Profile};

pub const DEFAULT_RELAYS: &str = "wss://relay.primal.net wss://relay.snort.social wss://relay.nostr.net";
pub const LOCK_AFTER: &[&str] = &["off", "1m", "5m", "15m", "30m"];
pub const LOCK_AFTER_SECONDS: &[u32] = &[0, 60, 300, 900, 1800];
pub const LOCK_KEYS: &[&str] = &["off", "ctrl+l", "ctrl+g", "ctrl+k", "f9"];
pub const PANIC_KEYS: &[&str] = &["off", "ctrl+\\", "ctrl+q", "ctrl+x", "f12"];

/// Every row, in the order a save writes them.
pub const DEFS: &[Def] = &[
    row("routing", Network, Choice(&["udp", "tor"]), "tor"),
    row("dht", Network, Toggle, ON),
    row("dht6", Network, Toggle, ON),
    row("portmap", Network, Toggle, ON),
    row("lan", Network, Toggle, ON),
    row("torlaunch", Network, Choice(&["auto", "always", "never"]), "auto"),
    row("torpath", Network, Text, ""),
    row("torsocks", Network, Text, "127.0.0.1:9050"),
    row("torcontrol", Network, Text, "127.0.0.1:9051"),
    row("torpassword", Network, NotSaved, ""),
    row("bridges", Network, Text, ""),
    row("transports", Network, Text, ""),
    row("torguards", Network, Toggle, OFF),
    row("nostr", Network, Choice(&["off", "fallback", "always"]), "fallback"),
    row("relays", Network, Text, DEFAULT_RELAYS),
    row("nick", Profile, Text, ""),
    row("colour", Profile, Text, ""),
    row("sign", Profile, NotSaved, ""),
    row("agerecipient", Profile, NotSaved, ""),
    row("pgpkey", Profile, NotSaved, ""),
    row("exportkey", Profile, NotSaved, ""),
    row("autosave", Profile, Toggle, OFF),
    row("devicelock", Profile, NotSaved, ""),
    row("securitykey", Profile, NotSaved, ""),
    row("authenticator", Profile, NotSaved, ""),
    row("destroy", Profile, NotSaved, ""),
    row("shadow", Profile, NotSaved, ""),
    row("lock", Profile, Choice(LOCK_AFTER), "off"),
    row("lockkey", Profile, Choice(LOCK_KEYS), "ctrl+l"),
    row("panickey", Profile, Choice(PANIC_KEYS), "ctrl+\\"),
    row("panicwipe", Profile, Toggle, OFF),
    row("panichistory", Profile, Toggle, OFF),
    row("sandbox", Profile, Toggle, ON),
    row("updater", Profile, Toggle, ON),
    row("verify", Chat, Choice(&["required", "optional"]), "optional"),
    row("filelimit", Chat, Text, "8M"),
    row("fastfiles", Chat, Toggle, OFF),
    row("noise", Chat, Toggle, ON),
    row("notify", Chat, Choice(&["none", "mentions", "all"]), "mentions"),
    row("preview", Chat, Choice(&["off", "nick", "message"]), "off"),
    row("history", Chat, Toggle, OFF),
    row("reopen", Chat, Toggle, OFF),
    row("net", Chat, Choice(&["normal", "verbose", "off"]), "normal"),
    row("port", Chat, Text, "0"),
    row("betas", Chat, Toggle, OFF),
];

pub fn def(name: &str) -> Option<&'static Def> {
    DEFS.iter().find(|d| d.name == name)
}

pub const ROOMS_MAX: usize = 16;
pub const ROOM_LABEL_MAX: usize = 32;
pub const RELAYS_MAX: usize = 6;
const START: &str = "start";

/// A room kept to join again: its label, id and password, and whether it's joined at the start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptRoom {
    pub label: String,
    pub id: String,
    pub password: String,
    pub at_start: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    rows: Vec<String>,
    pub rooms: Vec<KeptRoom>,
    /// Sessions open when the save was last written, to open again (id, password).
    pub reopen: Vec<(String, String)>,
    pub ignored: Vec<TrustEntry>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            rows: DEFS.iter().map(|d| d.default.to_string()).collect(),
            rooms: Vec::new(),
            reopen: Vec::new(),
            ignored: Vec::new(),
        }
    }
}

fn host_port_ok(v: &str) -> bool {
    v.rsplit_once(':')
        .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok_and(|p| p > 0))
}

impl Settings {
    /// A row's value; "" for one that isn't a row.
    pub fn get(&self, name: &str) -> &str {
        DEFS.iter().position(|d| d.name == name).map_or("", |i| &self.rows[i])
    }

    pub fn on(&self, name: &str) -> bool {
        self.get(name) == ON
    }

    /// Sets a row from a value in the form `set` takes, as it's kept (a size, say, in its exact
    /// form). An error says what the row takes.
    pub fn set(&mut self, name: &str, value: &str) -> Result<(), String> {
        let i = DEFS
            .iter()
            .position(|d| d.name == name)
            .ok_or_else(|| format!("there's no setting called {name}"))?;
        let d = &DEFS[i];
        let value = value.trim();
        let kept = match (d.kind, name) {
            (NotSaved, _) => return Err(format!("{name} isn't set this way")),
            (Toggle, _) if value == ON || value == OFF => value.to_string(),
            (Toggle, _) => return Err("it takes on or off".into()),
            (Choice(names), _) if names.contains(&value) => value.to_string(),
            (Choice(names), _) => return Err(format!("it takes {}", names.join(", "))),
            (_, "port") => value
                .parse::<u16>()
                .map_err(|_| "it takes a port number, or 0 for a free one")?
                .to_string(),
            (_, "filelimit") => format_size_exact(parse_size(value).filter(|n| *n > 0).ok_or("it takes a size: 8M, 500K, 1G")?),
            (_, "relays") => {
                let urls: Vec<&str> = value.split_whitespace().collect();
                if urls.len() > RELAYS_MAX || !urls.iter().all(|u| u.starts_with("wss://") && crate::net::nostr::url_ok(u)) {
                    return Err(format!("it takes up to {RELAYS_MAX} wss:// addresses, separated by spaces"));
                }
                urls.join(" ")
            }
            (_, "bridges") => {
                let mut b = Bridges::default();
                b.set_lines(value)?;
                // Kept as typed, lines separated by "; ", for the save; Tor gets them from it.
                value
                    .split([';', '\r', '\n'])
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .collect::<Vec<_>>()
                    .join("; ")
            }
            (_, "torsocks" | "torcontrol") if host_port_ok(value) => value.to_string(),
            (_, "torsocks" | "torcontrol") => return Err("it takes HOST:PORT".into()),
            (_, "nick") => {
                let n = text::clean_nick(value.as_bytes());
                if n.is_empty() {
                    return Err("a nick needs a letter or digit".into());
                }
                n
            }
            (_, "colour") if value.is_empty() || names::Colour::parse(value).is_some() => value.to_lowercase(),
            (_, "colour") => return Err("it takes a colour name or #RRGGBB".into()),
            _ => value.to_string(),
        };
        self.rows[i] = kept;
        Ok(())
    }

    /// How rooms opened from now on are routed, from the network rows.
    pub fn route(&self) -> Route {
        let mut r = Route {
            mode: if self.get("routing") == "udp" {
                RouteMode::Direct
            } else {
                RouteMode::Tor
            },
            port: self.get("port").parse().unwrap_or(0),
            dht: self.on("dht"),
            ipv6: self.on("dht6"),
            lan: self.on("lan"),
            portmap: self.on("portmap"),
            nostr: match self.get("nostr") {
                "off" => NostrMode::Off,
                "always" => NostrMode::Always,
                _ => NostrMode::Fallback,
            },
            ..Route::default()
        };
        r.relays = self.get("relays").split_whitespace().map(String::from).collect();
        r
    }

    pub fn net_log(&self) -> NetLog {
        match self.get("net") {
            "verbose" => NetLog::Verbose,
            "off" => NetLog::Off,
            _ => NetLog::Normal,
        }
    }

    /// The biggest file fetched without asking.
    pub fn file_limit(&self) -> u64 {
        parse_size(self.get("filelimit")).unwrap_or(8 * 1024 * 1024)
    }

    /// The screen locks after this long without a key (None: never).
    pub fn lock_after(&self) -> Option<u32> {
        let i = LOCK_AFTER.iter().position(|n| *n == self.get("lock"))?;
        (i > 0).then(|| LOCK_AFTER_SECONDS[i])
    }

    /// The TOML a save keeps: rows that aren't their default (and `routing` always), by table, then
    /// the kept rooms, the sessions to reopen and the ignored keys.
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        let mut table = None;
        for (d, v) in DEFS.iter().zip(&self.rows) {
            if d.kind == NotSaved || (v == d.default && d.name != "routing") {
                continue;
            }
            if table != Some(d.table) {
                out.push_str(if out.is_empty() { "[" } else { "\n[" });
                out.push_str(d.table.name());
                out.push_str("]\n");
                table = Some(d.table);
            }
            out.push_str(d.name);
            out.push_str(" = ");
            match (d.kind, d.name) {
                (Toggle, _) => out.push_str(if v == ON { "true" } else { "false" }),
                (_, "port") => out.push_str(v),
                (_, "relays") => put_list(&mut out, v.split(' ')),
                (_, "bridges") => put_list(&mut out, v.split(';').map(str::trim_start)),
                _ => put_str(&mut out, v),
            }
            out.push('\n');
        }
        let mut entries = |name: &str, rows: Vec<Vec<&str>>| {
            if rows.is_empty() {
                return;
            }
            out.push_str(if out.is_empty() { "[" } else { "\n[" });
            out.push_str(name);
            out.push_str("]\n");
            for (i, r) in rows.into_iter().enumerate() {
                out.push_str(&format!("{} = ", i + 1));
                put_list(&mut out, r.into_iter());
                out.push('\n');
            }
        };
        let rooms = self.rooms.iter().map(|r| {
            let mut v = vec![r.label.as_str(), r.id.as_str(), r.password.as_str()];
            if r.at_start {
                v.push(START);
            }
            v
        });
        entries("rooms", rooms.collect());
        entries("open", self.reopen.iter().map(|(id, pw)| vec![id.as_str(), pw.as_str()]).collect());
        let hexes: Vec<String> = self.ignored.iter().map(|e| hex::encode(&e.public)).collect();
        let ignored = self
            .ignored
            .iter()
            .zip(&hexes)
            .map(|(e, h)| vec![kind_name(e.kind), h.as_str(), e.nick.as_str()]);
        entries("ignored", ignored.collect());
        out
    }

    /// Settings from a save's TOML, over the defaults. What can't be used is left out, and the notes
    /// say what and why (never what a bridge line holds).
    pub fn from_toml(toml: &str) -> (Settings, Vec<String>) {
        let mut s = Settings::default();
        let mut notes = Vec::new();
        let mut table = String::new();
        for (n, line) in toml.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(t) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                table = t.trim().to_string();
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                notes.push(format!("line {} can't be read - left out", n + 1));
                continue;
            };
            let key = key.trim().trim_matches('"');
            let Some(v) = parse_value(value.trim()) else {
                notes.push(format!("[{table}] {key:.40} can't be read - left out"));
                continue;
            };
            if let Err(why) = s.load(&table, key, v) {
                notes.push(why);
            }
        }
        (s, notes)
    }

    /// Whether a save's TOML gives the row `name` a value it takes, as [`Settings::from_toml`]
    /// would: a routing the save chose, say, rather than the default.
    pub fn toml_sets(toml: &str, name: &str) -> bool {
        let mut table = "";
        toml.lines().map(str::trim).any(|line| {
            if let Some(t) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                table = t.trim();
                return false;
            }
            line.split_once('=').is_some_and(|(key, value)| {
                key.trim().trim_matches('"') == name
                    && parse_value(value.trim()).is_some_and(|v| Settings::default().load(table, name, v).is_ok())
            })
        })
    }

    fn load(&mut self, table: &str, key: &str, v: Value) -> Result<(), String> {
        let strings = |v: &Value| match v {
            Value::List(items) => Some(items.clone()),
            _ => None,
        };
        match table {
            "rooms" => {
                let r = strings(&v).filter(|r| (3..=4).contains(&r.len()) && (r.len() == 3 || r[3] == START));
                match r {
                    Some(r) if self.rooms.len() < ROOMS_MAX && !r[1].is_empty() && r[0].chars().count() <= ROOM_LABEL_MAX => {
                        let at_start = r.len() == 4;
                        let mut it = r.into_iter();
                        let (label, id, password) = (
                            it.next().unwrap_or_default(),
                            it.next().unwrap_or_default(),
                            it.next().unwrap_or_default(),
                        );
                        self.rooms.push(KeptRoom {
                            label,
                            id,
                            password,
                            at_start,
                        });
                        Ok(())
                    }
                    _ => Err(format!("kept room {key:.10} can't be read - left out")),
                }
            }
            "open" => match strings(&v) {
                Some(r) if r.len() == 2 && self.reopen.len() < ROOMS_MAX && !r[0].is_empty() => {
                    self.reopen.push((r[0].clone(), r[1].clone()));
                    Ok(())
                }
                _ => Err(format!("session to reopen {key:.10} can't be read - left out")),
            },
            "ignored" => {
                let e = strings(&v).filter(|r| r.len() == 3).and_then(|r| {
                    Some(TrustEntry {
                        kind: kind_from_name(&r[0])?,
                        public: hex::decode_array::<32>(&r[1])?,
                        nick: r[2].clone(),
                    })
                });
                match e {
                    Some(e) if !self.ignored.iter().any(|i| i.public == e.public) => {
                        self.ignored.push(e);
                        Ok(())
                    }
                    Some(_) => Ok(()),
                    None => Err(format!("ignored key {key:.10} can't be read - left out")),
                }
            }
            _ => {
                let d = def(key).filter(|d| d.table.name() == table && d.kind != NotSaved);
                let Some(d) = d else {
                    return Err(format!("[{table:.20}] {key:.40} isn't a setting chat saves - left out"));
                };
                let text = match (d.kind, d.name, v) {
                    (Toggle, _, Value::Bool(b)) => (if b { ON } else { OFF }).to_string(),
                    (Toggle, _, _) => return Err(format!("{key} takes true or false - left out")),
                    (_, "relays", Value::List(l)) => l.join(" "),
                    (_, "bridges", Value::List(l)) => l.join("; "),
                    (_, "relays", _) => return Err("relays takes a list of \"wss://...\" strings - left out".into()),
                    (_, "bridges", _) => return Err("bridges takes a list of strings - left out".into()),
                    (_, "port" | "filelimit", Value::Int(i)) => i.to_string(),
                    (_, "port", _) => return Err("port takes a number - left out".into()),
                    (_, _, Value::Str(s)) => s,
                    _ => return Err(format!("{key} takes a string in quotes - left out")),
                };
                // Bridge lines are kept out of the notes.
                self.set(key, &text).map_err(|why| match key {
                    "bridges" => format!("the bridges weren't used - {why}"),
                    _ => format!("{key} {text:.60} wasn't used - {why}"),
                })
            }
        }
    }
}

/// A row as a settings page shows it, in the page's order: the section it starts (if it starts
/// one), the heading above it (if any), its label, the values it takes, and its help.
pub struct PageRow {
    pub name: &'static str,
    pub section: Option<&'static str>,
    pub group: Option<&'static str>,
    pub label: &'static str,
    pub values: &'static str,
    pub help: &'static str,
}

/// Every row, in the order a settings page shows them.
pub const PAGE: &[PageRow] = &[
    PageRow {
        name: "routing",
        section: Some("Network"),
        group: None,
        label: "Routing",
        values: "udp|tor",
        help: "udp: UDP straight between peers, found using the options below. Peers see your IP address. tor: onion services, which hide your IP address from everyone. Uses a running tor or starts chat's own, and connecting takes longer. UDP and Tor members only meet on the Nostr relays. Applies to sessions you open from now on.",
    },
    PageRow {
        name: "dht",
        section: None,
        group: Some("UDP"),
        label: "BitTorrent DHT (IPv4)",
        values: "on|off",
        help: "Finds peers on the internet through the public BitTorrent DHT. DHT nodes see your IP address next to a lookup key only room members can work out, and a node id that changes with it every hour.",
    },
    PageRow {
        name: "dht6",
        section: None,
        group: None,
        label: "IPv6 DHT",
        values: "on|off",
        help: "Also looks for peers on the IPv6 DHT (BEP 32). IPv6 usually has no NAT to punch through, so peers there connect more reliably.",
    },
    PageRow {
        name: "portmap",
        section: None,
        group: None,
        label: "Router port mapping",
        values: "on|off",
        help: "Asks your router to forward this session's UDP port (PCP, NAT-PMP or UPnP-IGD), so peers behind NATs that can't be hole punched can still reach you. Removed when the session ends. The router may log it.",
    },
    PageRow {
        name: "lan",
        section: None,
        group: None,
        label: "LAN discovery",
        values: "on|off",
        help: "Broadcasts an encrypted beacon on your local network, so room members on it can find you without the internet.",
    },
    PageRow {
        name: "torlaunch",
        section: None,
        group: Some("Tor"),
        label: "Start chat's own tor",
        values: "auto|always|never",
        help: "auto: a running tor if its control port lets chat log in, otherwise chat's own, as always with bridges set. always: chat's own, ignoring any running tor. never: only a running tor. Chat's own tor is built in, so there's nothing to install (or it's the program Tor program names): it keeps its state in a private temporary folder deleted on exit, and gets new entry guards each run unless Keep tor's guards is on. A change applies to rooms you open from now on.",
    },
    PageRow {
        name: "torpath",
        section: None,
        group: None,
        label: "Tor program",
        values: "PATH",
        help: "The tor program chat starts as its own tor, in place of the built-in one: a full path, or a name on PATH or in the usual folders. Empty: the built-in Tor, with nothing to install. It must be a program that only root or you can change. With the sandbox on, only one given with --tor-path as chat starts can run. Applies to sessions you open from now on.",
    },
    PageRow {
        name: "torsocks",
        section: None,
        group: None,
        label: "Tor SOCKS port",
        values: "HOST:PORT",
        help: "Where to look for a running tor's SOCKS port (host:port). With the defaults, Tor Browser's 127.0.0.1:9150 is tried too. Applies to sessions you open from now on.",
    },
    PageRow {
        name: "torcontrol",
        section: None,
        group: None,
        label: "Tor control port",
        values: "HOST:PORT",
        help: "Where to look for a running tor's control port (host:port). It needs ControlPort on, and chat has to be able to read its cookie file (or have its password). Applies to sessions you open from now on.",
    },
    PageRow {
        name: "torpassword",
        section: None,
        group: None,
        label: "Tor control password",
        values: "",
        help: "Only for a tor set up with HashedControlPassword. Kept in memory only. Applies to sessions you open from now on.",
    },
    PageRow {
        name: "bridges",
        section: None,
        group: None,
        label: "Bridges",
        values: "LINE; LINE ...",
        help: "Bridge lines for chat's own tor, from bridges.torproject.org or a friend, separated by ;. With any set, chat starts its own tor, which reaches the Tor network only through them: they go to it over its control port, never on its command line or on disk. Sealed in the save, never shown in the console. obfs4, webtunnel and meek_lite need lyrebird, snowflake needs snowflake-client (Transport programs).",
    },
    PageRow {
        name: "transports",
        section: None,
        group: None,
        label: "Transport programs",
        values: "FOLDER",
        help: "The folder with lyrebird and snowflake-client, for bridges. Empty: next to tor (the Tor Expert Bundle and Tor Browser keep them in a folder beside it), then on PATH and in the usual folders. They must be programs only root or you can change, in a path without spaces. With the sandbox up, only those found as it went up can run.",
    },
    PageRow {
        name: "torguards",
        section: None,
        group: None,
        label: "Keep tor's guards",
        values: "on|off",
        help: "on: when chat's own tor stops, its entry guards and its copy of the Tor directory are sealed into the open save, and the next one starts from them: the same guards each run, as Tor's design expects, and connected in seconds. It adds tens of MB to the save, and anyone who opens the save sees which guards you use. Its decoy gets none. off: deletes them. Needs a save; a tor already running keeps its own.",
    },
    PageRow {
        name: "nostr",
        section: None,
        group: Some("Relays"),
        label: "Nostr relays",
        values: "off|fallback|always",
        help: "Public relays that carry traffic the route can't, and where UDP and Tor members meet. Tor routing reaches them through Tor. fallback: connected only while needed (nobody reached yet, or a peer the route can't reach), until a minute after. always: stays connected, so members on the other route can find a room whose members all reach each other. Each event has a one-off key, a random kind, a fixed size and fresh encryption.",
    },
    PageRow {
        name: "relays",
        section: None,
        group: None,
        label: "Relay list",
        values: "wss://URL ... (up to 6)",
        help: "The relays the fallback uses: up to 6 wss:// URLs, separated by spaces or commas.",
    },
    PageRow {
        name: "port",
        section: None,
        group: Some("Advanced"),
        label: "UDP port for new sessions",
        values: "N",
        help: "The UDP port new sessions listen on. 0 picks a free one each time. :port moves an open session to another.",
    },
    PageRow {
        name: "net",
        section: None,
        group: None,
        label: "Network log",
        values: "normal|verbose|off",
        help: "How much of the network the console shows, in every session. verbose adds every handshake packet, relay and Tor event. off leaves out its news too (lookups, relays dropping and coming back, Tor starting up), showing only problems that keep a session from connecting.",
    },
    PageRow {
        name: "nick",
        section: Some("Profile"),
        group: None,
        label: "Nickname",
        values: "NAME",
        help: "Your name in every session.",
    },
    PageRow {
        name: "colour",
        section: None,
        group: None,
        label: "Colour",
        values: "NAME|#RRGGBB",
        help: "Your colour in every session. h/l step through the palette, and Enter takes a name or #RRGGBB.",
    },
    PageRow {
        name: "sign",
        section: None,
        group: Some("Keys"),
        label: "Signing identity",
        values: "off|age|pgp|age-nonick|pgp-nonick|age:PATH|pgp:PATH",
        help: "A key that signs your handshakes so peers can check it's you. Either an AGE or PGP key made here from a password, or your own key from a file or pasted in. Enter picks one, replaces it or turns signing off. Kept in memory only, unless :install saves it: a key file's path, or any other key sealed to disk.",
    },
    PageRow {
        name: "agerecipient",
        section: None,
        group: None,
        label: "AGE recipient",
        values: "",
        help: "The age1... string others give to age -r to encrypt files to you. Enter copies it to the clipboard.",
    },
    PageRow {
        name: "pgpkey",
        section: None,
        group: None,
        label: "PGP public key",
        values: "",
        help: "The public half of the PGP key made here, shown by its fingerprint, for others to gpg --import. Enter copies it to the clipboard. It's in the console too.",
    },
    PageRow {
        name: "exportkey",
        section: None,
        group: None,
        label: "Export signing key",
        values: "",
        help: "Writes your signing key, unencrypted, to a new file in a folder you pick, after asking: to load it on another device, or keep a key made here. An AGE key comes out as age-keygen writes one, a PGP key made here armored, as gpg --export-secret-keys writes it. Anyone who reads the file can sign as you.",
    },
    PageRow {
        name: "autosave",
        section: Some("Security"),
        group: None,
        label: "Autosave",
        values: "on|off",
        help: "Once chat is installed: on saves a setting you change, and a key you verify or forget, as you change it. off keeps changes until chat exits, unless :save saves them. The signing key is only saved by :save or :install either way, so a key you're trying out isn't kept by accident.",
    },
    PageRow {
        name: "devicelock",
        section: None,
        group: Some("Unlocking"),
        label: "Device lock",
        values: "on|off",
        help: "Requires a secret this device keeps (in its TPM, where there's one) to unlock the save, so it can't be unlocked anywhere else.",
    },
    PageRow {
        name: "securitykey",
        section: None,
        group: None,
        label: "Security key",
        values: "on|off",
        help: "Requires your FIDO2 security key (a YubiKey, say) to unlock the save: a touch each time, and its PIN if it has one.",
    },
    PageRow {
        name: "authenticator",
        section: None,
        group: None,
        label: "Authenticator app",
        values: "on|off",
        help: "Requires the 6-digit code from an authenticator app (Aegis, Google Authenticator, 2FAS...) to unlock the save.",
    },
    PageRow {
        name: "lock",
        section: None,
        group: Some("Lock screen"),
        label: "Auto-lock",
        values: "off|1m|5m|15m|30m",
        help: "Locks the screen after this long without a key, as the lock key and :lock do at once. Locked, chat draws nothing but a box for the open save's passphrase, or with no save open, a PIN it asks for first, kept hashed in memory until chat exits. Sessions carry on behind it, and notifications show no preview. Wrong passphrases count toward self-destruct, and the shadow passphrase panics, leaving the decoy in the save's place. Each try takes a second or two.",
    },
    PageRow {
        name: "lockkey",
        section: None,
        group: None,
        label: "Lock key",
        values: "off|ctrl+l|ctrl+g|ctrl+k|f9",
        help: "The key that locks the screen at once, from anywhere in chat. off leaves :lock and auto-lock.",
    },
    PageRow {
        name: "destroy",
        section: None,
        group: Some("Duress"),
        label: "Self-destruct",
        values: "off|3|5|10",
        help: "Deletes what :install saves after this many wrong passphrases in a row, so a found or taken device can't be guessed at forever. The count and the limit are kept next to the save, not sealed (they have to be read before the passphrase opens anything), so anyone who can read the files sees them, and someone who copies the files first can reset the count: this stops guessing at the keyboard, not a forensic copy. A right passphrase clears the count.",
    },
    PageRow {
        name: "shadow",
        section: None,
        group: None,
        label: "Shadow password",
        values: "on|off",
        help: "A second passphrase that opens a decoy, a clean save with no key or verified peers, in place of the real one, whose files it replaces or deletes. The decoy needs the same security key, device and code, every passphrase takes as long, and every save has a decoy's file, filled with random bytes when there's no decoy, so neither the files nor the time it takes say which passphrase opened it. Deleting isn't erasing: a copy made before, a backup or the disk itself can still hold the real save, sealed under its own passphrase. Enter sets or removes it. Only while a save is open, and it needs the save's own factors to hand.",
    },
    PageRow {
        name: "panickey",
        section: None,
        group: None,
        label: "Panic key",
        values: "off|ctrl+\\|ctrl+q|ctrl+x|f12",
        help: "A key that, from anywhere in chat (the lock screen too), clears the screen and quits at once, without asking: every session says bye (one kept to reopen goes offline), memory is wiped and chat's own tor stops. Nothing is saved but what the rows below keep. Anyone at the keyboard can press it. Ctrl+\\ is awkward on some keyboards, so there are others. In --simple, the terminal's Ctrl+\\ panics unless this is off.",
    },
    PageRow {
        name: "panicwipe",
        section: None,
        group: None,
        label: "Panic deletes the save",
        values: "on|off",
        help: "on: the panic key also deletes the open save, as :uninstall does but without asking: its settings, signing key, verified keys and history. Deleting isn't erasing: the disk and its backups can keep traces of the files. The shadow passphrase on the lock screen leaves the decoy instead.",
    },
    PageRow {
        name: "panichistory",
        section: None,
        group: None,
        label: "Panic writes history",
        values: "on|off",
        help: "on: the panic key writes the history kept for each session before it quits. off: it isn't written, so each history loses up to its last 30 seconds.",
    },
    PageRow {
        name: "sandbox",
        section: None,
        group: Some("Sandbox"),
        label: "Sandbox",
        values: "on|off",
        help: "on: once chat reaches the network, it can only write to your home's folders that aren't hidden or on PATH, its own and the temporary ones, and only run tor and its transport programs. Calls it never makes (ptrace, mount, bpf...) are refused, for tor too. A bug can't plant anything that runs later (.bashrc, ~/.local/bin), and saving elsewhere fails, though /update still works through the updater. Linux 5.13 or later. From the next start.",
    },
    PageRow {
        name: "updater",
        section: None,
        group: None,
        label: "Updater",
        values: "on|off",
        help: "on: just before the sandbox goes up, chat starts chat-updater, a second process that :update asks to replace chat, since chat can't once it's sandboxed. It holds none of chat's keys, saves or messages, can only write in chat's executable's folder and run curl, and installs only what the release key signed. off: no second process, and :update sends you to chat --update. off stops it now, on waits for the next start.",
    },
    PageRow {
        name: "verify",
        section: Some("Chat"),
        group: None,
        label: "Compare verify codes",
        values: "required|optional",
        help: "Anyone with a session's id and password could sit between two members and read what they say. When a peer joins, chat shows a code to compare with them over another channel. It only matches on both ends if nobody is in the middle. required: nothing you send goes to a peer until you mark it as matching (:verify NICK ok). optional: messages go to everyone, compared or not.",
    },
    PageRow {
        name: "notify",
        section: None,
        group: None,
        label: "Notifications",
        values: "all|mentions|none",
        help: "Desktop notifications, for open and new sessions: every message, mentions of your nick, or none.",
    },
    PageRow {
        name: "preview",
        section: None,
        group: None,
        label: "Notification preview",
        values: "off|nick|message",
        help: "What a notification shows. off: only that a message came in. nick: who it's from. message: who, and what they said. Desktops keep notifications (Windows writes them to disk), so what they show can outlast chat. The session is never shown, since its id is all someone needs to join one with a blank password.",
    },
    PageRow {
        name: "history",
        section: None,
        group: Some("History"),
        label: "Keep history",
        values: "on|off",
        help: "Keeps each session's messages, sealed in the save that's open (so it needs :install), and shows them when you join that session again with the same id and password. Everyone in the session is told while you keep it, and you're told when they do. Only the full-screen UI keeps it. :history forget deletes this session's, :history forget all every session's.",
    },
    PageRow {
        name: "reopen",
        section: None,
        group: None,
        label: "Reopen sessions",
        values: "on|off",
        help: "on: keeps the sessions you have open, their ids and passwords sealed in the save that's open (so it needs :install), and opens them again when chat starts. Ctrl+C then quits without leaving them: peers see you go offline, or leave on older versions. :quit leaves one for good, :quitall every one. Calls aren't kept. Only the full-screen UI keeps them.",
    },
    PageRow {
        name: "filelimit",
        section: None,
        group: Some("Files"),
        label: "File size limit",
        values: "SIZE (8M, 500K, 1G)",
        help: "The largest file chat fetches when you ask. An offer over the limit says so, and :download N anyway (or :show N anyway) fetches it regardless. Nothing is fetched until you ask. Files can be up to 1 GB.",
    },
    PageRow {
        name: "fastfiles",
        section: None,
        group: None,
        label: "Fast file transfers",
        values: "on|off",
        help: "off: files are sent in chat's regular slots, so a transfer doesn't show up on the network, but it's slow: about 25 KB a minute, half that through the relays (where Tor and UDP members meet). on: while you send a file, your slots to that peer come every few milliseconds. It takes seconds instead of minutes, but anyone watching the network sees a burst about the size of the file. Through the relays it goes as often as they allow, about twice the normal rate, and the relays can see that. Only the sender's setting matters.",
    },
    PageRow {
        name: "noise",
        section: None,
        group: None,
        label: "Noise in pictures",
        values: "on|off",
        help: "on: a JPEG you send also gets noise nobody can see, on top of what's always taken out (where, when and with what it was made): some coefficients move a step, so no two copies are the same bytes or pixels, even of one photo sent twice. It doesn't hide which camera took it from someone who studies its sensor's noise, or stop it being recognised. Baseline JPEGs only (most photos). :send asis sends a file as it is.",
    },
    PageRow {
        name: "betas",
        section: None,
        group: Some("Updates"),
        label: "Beta releases",
        values: "on|off",
        help: "on: :update installs betas too, the test builds of the next release. They're signed and checked like a release, but have had less testing. off: only releases, so a beta you're on stays until its release is out, and :update then takes you on to that.",
    },
];

/// A TOML basic string: quotes and backslashes escaped, control characters as \uXXXX.
fn put_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn put_list<'a>(out: &mut String, items: impl Iterator<Item = &'a str>) {
    out.push('[');
    for (i, s) in items.enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        put_str(out, s);
    }
    out.push(']');
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Str(String),
    Bool(bool),
    Int(i64),
    List(Vec<String>),
}

/// One value, and nothing but a comment after it: a string (basic or literal), true or false, an
/// integer, or a list of strings.
fn parse_value(v: &str) -> Option<Value> {
    let (value, rest) = parse_one(v)?;
    let rest = rest.trim_start();
    (rest.is_empty() || rest.starts_with('#')).then_some(value)
}

fn parse_one(v: &str) -> Option<(Value, &str)> {
    if let Some(rest) = v.strip_prefix('[') {
        let mut items = Vec::new();
        let mut rest = rest.trim_start();
        loop {
            if let Some(r) = rest.strip_prefix(']') {
                return Some((Value::List(items), r));
            }
            let (Value::Str(s), r) = parse_one(rest)? else { return None };
            items.push(s);
            rest = r.trim_start();
            rest = rest.strip_prefix(',').map_or(rest, str::trim_start);
        }
    }
    if let Some(rest) = v.strip_prefix('\'') {
        let end = rest.find('\'')?;
        return Some((Value::Str(rest[..end].to_string()), &rest[end + 1..]));
    }
    if let Some(rest) = v.strip_prefix('"') {
        let mut s = String::new();
        let mut chars = rest.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => return Some((Value::Str(s), &rest[i + 1..])),
                '\\' => {
                    let (_, e) = chars.next()?;
                    match e {
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        'r' => s.push('\r'),
                        'b' => s.push('\u{8}'),
                        'f' => s.push('\u{c}'),
                        '"' | '\\' => s.push(e),
                        'u' | 'U' => {
                            let len = if e == 'u' { 4 } else { 8 };
                            let hex: String = (0..len).filter_map(|_| chars.next().map(|(_, c)| c)).collect();
                            s.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                        }
                        _ => return None,
                    }
                }
                c => s.push(c),
            }
        }
        return None;
    }
    let end = v
        .find(|c: char| c == ',' || c == ']' || c == '#' || c.is_whitespace())
        .unwrap_or(v.len());
    let (word, rest) = v.split_at(end);
    match word {
        "true" => Some((Value::Bool(true), rest)),
        "false" => Some((Value::Bool(false), rest)),
        w => Some((Value::Int(w.replace('_', "").parse().ok()?), rest)),
    }
}

// ---- the settings page: its sections, which rows it lists, and its search ----

/// How a page shows a row and what choosing it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowKind {
    /// On or off, shown as a switch.
    Toggle,
    /// One of the values [`steps`] gives, stepped through.
    Choice,
    /// Typed in.
    Text,
    /// Typed in, and never shown.
    Secret,
    /// Opens something: a picker, a box, or a copy.
    Action,
}

pub fn row_kind(name: &str) -> RowKind {
    match name {
        "torpassword" => RowKind::Secret,
        "sign" | "agerecipient" | "pgpkey" | "exportkey" | "shadow" => RowKind::Action,
        "devicelock" | "securitykey" | "authenticator" => RowKind::Toggle,
        "destroy" => RowKind::Choice,
        n => match def(n).map(|d| d.kind) {
            Some(Kind::Toggle) => RowKind::Toggle,
            Some(Kind::Choice(_)) => RowKind::Choice,
            _ => RowKind::Text,
        },
    }
}

/// The wrong passphrases a save takes before it deletes itself.
pub const DESTROY: &[&str] = &["off", "3", "5", "10"];

/// The values a row steps through, in order (h/l on the page), or None for a row that's typed or
/// opened. The colour steps through the palette.
pub fn steps(name: &str) -> Option<Vec<&'static str>> {
    match (row_kind(name), name) {
        (_, "colour") => Some(names::PALETTE.iter().map(|(n, _)| *n).collect()),
        (_, "destroy") => Some(DESTROY.to_vec()),
        (RowKind::Toggle, _) => Some(vec![OFF, ON]),
        (RowKind::Choice, _) => match def(name)?.kind {
            Kind::Choice(c) => Some(c.to_vec()),
            _ => None,
        },
        _ => None,
    }
}

/// The page's sections, in order.
pub fn sections() -> Vec<&'static str> {
    PAGE.iter().filter_map(|r| r.section).collect()
}

/// Section s's first row in [`PAGE`], or `PAGE.len()` after the last section.
pub fn section_begin(s: usize) -> usize {
    PAGE.iter()
        .enumerate()
        .filter(|(_, r)| r.section.is_some())
        .nth(s)
        .map_or(PAGE.len(), |(i, _)| i)
}

/// The section row i is in.
pub fn section_of(i: usize) -> usize {
    PAGE[..=i].iter().filter(|r| r.section.is_some()).count().saturating_sub(1)
}

/// The group row i is in, if any: the heading it's under in its section.
pub fn group_of(i: usize) -> Option<&'static str> {
    PAGE[section_begin(section_of(i))..=i].iter().rev().find_map(|r| r.group)
}

/// Where row i is on the page: its section, and its group if it's in one ("Network › Tor").
pub fn place(i: usize) -> String {
    let section = sections()[section_of(i)];
    match group_of(i) {
        Some(g) => format!("{section} \u{203a} {g}"),
        None => section.to_string(),
    }
}

/// Row i's label under its group's heading, which it doesn't repeat: "Tor SOCKS port" under Tor
/// is "SOCKS port".
pub fn short_label(i: usize) -> String {
    let label = PAGE[i].label;
    let rest = group_of(i).and_then(|g| label.strip_prefix(g)).and_then(|r| r.strip_prefix(' '));
    match rest {
        Some(r) => {
            let mut c = r.chars();
            c.next().map_or(String::new(), |f| f.to_uppercase().chain(c).collect())
        }
        None => label.to_string(),
    }
}

/// How well row i matches a word of a search, lower being better: its label starting with it,
/// then a word of its label or its name starting with it, either holding it, its place on the
/// page holding it, and last its help.
fn word_rank(i: usize, word: &str) -> Option<u32> {
    let r = &PAGE[i];
    let w = word.to_ascii_lowercase();
    let label = r.label.to_ascii_lowercase();
    let word_start = (0..label.len())
        .any(|p| label.is_char_boundary(p) && (p == 0 || !label.as_bytes()[p - 1].is_ascii_alphanumeric()) && label[p..].starts_with(&w));
    Some(if label.starts_with(&w) {
        0
    } else if word_start || r.name.starts_with(&w) {
        1
    } else if label.contains(&w) || r.name.contains(&w) {
        2
    } else if place(i).to_ascii_lowercase().contains(&w) {
        3
    } else if r.help.to_ascii_lowercase().contains(&w) {
        4
    } else {
        return None;
    })
}

/// The rows that match every word of `query`, best first and otherwise in the page's order, with
/// the ones `listed` says aren't on the page right now after the rest. An empty query matches
/// every row.
pub fn search(query: &str, listed: impl Fn(&str) -> bool) -> Vec<usize> {
    let mut found: Vec<(u32, usize)> = (0..PAGE.len())
        .filter_map(|i| {
            let base = if listed(PAGE[i].name) { 0 } else { 100 };
            query
                .split(' ')
                .filter(|w| !w.is_empty())
                .try_fold(base, |r, w| Some(r + word_rank(i, w)?))
                .map(|r| (r, i))
        })
        .collect();
    found.sort_by_key(|&(r, _)| r);
    found.into_iter().map(|(_, i)| i).collect()
}

/// A choice on the signing identity's page: the heading it starts (if any), its label, its help,
/// and the `set sign` value that does the same (None for one only the page does).
pub struct SignPick {
    pub section: Option<&'static str>,
    pub label: &'static str,
    pub help: &'static str,
    pub set: Option<&'static str>,
}

macro_rules! why_secret {
    () => {
        "chat signs your handshakes with it, and only the secret key can make a signature. "
    };
}

/// The signing identity's choices, in the page's order: off, then AGE's and PGP's.
pub const SIGN_PICKS: &[SignPick] = &[
    SignPick {
        section: None,
        label: "Off",
        help: "Don't sign. Peers see you as unverified.",
        set: Some("off"),
    },
    SignPick {
        section: Some("AGE"),
        label: "Native",
        help: "A key made here, with an age1... recipient others can encrypt files to you with (age -r). Enter asks for a password: it and your nick always make the same key on this device and OS, so keep both to keep an established signing identity. A new nick asks for the password again. Blank makes a new key that lasts until chat exits.",
        set: Some("age"),
    },
    SignPick {
        section: None,
        label: "Native, without nick",
        help: "A key made here from a password alone, as earlier versions made it, so the same password on this device and OS gives back the key you had then, whatever your nick. Blank makes a new key that lasts until chat exits.",
        set: Some("age-nonick"),
    },
    SignPick {
        section: None,
        label: "Pick a key file",
        help: concat!(
            "Your own AGE key, picked in a file browser: the file age-keygen writes. ",
            why_secret!(),
            "It stays in memory and isn't sent. :install saves the file's path, not the key."
        ),
        set: Some("age:PATH"),
    },
    SignPick {
        section: None,
        label: "Type a key file path",
        help: concat!(
            "Your own AGE key from a file whose path you type, such as ~/.config/age/key.txt. ",
            why_secret!(),
            ":install saves the path, not the key."
        ),
        set: Some("age:PATH"),
    },
    SignPick {
        section: None,
        label: "Paste a key",
        help: concat!(
            "Your own AGE key pasted in: the AGE-SECRET-KEY-1... line. ",
            why_secret!(),
            "There's no file to point to, so :install seals the key itself to disk."
        ),
        set: None,
    },
    SignPick {
        section: Some("PGP"),
        label: "Native",
        help: "A PGP key made here, whose public key is in the settings and the console for others to import. Enter asks for a password: it and your nick always make the same key on this device and OS, so keep both to keep an established signing identity. A new nick asks for the password again. Blank makes a new key that lasts until chat exits.",
        set: Some("pgp"),
    },
    SignPick {
        section: None,
        label: "Native, without nick",
        help: "A PGP key made here from a password alone, as earlier versions made it, so the same password on this device and OS gives back the key you had then, whatever your nick. Blank makes a new key that lasts until chat exits.",
        set: Some("pgp-nonick"),
    },
    SignPick {
        section: None,
        label: "Pick a key file",
        help: concat!(
            "Your own key, picked in a file browser: an unencrypted EdDSA/Ed25519 secret key, armored, as gpg --export-secret-keys --armor writes it. ",
            why_secret!(),
            ":install saves the file's path, not the key."
        ),
        set: Some("pgp:PATH"),
    },
    SignPick {
        section: None,
        label: "Type a key file path",
        help: concat!(
            "Your own key from a file whose path you type: an unencrypted, armored EdDSA/Ed25519 secret key. ",
            why_secret!(),
            ":install saves the path, not the key."
        ),
        set: Some("pgp:PATH"),
    },
    SignPick {
        section: None,
        label: "Paste a key",
        help: concat!(
            "Your own key pasted in, armored. ",
            why_secret!(),
            "There's no file to point to, so :install seals the key itself to disk."
        ),
        set: None,
    },
];

impl Settings {
    /// Whether rooms use a tor that's already running, and where it is: the Tor rows, with the
    /// control password (which a save never keeps) given.
    pub fn tor_use(&self, password: &str) -> crate::net::tor_ext::TorUse {
        crate::net::tor_ext::TorUse {
            launch: self.get("torlaunch").into(),
            socks: self.get("torsocks").into(),
            control: self.get("torcontrol").into(),
            password: password.into(),
            path: self.get("torpath").into(),
        }
    }

    /// Why a row isn't on the page right now, or None if it is: the UDP rows with Tor routing, the
    /// Tor rows with UDP, the relay list with the relays off, and the rows of a signing key that
    /// isn't in use. `key` is the signing key in use, and whether it was made here (not read from a
    /// file or pasted).
    pub fn hidden(&self, name: &str, key: Option<(IdentityKind, bool)>) -> Option<&'static str> {
        let tor = self.get("routing") == "tor";
        let age = matches!(key, Some((IdentityKind::Age, _)));
        let pgp_here = matches!(key, Some((IdentityKind::Pgp, true)));
        match name {
            "portmap" | "lan" if tor => Some("it only applies with udp routing"),
            "dht" | "dht6" if tor => Some("it doesn't apply with tor routing"),
            "torlaunch" | "torpath" | "torsocks" | "torcontrol" | "torpassword" | "bridges" | "transports" | "torguards" if !tor => {
                Some("it only applies with tor routing")
            }
            "relays" if self.get("nostr") == "off" => Some("it only applies with the Nostr relays on"),
            "agerecipient" if !age => Some("it needs an AGE signing identity"),
            "pgpkey" if !pgp_here => Some("it needs a PGP signing key made here"),
            "exportkey" if !age && !pgp_here => Some("it needs an AGE signing key, or a PGP key made here"),
            "sandbox" | "updater" if !cfg!(target_os = "linux") => Some("the sandbox is only on Linux"),
            "updater" if !self.on("sandbox") => Some("it only applies with the sandbox on"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::crypto::identity::IdentityKind;

    #[test]
    fn saves_only_what_changed_and_reads_it_back() {
        let mut s = Settings::default();
        assert_eq!(s.to_toml(), "[network]\nrouting = \"tor\"\n");
        s.set("lan", "off").unwrap();
        s.set("relays", "wss://relay.primal.net  wss://relay.snort.social").unwrap();
        s.set("nick", "alice").unwrap();
        s.set("colour", "Purple").unwrap();
        s.set("filelimit", "64m").unwrap();
        s.set("notify", "all").unwrap();
        s.set("port", "4444").unwrap();
        s.rooms.push(KeptRoom {
            label: "book \"club\"".into(),
            id: "K7M2Q9XRT4".into(),
            password: "correct horse".into(),
            at_start: true,
        });
        s.reopen.push(("P3W8C6NHVA".into(), "plum orbit".into()));
        s.ignored.push(TrustEntry {
            kind: IdentityKind::Age,
            public: [5; 32],
            nick: "mallory".into(),
        });
        let toml = s.to_toml();
        assert_eq!(
            toml,
            format!(
                "[network]\nrouting = \"tor\"\nlan = false\nrelays = [\"wss://relay.primal.net\", \"wss://relay.snort.social\"]\n\n\
                 [profile]\nnick = \"alice\"\ncolour = \"purple\"\n\n\
                 [chat]\nfilelimit = \"64M\"\nnotify = \"all\"\nport = 4444\n\n\
                 [rooms]\n1 = [\"book \\\"club\\\"\", \"K7M2Q9XRT4\", \"correct horse\", \"start\"]\n\n\
                 [open]\n1 = [\"P3W8C6NHVA\", \"plum orbit\"]\n\n\
                 [ignored]\n1 = [\"age\", \"{}\", \"mallory\"]\n",
                "05".repeat(32)
            )
        );
        let (back, notes) = Settings::from_toml(&toml);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(back, s);
    }

    #[test]
    fn tells_a_row_the_save_set_from_its_default() {
        assert!(Settings::toml_sets("[network]\nrouting = \"tor\"\n", "routing"));
        assert!(!Settings::toml_sets("[network]\nlan = false\n", "routing"));
        // In another table, with a value it doesn't take, or commented out.
        assert!(!Settings::toml_sets("[chat]\nrouting = \"tor\"\n", "routing"));
        assert!(!Settings::toml_sets("[network]\nrouting = \"pigeon\"\n", "routing"));
        assert!(!Settings::toml_sets("[network]\n# routing = \"udp\"\n", "routing"));
    }

    #[test]
    fn leaves_out_what_it_cant_use() {
        let (s, notes) = Settings::from_toml(
            "[network]\nlan = \"no\"\nwhat = 1\n[chat]\nnotify = \"loud\" # a comment\nport = \"80\"\n\
             filelimit = 1048576\nnet = 'verbose'\n[profile]\nnick = \"b\\u00f6b\"\n[rooms]\n1 = [\"x\"]\n",
        );
        assert_eq!(notes.len(), 5, "{notes:?}");
        assert_eq!((s.get("lan"), s.get("notify"), s.get("port")), (ON, "mentions", "0"));
        assert_eq!((s.get("filelimit"), s.get("net"), s.get("nick")), ("1M", "verbose", "böb"));
        assert!(s.rooms.is_empty());
        assert_eq!(s.route().mode, RouteMode::Tor);
        assert!(!Settings::default().set("routing", "carrier pigeon").is_ok());
        assert_eq!(parse_value("[\"a\",\"b\" , ]"), Some(Value::List(vec!["a".into(), "b".into()])));
    }

    #[test]
    fn the_page_shows_every_row_once() {
        assert_eq!(PAGE.len(), DEFS.len());
        for r in PAGE {
            assert!(def(r.name).is_some(), "{}", r.name);
            assert_eq!(PAGE.iter().filter(|q| q.name == r.name).count(), 1, "{}", r.name);
        }
    }

    #[test]
    fn the_page_lists_finds_and_steps_rows() {
        let at = |n: &str| PAGE.iter().position(|r| r.name == n).unwrap();
        assert_eq!(sections(), ["Network", "Profile", "Security", "Chat"]);
        assert_eq!((section_begin(0), section_begin(4)), (0, PAGE.len()));
        assert_eq!(
            (short_label(at("torsocks")), place(at("torsocks"))),
            ("SOCKS port".into(), "Network \u{203a} Tor".into())
        );
        assert_eq!(
            (short_label(at("routing")), place(at("nick"))),
            ("Routing".into(), "Profile".into())
        );
        assert_eq!(search("nick", |_| true)[0], at("nick"));
        assert_eq!(search("socks", |n| n != "torsocks"), [at("torsocks")]);
        assert_eq!(search("", |_| true).len(), PAGE.len());
        let s = Settings::default();
        assert!(s.hidden("lan", None).is_some() && s.hidden("bridges", None).is_none());
        assert!(s.hidden("exportkey", Some((IdentityKind::Pgp, false))).is_some());
        assert!(s.hidden("exportkey", Some((IdentityKind::Age, false))).is_none());
        assert_eq!(steps("routing"), Some(vec!["udp", "tor"]));
        assert_eq!((steps("devicelock"), steps("shadow")), (Some(vec![OFF, ON]), None));
    }
}
