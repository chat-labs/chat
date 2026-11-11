// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The JSON interface: one room, driven by another program over JSON Lines, as `chat-json` and
//! an interface's `--json` serve it.
//!
//! It speaks version 1 of chat's JSON interface: what happens comes out on stdout, one object a
//! line with its type in "t", and commands come in on stdin, each named by "cmd".

use crate::protocol::crypto::{self, identity::IdentityKeypair};
use crate::protocol::{hex, names};
use crate::*;
use serde_json::{Map, Value, json};
use std::io::Write;
use tokio::io::{AsyncBufReadExt, BufReader};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// "HH:MM", local time.
fn hhmm() -> String {
    net::history::hhmm(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    )
}

tokio::task_local! {
    /// Where lines go when the interface is served in-process ([`crate::ffi`]) rather than on stdout.
    static OUT: std::sync::mpsc::Sender<String>;
}

/// One object a line. A program that stops reading ends the room rather than blocking it.
fn emit(v: Value) -> bool {
    OUT.try_with(|out| out.send(v.to_string()).is_ok()).unwrap_or_else(|_| {
        let mut out = std::io::stdout().lock();
        writeln!(out, "{v}").and_then(|_| out.flush()).is_ok()
    })
}

fn obj(t: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("t".into(), t.into());
    m
}

fn error(text: impl std::fmt::Display) -> bool {
    emit(json!({"t": "error", "text": text.to_string()}))
}

#[derive(Clone, Copy, PartialEq)]
enum Notify {
    None,
    Mentions,
    All,
}

#[derive(Clone, Copy, PartialEq, PartialOrd)]
enum Preview {
    Off,
    Nick,
    Message,
}

struct State {
    client: Client,
    identity: Option<(IdentityKind, IdentityKeypair)>,
    notify: Notify,
    preview: Preview,
    trust_seen: u64,
    peers_json: Option<Value>,
    net_json: Option<Value>,
    files_json: Option<Value>,
    /// The room is a call's (`call` in start), for this day.
    call_day: Option<u64>,
    /// The request to move as last said ("seq" 0: none).
    move_json: Value,
    /// :move opened a new room: this process runs that one from now on.
    moved: Option<(Room, RoomEvents)>,
    /// A picture object's largest side, and the colour drawn under transparency.
    picture_max: u32,
    picture_bg: [u8; 3],
}

/// A picture object's largest side: 1024 unless asked for smaller, and never under 16.
const PICTURE_MAX: u32 = 1024;
const PICTURE_MIN: u32 = 16;

/// "ready" for the room "start" opened, "moved" for the one :move went to.
fn room_json(t: &str, i: &RoomInfo, call_day: Option<u64>) -> Value {
    // The invite as a QR code: one string per row, "1" for dark.
    let qr = i
        .invite
        .as_deref()
        .and_then(crate::protocol::qr::encode)
        .map_or_else(Vec::new, |q| q.rows());
    let mut v = json!({
        "t": t, "room": i.room, "password": i.password, "created": i.created, "invite": i.invite, "qr": qr,
        "me": {"id": i.me.hex(), "nick": i.nick, "colour": i.colour.to_string()},
        "route": if i.mode == RouteMode::Tor { "tor" } else { "udp" }, "history": i.history,
    });
    if i.mode == RouteMode::Direct {
        v["port"] = i.port.into();
    }
    if let Some(from) = &i.moved_from {
        v["from"] = from.clone().into();
    }
    if let Some(day) = call_day {
        v["call"] = true.into();
        v["day"] = day.into();
    }
    v
}

/// Each item of the "files" list.
fn file_json(f: &FileInfo, me: PeerId) -> Value {
    let mut o = Map::new();
    o.insert("num".into(), f.num.into());
    o.insert("name".into(), f.name.clone().into());
    o.insert("size".into(), f.size.into());
    o.insert("mine".into(), f.mine.into());
    o.insert("from".into(), f.from.unwrap_or(me).hex().into());
    o.insert("image".into(), f.image.into());
    o.insert("at".into(), net::history::hhmm(f.at).into());
    let state = match &f.state {
        FileState::Offered | FileState::Withdrawn => "offered",
        FileState::Fetching { .. } => "fetching",
        FileState::Queued { .. } => "queued",
        FileState::Done => "done",
        FileState::Failed { .. } => "failed",
    };
    o.insert("state".into(), state.into());
    match &f.state {
        FileState::Fetching { got, eta } => {
            o.insert("show".into(), f.show.into());
            o.insert("got".into(), (*got).into());
            match eta {
                Eta::Seconds(s) => o.insert("eta".into(), (*s).into()),
                Eta::WaitingSender => o.insert("waiting".into(), "sender".into()),
                Eta::WaitingVerify => o.insert("waiting".into(), "verify".into()),
            };
        }
        FileState::Queued { after } => {
            o.insert("show".into(), f.show.into());
            o.insert("after".into(), after.unwrap_or(0).into());
        }
        FileState::Failed { why } if !why.is_empty() => {
            o.insert("why".into(), why.clone().into());
        }
        _ => {}
    }
    if let Some(saved) = &f.saved {
        o.insert("saved".into(), saved.clone().into());
    }
    if let Some(s) = &f.sending {
        o.insert("sending".into(), json!({"count": s.count, "name": s.name, "permille": s.permille}));
    }
    let to = match (f.sent_to.as_slice(), f.sent_count) {
        ([], _) => String::new(),
        ([one], 1) => one.clone(),
        ([a, b], 2) => format!("{a} and {b}"),
        ([first, ..], n) => format!("{first} and {} others", n - 1),
    };
    if !to.is_empty() {
        o.insert("sent_to".into(), to.into());
    }
    Value::Object(o)
}

/// "files" in start and settings: where files are saved, the size limit, fast transfers and
/// noise in pictures.
fn file_options(v: &Value, mut o: FileOptions) -> Result<FileOptions, String> {
    if let Some(limit) = v.get("limit").and_then(Value::as_u64) {
        if limit > crate::protocol::files::FILE_HARD_MAX {
            return Err("files \"limit\" is 1 byte to 1 GB".into());
        }
        if limit > 0 {
            o.limit = limit;
        }
    }
    if let Some(fast) = v.get("fast").and_then(Value::as_bool) {
        o.fast = fast;
    }
    if let Some(noise) = v.get("noise").and_then(Value::as_bool) {
        o.noise = noise;
    }
    if let Some(dir) = v.get("dir").and_then(Value::as_str) {
        o.dir = (!dir.is_empty()).then(|| dir.to_string());
    }
    Ok(o)
}

fn key_kind(source: &str) -> Option<IdentityKind> {
    match source {
        "key" | "native" => Some(IdentityKind::Native),
        "age" => Some(IdentityKind::Age),
        "pgp" => Some(IdentityKind::Pgp),
        _ => None,
    }
}

fn key_source(kind: IdentityKind) -> &'static str {
    match kind {
        IdentityKind::Native => "key",
        IdentityKind::Age => "age",
        IdentityKind::Pgp => "pgp",
    }
}

/// A list of {source, pub, nick}, as "trust" and "ignored" take it.
fn key_list(v: Option<&Value>) -> Result<Vec<TrustEntry>, String> {
    let Some(v) = v else { return Ok(Vec::new()) };
    let arr = v.as_array().ok_or("a key list is an array")?;
    arr.iter()
        .map(|e| {
            let kind = e
                .get("source")
                .and_then(Value::as_str)
                .and_then(key_kind)
                .ok_or("a key's source is age, pgp or key")?;
            let public = e
                .get("pub")
                .and_then(Value::as_str)
                .and_then(|p| hex::decode_array::<32>(&p.to_ascii_lowercase()))
                .ok_or("a key's pub is 64 hex digits")?;
            let nick = crate::protocol::text::clean_nick(e.get("nick").and_then(Value::as_str).unwrap_or("").as_bytes());
            Ok(TrustEntry { kind, public, nick })
        })
        .collect()
}

fn key_list_json(t: &str, list: &[TrustEntry]) -> Value {
    let list: Vec<Value> = list
        .iter()
        .map(|e| {
            json!({"source": key_source(e.kind), "pub": hex::encode(&e.public), "fingerprint": hex::groups(&crypto::fingerprint(&e.public)), "nick": e.nick})
        })
        .collect();
    json!({"t": t, "list": list})
}

impl State {
    /// "identity": made here, made from a password (with this device's id, and the nick unless
    /// "with_nick" is false), read from a key, or none. Used from then on, in the room too.
    fn identity_cmd(&mut self, v: &Value, room: Option<&Room>) -> bool {
        let s = |k: &str| v.get(k).and_then(Value::as_str).filter(|x| !x.is_empty());
        let flag = |k: &str| v.get(k).and_then(Value::as_bool);
        let kind = match s("kind") {
            Some("none") => {
                self.identity = None;
                if let Some(r) = room {
                    r.set_identity(None);
                }
                return emit(json!({"t": "identity", "kind": "none"}));
            }
            Some("age") => IdentityKind::Age,
            Some("pgp") => IdentityKind::Pgp,
            _ => return error("identity needs \"kind\": age, pgp or none"),
        };
        let mut created = v.get("created").and_then(Value::as_u64).filter(|&c| c > 0).map_or_else(
            || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()) as u32
            },
            |c| c as u32,
        );
        let mut secret_out = flag("new") == Some(true) || flag("export") == Some(true);
        let kp = if let Some(pw) = s("password") {
            let Some(device) = s("device").map(str::to_string).or_else(crate::net::device::machine_id) else {
                return error("this system has no machine id to make the key with");
            };
            let nick = if flag("with_nick").unwrap_or(true) {
                let nick = s("nick").map(str::to_string).or_else(|| room.map(|r| r.info().nick.clone()));
                match nick {
                    Some(n) => Some(crate::protocol::text::clean_nick(n.as_bytes())),
                    None => return error("a key made with the nick needs \"nick\" before a room is open"),
                }
            } else {
                None
            };
            let Ok(kp) = IdentityKeypair::from_password(pw, &device, nick.as_deref()) else {
                return error("couldn't make the key - it needs 512 MiB of free memory for a moment");
            };
            created = crypto::pgp::DERIVED_CREATED;
            secret_out = true;
            kp
        } else if flag("new") == Some(true) {
            IdentityKeypair::generate()
        } else {
            let read = s("key").and_then(IdentityKeypair::from_key_text).filter(|(k, _)| *k == kind);
            match read {
                Some((_, kp)) => kp,
                None if kind == IdentityKind::Pgp => return error("\"key\" isn't an unencrypted PGP EdDSA secret key"),
                None => return error("\"key\" isn't an AGE secret key"),
            }
        };
        let mut o = obj("identity");
        o.insert("kind".into(), key_source(kind).into());
        o.insert("pub".into(), hex::encode(&kp.public).into());
        o.insert("fingerprint".into(), hex::groups(&crypto::fingerprint(&kp.public)).into());
        if kind == IdentityKind::Pgp {
            let uid = room.map_or_else(|| "chat".to_string(), |r| r.info().nick.clone());
            o.insert("created".into(), created.into());
            if secret_out && let Some((secret, _)) = crypto::pgp::export_secret(&kp, &uid, created) {
                o.insert("secret".into(), secret.as_str().into());
            }
            o.insert("public".into(), crypto::pgp::export_public(&kp, &uid, created).0.into());
        } else if let Some((recipient, secret)) = kp.age_strings() {
            o.insert("public".into(), recipient.into());
            if secret_out {
                o.insert("secret".into(), secret.as_str().into());
            }
        }
        if let Some(r) = room {
            r.set_identity(Some((kind, kp.clone())));
        }
        self.identity = Some((kind, kp));
        emit(Value::Object(o))
    }

    fn apply_notify(&mut self, v: Option<&Value>) {
        let Some(v) = v else { return };
        match v.get("mode").and_then(Value::as_str) {
            Some("none") => self.notify = Notify::None,
            Some("mentions") => self.notify = Notify::Mentions,
            Some("all") => self.notify = Notify::All,
            _ => {}
        }
        match v.get("preview").and_then(Value::as_str) {
            Some("off") => self.preview = Preview::Off,
            Some("nick") => self.preview = Preview::Nick,
            Some("message") => self.preview = Preview::Message,
            _ => {}
        }
    }

    fn apply_picture(&mut self, v: Option<&Value>) -> Result<(), String> {
        let Some(v) = v else { return Ok(()) };
        if let Some(max) = v.get("max").and_then(Value::as_u64) {
            self.picture_max = (max as u32).clamp(PICTURE_MIN, PICTURE_MAX);
        }
        if let Some(bg) = v.get("background").and_then(Value::as_str) {
            self.picture_bg = Colour::parse(bg).ok_or_else(|| format!("unknown picture background {bg}"))?.0;
        }
        Ok(())
    }

    /// The file list, when it has changed (the engine sends it at most twice a second).
    fn say_files(&mut self, list: &[FileInfo], me: PeerId, force: bool) -> bool {
        let v = json!({"t": "files", "list": list.iter().map(|f| file_json(f, me)).collect::<Vec<_>>()});
        if !force && self.files_json.as_ref() == Some(&v) {
            return true;
        }
        self.files_json = Some(v.clone());
        emit(v)
    }

    /// A picture fetched to be shown, as pixels: decoded here, so the program showing it never
    /// parses what a peer sent.
    async fn say_picture(&self, num: u32, name: String, data: Vec<u8>) -> bool {
        let (max, bg) = (self.picture_max, self.picture_bg);
        let thumb = tokio::task::spawn_blocking(move || crate::protocol::picture::decode(&data, max, max, bg))
            .await
            .unwrap_or_else(|_| Err("it couldn't be decoded".into()));
        match thumb {
            Ok(t) => emit(json!({
                "t": "picture", "num": num, "name": name, "w": t.w, "h": t.h, "src_w": t.src_w, "src_h": t.src_h,
                "rgb": crate::protocol::base64::encode(&t.rgb),
            })),
            Err(why) => emit(json!({"t": "picture", "num": num, "name": name, "error": why})),
        }
    }

    fn apply_lists(&mut self, v: &Value) -> Result<(), String> {
        let mut t = self.client.trust().lock().expect("trust lock");
        if v.get("trust").is_some() {
            t.set_verified(key_list(v.get("trust"))?);
        }
        if v.get("ignored").is_some() {
            t.set_ignored(key_list(v.get("ignored"))?);
        }
        Ok(())
    }

    /// The lists, when something changed them (a peer verified, ignored, or renamed).
    fn say_lists_if_changed(&mut self) -> bool {
        let (version, verified, ignored) = {
            let t = self.client.trust().lock().expect("trust lock");
            (t.version(), t.verified().to_vec(), t.ignored().to_vec())
        };
        if version == self.trust_seen {
            return true;
        }
        self.trust_seen = version;
        emit(key_list_json("trust", &verified)) && emit(key_list_json("ignored", &ignored))
    }

    fn start_config(&mut self, v: &Value) -> Result<RoomConfig, String> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let mut cfg = RoomConfig {
            room: s("room"),
            password: s("password"),
            invite: s("invite"),
            ..Default::default()
        };
        cfg.create = v
            .get("create")
            .and_then(Value::as_bool)
            .unwrap_or(cfg.room.is_none() && cfg.invite.is_none());
        if let Some(call) = s("call") {
            let (_, kp) = self.identity.as_ref().ok_or("a call needs a signing identity first")?;
            let their = hex::decode_array::<32>(&call.to_ascii_lowercase()).ok_or("call takes a signing public key, 64 hex digits")?;
            let unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let day = v.get("day").and_then(Value::as_u64).unwrap_or(names::contact_day(unix));
            let (room, password) = names::contact_room(kp, &their, day).ok_or("that key can't make a call's room")?;
            cfg.room = Some(room);
            cfg.password = Some(password);
            self.call_day = Some(day);
            cfg.invite = None;
            cfg.create = false;
            cfg.verify_required = true;
        } else if cfg.password.is_none() && cfg.room.is_some() && cfg.invite.is_none() {
            cfg.password = Some(std::env::var("CHAT_PASSWORD").unwrap_or_default());
        }
        cfg.nick = s("nick").unwrap_or_else(names::random_nick);
        if let Some(c) = s("colour") {
            cfg.colour = Some(Colour::parse(&c).ok_or_else(|| format!("unknown colour {c}"))?);
        }
        if s("verify").as_deref() == Some("required") {
            cfg.verify_required = true;
        }
        cfg.history = v.get("history").and_then(Value::as_bool).unwrap_or(false);
        cfg.kept = v.get("kept").and_then(Value::as_bool).unwrap_or(false);
        cfg.timer = v.get("timer").and_then(Value::as_u64).unwrap_or(0) as u32;
        cfg.net_log = s("net_log").and_then(|l| net_log(&l));
        self.apply_notify(v.get("notify"));
        if let Some(f) = v.get("files") {
            cfg.files = file_options(f, cfg.files)?;
        }
        self.apply_picture(v.get("picture"))?;
        let route = v.get("route").cloned().unwrap_or(json!({}));
        // Tor unless asked for direct: onion services hide your IP address, peers included.
        cfg.route.mode = match route.get("mode").and_then(Value::as_str) {
            None | Some("tor") => RouteMode::Tor,
            Some("udp" | "direct") => RouteMode::Direct,
            Some(other) => return Err(format!("a route's mode is tor or direct, not {other}")),
        };
        let flag = |k: &str, d: bool| route.get(k).and_then(Value::as_bool).unwrap_or(d);
        cfg.route.dht = flag("dht", true);
        cfg.route.ipv6 = flag("ipv6", true);
        cfg.route.lan = flag("lan", true);
        cfg.route.portmap = flag("portmap", true);
        cfg.route.nostr = match route.get("nostr").and_then(Value::as_str) {
            Some("off") => NostrMode::Off,
            Some("always") => NostrMode::Always,
            _ => NostrMode::Fallback,
        };
        if let Some(relays) = route.get("relays").and_then(Value::as_array) {
            cfg.route.relays = relays.iter().filter_map(Value::as_str).map(str::to_string).collect();
        }
        // A tor that's already running, or the one to start, as the Tor rows of the settings have it.
        if let Some(t) = route.get("tor") {
            let field = |k: &str| t.get(k).and_then(Value::as_str);
            let mut rows = net::settings::Settings::default();
            for (k, row) in [("socks", "torsocks"), ("control", "torcontrol")] {
                if let Some(x) = field(k) {
                    rows.set(row, x).map_err(|_| "tor \"socks\" and \"control\" are host:port")?;
                }
            }
            if let Some(x) = field("launch") {
                rows.set("torlaunch", x).map_err(|_| "tor \"launch\" is auto, always or never")?;
            }
            if let Some(p) = field("path") {
                let found = net::tor_ext::tor_program(p)
                    .ok_or_else(|| format!("can't use {p} as tor - it has to be a full path to a program only root or you can change"))?;
                rows.set("torpath", &found.to_string_lossy())?;
            }
            self.client.set_tor_use(rows.tor_use(field("password").unwrap_or_default()));
        }
        // Both at the top level and inside route, where apps put them too.
        cfg.route.port = v.get("port").or_else(|| route.get("port")).and_then(Value::as_u64).unwrap_or(0) as u16;
        if let Some(peers) = v.get("peers").or_else(|| route.get("peers")).and_then(Value::as_array) {
            cfg.route.peers = peers.iter().filter_map(Value::as_str).map(str::to_string).collect();
        }
        if let Some(id) = v.get("identity")
            && !self.identity_cmd(id, None)
        {
            return Err("stdout closed".into());
        }
        self.apply_lists(v)?;
        cfg.identity = self.identity.clone();
        // For interop tests that need rekeys sooner than every five minutes.
        cfg.rekey_interval = std::env::var("CHAT_TEST_REKEY_SECONDS").ok().and_then(|s| s.parse().ok());
        Ok(cfg)
    }

    fn peers_value(&self, peers: &[PeerInfo]) -> Value {
        let list: Vec<Value> = peers
            .iter()
            .map(|p| {
                let mut o = Map::new();
                o.insert("id".into(), p.id.hex().into());
                o.insert("name".into(), p.name.clone().into());
                o.insert("nick".into(), p.nick.clone().into());
                o.insert("colour".into(), p.colour.to_string().into());
                o.insert(
                    "identity".into(),
                    p.identity
                        .as_ref()
                        .map_or("none", |i| match i.kind {
                            IdentityKind::Native => "native",
                            IdentityKind::Age => "age",
                            IdentityKind::Pgp => "pgp",
                        })
                        .into(),
                );
                if let Some(i) = &p.identity {
                    o.insert("signed".into(), serde_json::to_value(i.signature).unwrap_or_default());
                    o.insert("fingerprint".into(), i.fingerprint.clone().into());
                }
                let mut code = Map::new();
                code.insert("state".into(), serde_json::to_value(p.code_state).unwrap_or_default());
                if let Some(c) = &p.code {
                    code.insert("words".into(), c.words.clone().into());
                    code.insert("hex".into(), c.hex.clone().into());
                }
                o.insert("code".into(), Value::Object(code));
                let v = p.version.clone().unwrap_or_default();
                let label = match p.build {
                    crate::BuildState::Official => format!("says official v{v}"),
                    crate::BuildState::Modified => format!("modified client (says v{v})"),
                    crate::BuildState::Unchecked => format!("v{v}, build not checked"),
                    crate::BuildState::Unknown => "build unknown".into(),
                };
                o.insert(
                    "build".into(),
                    json!({"state": serde_json::to_value(p.build).unwrap_or_default(), "label": label}),
                );
                o.insert("history".into(), p.keeps_history.into());
                o.insert("ignored".into(), p.ignored.into());
                o.insert("dm".into(), p.can_dm.into());
                Value::Object(o)
            })
            .collect();
        json!({"t": "peers", "list": list})
    }

    /// "peers", whenever the list changed.
    async fn say_peers(&mut self, room: &Room, force: bool) -> bool {
        let v = self.peers_value(&room.peers().await);
        if !force && self.peers_json.as_ref() == Some(&v) {
            return true;
        }
        self.peers_json = Some(v.clone());
        emit(v)
    }

    fn say_net(&mut self, n: &NetStatus, force: bool) -> bool {
        let mut o = obj("net");
        o.insert("ready".into(), n.ready.into());
        o.insert("online".into(), n.online.into());
        o.insert("pending".into(), n.pending.into());
        o.insert("rx".into(), n.rx.into());
        if n.mode == RouteMode::Tor {
            o.insert("tor".into(), (if n.tor_ready { "connected" } else { "connecting" }).into());
            o.insert("onion".into(), n.onion_up.into());
        } else if let Some(d) = n.dht {
            o.insert("dht".into(), d.into());
            o.insert("dht_found".into(), n.dht_found.into());
            if let Some(pm) = n.portmap {
                o.insert("portmap".into(), pm.into());
            }
        }
        if let Some(r) = &n.relays {
            o.insert("relays".into(), json!({"used": r.used, "up": r.up, "total": r.total}));
        }
        let v = Value::Object(o);
        if !force && self.net_json.as_ref() == Some(&v) {
            return true;
        }
        self.net_json = Some(v.clone());
        emit(v)
    }

    /// What the room says, as v1 objects.
    async fn on_event(&mut self, room: &Room, e: Event) -> bool {
        match e {
            Event::Message(m) => {
                let mut o = obj("line");
                o.insert("at".into(), hhmm().into());
                o.insert("kind".into(), "message".into());
                o.insert("text".into(), m.text.clone().into());
                if !m.mid.is_empty() {
                    o.insert("mid".into(), m.mid.clone().into());
                }
                if let Some(num) = m.file {
                    o.insert("file".into(), num.into());
                }
                o.insert("from".into(), m.from.hex().into());
                o.insert("mine".into(), m.mine.into());
                o.insert("nick".into(), m.nick.clone().into());
                if let Some(p) = m.peer {
                    o.insert("peer".into(), p.hex().into());
                }
                if let Some(own) = m.own {
                    o.insert("own".into(), own.into());
                }
                if m.direct {
                    o.insert("direct".into(), true.into());
                }
                if m.mention {
                    o.insert("mention".into(), true.into());
                }
                if m.quote_len > 0 {
                    o.insert("quote".into(), m.quote_len.into());
                }
                if let Some(c) = m.colour {
                    o.insert("colour".into(), c.to_string().into());
                }
                if !emit(Value::Object(o)) {
                    return false;
                }
                if !m.mine && (self.notify == Notify::All || (self.notify == Notify::Mentions && m.mention)) {
                    let mut n = obj("notify");
                    if self.preview >= Preview::Nick {
                        n.insert("nick".into(), m.name.clone().into());
                    }
                    if self.preview == Preview::Message {
                        n.insert("text".into(), m.text.into());
                    }
                    n.insert("mention".into(), m.mention.into());
                    return emit(Value::Object(n));
                }
                true
            }
            Event::Notice { level, text } => {
                let kind = if level == Level::Warn { "warn" } else { "note" };
                emit(json!({"t": "line", "at": hhmm(), "kind": kind, "text": format!("* {text}")})) && self.say_lists_if_changed()
            }
            Event::Log { text } => emit(json!({"t": "line", "at": hhmm(), "kind": "note", "text": format!("* {text}")})),
            Event::Delivery { own, delivery } => match delivery {
                Delivery::Missed { name, .. } => emit(json!({"t": "delivery", "own": own, "missed": name})),
                Delivery::Settled => emit(json!({"t": "delivery", "own": own, "settled": true})),
                // v1 has no per-peer receipt; the native API does.
                Delivery::Delivered { .. } => true,
            },
            Event::PeerJoined(_) | Event::PeerChanged(_) | Event::PeerLeft { .. } => {
                self.say_peers(room, false).await && self.say_lists_if_changed()
            }
            Event::Timer { seconds, who } => emit(json!({"t": "timer", "seconds": seconds, "who": who})),
            Event::Net(n) => self.say_net(&n, false),
            Event::Opened => true,
            Event::Files { list } => self.say_files(&list, room.info().me, false),
            Event::MoveAsked { ask } => {
                self.move_json = match ask {
                    Some(a) => json!({
                        "t": "move", "seq": a.seq, "from": a.from, "coming": a.coming.len(),
                        "names": names::list(&a.coming), "at": net::history::hhmm(a.at),
                    }),
                    None => json!({"t": "move", "seq": 0}),
                };
                emit(self.move_json.clone())
            }
            Event::Picture { num, name, data } => self.say_picture(num, name, data).await,
        }
    }

    /// A command in a room. Returns false once the room is over.
    async fn room_cmd(&mut self, room: &Room, v: &Value) -> bool {
        let s = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let peer = || s("peer").parse::<PeerId>().map_err(|e| e.to_string());
        let result: Result<(), String> = match v.get("cmd").and_then(Value::as_str).unwrap_or("") {
            "send" => room.send(&s("text")).await.map(drop).map_err(|e| e.to_string()),
            "reply" => room.reply(&s("mid"), &s("text")).await.map(drop).map_err(|e| e.to_string()),
            "dm" => match peer() {
                Ok(p) => room.dm(p, &s("text")).await.map(drop).map_err(|e| e.to_string()),
                Err(e) => Err(e),
            },
            "verify" => match peer() {
                Ok(p) => room
                    .verify(p, v.get("same").and_then(Value::as_bool).unwrap_or(false))
                    .await
                    .map(drop)
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e),
            },
            "ignore" => match peer() {
                Ok(p) => room
                    .command(Command::Ignore {
                        peer: p,
                        on: v.get("on").and_then(Value::as_bool).unwrap_or(true),
                    })
                    .await
                    .map(drop)
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e),
            },
            "timer" => room
                .command(Command::SetTimer {
                    seconds: v.get("seconds").and_then(Value::as_u64).unwrap_or(0) as u32,
                })
                .await
                .map(drop)
                .map_err(|e| e.to_string()),
            "history" => room
                .command(Command::SetHistory {
                    on: v.get("on").and_then(Value::as_bool).unwrap_or(false),
                })
                .await
                .map(drop)
                .map_err(|e| e.to_string()),
            "settings" => self.settings(room, v).await,
            "trust" | "ignored" => {
                let field = if v.get("cmd").and_then(Value::as_str) == Some("trust") {
                    "trust"
                } else {
                    "ignored"
                };
                let mut wrapped = Map::new();
                wrapped.insert(field.into(), v.get("list").cloned().unwrap_or(json!([])));
                self.apply_lists(&Value::Object(wrapped))
            }
            "identity" => return self.identity_cmd(v, Some(room)),
            "state" => {
                let n = room.net().await;
                let (seconds, who) = room.timer().await;
                return self.say_peers(room, true).await
                    && self.say_net(&n, true)
                    && self.say_files(&room.files().await, room.info().me, true)
                    && emit(json!({"t": "timer", "seconds": seconds, "who": who}))
                    && emit(self.move_json.clone());
            }
            "command" => match s("line").trim_start_matches(':').split_whitespace().next().unwrap_or("") {
                "net" => room.command(Command::NetReport).await.map(drop).map_err(|e| e.to_string()),
                "peers" => {
                    for p in room.peers().await {
                        let code = p.code.map(|c| c.hex).unwrap_or_default();
                        let line = format!("*   {}#{} (verify {code}, {:?})", p.nick, p.id.short(), p.code_state);
                        if !emit(json!({"t": "line", "at": hhmm(), "kind": "note", "text": line})) {
                            return false;
                        }
                    }
                    Ok(())
                }
                other => Err(format!("unknown command :{other} here - try net or peers")),
            },
            "quit" => {
                if v.get("kept").and_then(Value::as_bool) == Some(true) {
                    let _ = room.command(Command::SetComingBack { on: true }).await;
                }
                room.leave().await;
                emit(json!({"t": "bye"}));
                return false;
            }
            "fetch" => match v
                .get("num")
                .and_then(Value::as_u64)
                .filter(|n| (1..=u64::from(u32::MAX)).contains(n))
            {
                None => Err("fetch needs a file's \"num\"".into()),
                Some(num) => {
                    let flag = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
                    room.fetch(num as u32, flag("show"), flag("anyway"), None)
                        .await
                        .map(drop)
                        .map_err(|e| e.to_string())
                }
            },
            "offer" => match v.get("path").and_then(Value::as_str) {
                None => Err("offer needs \"path\"".into()),
                Some(path) => room
                    .offer(path, v.get("asis").and_then(Value::as_bool).unwrap_or(false))
                    .await
                    .map(drop)
                    .map_err(|e| e.to_string()),
            },
            "cancel" => match v
                .get("num")
                .and_then(Value::as_u64)
                .filter(|n| (1..=u64::from(u32::MAX)).contains(n))
            {
                None => Err("cancel needs a file's \"num\"".into()),
                Some(num) => room.cancel(num as u32).await.map(drop).map_err(|e| e.to_string()),
            },
            "move" => match v.get("answer").and_then(Value::as_bool) {
                None => match room.command(Command::Move { answer: None }).await {
                    Ok(Outcome::MovePlan(p)) => {
                        return emit(json!({
                            "t": "move_plan", "coming": p.coming.len(), "coming_names": names::list(&p.coming),
                            "left": p.left.len(), "left_names": names::list(&p.left),
                        }));
                    }
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.to_string()),
                },
                Some(yes) => match room.answer_move(yes).await {
                    Ok(Some(moved)) => {
                        self.moved = Some(moved);
                        Ok(())
                    }
                    Ok(None) => Ok(()),
                    Err(e) => Err(e.to_string()),
                },
            },
            "newtor" => {
                let text = if room.newtor().await {
                    "* new Tor circuits and onion address for 1 session"
                } else {
                    "* no session goes through Tor"
                };
                return emit(json!({"t": "log", "at": hhmm(), "text": text}));
            }
            other => Err(format!("unknown command {other}")),
        };
        match result {
            Ok(()) => self.say_lists_if_changed(),
            Err(e) => error(e),
        }
    }

    async fn settings(&mut self, room: &Room, v: &Value) -> Result<(), String> {
        if let Some(nick) = v.get("nick").and_then(Value::as_str) {
            room.command(Command::SetNick { nick: nick.into() })
                .await
                .map_err(|e| e.to_string())?;
        }
        if let Some(c) = v.get("colour").and_then(Value::as_str) {
            let colour = Colour::parse(c).ok_or_else(|| format!("unknown colour {c}"))?;
            room.command(Command::SetColour { colour }).await.map_err(|e| e.to_string())?;
        }
        if let Some(verify) = v.get("verify").and_then(Value::as_str) {
            room.command(Command::SetVerifyRequired { on: verify == "required" })
                .await
                .map_err(|e| e.to_string())?;
        }
        if let Some(level) = v.get("net_log").and_then(Value::as_str).and_then(net_log) {
            room.command(Command::SetNetLog { level }).await.map_err(|e| e.to_string())?;
        }
        self.apply_notify(v.get("notify"));
        if let Some(f) = v.get("files") {
            let o = file_options(f, room.file_options())?;
            room.set_file_options(o).await.map_err(|e| e.to_string())?;
        }
        self.apply_picture(v.get("picture"))?;
        Ok(())
    }
}

fn net_log(s: &str) -> Option<NetLog> {
    match s {
        "normal" => Some(NetLog::Normal),
        "verbose" => Some(NetLog::Verbose),
        "off" => Some(NetLog::Off),
        _ => None,
    }
}

/// Serves one room over stdin and stdout until stdin ends or the room is left. Call
/// [`harden_process`] first, as every interface does.
pub async fn serve() {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    serve_lines(rx).await;
}

/// Serves one room in-process: commands come in on `lines`, and what happens goes out on `out`,
/// a line each, until `lines` ends or the room is left.
pub async fn serve_on(lines: tokio::sync::mpsc::UnboundedReceiver<String>, out: std::sync::mpsc::Sender<String>) {
    OUT.scope(out, serve_lines(lines)).await;
}

async fn serve_lines(mut lines: tokio::sync::mpsc::UnboundedReceiver<String>) {
    let mut st = State {
        client: Client::new(),
        identity: None,
        notify: Notify::Mentions,
        preview: Preview::Off,
        trust_seen: 0,
        peers_json: None,
        net_json: None,
        files_json: None,
        call_day: None,
        move_json: json!({"t": "move", "seq": 0}),
        moved: None,
        picture_max: PICTURE_MAX,
        picture_bg: [0, 0, 0],
    };
    if !emit(json!({"t": "hello", "v": 1, "version": VERSION, "built": format!("chat-core {VERSION}")})) {
        return;
    }
    // Before a room: an identity, then start (or quit).
    let (room, events) = loop {
        let Some(line) = lines.recv().await else {
            emit(json!({"t": "bye"}));
            return;
        };
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            error("that isn't a JSON object");
            continue;
        };
        match v.get("cmd").and_then(Value::as_str) {
            Some("identity") => {
                if !st.identity_cmd(&v, None) {
                    return;
                }
            }
            Some("quit") => {
                emit(json!({"t": "bye"}));
                return;
            }
            Some("start") => {
                let cfg = match st.start_config(&v) {
                    Ok(c) => c,
                    Err(e) => {
                        error(e);
                        emit(json!({"t": "bye"}));
                        return;
                    }
                };
                match st.client.join(cfg).await {
                    Ok(r) => break r,
                    Err(e) => {
                        error(e);
                        emit(json!({"t": "bye"}));
                        return;
                    }
                }
            }
            _ => {
                error("start a room first");
            }
        }
    };

    let (mut room, mut events) = (room, events);
    st.trust_seen = st.client.trust().lock().map(|t| t.version()).unwrap_or(0);
    if !emit(room_json("ready", room.info(), st.call_day)) || !st.say_peers(&room, true).await {
        room.leave().await;
        return;
    }
    loop {
        tokio::select! {
            line = lines.recv() => {
                let Some(line) = line else {
                    // stdin closed: quit, as "quit" does.
                    room.leave().await;
                    emit(json!({"t": "bye"}));
                    return;
                };
                match serde_json::from_str::<Value>(&line) {
                    Ok(v) => if !st.room_cmd(&room, &v).await { return },
                    Err(_) => { error("that isn't a JSON object"); }
                }
                // :move went to a new room: this process runs it from now on, and the one left
                // closes on its own once those moving with us have our key.
                if let Some((r, e)) = st.moved.take() {
                    (room, events) = (r, e);
                    st.peers_json = None;
                    st.net_json = None;
                    st.files_json = None;
                    st.move_json = json!({"t": "move", "seq": 0});
                    st.call_day = None;
                    if !emit(room_json("moved", room.info(), None)) || !st.say_peers(&room, true).await {
                        room.leave().await;
                        return;
                    }
                }
            }
            e = events.recv() => {
                let Some(e) = e else {
                    emit(json!({"t": "bye"}));
                    return;
                };
                if !st.on_event(&room, e).await {
                    room.leave().await;
                    return;
                }
            }
        }
    }
}
