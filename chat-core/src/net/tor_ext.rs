// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! A tor that's already running, used in place of the built-in one: its SOCKS port carries our
//! streams, each room's on circuits of its own (tor isolates streams by their SOCKS credentials),
//! and its control port hosts our onion services (ADD_ONION, with the room's own key). The
//! services go when the control connection closes, so nothing is left behind in that tor.

use crate::protocol::crypto::sodium;
use crate::protocol::{base64, hex};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// How long a control port or SOCKS port is given to answer.
const ANSWER: Duration = Duration::from_secs(10);
/// The longest line a control reply holds that's read.
const LINE_MAX: usize = 16 * 1024;

/// Where a running tor is, and how to log in to its control port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TorUse {
    /// "auto": a running tor if one answers, else the built-in one; "always": the built-in one;
    /// "never": only a running tor.
    pub launch: String,
    pub socks: String,
    pub control: String,
    /// The control port's password, if it takes one (HashedControlPassword). Never saved.
    pub password: String,
    /// The tor program chat starts as its own tor (a path, or a name on PATH); empty for the
    /// built-in one.
    pub path: String,
}

impl Default for TorUse {
    fn default() -> Self {
        TorUse {
            launch: "auto".into(),
            socks: "127.0.0.1:9050".into(),
            control: "127.0.0.1:9051".into(),
            password: String::new(),
            path: String::new(),
        }
    }
}

struct Control {
    r: BufReader<tokio::net::tcp::OwnedReadHalf>,
    w: tokio::net::tcp::OwnedWriteHalf,
}

pub struct ExtTor {
    socks: String,
    control: tokio::sync::Mutex<Control>,
    ready: AtomicBool,
    progress: std::sync::Mutex<String>,
    /// A tor chat started, which stops with it.
    child: std::sync::Mutex<Option<std::process::Child>>,
}

impl Drop for ExtTor {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.lock().ok().and_then(|mut c| c.take()) {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// HashedControlPassword for a password, as `tor --hash-password` makes it: OpenPGP's salted and
/// iterated S2K (RFC 4880 3.7.1.3), SHA-1 over the salt and password repeated to 65536 bytes.
fn hash_password(password: &str, salt: [u8; 8]) -> String {
    const COUNT_BYTE: u8 = 0x60;
    let count = (16 + usize::from(COUNT_BYTE & 15)) << ((COUNT_BYTE >> 4) + 6);
    let unit: Vec<u8> = salt.iter().chain(password.as_bytes()).copied().collect();
    let mut c = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY);
    let mut left = count.max(unit.len());
    while left > 0 {
        let n = left.min(unit.len());
        c.update(&unit[..n]);
        left -= n;
    }
    let mut spec = salt.to_vec();
    spec.push(COUNT_BYTE);
    spec.extend_from_slice(c.finish().as_ref());
    format!("16:{}", hex::encode(&spec).to_uppercase())
}

/// The tor program `torpath` names: a path, or a name on PATH or in the usual folders. None if
/// there isn't one, or it's one others could change.
pub fn tor_program(path: &str) -> Option<std::path::PathBuf> {
    if path.contains('/') {
        crate::net::bridges::program_ok(std::path::Path::new(&crate::net::files::typed_path_here(path)))
    } else {
        crate::net::bridges::find_program(path)
    }
}

/// Starts the tor program at `program` as chat's own tor, with its data in `dir` (which it keeps
/// for itself): nothing from the system's torrc, two free local ports, a control password made at
/// random (tor only gets its hash), and gone once chat is. With bridges, it reaches the network only
/// once it has them.
pub async fn launch(program: &str, dir: &std::path::Path, bridges: &crate::net::Bridges) -> Result<Arc<ExtTor>, String> {
    let program =
        tor_program(program).ok_or_else(|| format!("can't use {program} as tor - it has to be a program only root or you can change"))?;
    let conf = bridges.setconf()?;
    let data = dir.join("tor-data");
    let torrc = dir.join("torrc");
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.recursive(true)
        .create(&data)
        .map_err(|e| format!("can't make tor's folder: {e}"))?;
    // An empty config file for both the torrc and the defaults, so nothing in the system's torrc
    // (hidden services, other ports) applies.
    std::fs::write(&torrc, b"").map_err(|e| format!("can't write tor's configuration: {e}"))?;
    // Two free ports, held open together so they're different. Another program could take one
    // before tor does; tor then stops, and the next room starts it again.
    let (a, b2) = (
        std::net::TcpListener::bind("127.0.0.1:0"),
        std::net::TcpListener::bind("127.0.0.1:0"),
    );
    let (Ok(a), Ok(b2)) = (a, b2) else {
        return Err("no free local ports for tor".into());
    };
    let socks = a.local_addr().map_err(|e| e.to_string())?.to_string();
    let control = b2.local_addr().map_err(|e| e.to_string())?.to_string();
    drop((a, b2));
    let password = zeroize::Zeroizing::new(hex::encode(&sodium::random_array::<16>()));
    let hashed = hash_password(&password, sodium::random_array());
    let p = |x: &std::path::Path| x.to_string_lossy().into_owned();
    let mut args = vec![
        "-f".to_string(),
        p(&torrc),
        "--defaults-torrc".into(),
        p(&torrc),
        "--DataDirectory".into(),
        p(&data),
        "--SocksPort".into(),
        socks.clone(),
        "--ControlPort".into(),
        control.clone(),
        // Only the hash is on tor's command line, which anyone can read; the password stays in chat.
        "--HashedControlPassword".into(),
        hashed,
        "--CookieAuthentication".into(),
        "0".into(),
        // tor exits by itself once chat's process is gone, crash or not.
        "--__OwningControllerProcess".into(),
        std::process::id().to_string(),
        "--AvoidDiskWrites".into(),
        "1".into(),
        // Refuse SOCKS requests with an IP address, since that means a DNS lookup happened outside Tor.
        "--SafeSocks".into(),
        "1".into(),
        "--RunAsDaemon".into(),
        "0".into(),
    ];
    // Not a byte to the Tor network until it has its bridges.
    if conf.is_some() {
        args.extend(["--DisableNetwork".into(), "1".into()]);
    }
    let mut child = std::process::Command::new(&program)
        .args(&args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => format!(
                "couldn't start {} - the sandbox only runs a tor given with --tor-path as chat starts",
                program.display()
            ),
            _ => format!("couldn't start {}: {e}", program.display()),
        })?;
    let u = TorUse {
        launch: "never".into(),
        socks,
        control,
        password: password.to_string(),
        path: String::new(),
    };
    // Its ports open a moment after it starts.
    let mut tries = 0;
    let t = loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("tor stopped as it started ({status})"));
        }
        match ExtTor::connect(&u).await {
            Ok(t) => break t,
            Err(e) if tries >= 60 => {
                let _ = child.kill();
                return Err(format!("tor started but didn't answer: {e}"));
            }
            Err(_) => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };
    *t.child.lock().expect("child") = Some(child);
    if let Some(conf) = conf {
        let mut c = t.control.lock().await;
        c.command(&format!("SETCONF {conf}"))
            .await
            .map_err(|e| format!("couldn't give tor its bridges: {e}"))?;
        c.command("SETCONF DisableNetwork=0")
            .await
            .map_err(|e| format!("couldn't let tor reach the network: {e}"))?;
    }
    Ok(t)
}

/// A control string in quotes, with '\' and '"' escaped.
fn quoted(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The value of KEY=VALUE or KEY="VALUE" in a reply line.
fn field(line: &str, key: &str) -> Option<String> {
    let at = line.find(&format!("{key}="))? + key.len() + 1;
    let rest = &line[at..];
    match rest.strip_prefix('"') {
        Some(q) => {
            let mut out = String::new();
            let mut chars = q.chars();
            while let Some(c) = chars.next() {
                match c {
                    '"' => return Some(out),
                    '\\' => out.push(chars.next()?),
                    c => out.push(c),
                }
            }
            None
        }
        None => Some(rest.split(' ').next().unwrap_or("").to_string()),
    }
}

impl Control {
    /// One command and its reply's lines, without their status codes. An error reply is an Err.
    async fn command(&mut self, line: &str) -> Result<Vec<String>, String> {
        self.w
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        loop {
            let mut l = String::new();
            let n = timeout(ANSWER, (&mut self.r).take(LINE_MAX as u64).read_line(&mut l))
                .await
                .map_err(|_| "tor's control port stopped answering".to_string())?
                .map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("tor closed its control port".into());
            }
            let l = l.trim_end_matches(['\r', '\n']);
            if l.len() < 4 {
                return Err(format!("tor said something unexpected: {l:.80}"));
            }
            let (code, sep, text) = (&l[..3], l.as_bytes()[3], &l[4..]);
            if !code.starts_with('2') {
                return Err(format!("tor said: {text:.200}"));
            }
            // "250+KEY=": the value follows on its own lines, up to a ".".
            if sep == b'+' {
                let mut data = text.to_string();
                loop {
                    let mut d = String::new();
                    if (&mut self.r)
                        .take(LINE_MAX as u64)
                        .read_line(&mut d)
                        .await
                        .map_err(|e| e.to_string())?
                        == 0
                    {
                        return Err("tor closed its control port".into());
                    }
                    let d = d.trim_end_matches(['\r', '\n']);
                    if d == "." {
                        break;
                    }
                    data.push('\n');
                    data.push_str(d);
                }
                out.push(data);
                continue;
            }
            out.push(text.to_string());
            if sep == b' ' {
                return Ok(out);
            }
        }
    }
}

/// SAFECOOKIE's proof for one side: HMAC-SHA256 under the side's key, of the cookie and the
/// nonces.
fn safecookie_hash(key: &[u8], cookie: &[u8], client: &[u8], server: &[u8]) -> Vec<u8> {
    let k = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
    let mut c = aws_lc_rs::hmac::Context::with_key(&k);
    c.update(cookie);
    c.update(client);
    c.update(server);
    c.sign().as_ref().to_vec()
}

impl ExtTor {
    /// Logs in to the tor at `u.control` (with no password, its password, or its cookie, as it
    /// takes), and checks its SOCKS port answers.
    pub async fn connect(u: &TorUse) -> Result<Arc<ExtTor>, String> {
        let stream = timeout(ANSWER, TcpStream::connect(&u.control))
            .await
            .map_err(|_| format!("no tor answers at {}", u.control))?
            .map_err(|e| format!("no tor control port at {} ({e})", u.control))?;
        let (r, w) = stream.into_split();
        let mut c = Control { r: BufReader::new(r), w };
        let info = c.command("PROTOCOLINFO 1").await?;
        let auth = info.iter().find(|l| l.starts_with("AUTH ")).cloned().unwrap_or_default();
        let methods: Vec<String> = field(&auth, "METHODS").unwrap_or_default().split(',').map(String::from).collect();
        let has = |m: &str| methods.iter().any(|x| x == m);
        let cookie_file = field(&auth, "COOKIEFILE");
        if !u.password.is_empty() && has("HASHEDPASSWORD") {
            c.command(&format!("AUTHENTICATE {}", quoted(&u.password)))
                .await
                .map_err(|_| "tor's control password is wrong".to_string())?;
        } else if has("NULL") {
            c.command("AUTHENTICATE").await?;
        } else if let (true, Some(file)) = (has("SAFECOOKIE") || has("COOKIE"), cookie_file) {
            let cookie = std::fs::read(&file).map_err(|e| format!("can't read tor's cookie, {file} ({e})"))?;
            if has("SAFECOOKIE") {
                let mine: [u8; 32] = sodium::random_array();
                let reply = c.command(&format!("AUTHCHALLENGE SAFECOOKIE {}", hex::encode(&mine))).await?;
                let line = reply.first().cloned().unwrap_or_default();
                let theirs = field(&line, "SERVERNONCE")
                    .and_then(|h| hex::decode(&h))
                    .ok_or("tor's challenge is malformed")?;
                let proof = field(&line, "SERVERHASH")
                    .and_then(|h| hex::decode(&h))
                    .ok_or("tor's challenge is malformed")?;
                let expected = safecookie_hash(b"Tor safe cookie authentication server-to-controller hash", &cookie, &mine, &theirs);
                if !sodium::ct_eq(&proof, &expected) {
                    return Err("that isn't the tor whose cookie this is".into());
                }
                let ours = safecookie_hash(b"Tor safe cookie authentication controller-to-server hash", &cookie, &mine, &theirs);
                c.command(&format!("AUTHENTICATE {}", hex::encode(&ours))).await?;
            } else {
                c.command(&format!("AUTHENTICATE {}", hex::encode(&cookie))).await?;
            }
        } else if has("HASHEDPASSWORD") {
            return Err("tor's control port needs a password: /set torpassword".into());
        } else {
            return Err("tor's control port takes no way of logging in that chat knows".into());
        }
        let t = Arc::new(ExtTor {
            socks: u.socks.clone(),
            control: tokio::sync::Mutex::new(c),
            ready: AtomicBool::new(false),
            progress: std::sync::Mutex::new("asking".into()),
            child: std::sync::Mutex::new(None),
        });
        // Its SOCKS port, which every stream goes through.
        timeout(ANSWER, TcpStream::connect(&u.socks))
            .await
            .map_err(|_| format!("no tor SOCKS port answers at {}", u.socks))?
            .map_err(|e| format!("no tor SOCKS port at {} ({e})", u.socks))?;
        t.poll().await;
        let weak = Arc::downgrade(&t);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let Some(t) = weak.upgrade() else { return };
                t.poll().await;
            }
        });
        Ok(t)
    }

    /// Whether it has circuits, and how far it has got, for the network report.
    async fn poll(&self) {
        let r = self
            .control
            .lock()
            .await
            .command("GETINFO status/circuit-established status/bootstrap-phase")
            .await;
        let Ok(lines) = r else {
            self.ready.store(false, Ordering::Relaxed);
            *self.progress.lock().expect("progress") = "its control port closed".into();
            return;
        };
        let ready = lines.iter().any(|l| l == "status/circuit-established=1");
        self.ready.store(ready, Ordering::Relaxed);
        if let Some(p) = lines.iter().find_map(|l| l.strip_prefix("status/bootstrap-phase=")) {
            let summary = field(p, "SUMMARY").unwrap_or_else(|| p.to_string());
            let done = field(p, "PROGRESS").unwrap_or_default();
            *self.progress.lock().expect("progress") = format!("a running tor: {done}% - {summary}");
        }
    }

    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    pub fn progress(&self) -> String {
        self.progress.lock().expect("progress").clone()
    }

    /// A stream to host:port through the SOCKS port. Streams with the same `isolation` may share
    /// circuits; others never do.
    pub async fn stream(&self, host: &str, port: u16, isolation: &str) -> Result<TcpStream, String> {
        let mut s = timeout(ANSWER, TcpStream::connect(&self.socks))
            .await
            .map_err(|_| "tor's SOCKS port didn't answer".to_string())?
            .map_err(|e| format!("tor's SOCKS port: {e}"))?;
        let io = |e: std::io::Error| format!("tor's SOCKS port: {e}");
        // SOCKS5, with a user name and password: the isolation, as tor reads them.
        s.write_all(&[5, 1, 2]).await.map_err(io)?;
        let mut two = [0u8; 2];
        s.read_exact(&mut two).await.map_err(io)?;
        if two != [5, 2] {
            return Err("tor's SOCKS port won't isolate streams".into());
        }
        let user = isolation.as_bytes();
        let mut auth = vec![1, user.len() as u8];
        auth.extend_from_slice(user);
        auth.extend_from_slice(&[1, b'x']);
        s.write_all(&auth).await.map_err(io)?;
        s.read_exact(&mut two).await.map_err(io)?;
        if two[1] != 0 {
            return Err("tor's SOCKS port refused us".into());
        }
        let host_b = host.as_bytes();
        if host_b.len() > 255 {
            return Err("that name is too long".into());
        }
        let mut req = vec![5, 1, 0, 3, host_b.len() as u8];
        req.extend_from_slice(host_b);
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).await.map_err(io)?;
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.map_err(io)?;
        if head[1] != 0 {
            return Err(match head[1] {
                4 => "its host can't be reached".into(),
                5 => "it refused the connection".into(),
                6 => "it timed out".into(),
                n => format!("tor couldn't connect (SOCKS error {n})"),
            });
        }
        // The address it's bound to, which isn't used.
        let skip = match head[3] {
            1 => 4,
            4 => 16,
            3 => {
                let mut n = [0u8; 1];
                s.read_exact(&mut n).await.map_err(io)?;
                usize::from(n[0])
            }
            _ => return Err("tor's SOCKS port answered something unexpected".into()),
        };
        let mut rest = vec![0u8; skip + 2];
        s.read_exact(&mut rest).await.map_err(io)?;
        Ok(s)
    }

    /// Hosts an onion service on its port `vport`, with this expanded ed25519 key (or a new one),
    /// whose streams come to the listener returned. Its address (without ".onion") too.
    pub async fn add_onion(&self, key: Option<&[u8; 64]>, vport: u16) -> Result<(String, TcpListener), String> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("can't listen for tor: {e}"))?;
        let local = listener.local_addr().map_err(|e| e.to_string())?.port();
        let key = match key {
            Some(k) => zeroize::Zeroizing::new(format!("ED25519-V3:{}", base64::encode(k))),
            None => zeroize::Zeroizing::new("NEW:ED25519-V3 Flags=DiscardPK".into()),
        };
        let reply = self
            .control
            .lock()
            .await
            .command(&format!("ADD_ONION {} Port={vport},127.0.0.1:{local}", key.as_str()))
            .await?;
        let id = reply
            .iter()
            .find_map(|l| l.strip_prefix("ServiceID="))
            .ok_or("tor didn't say the service's address")?;
        Ok((id.to_string(), listener))
    }

    pub async fn del_onion(&self, id: &str) {
        let _ = self.control.lock().await.command(&format!("DEL_ONION {id}")).await;
    }

    /// New circuits for new streams.
    pub async fn newnym(&self) {
        let _ = self.control.lock().await.command("SIGNAL NEWNYM").await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_reply_fields() {
        let auth = r#"AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/run/tor/control.authcookie""#;
        assert_eq!(field(auth, "METHODS").as_deref(), Some("COOKIE,SAFECOOKIE"));
        assert_eq!(field(auth, "COOKIEFILE").as_deref(), Some("/run/tor/control.authcookie"));
        assert_eq!(field(r#"X="a \"b\" c""#, "X").as_deref(), Some(r#"a "b" c"#));
        assert_eq!(quoted(r#"p"w\d"#), r#""p\"w\\d""#);
        // 16:, then the salt, the count byte and SHA-1's 20 bytes, in hex.
        let h = hash_password("secret", [1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(h.starts_with("16:010203040506070860") && h.len() == 3 + 2 * 29, "{h}");
        assert_eq!(h, hash_password("secret", [1, 2, 3, 4, 5, 6, 7, 8]));
        assert_ne!(h, hash_password("secret!", [1, 2, 3, 4, 5, 6, 7, 8]));
    }
}
