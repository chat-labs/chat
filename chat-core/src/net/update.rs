// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Updating chat from its GitHub releases: the newest release (with betas, the newest of any), its
//! SHA256SUMS, signed offline with the release key, and this system's binary, checked against it,
//! put in place of the running executable. curl downloads, through Tor when a proxy is given.
//!
//! On Linux with the sandbox up chat can't replace itself, so just before the sandbox goes up an
//! interface starts the updater ([`helper_start`]): chat again, as a second process outside the
//! sandbox, with a sandbox of its own (it writes only in the executable's folder, and runs only
//! curl), which runs each update chat asks for and reports its progress back.

use crate::protocol::crypto::minisign;
use crate::protocol::crypto::sodium;
use crate::protocol::files::format_size;
use crate::protocol::hex;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Read, Write};
/// The updater is only on Linux: elsewhere no link is ever made, and this only gives it a type.
#[cfg(not(unix))]
use std::net::TcpStream as Link;
#[cfg(unix)]
use std::os::unix::net::UnixStream as Link;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const REPO: &str = "chat-labs/chat";
/// The most a download may be, and how long curl gets for one.
const MAX_BYTES: u64 = 64 << 20;
const FETCH_TIMEOUT_S: &str = "300";
/// What the release's JSON, its SHA256SUMS and the signature of that are read up to.
const RELEASE_JSON_MAX: u64 = 1 << 20;
const SUMS_MAX: u64 = 1 << 16;
const SIG_MAX: u64 = 4096;
const TAG_MAX: usize = 39;
/// The console keeps this many lines, each at most LINE_MAX bytes.
const LOG_MAX: usize = 24;
const LINE_MAX: usize = 159;

/// chat started with this alone is the updater; the process list shows it as HELPER_NAME.
pub const HELPER_ARG: &str = "--updater";
#[cfg(target_os = "linux")]
const HELPER_NAME: &str = "chat-updater";
#[cfg(target_os = "linux")]
const HELPER_STOP: std::time::Duration = std::time::Duration::from_secs(1);
/// The longest line on the link between chat and the updater.
const LINK_LINE_MAX: u64 = 1 << 16;

/// Where each step puts the bar, in thousandths. The download moves it from DOWNLOAD to
/// DOWNLOADED.
const AT_CHECKING: u32 = 0;
const AT_FOUND: u32 = 100;
const AT_SIGNATURE: u32 = 130;
const AT_DOWNLOAD: u32 = 200;
const AT_DOWNLOADED: u32 = 900;
const AT_VERIFYING: u32 = 920;
const AT_INSTALLING: u32 = 960;
const AT_DONE: u32 = 1000;

/// A line in the console: a detail faint, then plain, good green, bad red.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LineKind {
    Detail,
    Info,
    Good,
    Bad,
}

/// An update's progress, for its box: what it has done so far (the console, oldest first), how far
/// along it is in thousandths, how much has downloaded ("8.4 MB of 20.1 MB", else ""), and the
/// current step.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct View {
    /// A run since chat began; the rest is about the last one.
    pub started: bool,
    pub running: bool,
    /// Finished: installed, or already up to date.
    pub ok: bool,
    pub permille: u32,
    pub amount: String,
    pub step: String,
    pub log: Vec<(LineKind, String)>,
    /// The download on its way, and its size as GitHub gives it: curl writes straight to the file,
    /// so its size is the progress.
    dl_path: Option<PathBuf>,
    dl_total: u64,
}

impl View {
    const fn new() -> View {
        View {
            started: false,
            running: false,
            ok: false,
            permille: 0,
            amount: String::new(),
            step: String::new(),
            log: Vec::new(),
            dl_path: None,
            dl_total: 0,
        }
    }
}

const IDLE: u8 = 0;
const RUNNING: u8 = 1;
const DONE: u8 = 2;
static STATE: AtomicU8 = AtomicU8::new(IDLE);
static VIEW: Mutex<View> = Mutex::new(View::new());
/// The last run's result: whether it succeeded, and what it said.
static RESULT: Mutex<(bool, String)> = Mutex::new((false, String::new()));
/// In the updater: where its reports go.
static REPORT: Mutex<Option<Link>> = Mutex::new(None);
/// In chat: the updater, and the link to it.
static HELPER: Mutex<Option<Helper>> = Mutex::new(None);
/// The updater setting was turned off during an update, so it stops once that's done.
static HELPER_OFF: AtomicBool = AtomicBool::new(false);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What chat asks the updater for, and what the updater sends back after each step.
#[derive(Serialize, Deserialize)]
struct Ask {
    betas: bool,
    proxy: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Report {
    view: View,
    done: bool,
    ok: bool,
    msg: String,
}

fn report(done: bool) {
    let mut link = lock(&REPORT);
    let Some(l) = link.as_mut() else { return };
    let (ok, msg) = lock(&RESULT).clone();
    let r = Report {
        view: lock(&VIEW).clone(),
        done,
        ok,
        msg,
    };
    if let Ok(mut line) = serde_json::to_vec(&r) {
        line.push(b'\n');
        let _ = l.write_all(&line);
    }
}

fn view_reset() {
    *lock(&VIEW) = View {
        started: true,
        running: true,
        ..View::new()
    };
}

fn cut(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut at = max;
        while !s.is_char_boundary(at) {
            at -= 1;
        }
        s.truncate(at);
    }
    s
}

/// A line in the console. The oldest goes once it's full.
fn say(kind: LineKind, line: impl Into<String>) {
    {
        let mut v = lock(&VIEW);
        if v.log.len() == LOG_MAX {
            v.log.remove(0);
        }
        v.log.push((kind, cut(line.into(), LINE_MAX)));
    }
    report(false);
}

/// The current step, and how far along it is.
fn stage(permille: u32, step: impl Into<String>) {
    {
        let mut v = lock(&VIEW);
        v.permille = permille;
        v.step = step.into();
    }
    report(false);
}

fn downloading(path: Option<&Path>, total: u64) {
    {
        let mut v = lock(&VIEW);
        v.dl_path = path.map(Path::to_path_buf);
        v.dl_total = total;
    }
    report(false);
}

/// A copy of the current (or last) update's progress.
pub fn view() -> View {
    let mut v = lock(&VIEW).clone();
    let Some(path) = v.dl_path.as_ref().filter(|_| v.running) else {
        return v;
    };
    let got = std::fs::metadata(path).map_or(0, |m| m.len());
    if v.dl_total > 0 {
        let got = got.min(v.dl_total);
        v.permille = AT_DOWNLOAD + ((AT_DOWNLOADED - AT_DOWNLOAD) as u64 * got / v.dl_total) as u32;
        v.amount = format!("{} of {}", format_size(got), format_size(v.dl_total));
    } else {
        v.amount = format!("{} so far", format_size(got));
    }
    v
}

/// The message goes to the console and into the box. A failure replaces the step it failed at,
/// and leaves the bar where it stopped.
fn finish(ok: bool, msg: String) {
    say(if ok { LineKind::Good } else { LineKind::Bad }, msg.clone());
    *lock(&RESULT) = (ok, msg);
    {
        let mut v = lock(&VIEW);
        v.dl_path = None;
        v.dl_total = 0;
        if ok {
            v.permille = AT_DONE;
        } else {
            v.step = "Update failed".into();
        }
        v.ok = ok;
        v.running = false;
    }
    report(true);
    STATE.store(DONE, Ordering::Release);
}

/// This system's release binary, if releases are built for it.
fn asset() -> Option<String> {
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        return None;
    };
    Some(if cfg!(windows) {
        format!("chat-windows-{arch}.exe")
    } else if cfg!(target_os = "macos") {
        format!("chat-macos-{arch}")
    } else {
        format!("chat-linux-{arch}")
    })
}

/// The running executable: where it is now, even after it's been replaced.
fn exe_path() -> Option<PathBuf> {
    let p = std::env::current_exe().ok()?;
    // The kernel adds " (deleted)" once the file chat started from is replaced.
    let s = p.to_string_lossy();
    Some(match s.strip_suffix(" (deleted)") {
        Some(rest) => PathBuf::from(rest),
        None => p,
    })
}

fn with_suffix(p: &Path, suffix: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn fetch(url: &str, out: &Path, api: bool, proxy: Option<&str>) -> bool {
    let Some(curl) = super::bridges::find_program("curl") else {
        return false;
    };
    let mut c = Command::new(curl);
    // -q must come first: it stops curl reading a .curlrc that could turn off TLS checks or add a
    // proxy. --socks5-hostname leaves name lookups to the proxy, so Tor resolves GitHub, not local DNS.
    c.args([
        "-q",
        "-fsL",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "--max-time",
    ])
    .arg(FETCH_TIMEOUT_S)
    .arg("--max-filesize")
    .arg(MAX_BYTES.to_string())
    .arg("-H")
    .arg(if api {
        "Accept: application/vnd.github+json"
    } else {
        "Accept: application/octet-stream"
    })
    .arg("-o")
    .arg(out)
    .arg(url);
    if let Some(p) = proxy {
        // Made-up SOCKS credentials give each download circuits of its own, so the exit can't tie
        // one download to another, or to chat's own streams.
        let user = format!("{}:x", hex::encode(&sodium::random_array::<8>()));
        c.args(["--socks5-hostname", p, "--proxy-user", &user]);
    }
    c.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn slurp(path: &Path, max: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    std::fs::File::open(path).ok()?.take(max).read_to_end(&mut out).ok()?;
    Some(out)
}

fn skip_ws(s: &[u8], mut i: usize) -> usize {
    while i < s.len() && s[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    hay.get(from..)?.windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

/// The release's tag, from GitHub's JSON: letters, digits and . - _ only.
fn parse_tag(json: &[u8]) -> Option<String> {
    let key = b"\"tag_name\"";
    let mut i = skip_ws(json, find(json, key, 0)? + key.len());
    if json.get(i) != Some(&b':') {
        return None;
    }
    i = skip_ws(json, i + 1);
    if json.get(i) != Some(&b'"') {
        return None;
    }
    let rest = &json[i + 1..];
    let end = rest.iter().position(|&b| b == b'"')?;
    let tag = &rest[..end];
    let ok = !tag.is_empty() && tag.len() <= TAG_MAX && tag.iter().all(|&b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    ok.then(|| String::from_utf8_lossy(tag).into_owned())
}

/// A version's numbers, and its beta's number ("0.5.0-beta.2" is 2), or i64::MAX for a release,
/// which comes after its betas.
fn parse_version(s: &str) -> ([i64; 3], i64) {
    let s = s.strip_prefix(['v', 'V']).unwrap_or(s).as_bytes();
    let mut v = [0i64; 3];
    let mut i = 0;
    for slot in &mut v {
        let start = i;
        while i < s.len() && s[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            break;
        }
        *slot = std::str::from_utf8(&s[start..i])
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(i64::MAX);
        if s.get(i) != Some(&b'.') {
            break;
        }
        i += 1;
    }
    if s.get(i) != Some(&b'-') {
        return (v, i64::MAX);
    }
    let rest = std::str::from_utf8(&s[i..]).unwrap_or("");
    let n = rest.rsplit_once('.').map_or(0, |(_, n)| {
        let digits: String = n.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<i64>().unwrap_or(0)
    });
    (v, if n > 0 && n < i64::MAX { n } else { 1 })
}

fn version_newer(remote: &str, local: &str) -> bool {
    let (r, rb) = parse_version(remote);
    let (l, lb) = parse_version(local);
    (r, rb) > (l, lb)
}

/// name's SHA-256 in a SHA256SUMS ("HASH  NAME" or "HASH *NAME" lines).
fn sums_lookup(sums: &[u8], name: &str) -> Option<[u8; 32]> {
    for line in sums.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.len() < 66 || !matches!(line[64], b' ' | b'\t') {
            continue;
        }
        let mut f = &line[65..];
        if let [b' ' | b'*', rest @ ..] = f {
            f = rest;
        }
        if f == name.as_bytes() {
            return hex::decode_array(std::str::from_utf8(&line[..64]).ok()?);
        }
    }
    None
}

/// The size GitHub gives for the release file called name, or 0 if it isn't there. It's only for
/// the progress bar: the file is checked by the signed SHA-256.
fn asset_size(json: &[u8], name: &str) -> u64 {
    let want = format!("\"{name}\"");
    let mut from = 0;
    while let Some(p) = find(json, want.as_bytes(), from) {
        from = p + want.len();
        // As the value of a "name": a download URL ends in the name too, and a label may be it.
        let mut k = p;
        while k > 0 && json[k - 1].is_ascii_whitespace() {
            k -= 1;
        }
        if k == 0 || json[k - 1] != b':' {
            continue;
        }
        k -= 1;
        while k > 0 && json[k - 1].is_ascii_whitespace() {
            k -= 1;
        }
        if k < 6 || &json[k - 6..k] != b"\"name\"" {
            continue;
        }
        let Some(s) = find(json, b"\"size\"", p) else { return 0 };
        let mut i = skip_ws(json, s + 6);
        if json.get(i) != Some(&b':') {
            return 0;
        }
        i = skip_ws(json, i + 1);
        let digits: Vec<u8> = json[i..].iter().take_while(|b| b.is_ascii_digit()).copied().collect();
        let v: u64 = std::str::from_utf8(&digits).ok().and_then(|d| d.parse().ok()).unwrap_or(0);
        return if v <= MAX_BYTES { v } else { 0 };
    }
    0
}

/// SHA256SUMS signed with the release key or its backup, for this tag: the trusted comment must be
/// "chat TAG", so an older release's signed SHA256SUMS can't pass for a newer one's.
fn signed(sums: &[u8], sig: &str, tag: &str) -> bool {
    let trusted = format!("chat {tag}");
    [minisign::RELEASE_KEY, minisign::RELEASE_BACKUP_KEY]
        .iter()
        .filter_map(|k| minisign::PublicKey::from_base64(k))
        .any(|k| k.verify_minisig(sums, sig, &trusted))
}

fn hash_file(path: &Path) -> Option<([u8; 32], u64)> {
    hash_stream(std::fs::File::open(path).ok()?)
}

/// This program's build, as peers are told it ("v"). Read the first time it's asked for, which an
/// interface does as it starts, before an update can replace the file.
pub fn self_build() -> Option<&'static crate::protocol::session::Build> {
    static BUILD: std::sync::OnceLock<Option<crate::protocol::session::Build>> = std::sync::OnceLock::new();
    BUILD.get_or_init(read_self_build).as_ref()
}

fn read_self_build() -> Option<crate::protocol::session::Build> {
    use std::io::{Seek, SeekFrom};
    /// What a release appends to each binary: its signed list, then the list's length in
    /// LEN_DIGITS digits and MAGIC.
    const MAGIC: &[u8] = b"CHATBLD1";
    const LEN_DIGITS: usize = 8;
    const FOOTER: u64 = (LEN_DIGITS + MAGIC.len()) as u64;
    const LIST_MAX: u64 = 1024;
    // The file this process was started from, even if an update has replaced it since.
    #[cfg(target_os = "linux")]
    let mut f = std::fs::File::open("/proc/self/exe").ok()?;
    #[cfg(not(target_os = "linux"))]
    let mut f = std::fs::File::open(exe_path()?).ok()?;
    let size = f.metadata().ok()?.len();
    let mut b = crate::protocol::session::Build {
        version: VERSION.to_string(),
        ..Default::default()
    };
    let mut core = size;
    let mut foot = [0u8; FOOTER as usize];
    if size > FOOTER
        && f.seek(SeekFrom::Start(size - FOOTER)).is_ok()
        && f.read_exact(&mut foot).is_ok()
        && &foot[LEN_DIGITS..] == MAGIC
        && foot[..LEN_DIGITS].iter().all(u8::is_ascii_digit)
        && let Some(len) = std::str::from_utf8(&foot[..LEN_DIGITS]).ok().and_then(|d| d.parse::<u64>().ok())
        && len > 0
        && len <= LIST_MAX
        && len <= size - FOOTER
    {
        // The hash doesn't include the list, since the list can't contain its own hash.
        core = size - FOOTER - len;
        let mut text = vec![0u8; len as usize];
        if f.seek(SeekFrom::Start(core)).is_ok()
            && f.read_exact(&mut text).is_ok()
            && let Some((list, sig)) = parse_build_list(&text)
        {
            (b.list, b.list_sig) = (list, sig);
        }
    }
    f.seek(SeekFrom::Start(0)).ok()?;
    let (hash, hashed) = hash_stream(f.take(core))?;
    (hashed == core).then_some(())?;
    b.hash = hash;
    Some(b)
}

/// A release's list: "chat vVERSION", each binary's hash as sha256sum writes it, then the signature
/// line, a line each. Only one for this version: the hashes comma-separated, and the signature.
fn parse_build_list(text: &[u8]) -> Option<(String, String)> {
    /// At most 3 hashes, which keeps "v" inside one normal sized frame; a signature line's length.
    const HASHES_MAX: usize = 3;
    const SIG_LINE_LEN: usize = 100;
    let text = std::str::from_utf8(text).ok()?.strip_suffix('\n')?;
    let lines: Vec<&str> = text.split('\n').collect();
    let (first, rest) = lines.split_first()?;
    let (sig, hashes) = rest.split_last()?;
    let hex_ok = |h: &&str| h.len() == 64 && h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    (*first == format!("chat v{VERSION}")
        && sig.len() == SIG_LINE_LEN
        && !hashes.is_empty()
        && hashes.len() <= HASHES_MAX
        && hashes.iter().all(hex_ok))
    .then(|| (hashes.join(","), sig.to_string()))
}

fn hash_stream(mut f: impl Read) -> Option<([u8; 32], u64)> {
    let mut h = sodium::Sha256::new();
    let mut buf = vec![0u8; 16384];
    let mut total = 0u64;
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                h.update(&buf[..n]);
                total += n as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some((h.finish(), total))
}

/// The new executable in place of the old, runnable as the old was.
#[cfg(unix)]
fn replace_exe(new: &Path, exe: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(exe).map_or(0o755, |m| m.permissions().mode() & 0o777);
    std::fs::set_permissions(new, std::fs::Permissions::from_mode(mode | 0o100))?;
    std::fs::rename(new, exe)
}

/// A running executable can be renamed but not overwritten: it goes to .old, which the next start
/// deletes ([`cleanup_stale`]).
#[cfg(windows)]
fn replace_exe(new: &Path, exe: &Path) -> std::io::Result<()> {
    let old = with_suffix(exe, ".old");
    let _ = std::fs::remove_file(&old);
    std::fs::rename(exe, &old)?;
    std::fs::rename(new, exe).inspect_err(|_| {
        let _ = std::fs::rename(&old, exe);
    })
}

/// A URL without its "https://", as the console shows it.
fn shown(url: &str) -> &str {
    url.strip_prefix("https://").unwrap_or(url)
}

/// The update, step by step: Ok with what it did, or Err with why it stopped.
fn check(betas: bool, proxy: Option<&str>) -> Result<String, String> {
    stage(
        AT_CHECKING,
        format!("Checking GitHub for a newer release{}", if betas { " or beta" } else { "" }),
    );
    let asset = asset().ok_or("no release builds exist for this CPU architecture")?;
    let exe = exe_path().ok_or("could not locate the running executable")?;
    let (tmp_json, tmp_sums, tmp_sig, tmp_bin) = (
        with_suffix(&exe, ".release"),
        with_suffix(&exe, ".sums"),
        with_suffix(&exe, ".sums.minisig"),
        with_suffix(&exe, ".download"),
    );

    say(LineKind::Info, format!("this is v{VERSION}, {asset}"));
    if let Some(p) = proxy {
        say(LineKind::Detail, format!("downloads go through Tor ({p})"));
    }
    // GitHub's latest release is never a pre-release, so betas come from the list, newest first.
    let url = format!(
        "https://api.github.com/repos/{REPO}/releases{}",
        if betas { "?per_page=1" } else { "/latest" }
    );
    say(LineKind::Detail, format!("GET {}", shown(&url)));
    let got = fetch(&url, &tmp_json, true, proxy);
    let json = got.then(|| slurp(&tmp_json, RELEASE_JSON_MAX)).flatten();
    let _ = std::fs::remove_file(&tmp_json);
    if !got {
        return Err(format!(
            "could not reach GitHub (is curl installed, and is {}'s folder writable?)",
            exe.display()
        ));
    }
    let json = json.unwrap_or_default();
    let tag = parse_tag(&json).ok_or("GitHub's reply had no usable release tag")?;
    let total = asset_size(&json, &asset);
    say(
        LineKind::Info,
        if betas {
            format!("newest release, betas included, is {tag}")
        } else {
            format!("latest release is {tag}")
        },
    );
    if !version_newer(&tag, VERSION) {
        stage(AT_DONE, "Already up to date");
        return Ok(if betas {
            format!("already up to date (v{VERSION}, newest with betas is {tag})")
        } else {
            format!("already up to date (v{VERSION}, latest is {tag})")
        });
    }
    stage(AT_FOUND, format!("Release {tag} found"));

    let base = format!("https://github.com/{REPO}/releases/download/{tag}");
    let url = format!("{base}/SHA256SUMS");
    say(LineKind::Detail, format!("GET {}", shown(&url)));
    let got = fetch(&url, &tmp_sums, false, proxy);
    let sums = got.then(|| slurp(&tmp_sums, SUMS_MAX)).flatten();
    let _ = std::fs::remove_file(&tmp_sums);
    if !got {
        return Err(format!("release {tag} has no SHA256SUMS - refusing to install it"));
    }

    // SHA256SUMS comes from the same place as the binary, so on its own it only catches
    // corruption. The signature, made offline with the release key, is what vouches for it.
    stage(AT_SIGNATURE, format!("Checking {tag}'s signature"));
    let url = format!("{base}/SHA256SUMS.minisig");
    say(LineKind::Detail, format!("GET {}", shown(&url)));
    let sig = fetch(&url, &tmp_sig, false, proxy)
        .then(|| slurp(&tmp_sig, SIG_MAX))
        .flatten()
        .map(|s| String::from_utf8_lossy(&s).into_owned());
    let _ = std::fs::remove_file(&tmp_sig);
    let sums = match (sums, sig) {
        (Some(sums), Some(sig)) if signed(&sums, &sig, &tag) => sums,
        _ => return Err(format!("release {tag} has no valid release-key signature - refusing to install it")),
    };
    say(LineKind::Good, format!("SHA256SUMS is signed by the release key, for {tag}"));

    let want = sums_lookup(&sums, &asset).ok_or_else(|| format!("SHA256SUMS lists no {asset} for {tag} - nothing installed"))?;
    say(LineKind::Detail, format!("expecting SHA-256 {:.16}...", hex::encode(&want)));

    stage(AT_DOWNLOAD, format!("Downloading {tag}"));
    let url = format!("{base}/{asset}");
    if total > 0 {
        say(LineKind::Detail, format!("GET {} ({})", shown(&url), format_size(total)));
    } else {
        say(LineKind::Detail, format!("GET {}", shown(&url)));
    }
    downloading(Some(&tmp_bin), total);
    let got = fetch(&url, &tmp_bin, false, proxy);
    downloading(None, 0);
    if !got {
        let _ = std::fs::remove_file(&tmp_bin);
        return Err(format!("downloading {asset} from {tag} failed - nothing installed"));
    }
    stage(AT_VERIFYING, "Verifying the download");
    match hash_file(&tmp_bin) {
        Some((h, size)) if size > 0 && sodium::ct_eq(&h, &want) => {
            say(
                LineKind::Good,
                format!("downloaded {}; its SHA-256 matches SHA256SUMS", format_size(size)),
            );
        }
        _ => {
            let _ = std::fs::remove_file(&tmp_bin);
            return Err(format!(
                "SHA-256 of the {tag} download does NOT match SHA256SUMS - discarded, nothing installed"
            ));
        }
    }

    stage(AT_INSTALLING, format!("Installing {tag}"));
    say(LineKind::Detail, format!("replacing {}", exe.display()));
    if replace_exe(&tmp_bin, &exe).is_err() {
        let _ = std::fs::remove_file(&tmp_bin);
        return Err(format!("verified {tag} but could not replace the executable (permissions?)"));
    }
    stage(AT_DONE, format!("Installed {tag} - restart chat to run it"));
    Ok(format!("installed {tag} (signature and SHA-256 verified) - restart chat to run it"))
}

fn check_and_finish(betas: bool, proxy: Option<&str>) {
    sodium::init();
    match check(betas, proxy) {
        Ok(msg) => finish(true, msg),
        Err(msg) => finish(false, msg),
    }
}

/// Runs an update here, to its end: whether it succeeded (installed, or already up to date), and
/// what it said. `proxy`: a SOCKS5 proxy (host:port) to download through.
pub fn run(betas: bool, proxy: Option<&str>) -> (bool, String) {
    view_reset();
    *lock(&RESULT) = (false, String::new());
    check_and_finish(betas, proxy);
    STATE.store(IDLE, Ordering::Release);
    lock(&RESULT).clone()
}

/// Starts an update on a thread of its own, in the updater if it's running: false if one is
/// running already.
pub fn start(betas: bool, proxy: Option<String>) -> bool {
    if STATE.compare_exchange(IDLE, RUNNING, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return false;
    }
    *lock(&RESULT) = (false, String::new());
    view_reset();
    let relayed = helper_running();
    let spawned = std::thread::Builder::new().name("update".into()).spawn(move || {
        if relayed {
            relay(betas, proxy);
        } else {
            check_and_finish(betas, proxy.as_deref());
        }
    });
    if spawned.is_err() {
        lock(&VIEW).running = false;
        STATE.store(IDLE, Ordering::Release);
        return false;
    }
    true
}

/// The update's result once it has finished, once: whether it succeeded, and what it said.
pub fn poll() -> Option<(bool, String)> {
    if STATE.compare_exchange(DONE, IDLE, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return None;
    }
    if HELPER_OFF.load(Ordering::Acquire) {
        helper_stop();
    }
    Some(lock(&RESULT).clone())
}

/// What an earlier update left next to the executable.
pub fn cleanup_stale() {
    if let Some(exe) = exe_path() {
        let _ = std::fs::remove_file(with_suffix(&exe, ".old"));
    }
}

// ---- downloading through chat's Tor ----

/// A SOCKS5 proxy on 127.0.0.1 into chat's Tor, for curl while an update runs: each connection on
/// circuits of its own, and only to a name, which Tor resolves. Dropping it closes it, and the
/// connections through it.
pub struct TorProxy {
    pub addr: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TorProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn tor_proxy(tor: Arc<super::tor::Tor>) -> std::io::Result<TorProxy> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    let task = tokio::spawn(async move {
        let mut conns = tokio::task::JoinSet::new();
        while let Ok((c, _)) = listener.accept().await {
            while conns.try_join_next().is_some() {}
            let tor = tor.clone();
            conns.spawn(socks(c, move |host: String, port| async move {
                tor.connect_isolated(&host, port).await
            }));
        }
    });
    Ok(TorProxy { addr, task })
}

/// One SOCKS5 connection: no authentication, or a username and password, which curl makes up (see
/// `fetch`) and aren't checked, then a CONNECT to a name and port.
async fn socks<C, S, F, Fut>(mut c: C, connect: F)
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    F: FnOnce(String, u16) -> Fut,
    Fut: std::future::Future<Output = Result<S, String>>,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let reply = |code: u8| [5, code, 0, 1, 0, 0, 0, 0, 0, 0];
    let mut head = [0u8; 2];
    if c.read_exact(&mut head).await.is_err() || head[0] != 5 {
        return;
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    if c.read_exact(&mut methods).await.is_err() {
        return;
    }
    let method = [2u8, 0].into_iter().find(|m| methods.contains(m)).unwrap_or(0xff);
    if c.write_all(&[5, method]).await.is_err() || method == 0xff {
        return;
    }
    if method == 2 {
        // Version and the username's length, then the username and the password's length.
        let mut b = [0u8; 2];
        if c.read_exact(&mut b).await.is_err() {
            return;
        }
        let mut user = vec![0u8; usize::from(b[1]) + 1];
        if c.read_exact(&mut user).await.is_err() {
            return;
        }
        let mut pass = vec![0u8; usize::from(user[usize::from(b[1])])];
        if c.read_exact(&mut pass).await.is_err() || c.write_all(&[1, 0]).await.is_err() {
            return;
        }
    }
    let mut req = [0u8; 5];
    if c.read_exact(&mut req).await.is_err() {
        return;
    }
    if req[0] != 5 || req[1] != 1 || req[3] != 3 {
        // Only CONNECT (else 7), and only to a name (else 8).
        let _ = c.write_all(&reply(if req[1] != 1 { 7 } else { 8 })).await;
        return;
    }
    let mut rest = vec![0u8; usize::from(req[4]) + 2];
    if c.read_exact(&mut rest).await.is_err() {
        return;
    }
    let (name, port) = rest.split_at(usize::from(req[4]));
    let Ok(host) = std::str::from_utf8(name) else { return };
    match connect(host.to_string(), u16::from_be_bytes([port[0], port[1]])).await {
        Ok(mut s) => {
            if c.write_all(&reply(0)).await.is_ok() {
                let _ = tokio::io::copy_bidirectional(&mut c, &mut s).await;
            }
        }
        Err(_) => {
            let _ = c.write_all(&reply(4)).await;
        }
    }
}

// ---- the updater, outside chat's sandbox (Linux) ----

struct Helper {
    child: std::process::Child,
    link: Link,
}

/// A line from the link, at most LINK_LINE_MAX long; None at its end.
fn read_line(r: &mut impl BufRead) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    r.take(LINK_LINE_MAX).read_until(b'\n', &mut line).ok()?;
    line.ends_with(b"\n").then_some(line)
}

/// The update runs in the updater, and its progress shows here as if it ran in chat.
fn relay(betas: bool, proxy: Option<String>) {
    let link = lock(&HELPER).as_ref().and_then(|h| h.link.try_clone().ok());
    if let Some(mut link) = link
        && let Ok(mut ask) = serde_json::to_vec(&Ask { betas, proxy })
    {
        ask.push(b'\n');
        if link.write_all(&ask).is_ok() {
            let mut r = std::io::BufReader::new(link);
            while let Some(line) = read_line(&mut r) {
                let Ok(mut rep) = serde_json::from_slice::<Report>(&line) else {
                    break;
                };
                let n = rep.view.log.len();
                rep.view.log.drain(..n.saturating_sub(LOG_MAX));
                for l in &mut rep.view.log {
                    l.1 = cut(std::mem::take(&mut l.1), LINE_MAX);
                }
                *lock(&VIEW) = rep.view;
                if rep.done {
                    *lock(&RESULT) = (rep.ok, rep.msg);
                    STATE.store(DONE, Ordering::Release);
                    return;
                }
            }
        }
    }
    helper_stop();
    finish(false, "the updater has stopped - quit chat and run chat --update".into());
}

/// Just before the sandbox goes up: chat starts itself again as the updater, which the sandbox
/// doesn't cover, so an update can still replace chat. It holds none of chat's data.
pub fn helper_start() {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let Ok((ours, theirs)) = Link::pair() else {
            return;
        };
        // The file this process started from, even if it has been replaced since: the same build.
        let child = Command::new("/proc/self/exe")
            .arg0(HELPER_NAME)
            .arg(HELPER_ARG)
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // Not in the terminal's process group, so Ctrl+C there doesn't reach it.
            .process_group(0)
            .spawn();
        if let Ok(child) = child {
            *lock(&HELPER) = Some(Helper { child, link: ours });
        }
    }
}

/// Stops the updater: its link closes, and it's killed if it hasn't gone a second later.
pub fn helper_stop() {
    let Some(mut h) = lock(&HELPER).take() else { return };
    let _ = h.link.shutdown(std::net::Shutdown::Both);
    #[cfg(target_os = "linux")]
    {
        let until = std::time::Instant::now() + HELPER_STOP;
        while std::time::Instant::now() < until {
            if h.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    let _ = h.child.kill();
    let _ = h.child.wait();
}

pub fn helper_running() -> bool {
    lock(&HELPER).is_some()
}

/// The updater setting: off stops it now, or once the update it's running is done; on keeps it.
pub fn helper_enable(on: bool) {
    HELPER_OFF.store(!on, Ordering::Release);
    if !on && STATE.load(Ordering::Acquire) != RUNNING {
        helper_stop();
    }
}

/// A bug in chat could be what's asking, so the proxy can only be a host and port.
#[cfg(any(target_os = "linux", test))]
fn ask_ok(a: &Ask) -> bool {
    a.proxy
        .as_ref()
        .is_none_or(|p| !p.is_empty() && p.len() < 64 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b)))
}

/// The updater (chat started as `chat --updater` by [`helper_start`]): sandboxes itself to write
/// only in the executable's folder and run only curl, then runs each update chat asks for, until
/// chat goes. None if this isn't the updater (its stdin isn't chat's link).
pub fn helper() -> Option<i32> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::FromRawFd;
        let mut kind: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: getsockopt writes at most len bytes into kind.
        let rc = unsafe { libc::getsockopt(0, libc::SOL_SOCKET, libc::SO_TYPE, (&mut kind as *mut libc::c_int).cast(), &mut len) };
        if rc != 0 || kind != libc::SOCK_STREAM {
            return None;
        }
        // SAFETY: a name of at most 15 bytes and its NUL.
        unsafe { libc::prctl(libc::PR_SET_NAME, c"chat-updater".as_ptr(), 0, 0, 0) };
        let dir = exe_path().and_then(|e| e.parent().map(Path::to_path_buf));
        let Some(dir) = dir else { return Some(1) };
        let curl: Vec<PathBuf> = super::bridges::find_program("curl").into_iter().collect();
        let _ = super::sandbox::up_only(&curl, &[dir]);
        // SAFETY: fd 0 is the link, checked above, and nothing else owns it.
        let link = unsafe { Link::from_raw_fd(0) };
        *lock(&REPORT) = link.try_clone().ok();
        let mut r = std::io::BufReader::new(link);
        while let Some(line) = read_line(&mut r) {
            let Ok(ask) = serde_json::from_slice::<Ask>(&line) else { break };
            if !ask_ok(&ask) {
                break;
            }
            run(ask.betas, ask.proxy.as_deref());
        }
        Some(0)
    }
    #[cfg(not(target_os = "linux"))]
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_list_is_read_for_this_version_only() {
        let (h1, h2, sig) = ("a".repeat(64), "0".repeat(64), "R".repeat(100));
        let list = format!("chat v{VERSION}\n{h1}\n{h2}\n{sig}\n");
        assert_eq!(parse_build_list(list.as_bytes()), Some((format!("{h1},{h2}"), sig.clone())));
        // Another version's, uppercase hex, more than 3 hashes, none, or a short signature.
        assert_eq!(parse_build_list(format!("chat v0.0.1\n{h1}\n{sig}\n").as_bytes()), None);
        assert_eq!(
            parse_build_list(format!("chat v{VERSION}\n{}\n{sig}\n", "A".repeat(64)).as_bytes()),
            None
        );
        assert_eq!(
            parse_build_list(format!("chat v{VERSION}\n{h1}\n{h1}\n{h1}\n{h1}\n{sig}\n").as_bytes()),
            None
        );
        assert_eq!(parse_build_list(format!("chat v{VERSION}\n{sig}\n").as_bytes()), None);
        assert_eq!(parse_build_list(format!("chat v{VERSION}\n{h1}\nshort\n").as_bytes()), None);
        // Each line ends with a newline.
        assert_eq!(parse_build_list(format!("chat v{VERSION}\n{h1}\n{sig}").as_bytes()), None);
    }

    #[test]
    fn versions_order_with_betas_before_their_release() {
        assert!(version_newer("v0.6.0", "0.5.6"));
        assert!(version_newer("v0.6.0", "0.6.0-beta.3"));
        assert!(version_newer("v0.6.0-beta.2", "0.6.0-beta.1"));
        assert!(!version_newer("v0.6.0-beta.2", "0.6.0"));
        assert!(!version_newer("v0.5.6", "0.5.6"));
        assert!(version_newer("v0.10.0", "0.9.9"));
        assert_eq!(parse_version("0.6.0-alpha"), ([0, 6, 0], 1));
    }

    #[test]
    fn reads_the_release_json_and_sums() {
        let json = br#"{"tag_name" : "v0.6.1", "assets": [
            {"browser_download_url": "https://x/chat-linux-x86_64", "name": "chat-linux-x86_64", "size": 2048},
            {"name": "SHA256SUMS", "size": 99}]}"#;
        assert_eq!(parse_tag(json).as_deref(), Some("v0.6.1"));
        assert_eq!(asset_size(json, "chat-linux-x86_64"), 2048);
        assert_eq!(asset_size(json, "chat-macos-x86_64"), 0);
        assert_eq!(parse_tag(br#"{"tag_name": "v1;rm"}"#), None);
        let h = "ab".repeat(32);
        let sums = format!("{}  other\r\n{h} *chat-linux-x86_64\n", "cd".repeat(32));
        assert_eq!(sums_lookup(sums.as_bytes(), "chat-linux-x86_64"), Some([0xab; 32]));
        assert_eq!(sums_lookup(sums.as_bytes(), "chat-linux"), None);
    }

    #[tokio::test]
    async fn the_proxy_connects_a_name_through_what_it_was_given() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut curl, ours) = tokio::io::duplex(1024);
        let (far, mut github) = tokio::io::duplex(1024);
        let serve = tokio::spawn(socks(ours, move |host, port| async move {
            assert_eq!((host.as_str(), port), ("github.com", 443));
            Ok::<_, String>(far)
        }));
        curl.write_all(&[5, 2, 0, 2]).await.unwrap();
        let mut b = [0u8; 2];
        curl.read_exact(&mut b).await.unwrap();
        assert_eq!(b, [5, 2]);
        curl.write_all(&[1, 2, b'a', b'b', 1, b'x']).await.unwrap();
        curl.read_exact(&mut b).await.unwrap();
        assert_eq!(b, [1, 0]);
        let mut req = vec![5, 1, 0, 3, 10];
        req.extend_from_slice(b"github.com");
        req.extend_from_slice(&443u16.to_be_bytes());
        curl.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        curl.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0);
        curl.write_all(b"hi").await.unwrap();
        curl.shutdown().await.unwrap();
        let mut got = Vec::new();
        github.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hi");
        drop(github);
        serve.await.unwrap();
    }

    #[tokio::test]
    async fn the_proxy_refuses_an_address() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut curl, ours) = tokio::io::duplex(1024);
        let serve = tokio::spawn(socks(ours, |_, _| async { Err::<tokio::io::DuplexStream, _>("no".to_string()) }));
        curl.write_all(&[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1, 0, 80]).await.unwrap();
        let mut rep = [0u8; 12];
        curl.read_exact(&mut rep).await.unwrap();
        assert_eq!(&rep[..3], &[5, 0, 5]);
        assert_eq!(rep[3], 8);
        serve.await.unwrap();
    }

    #[test]
    fn the_updater_takes_only_a_host_and_port() {
        let ask = |p: &str| Ask {
            betas: false,
            proxy: Some(p.into()),
        };
        assert!(ask_ok(&ask("127.0.0.1:9050")));
        assert!(ask_ok(&Ask { betas: true, proxy: None }));
        assert!(!ask_ok(&ask("127.0.0.1:9050 --output /etc/x")));
        assert!(!ask_ok(&ask("")));
    }
}
