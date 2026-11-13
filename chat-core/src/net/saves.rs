// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Saves: settings, the signing key, verified keys, histories and Tor's state, each sealed on disk
//! under one passphrase ([`passlock`]). A save is a folder: `~/.config/chat` itself for the one
//! called "default", `~/.config/chat/saves/NAME` for the rest (`$XDG_CONFIG_HOME/chat` if that's
//! set, `%LOCALAPPDATA%\chat` on Windows). Only the owner can open the folders (0700) and files
//! (0600), and each file is written in full, then renamed into place.
//!
//! Every save also has a spare: a decoy sealed under a shadow passphrase, or chaff the same shape
//! and size, so having one says nothing. The shadow passphrase opens the decoy in the save's place.
//! A save can delete itself after too many wrong passphrases in a row (its "tries" file), and can
//! need factors besides the passphrase (see [`passlock`]).
//!
//! These calls block (Argon2id takes seconds and 512 MiB), so an async caller runs them on a
//! blocking thread.

use crate::protocol::api::Queued;
use crate::protocol::crypto::identity::{IdentityKeypair, IdentityKind};
use crate::protocol::crypto::passlock::{self, NEEDS_CODE, NEEDS_DEVICE, NEEDS_KEY, PassError, PassLock, SEAL_OVERHEAD, TOTP_SECRET_LEN};
use crate::protocol::crypto::sodium;
use crate::protocol::hex;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const SETTINGS: &str = "settings";
const KEY: &str = "key";
const VERIFIED: &str = "verified";
const CODE: &str = "authenticator";
const DEVICE: &str = "device";
const SECKEY: &str = "securitykey";
const TRIES: &str = "tries";
const SPARE: &str = "spare";
const SPARE_LOCK: &str = "spare-lock";
/// Tor's state between runs, named so it doesn't say so.
const CACHE: &str = "cache";
/// A decoy as an early format kept it, in files of its own: still opened, until the shadow
/// passphrase is set again.
const OLD_DECOY: [&str; 4] = ["shadow-settings", "shadow-key", "shadow-verified", "shadow-authenticator"];
const SEALED: [&str; 5] = [SETTINGS, KEY, VERIFIED, CODE, SPARE_LOCK];
const HISTORY_PREFIX: &str = "history-";
/// A call's messages that wait for its peer, by the call's contact id.
const OUTBOX_PREFIX: &str = "outbox-";
pub const HISTORY_ID_LEN: usize = 16;
const SAVES_DIR: &str = "saves";
const DEVICE_SEALED_MAX: usize = 8192;
pub const NAME_MAX: usize = 32;
const SAVES_MAX: usize = 32;
const HISTORIES_MAX: usize = 1024;

/// The settings are padded with NULs to a multiple of this, so the file's size says little about
/// how many rooms they keep.
const SETTINGS_PAD: usize = 4096;
pub const SETTINGS_MAX: usize = 20480;
pub const KEY_MAX: usize = 1280;
pub const VERIFIED_MAX: usize = 24576;
pub const HISTORY_MAX: usize = 256 * 1024;
/// A call keeps 64 messages waiting at most, each well under 1 KB.
pub const OUTBOX_MAX: usize = 64 * 1024;
pub const TOR_MAX: usize = 64 * 1024 * 1024;
const CODE_PLAIN_LEN: usize = 1 + TOTP_SECRET_LEN;
/// The spare: 1, whether the decoy asks for a code, and the code's secret.
const SPARE_HEAD: usize = 2;
const SPARE_PLAIN_LEN: usize = SPARE_HEAD + TOTP_SECRET_LEN;
/// The spare's lock, sealed with the save's other files: 1, whether there's a decoy, then the
/// decoy lock's header and passphrase key (or random bytes).
const SPARE_LOCK_PLAIN_LEN: usize = SPARE_HEAD + passlock::HEADER_LEN + passlock::KEY_LEN;
/// "CT1", then one byte each: the limit, and the count of wrong passphrases so far.
const TRIES_MAGIC: &[u8; 3] = b"CT1";
/// Without the pause, a script could try every code in minutes.
const WRONG_CODE_PAUSE: std::time::Duration = std::time::Duration::from_millis(1500);

fn file_max(file: &str) -> usize {
    SEAL_OVERHEAD
        + match file {
            SETTINGS => SETTINGS_MAX,
            KEY => KEY_MAX,
            CODE => CODE_PLAIN_LEN,
            f if f.starts_with(HISTORY_PREFIX) => HISTORY_MAX,
            f if f.starts_with(OUTBOX_PREFIX) => OUTBOX_MAX,
            _ => VERIFIED_MAX,
        }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SaveError {
    #[error("that's not the passphrase")]
    Wrong,
    #[error("not enough free memory to open it (it needs 512 MiB for a few seconds)")]
    NoMemory,
    #[error("its files are damaged, or weren't written by chat")]
    Format,
    #[error("there's no such save")]
    NoFile,
    #[error("it's locked to a device, and this one can't unseal it: {0}")]
    Device(String),
    #[error("it needs its security key")]
    Key,
    /// The security key needs its PIN, or that wasn't it.
    #[error("{0}")]
    KeyPin(String),
    #[error("{0}")]
    Lost(String),
    #[error("it was deleted: {0}")]
    Destroyed(String),
    /// The shadow passphrase: the decoy has taken the save's place. Open it again to use it.
    #[error("it was opened with its shadow passphrase")]
    Decoy,
    #[error("{0}")]
    Failed(String),
}

impl From<PassError> for SaveError {
    fn from(e: PassError) -> Self {
        match e {
            PassError::Wrong => SaveError::Wrong,
            PassError::NoMemory => SaveError::NoMemory,
            PassError::Format => SaveError::Format,
        }
    }
}

type Result<T> = std::result::Result<T, SaveError>;

/// "default" is the save kept in the folder itself.
fn stored_name(name: &str) -> &str {
    if name == "default" { "" } else { name }
}

/// A save's name: 1 to 32 letters, digits, '-' and '_'.
pub fn name_ok(name: &str) -> bool {
    (1..=NAME_MAX).contains(&name.len()) && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// The folder chat keeps its saves in: `$XDG_CONFIG_HOME/chat`, `~/.config/chat`, or on Windows
/// `%LOCALAPPDATA%\chat`, which a roaming profile doesn't carry.
pub fn config_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        return std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .map(|p| p.join("chat"));
    }
    // The XDG spec ignores a relative one.
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).filter(|p| p.is_absolute());
    let base = xdg.or_else(|| {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join(".config"))
            .filter(|p| p.is_absolute())
    })?;
    Some(base.join("chat"))
}

/// A folder only we can open, made if it isn't there, and never a link to somewhere else.
fn private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    if let Err(e) = b.create(path)
        && e.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(e);
    }
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_dir() {
        return Err(std::io::Error::other("not a folder"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: it can't fail and touches no memory.
        if m.uid() != unsafe { libc::geteuid() } {
            return Err(std::io::Error::other("someone else's folder"));
        }
        if m.mode() & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// Written in full to "PATH.new", synced, then renamed into place, so a crash can't leave half a
/// file. Only we can read it.
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".new");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let done = o.open(&tmp).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()
    });
    if let Err(e) = done.and_then(|()| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // The rename is only on disk once the folder is synced.
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

/// A regular file, not a link, and only up to `max` bytes: a longer one wasn't written by chat.
fn read_file(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut o, libc::O_NOFOLLOW);
    let f = o.open(path).map_err(|_| SaveError::NoFile)?;
    if !f.metadata().map(|m| m.is_file()).unwrap_or(false) {
        return Err(SaveError::NoFile);
    }
    let mut buf = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut buf).map_err(|_| SaveError::NoFile)?;
    if buf.len() > max {
        return Err(SaveError::Format);
    }
    Ok(buf)
}

fn read_sealed(dir: &Path, file: &str) -> Result<Vec<u8>> {
    read_file(&dir.join(file), file_max(file))
}

/// What's kept for rooms, by their history ids: histories, and calls' outboxes.
fn room_files(dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    rd.filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| {
            [HISTORY_PREFIX, OUTBOX_PREFIX]
                .iter()
                .any(|p| n.starts_with(p) && n.len() == p.len() + 2 * HISTORY_ID_LEN)
        })
        .take(2 * HISTORIES_MAX)
        .collect()
}

fn histories(dir: &Path) -> Vec<String> {
    room_files(dir).into_iter().filter(|n| n.starts_with(HISTORY_PREFIX)).collect()
}

fn history_file(id: &[u8; HISTORY_ID_LEN]) -> String {
    format!("{HISTORY_PREFIX}{}", hex::encode(id))
}

fn outbox_file(id: &[u8; HISTORY_ID_LEN]) -> String {
    format!("{OUTBOX_PREFIX}{}", hex::encode(id))
}

/// An outbox as its file has it: a line for each message, "AT\tMID\tTEXT".
fn outbox_text(messages: &[Queued]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    for m in messages {
        let text = m.text.replace(['\t', '\n', '\r'], " ");
        out.extend_from_slice(format!("{}\t{}\t{text}\n", m.at, m.mid).as_bytes());
    }
    out
}

/// The messages an outbox file has, skipping any that can't be read.
fn outbox_read(text: &[u8]) -> Vec<Queued> {
    String::from_utf8_lossy(text)
        .split('\n')
        .filter_map(|l| {
            let mut f = l.splitn(3, '\t');
            let (at, mid, text) = (f.next()?.parse().ok()?, f.next()?, f.next()?);
            (!mid.is_empty() && !text.is_empty()).then(|| Queued {
                mid: mid.to_string(),
                text: text.to_string(),
                at,
            })
        })
        .collect()
}

/// What the save's sealed files but one need, read from their headers.
fn needs_but(dir: &Path, skip: Option<&str>) -> u8 {
    SEALED
        .iter()
        .filter(|f| Some(**f) != skip)
        .filter_map(|f| read_file(&dir.join(f), file_max(f)).ok())
        .fold(0, |all, s| all | passlock::needs_of(&s))
}

/// The file that says how the save is locked: the settings, or the key if there are no settings.
fn lock_file(dir: &Path) -> &'static str {
    if dir.join(SETTINGS).exists() { SETTINGS } else { KEY }
}

fn read_tries(dir: &Path) -> Option<(u8, u8)> {
    let b = read_file(&dir.join(TRIES), 5).ok()?;
    (b.len() == 5 && &b[..3] == TRIES_MAGIC).then(|| (b[3], b[4]))
}

fn write_tries(dir: &Path, limit: u8, count: u8) {
    let _ = write_private(&dir.join(TRIES), &[b'C', b'T', b'1', limit, count]);
}

fn write_chaff(dir: &Path, needs: u8) -> std::io::Result<()> {
    write_private(&dir.join(SPARE), &passlock::chaff(needs, SPARE_PLAIN_LEN))
}

/// The device's secret for a save locked to this device.
fn device_unseal(dir: &Path) -> std::result::Result<Zeroizing<[u8; 32]>, String> {
    let sealed = read_file(&dir.join(DEVICE), DEVICE_SEALED_MAX).map_err(|_| "its device file is missing or damaged".to_string())?;
    crate::net::device::lock::unseal(&sealed)
}

/// `secret` sealed to this device, in place of a save's device file, which is read back to be sure.
/// What the device kept for the one it replaces is destroyed.
fn device_seal(dir: &Path, secret: &[u8; 32]) -> std::result::Result<(), String> {
    use crate::net::device::lock;
    let sealed = lock::seal(secret)?;
    let path = dir.join(DEVICE);
    let old = read_file(&path, DEVICE_SEALED_MAX).ok();
    let wrote = write_private(&path, &sealed).is_ok();
    match read_file(&path, DEVICE_SEALED_MAX) {
        Ok(back) if wrote && back == sealed => {
            if let Some(old) = old.filter(|o| *o != sealed) {
                lock::forget(&old);
            }
            Ok(())
        }
        _ => {
            lock::forget(&sealed);
            Err("couldn't write its device file".into())
        }
    }
}

/// A save's device file deleted, and what the device keeps for it.
fn forget_device(dir: &Path) {
    if let Ok(sealed) = read_file(&dir.join(DEVICE), DEVICE_SEALED_MAX) {
        crate::net::device::lock::forget(&sealed);
    }
    let _ = std::fs::remove_file(dir.join(DEVICE));
}

/// The securitykey file: "CSK1", the salt, how many keys, then for each whether it needs its PIN,
/// its credential's length (2 bytes, big-endian), the credential, and the save's key secret wrapped
/// by the key's hmac-secret.
const KEY_FILE_MAGIC: &[u8; 4] = b"CSK1";
const KEYS_MAX: usize = 4;

struct KeyEntry {
    uv: bool,
    cred: Vec<u8>,
    wrapped: [u8; passlock::WRAP_LEN],
}

struct KeyFile {
    salt: [u8; crate::net::seckey::SALT_LEN],
    keys: Vec<KeyEntry>,
}

impl KeyFile {
    /// What an entry's wrapped secret is bound to: the file's magic and salt, then the entry's PIN
    /// flag and credential.
    fn ad(&self, e: &KeyEntry) -> Vec<u8> {
        let mut ad = KEY_FILE_MAGIC.to_vec();
        ad.extend_from_slice(&self.salt);
        ad.push(u8::from(e.uv));
        ad.extend_from_slice(&e.cred);
        ad
    }

    fn pack(&self) -> Vec<u8> {
        let mut out = KEY_FILE_MAGIC.to_vec();
        out.extend_from_slice(&self.salt);
        out.push(self.keys.len() as u8);
        for e in &self.keys {
            out.push(u8::from(e.uv));
            out.extend_from_slice(&(e.cred.len() as u16).to_be_bytes());
            out.extend_from_slice(&e.cred);
            out.extend_from_slice(&e.wrapped);
        }
        out
    }

    fn parse(b: &[u8]) -> Option<KeyFile> {
        let rest = b.strip_prefix(&KEY_FILE_MAGIC[..])?;
        let salt = rest.get(..32)?.try_into().ok()?;
        let n = usize::from(*rest.get(32)?);
        if !(1..=KEYS_MAX).contains(&n) {
            return None;
        }
        let mut p = &rest[33..];
        let mut keys = Vec::new();
        for _ in 0..n {
            let (&uv, len) = (p.first()?, usize::from(u16::from_be_bytes([*p.get(1)?, *p.get(2)?])));
            if uv > 1 || len == 0 || len > crate::net::seckey::CRED_MAX {
                return None;
            }
            let cred = p.get(3..3 + len)?.to_vec();
            let wrapped = p.get(3 + len..3 + len + passlock::WRAP_LEN)?.try_into().ok()?;
            keys.push(KeyEntry {
                uv: uv == 1,
                cred,
                wrapped,
            });
            p = &p[3 + len + passlock::WRAP_LEN..];
        }
        p.is_empty().then_some(KeyFile { salt, keys })
    }
}

fn read_key_file(dir: &Path) -> Option<KeyFile> {
    let max = 4 + 32 + 1 + KEYS_MAX * (3 + crate::net::seckey::CRED_MAX + passlock::WRAP_LEN);
    KeyFile::parse(&read_file(&dir.join(SECKEY), max).ok()?)
}

/// One save on disk, as the list of saves shows it.
#[derive(Debug, Clone)]
pub struct SaveInfo {
    /// "default", or the folder's name.
    pub name: String,
    pub settings: bool,
    pub key: bool,
    /// What it needs besides the passphrase ([`passlock::NEEDS_DEVICE`] and the rest).
    pub factors: u8,
    pub modified: Option<std::time::SystemTime>,
}

/// Where the saves are.
#[derive(Debug, Clone)]
pub struct Saves {
    top: PathBuf,
}

impl Saves {
    /// The saves in the usual place ([`config_dir`]), if there is one.
    pub fn new() -> Option<Saves> {
        config_dir().map(Saves::at)
    }

    /// The saves in another folder (a test's, say).
    pub fn at(top: PathBuf) -> Saves {
        Saves { top }
    }

    /// A save's folder, made (with those above it) if `create` is set.
    fn dir(&self, name: &str, create: bool) -> Result<PathBuf> {
        let name = stored_name(name);
        if !name.is_empty() && !name_ok(name) {
            return Err(SaveError::Failed("a save's name is letters, digits, - and _".into()));
        }
        let made = |p: &Path| {
            if create {
                private_dir(p).map_err(|e| SaveError::Failed(format!("can't make {}: {e}", p.display())))
            } else {
                Ok(())
            }
        };
        if create && let Some(base) = self.top.parent() {
            let _ = private_dir(base);
        }
        made(&self.top)?;
        if name.is_empty() {
            return Ok(self.top.clone());
        }
        let saves = self.top.join(SAVES_DIR);
        made(&saves)?;
        let dir = saves.join(name);
        made(&dir)?;
        Ok(dir)
    }

    /// Where a save is, with "~" for the home folder.
    pub fn shown_dir(&self, name: &str) -> String {
        let dir = self.dir(name, false).map(|d| d.display().to_string()).unwrap_or_default();
        match crate::net::files::home_dir() {
            Some(h) if !cfg!(windows) && h.len() > 1 && dir.starts_with(&format!("{h}/")) => format!("~{}", &dir[h.len()..]),
            _ => dir,
        }
    }

    fn info(&self, name: &str) -> Option<SaveInfo> {
        let dir = self.dir(name, false).ok()?;
        let (settings, key) = (dir.join(SETTINGS).is_file(), dir.join(KEY).is_file());
        if !settings && !key {
            return None;
        }
        let modified = std::fs::metadata(dir.join(lock_file(&dir))).and_then(|m| m.modified()).ok();
        let name = if stored_name(name).is_empty() { "default" } else { name };
        Some(SaveInfo {
            name: name.into(),
            settings,
            key,
            factors: needs_but(&dir, None),
            modified,
        })
    }

    /// The saves there are: "default" first, then the rest by name.
    pub fn list(&self) -> Vec<SaveInfo> {
        let mut names: Vec<String> = std::fs::read_dir(self.top.join(SAVES_DIR))
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| name_ok(n) && n != "default")
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        let all = std::iter::once("default".to_string()).chain(names);
        all.filter_map(|n| self.info(&n)).take(SAVES_MAX).collect()
    }

    /// A new save (or a new lock for one) under `passphrase`, needing these factors. A code factor
    /// needs `code`, an authenticator secret whose code the user has typed back correctly.
    pub fn create(&self, name: &str, passphrase: &str, factors: u8, code: Option<&[u8; TOTP_SECRET_LEN]>) -> Result<Save> {
        let factors = factors & passlock::NEEDS_ALL;
        if factors & NEEDS_KEY != 0 {
            return Err(SaveError::Failed("this build can't lock a save to a security key yet".into()));
        }
        if factors & NEEDS_CODE != 0 && code.is_none() {
            return Err(SaveError::Failed("no authenticator app is set up for it".into()));
        }
        if self.info(name).is_some() {
            return Err(SaveError::Failed(format!("there's already a save called {name}")));
        }
        let dir = self.dir(name, true)?;
        // chat's folder is there now, if it wasn't.
        crate::net::sandbox::narrow();
        let device = if factors & NEEDS_DEVICE != 0 {
            let secret: Zeroizing<[u8; 32]> = Zeroizing::new(sodium::random_array());
            device_seal(&dir, &secret).map_err(SaveError::Device)?;
            Some(secret)
        } else {
            None
        };
        // A save that isn't made leaves nothing on the device either.
        let mut lock = PassLock::new(passphrase.as_bytes()).inspect_err(|_| forget_device(&dir))?;
        lock.set(factors, device.as_deref().unwrap_or(&[0; 32]), &[0; 32]);
        let save = Save::new(self, name, dir, Held { lock, device, key: None });
        if let Some(code) = code.filter(|_| factors & NEEDS_CODE != 0)
            && save.write_code(&save.held.lock, code).is_err()
        {
            let _ = std::fs::remove_file(save.dir.join(CODE));
            forget_device(&save.dir);
            return Err(SaveError::Failed("couldn't write its authenticator file".into()));
        }
        // Every save has a spare from the start, so having one says nothing.
        let _ = save.write_spare_lock(&save.held.lock, None);
        let _ = write_chaff(&save.dir, factors);
        Ok(save)
    }

    /// Opens a save with its passphrase. `act`: a wrong passphrase counts towards self-destruct,
    /// and the shadow passphrase opens the decoy in the save's place; without it, it's only a check.
    /// `key` is the save's security key's secret, if it needs one. A save that asks for an
    /// authenticator code comes back waiting for it.
    pub fn unlock(&self, name: &str, passphrase: &str, act: bool, key: Option<&[u8; 32]>) -> Result<Unlocked> {
        let dir = self.dir(name, false)?;
        let sealed = match read_sealed(&dir, SETTINGS) {
            Err(SaveError::NoFile) => read_sealed(&dir, KEY)?,
            r => r?,
        };
        let mut locked = passlock::needs_of(&sealed);
        let mut all = locked | needs_but(&dir, None);
        let mut device = None;
        if all & NEEDS_DEVICE != 0 {
            match device_unseal(&dir) {
                Ok(d) => device = Some(d),
                Err(why) if locked & NEEDS_DEVICE != 0 => return Err(SaveError::Device(why)),
                Err(_) => {}
            }
        }
        let key = match key {
            Some(k) if all & NEEDS_KEY != 0 => Some(Zeroizing::new(*k)),
            None if all & NEEDS_KEY != 0 => return Err(SaveError::Key),
            _ => None,
        };
        let (spare, old) = match read_file(&dir.join(SPARE), file_max(SETTINGS)) {
            Err(SaveError::NoFile) => (read_file(&dir.join(OLD_DECOY[0]), file_max(SETTINGS)).ok(), true),
            r => (r.ok(), false),
        };
        let rc = PassLock::of(passphrase.as_bytes(), &sealed);
        // Argon2id runs for the spare on every try, decoy or chaff, or on a new salt for a save
        // without one, so how long a passphrase takes doesn't say what it opened.
        let sl = match spare.as_deref().map(|s| PassLock::of(passphrase.as_bytes(), s)) {
            Some(Ok(l)) => Ok(l),
            Some(Err(PassError::NoMemory)) => Err(PassError::NoMemory),
            _ => PassLock::new(passphrase.as_bytes()).and(Err(PassError::Format)),
        };
        let zero = [0u8; 32];
        let (dv, ky) = (device.as_deref().unwrap_or(&zero), key.as_deref().unwrap_or(&zero));
        let opened = rc.and_then(|mut lock| {
            if matches!(sl, Err(PassError::NoMemory)) {
                return Err(PassError::NoMemory);
            }
            lock.set(locked, dv, ky);
            lock.unseal(&sealed).map(|_| lock)
        });
        let mut decoy = None;
        if let (Err(PassError::Wrong), Ok(mut sl), Some(spare)) = (&opened, sl, spare.as_deref()) {
            let sneeds = passlock::needs_of(spare);
            if (sneeds & NEEDS_DEVICE == 0 || device.is_some()) && (sneeds & NEEDS_KEY == 0 || key.is_some()) {
                sl.set(sneeds, dv, ky);
                if let Ok(plain) = sl.unseal(spare)
                    && (old || (plain.len() == SPARE_PLAIN_LEN && plain[0] == 1 && plain[1] <= 1))
                {
                    decoy = Some((sl, plain));
                }
            }
        }
        let lock = match (opened, decoy) {
            (Ok(lock), _) => lock,
            (Err(_), Some((sl, plain))) if act => {
                promote(&dir, &sl, &plain, old);
                locked = sl.needs();
                all = locked | needs_but(&dir, None);
                sl
            }
            (Err(PassError::Wrong), _) if act => return Err(wrong_passphrase(self, name, &dir)),
            (Err(e), _) => return Err(e.into()),
        };
        let mut save = Save::new(self, name, dir, Held { lock, device, key });
        save.refresh();
        if let Some((limit, count)) = read_tries(&save.dir)
            && limit > 0
            && count > 0
        {
            write_tries(&save.dir, limit, 0);
        }
        let usable = all & !(if save.held.device.is_some() { 0 } else { NEEDS_DEVICE });
        if all & NEEDS_CODE != 0 {
            let secret = save.read_code().map_err(|_| {
                SaveError::Lost("its authenticator file is missing or damaged, so the code it asks for can't be checked".into())
            })?;
            return Ok(Unlocked::Code(PendingCode { save, secret, all: usable }));
        }
        save.finish_open(usable);
        Ok(Unlocked::Open(save))
    }

    /// The secret a save's security key gives, to pass to [`Saves::unlock`]: whichever key plugged in
    /// has one of its credentials, with a touch, and its PIN where it needs one. This blocks while it
    /// waits for the key; `wait` says where it is, and cancels it.
    pub fn key_secret(&self, name: &str, pin: Option<&str>, wait: &crate::net::seckey::Wait) -> Result<Zeroizing<[u8; 32]>> {
        use crate::net::seckey::KeyError;
        let dir = self.dir(name, false)?;
        let f = read_key_file(&dir).ok_or_else(|| SaveError::Lost("its securitykey file is missing or damaged".into()))?;
        let creds: Vec<(Vec<u8>, bool)> = f.keys.iter().map(|e| (e.cred.clone(), e.uv)).collect();
        let (which, kek) = crate::net::seckey::secret(&creds, &f.salt, pin, wait).map_err(|e| match e {
            KeyError::Pin(why) => SaveError::KeyPin(why),
            KeyError::Cancelled => SaveError::Failed("cancelled".into()),
            e => SaveError::Failed(e.to_string()),
        })?;
        let e = &f.keys[which];
        passlock::secret_unwrap(&kek, &f.ad(e), &e.wrapped)
            .ok_or_else(|| SaveError::Failed("the security key gave a secret that doesn't open this save".into()))
    }

    /// Deletes a save's files, and its folder if nothing else is in it. The device's part goes last,
    /// once nothing sealed with it is left.
    pub fn remove(&self, name: &str) -> Result<()> {
        let dir = self.dir(name, false)?;
        let mut files: Vec<String> = [SETTINGS, KEY, VERIFIED, CODE, SECKEY, TRIES, SPARE, SPARE_LOCK, CACHE]
            .iter()
            .chain(OLD_DECOY.iter())
            .flat_map(|f| [f.to_string(), format!("{f}.new")])
            .collect();
        files.push(format!("{DEVICE}.new"));
        files.extend(room_files(&dir));
        let mut left = false;
        for f in &files {
            let p = dir.join(f);
            if std::fs::remove_file(&p).is_err() && p.exists() {
                left = true;
            }
        }
        if !left {
            forget_device(&dir);
            left = dir.join(DEVICE).exists();
        }
        if left {
            return Err(SaveError::Failed(format!(
                "some of its files in {} couldn't be deleted",
                dir.display()
            )));
        }
        // Another program could have a folder called chat too: only an empty one goes.
        let _ = std::fs::remove_dir(&dir);
        if !stored_name(name).is_empty() {
            let _ = std::fs::remove_dir(self.top.join(SAVES_DIR));
            let _ = std::fs::remove_dir(&self.top);
        }
        Ok(())
    }
}

/// A wrong passphrase: [`SaveError::Wrong`], or [`SaveError::Destroyed`] if it was one too many.
fn wrong_passphrase(saves: &Saves, name: &str, dir: &Path) -> SaveError {
    let Some((limit, count)) = read_tries(dir).filter(|t| t.0 > 0) else {
        return SaveError::Wrong;
    };
    let count = count.saturating_add(1);
    if count >= limit {
        let _ = saves.remove(name);
        return SaveError::Destroyed(format!("the wrong passphrase was entered {count} times in a row"));
    }
    write_tries(dir, limit, count);
    SaveError::Wrong
}

/// The decoy takes the save's place, settings first, so from then on the real passphrase opens
/// nothing. The save's key, histories and Tor state go; its device and securitykey files stay,
/// since the decoy needs them too. Then it gets a spare of chaff, as a save without a decoy has.
fn promote(dir: &Path, sl: &PassLock, spare_plain: &[u8], old: bool) {
    if old {
        for (from, to) in OLD_DECOY.iter().zip([SETTINGS, KEY, VERIFIED, CODE]) {
            match read_file(&dir.join(from), file_max(VERIFIED)) {
                Ok(b) if !b.is_empty() => {
                    let _ = write_private(&dir.join(to), &b);
                }
                _ => {
                    let _ = std::fs::remove_file(dir.join(to));
                }
            }
        }
    } else {
        let seal = |file: &str, plain: &[u8]| sl.seal(plain).map(|s| write_private(&dir.join(file), &s));
        let _ = seal(SETTINGS, &[0; SETTINGS_PAD]);
        let _ = std::fs::remove_file(dir.join(KEY));
        let _ = seal(VERIFIED, b"");
        if spare_plain.get(1) == Some(&1) && spare_plain.len() == SPARE_PLAIN_LEN {
            let mut code = Zeroizing::new([1u8; CODE_PLAIN_LEN]);
            code[1..].copy_from_slice(&spare_plain[SPARE_HEAD..]);
            let _ = seal(CODE, &code[..]);
        } else {
            let _ = std::fs::remove_file(dir.join(CODE));
        }
    }
    for h in room_files(dir) {
        let _ = std::fs::remove_file(dir.join(h));
    }
    let _ = std::fs::remove_file(dir.join(CACHE));
    let mut plain = Zeroizing::new([0u8; SPARE_LOCK_PLAIN_LEN]);
    plain[0] = 1;
    sodium::random(&mut plain[SPARE_HEAD..]);
    if let Ok(s) = sl.seal(&plain[..]) {
        let _ = write_private(&dir.join(SPARE_LOCK), &s);
    }
    let _ = write_chaff(dir, sl.needs());
    for f in OLD_DECOY {
        let _ = std::fs::remove_file(dir.join(f));
    }
}

/// A save's lock, and the secrets of its factors while they're known.
struct Held {
    lock: PassLock,
    device: Option<Zeroizing<[u8; 32]>>,
    key: Option<Zeroizing<[u8; 32]>>,
}

impl Held {
    fn lock_needing(&self, needs: u8) -> PassLock {
        let mut l = self.lock.clone();
        let zero = [0u8; 32];
        l.set(needs, self.device.as_deref().unwrap_or(&zero), self.key.as_deref().unwrap_or(&zero));
        l
    }

    /// A crash while the lock was being changed can leave a file sealed with other factors. One
    /// sealed with all of the save's and more is still read, if their secrets are held, but never
    /// one sealed with fewer.
    fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match self.lock.unseal(sealed) {
            Err(PassError::Wrong) => {}
            r => return Ok(r?),
        }
        let needs = passlock::needs_of(sealed);
        let have = self.lock.needs();
        if needs == have
            || have & !needs != 0
            || (needs & NEEDS_DEVICE != 0 && self.device.is_none())
            || (needs & NEEDS_KEY != 0 && self.key.is_none())
        {
            return Err(SaveError::Wrong);
        }
        Ok(self.lock_needing(needs).unseal(sealed)?)
    }
}

/// What [`Saves::unlock`] gives.
pub enum Unlocked {
    Open(Save),
    /// The save asks for an authenticator code before it's used.
    Code(PendingCode),
}

/// A save that's opened but waits for its authenticator code: nothing of it is used until then.
pub struct PendingCode {
    save: Save,
    secret: Zeroizing<[u8; TOTP_SECRET_LEN]>,
    all: u8,
}

impl PendingCode {
    /// The save, if `code` is the app's code now. A wrong one pauses first (this blocks), so a
    /// script can't try them all quickly; it comes back with the error to try again.
    pub fn check(self, code: &str) -> std::result::Result<Save, (Box<PendingCode>, SaveError)> {
        let Some(v) = passlock::parse_code(code) else {
            return Err((Box::new(self), SaveError::Format));
        };
        if !passlock::code_matches(&self.secret, v, unix_now()) {
            std::thread::sleep(WRONG_CODE_PAUSE);
            return Err((Box::new(self), SaveError::Wrong));
        }
        let PendingCode { mut save, all, .. } = self;
        save.finish_open(all);
        Ok(save)
    }

    pub fn name(&self) -> &str {
        self.save.name()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// An open save: the folder, and the lock its files are sealed under.
pub struct Save {
    saves: Saves,
    name: String,
    dir: PathBuf,
    held: Held,
    /// An authenticator being set up: its secret, and whether its code was typed back right.
    new_code: Option<(Zeroizing<[u8; TOTP_SECRET_LEN]>, bool)>,
    /// The decoy couldn't be kept when the save was last sealed again.
    decoy_lost: bool,
    /// Opened part way through a change of factors, and finished then: Some(whether that worked).
    relocked: Option<bool>,
}

impl Save {
    fn new(saves: &Saves, name: &str, dir: PathBuf, held: Held) -> Save {
        let name = if stored_name(name).is_empty() { "default" } else { name };
        Save {
            saves: saves.clone(),
            name: name.into(),
            dir,
            held,
            new_code: None,
            decoy_lost: false,
            relocked: None,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// What it needs besides the passphrase.
    pub fn factors(&self) -> u8 {
        self.held.lock.needs()
    }

    /// News from opening it: a change of factors finished then (and whether that worked), and
    /// whether its decoy couldn't be kept. Each is told once.
    pub fn news(&mut self) -> (Option<bool>, bool) {
        (self.relocked.take(), std::mem::take(&mut self.decoy_lost))
    }

    fn read(&self, file: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.held.unseal(&read_sealed(&self.dir, file)?)
    }

    fn write_with(&self, lock: &PassLock, file: &str, plain: &[u8]) -> Result<()> {
        let sealed = lock.seal(plain)?;
        write_private(&self.dir.join(file), &sealed).map_err(|e| SaveError::Failed(format!("couldn't write its {file} file: {e}")))
    }

    fn write(&self, file: &str, plain: &[u8]) -> Result<()> {
        self.write_with(&self.held.lock, file, plain)
    }

    /// The settings (TOML), or "" if there are none.
    pub fn settings(&self) -> Result<String> {
        let plain = match self.read(SETTINGS) {
            Err(SaveError::NoFile) => return Ok(String::new()),
            r => r?,
        };
        let end = plain.iter().position(|b| *b == 0).unwrap_or(plain.len());
        String::from_utf8(plain[..end].to_vec()).map_err(|_| SaveError::Format)
    }

    pub fn set_settings(&self, text: &str) -> Result<()> {
        let n = text.len() / SETTINGS_PAD * SETTINGS_PAD + SETTINGS_PAD;
        if n > SETTINGS_MAX {
            return Err(SaveError::Failed("there's too much to save in the settings".into()));
        }
        let mut padded = Zeroizing::new(vec![0u8; n]);
        padded[..text.len()].copy_from_slice(text.as_bytes());
        self.write_with(&self.held.lock, SETTINGS, &padded)
    }

    /// The signing key's file, as written by [`Save::set_key`], if there is one.
    pub fn key(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match self.read(KEY) {
            Err(SaveError::NoFile) => Ok(None),
            r => r.map(Some),
        }
    }

    pub fn set_key(&self, key: &[u8]) -> Result<()> {
        if key.len() > KEY_MAX {
            return Err(SaveError::Failed("the key is too big to save".into()));
        }
        self.write(KEY, key)
    }

    /// The verified and ignored keys (text), or "" if there are none.
    pub fn verified(&self) -> Result<String> {
        match self.read(VERIFIED) {
            Err(SaveError::NoFile) => Ok(String::new()),
            r => String::from_utf8(r?.to_vec()).map_err(|_| SaveError::Format),
        }
    }

    pub fn set_verified(&self, text: &str) -> Result<()> {
        if text.len() > VERIFIED_MAX {
            return Err(SaveError::Failed("there are too many verified keys to save".into()));
        }
        self.write(VERIFIED, text.as_bytes())
    }

    /// A room's history, by its history id, if it's kept.
    pub fn history(&self, id: &[u8; HISTORY_ID_LEN]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match self.read(&history_file(id)) {
            Err(SaveError::NoFile) => Ok(None),
            r => r.map(Some),
        }
    }

    pub fn set_history(&self, id: &[u8; HISTORY_ID_LEN], text: &[u8]) -> Result<()> {
        if text.len() > HISTORY_MAX {
            return Err(SaveError::Failed("the history is too long to save".into()));
        }
        self.write(&history_file(id), text)
    }

    /// Deletes one room's history, or with None, every one.
    pub fn forget_history(&self, id: Option<&[u8; HISTORY_ID_LEN]>) {
        let files = id.map_or_else(|| histories(&self.dir), |id| vec![history_file(id)]);
        for f in files {
            let _ = std::fs::remove_file(self.dir.join(f));
        }
    }

    /// What waits to go to a call's peer, by the call's history id.
    pub fn outbox(&self, id: &[u8; HISTORY_ID_LEN]) -> Result<Vec<Queued>> {
        match self.read(&outbox_file(id)) {
            Err(SaveError::NoFile) => Ok(Vec::new()),
            r => r.map(|t| outbox_read(&t)),
        }
    }

    /// Keeps what waits to go to a call's peer: with nothing, its file goes.
    pub fn set_outbox(&self, id: &[u8; HISTORY_ID_LEN], messages: &[Queued]) -> Result<()> {
        let file = outbox_file(id);
        if messages.is_empty() {
            return match std::fs::remove_file(self.dir.join(&file)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    Err(SaveError::Failed(format!("couldn't delete its {file} file: {e}")))
                }
                _ => Ok(()),
            };
        }
        let text = outbox_text(messages);
        if text.len() > OUTBOX_MAX {
            return Err(SaveError::Failed("too much waits to go to them to save".into()));
        }
        self.write(&file, &text)
    }

    /// How many rooms' histories it keeps.
    pub fn history_count(&self) -> usize {
        histories(&self.dir).len()
    }

    /// Tor's state, kept between runs, if there is any.
    pub fn tor_cache(&self) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match read_file(&self.dir.join(CACHE), TOR_MAX + SEAL_OVERHEAD) {
            Err(SaveError::NoFile) => Ok(None),
            Err(e) => Err(e),
            Ok(s) => self.held.unseal(&s).map(Some),
        }
    }

    pub fn set_tor_cache(&self, data: &[u8]) -> Result<()> {
        if data.len() > TOR_MAX {
            return Err(SaveError::Failed("Tor's state is too big to save".into()));
        }
        self.write(CACHE, data)
    }

    pub fn forget_tor_cache(&self) {
        let _ = std::fs::remove_file(self.dir.join(CACHE));
    }

    /// After how many wrong passphrases in a row it deletes itself (0: never).
    pub fn destroy_limit(&self) -> u8 {
        read_tries(&self.dir).map_or(0, |t| t.0)
    }

    pub fn set_destroy_limit(&self, limit: u8) -> Result<()> {
        if limit == 0 {
            let _ = std::fs::remove_file(self.dir.join(TRIES));
            return Ok(());
        }
        write_private(&self.dir.join(TRIES), &[b'C', b'T', b'1', limit, 0]).map_err(|e| SaveError::Failed(e.to_string()))
    }

    /// Wrong passphrases left before it deletes itself, if it would.
    pub fn tries_left(&self) -> Option<u8> {
        read_tries(&self.dir).filter(|t| t.0 > 0).map(|(l, c)| l.saturating_sub(c))
    }

    /// The lock screen: checks the lock held rather than the settings file, so someone who can
    /// change the files can't make the save's own passphrase fail (and, with self-destruct on,
    /// delete it). The shadow passphrase gives [`SaveError::Decoy`], with the decoy in the save's
    /// place, and a wrong one counts towards self-destruct.
    pub fn lock_try(&self, passphrase: &str) -> Result<()> {
        let (spare, old) = match read_file(&self.dir.join(SPARE), file_max(SETTINGS)) {
            Err(SaveError::NoFile) => (read_file(&self.dir.join(OLD_DECOY[0]), file_max(SETTINGS)).ok(), true),
            r => (r.ok(), false),
        };
        let rc = PassLock::like(passphrase.as_bytes(), &self.held.lock);
        let sl = match spare.as_deref().map(|s| PassLock::of(passphrase.as_bytes(), s)) {
            Some(Ok(l)) => Ok(l),
            Some(Err(PassError::NoMemory)) => Err(PassError::NoMemory),
            _ => PassLock::new(passphrase.as_bytes()).and(Err(PassError::Format)),
        };
        let rc = match rc {
            Ok(_) if matches!(sl, Err(PassError::NoMemory)) => Err(PassError::NoMemory),
            Ok(l) if l.same_passphrase(&self.held.lock) => Ok(()),
            Ok(_) => Err(PassError::Wrong),
            Err(e) => Err(e),
        };
        let mut result = rc.map_err(SaveError::from);
        if let (Err(SaveError::Wrong), Ok(mut sl), Some(spare)) = (&result, sl, spare.as_deref()) {
            let sneeds = passlock::needs_of(spare);
            if (sneeds & NEEDS_DEVICE == 0 || self.held.device.is_some()) && (sneeds & NEEDS_KEY == 0 || self.held.key.is_some()) {
                let zero = [0u8; 32];
                sl.set(
                    sneeds,
                    self.held.device.as_deref().unwrap_or(&zero),
                    self.held.key.as_deref().unwrap_or(&zero),
                );
                if let Ok(plain) = sl.unseal(spare)
                    && (old || (plain.len() == SPARE_PLAIN_LEN && plain[0] == 1 && plain[1] <= 1))
                {
                    promote(&self.dir, &sl, &plain, old);
                    result = Err(SaveError::Decoy);
                }
            }
        }
        if result == Err(SaveError::Wrong) {
            result = Err(wrong_passphrase(&self.saves, &self.name, &self.dir));
        }
        if matches!(result, Ok(()) | Err(SaveError::Decoy))
            && let Some((limit, count)) = read_tries(&self.dir)
            && limit > 0
            && count > 0
        {
            write_tries(&self.dir, limit, 0);
        }
        result
    }

    fn write_code(&self, lock: &PassLock, secret: &[u8; TOTP_SECRET_LEN]) -> Result<()> {
        let mut plain = Zeroizing::new([1u8; CODE_PLAIN_LEN]);
        plain[1..].copy_from_slice(secret);
        self.write_with(lock, CODE, &plain[..])
    }

    fn read_code(&self) -> Result<Zeroizing<[u8; TOTP_SECRET_LEN]>> {
        let plain = self.read(CODE)?;
        if plain.len() != CODE_PLAIN_LEN || plain[0] != 1 {
            return Err(SaveError::Format);
        }
        Ok(Zeroizing::new(plain[1..].try_into().expect("20 bytes")))
    }

    fn write_spare_lock(&self, lock: &PassLock, decoy: Option<&PassLock>) -> Result<()> {
        let mut plain = Zeroizing::new([0u8; SPARE_LOCK_PLAIN_LEN]);
        plain[0] = 1;
        match decoy {
            Some(d) => {
                plain[1] = 1;
                plain[SPARE_HEAD..SPARE_HEAD + passlock::HEADER_LEN].copy_from_slice(d.header());
                plain[SPARE_HEAD + passlock::HEADER_LEN..].copy_from_slice(d.base());
            }
            None => sodium::random(&mut plain[SPARE_HEAD..]),
        }
        self.write_with(lock, SPARE_LOCK, &plain[..])
    }

    /// Some(the decoy's lock, its factors still to set) if the save has a decoy, None if it hasn't,
    /// Err if its spare-lock file is missing or damaged.
    fn read_spare_lock(&self) -> std::result::Result<Option<PassLock>, ()> {
        let plain = self.read(SPARE_LOCK).map_err(|_| ())?;
        if plain.len() != SPARE_LOCK_PLAIN_LEN || plain[0] != 1 || plain[1] > 1 {
            return Err(());
        }
        Ok((plain[1] == 1).then(|| {
            let h = plain[SPARE_HEAD..SPARE_HEAD + passlock::HEADER_LEN].try_into().expect("a header");
            let b = plain[SPARE_HEAD + passlock::HEADER_LEN..].try_into().expect("a key");
            PassLock::from_parts(h, b)
        }))
    }

    fn write_decoy(&self, sl: &PassLock, code: Option<&[u8; TOTP_SECRET_LEN]>) -> Result<()> {
        let mut plain = Zeroizing::new([0u8; SPARE_PLAIN_LEN]);
        plain[0] = 1;
        if let Some(c) = code {
            plain[1] = 1;
            plain[SPARE_HEAD..].copy_from_slice(c);
        }
        self.write_with(sl, SPARE, &plain[..])
    }

    /// The spare made to need what the save needs: a decoy sealed again (with the save's code if it
    /// asks for one), or new chaff. Some(true) with a decoy, Some(false) without, None if it had one
    /// that couldn't be kept.
    fn spare_fit(&self, needs: u8) -> Option<bool> {
        let mut had = self.read_spare_lock();
        if let Ok(Some(sl)) = &mut had {
            let code = if needs & NEEDS_CODE != 0 { self.read_code().ok() } else { None };
            let zero = [0u8; 32];
            sl.set(
                needs,
                self.held.device.as_deref().unwrap_or(&zero),
                self.held.key.as_deref().unwrap_or(&zero),
            );
            if (code.is_some() || needs & NEEDS_CODE == 0) && self.write_decoy(sl, code.as_deref()).is_ok() {
                return Some(true);
            }
        }
        let _ = write_chaff(&self.dir, needs);
        if !matches!(had, Ok(None)) {
            let _ = self.write_spare_lock(&self.held.lock, None);
        }
        if matches!(had, Ok(Some(_))) { None } else { Some(false) }
    }

    fn old_decoy(&self) -> bool {
        self.dir.join(OLD_DECOY[0]).exists()
    }

    /// Opened with its own passphrase, a save is written just as when its decoy takes its place:
    /// every sealed file and the spare, so the files' times don't say which passphrase opened it.
    fn refresh(&mut self) {
        for f in SEALED.iter().map(|f| f.to_string()).chain(room_files(&self.dir)) {
            if let Ok(b) = read_file(&self.dir.join(&f), file_max(&f))
                && !b.is_empty()
            {
                let _ = write_private(&self.dir.join(&f), &b);
            }
        }
        // An early-format decoy can't be sealed again without its passphrase, so it stays as it is.
        if !self.old_decoy() && self.spare_fit(self.held.lock.needs()).is_none() {
            self.decoy_lost = true;
        }
    }

    /// Part way through a change (chat stopped, or a file swapped for one sealed with fewer
    /// factors), the save is finished the safer way: with every factor any of its files needs.
    fn finish_open(&mut self, all: u8) {
        if all != self.held.lock.needs() {
            self.relocked = Some(self.set_lock(all).is_ok());
        }
    }

    /// Whether the save has a decoy that a shadow passphrase opens.
    pub fn has_shadow(&self) -> bool {
        self.old_decoy() || matches!(self.read_spare_lock(), Ok(Some(_)))
    }

    /// A shadow passphrase: it opens a decoy (empty settings, no key) in the save's place. The decoy
    /// is sealed under its own passphrase and the save's factors, so it needs the same device,
    /// security key and code. Its spare is written first: until the spare's lock says so, the save
    /// doesn't count as having a decoy.
    pub fn set_shadow(&self, passphrase: &str) -> Result<()> {
        let needs = self.held.lock.needs();
        if (needs & NEEDS_DEVICE != 0 && self.held.device.is_none()) || (needs & NEEDS_KEY != 0 && self.held.key.is_none()) {
            return Err(SaveError::Failed("the save's own factors aren't all available".into()));
        }
        let sealed =
            read_sealed(&self.dir, lock_file(&self.dir)).map_err(|_| SaveError::Failed("the save's files can't be read".into()))?;
        if PassLock::of(passphrase.as_bytes(), &sealed)?.same_passphrase(&self.held.lock) {
            return Err(SaveError::Failed("that's the save's own passphrase".into()));
        }
        let mut sl = PassLock::new(passphrase.as_bytes())?;
        let zero = [0u8; 32];
        sl.set(
            needs,
            self.held.device.as_deref().unwrap_or(&zero),
            self.held.key.as_deref().unwrap_or(&zero),
        );
        let code = if needs & NEEDS_CODE != 0 {
            Some(
                self.read_code()
                    .map_err(|_| SaveError::Failed("its authenticator file can't be read".into()))?,
            )
        } else {
            None
        };
        if self.write_decoy(&sl, code.as_deref()).is_err() || self.write_spare_lock(&self.held.lock, Some(&sl)).is_err() {
            let _ = write_chaff(&self.dir, needs);
            return Err(SaveError::Failed("couldn't write the decoy's files".into()));
        }
        for f in OLD_DECOY {
            let _ = std::fs::remove_file(self.dir.join(f));
        }
        Ok(())
    }

    /// No shadow passphrase any more. The decoy goes before the spare's lock says there's none, so a
    /// passphrase the save is said not to have never opens one.
    pub fn clear_shadow(&self) -> Result<()> {
        write_chaff(&self.dir, self.held.lock.needs()).map_err(|e| SaveError::Failed(format!("couldn't write the spare's files: {e}")))?;
        self.write_spare_lock(&self.held.lock, None)?;
        for f in OLD_DECOY {
            let _ = std::fs::remove_file(self.dir.join(f));
        }
        Ok(())
    }

    /// A new authenticator secret to set up: its base32 text, and the otpauth:// link a QR code
    /// carries. The code it shows has to come back right ([`Save::confirm_code`]) before the save
    /// can ask for it.
    pub fn new_code(&mut self) -> (String, String) {
        let secret: Zeroizing<[u8; TOTP_SECRET_LEN]> = Zeroizing::new(sodium::random_array());
        let b32 = base32(&secret[..]);
        let uri = format!("otpauth://totp/chat:{}?secret={b32}&issuer=chat", self.name);
        self.new_code = Some((secret, false));
        (b32, uri)
    }

    /// Whether `code` is the new authenticator's code now.
    pub fn confirm_code(&mut self, code: &str) -> Result<()> {
        let Some((secret, confirmed)) = self.new_code.as_mut() else {
            return Err(SaveError::Wrong);
        };
        let v = passlock::parse_code(code).ok_or(SaveError::Format)?;
        if !passlock::code_matches(secret, v, unix_now()) {
            return Err(SaveError::Wrong);
        }
        *confirmed = true;
        Ok(())
    }

    /// Turns a factor on or off: every file is sealed again under the lock that needs the new set.
    pub fn set_factor(&mut self, factor: u8, on: bool) -> Result<()> {
        let have = self.held.lock.needs();
        let held = match factor {
            NEEDS_DEVICE => self.held.device.is_some(),
            NEEDS_KEY => self.held.key.is_some(),
            _ => false,
        };
        // Off, with a secret for it still held, some files may be left needing it, and are finished.
        if if on { have & factor != 0 } else { have & factor == 0 && !held } {
            return Ok(());
        }
        if on && factor == NEEDS_KEY && self.held.key.is_none() {
            return Err(SaveError::Failed("register a security key for it first".into()));
        }
        if on && factor == NEEDS_DEVICE {
            self.device_ready()?;
        }
        if on && factor == NEEDS_CODE && !matches!(self.new_code, Some((_, true))) {
            return Err(SaveError::Failed("no authenticator app is set up for it".into()));
        }
        self.set_lock(if on { have | factor } else { have & !factor })
    }

    /// Registers the security key plugged in for this save (another, if it has some already, up to
    /// four), and from then on the save needs one of them: a touch, and its PIN where it needs one.
    /// This blocks while it waits for the key.
    pub fn register_key(&mut self, pin: Option<&str>, wait: &crate::net::seckey::Wait) -> Result<()> {
        use crate::net::seckey::KeyError;
        if needs_but(&self.dir, None) & NEEDS_KEY != 0 && self.held.key.is_none() {
            return Err(SaveError::Failed(
                "some of its files need a security key whose secret chat doesn't have".into(),
            ));
        }
        let mut file = match (read_key_file(&self.dir), &self.held.key) {
            (Some(f), Some(_)) => f,
            _ => KeyFile {
                salt: sodium::random_array(),
                keys: Vec::new(),
            },
        };
        if file.keys.len() >= KEYS_MAX {
            return Err(SaveError::Failed(format!("{KEYS_MAX} security keys are registered already")));
        }
        let secret = self.held.key.clone().unwrap_or_else(|| Zeroizing::new(sodium::random_array()));
        let (cred, uv, kek) = crate::net::seckey::make(&file.salt, pin, wait).map_err(|e| match e {
            KeyError::Pin(why) => SaveError::KeyPin(why),
            e => SaveError::Failed(e.to_string()),
        })?;
        let mut entry = KeyEntry {
            uv,
            cred,
            wrapped: [0; passlock::WRAP_LEN],
        };
        entry.wrapped = passlock::secret_wrap(&kek, &file.ad(&entry), &secret);
        file.keys.push(entry);
        // Written before anything depends on it.
        write_private(&self.dir.join(SECKEY), &file.pack()).map_err(|_| SaveError::Failed("couldn't write its securitykey file".into()))?;
        self.held.key = Some(secret);
        let have = self.held.lock.needs();
        if have & NEEDS_KEY == 0 {
            self.set_lock(have | NEEDS_KEY)
        } else {
            Ok(())
        }
    }

    /// The device's secret, in the save's device file. One this device unsealed already is kept:
    /// files a crash left locked to it need it. If the file no longer gives it back, it's sealed
    /// again before anything depends on it.
    fn device_ready(&mut self) -> Result<()> {
        let secret = match &self.held.device {
            Some(d) => {
                if device_unseal(&self.dir).is_ok_and(|back| sodium::ct_eq(&back[..], &d[..])) {
                    return Ok(());
                }
                d.clone()
            }
            None if needs_but(&self.dir, None) & NEEDS_DEVICE != 0 => {
                return Err(SaveError::Device(
                    "some of its files are locked to a device secret this device can't unseal".into(),
                ));
            }
            None => Zeroizing::new(sodium::random_array()),
        };
        device_seal(&self.dir, &secret).map_err(SaveError::Device)?;
        self.held.device = Some(secret);
        Ok(())
    }

    /// Sealed again under the lock for `next`, if it isn't already: Ok(true), or Ok(false) if it
    /// couldn't be read (and is left as it was).
    fn reseal(&self, file: &str, next: &PassLock) -> Result<bool> {
        let sealed = match read_sealed(&self.dir, file) {
            Err(SaveError::NoFile) => return Ok(true),
            Ok(s) if s.len() >= passlock::HEADER_LEN && s[..passlock::HEADER_LEN] == next.header()[..] => return Ok(true),
            r => r,
        };
        let Ok(plain) = sealed.and_then(|s| self.held.unseal(&s)) else {
            return Ok(false);
        };
        self.write_with(next, file, &plain).map(|()| true)
    }

    /// The file that says how the save is locked, sealed again; from then on `next` is its lock.
    fn reseal_lock_file(&mut self, first: &str, next: &PassLock) -> Result<()> {
        if !self.reseal(first, next)? {
            return Err(SaveError::Failed(format!("its {first} file can't be read")));
        }
        self.held.lock = next.clone();
        Ok(())
    }

    /// Every file sealed again under the lock for `target`, whose factors' secrets are held. The
    /// lock file says how the save is locked, so it's sealed again last when adding factors and
    /// first when taking them away; a factor's own files are written before anything depends on
    /// them and deleted after nothing does. A crash in between leaves files sealed both ways, which
    /// [`Saves::unlock`] opens with all their factors.
    fn set_lock(&mut self, target: u8) -> Result<()> {
        let next = self.held.lock_needing(target);
        let have = self.held.lock.needs();
        let fewer = have & !target != 0;
        let first = lock_file(&self.dir);
        if target & NEEDS_CODE != 0
            && have & NEEDS_CODE == 0
            && let Some((secret, true)) = &self.new_code
        {
            self.write_code(&next, secret)?;
        }
        if fewer {
            self.reseal_lock_file(first, &next)?;
        }
        let mut skipped = 0;
        let rest = SEALED
            .iter()
            .map(|f| f.to_string())
            .filter(|f| f != first && !(f == CODE && target & NEEDS_CODE == 0));
        for f in rest.chain(room_files(&self.dir)) {
            if !self.reseal(&f, &next)? {
                skipped += 1;
            }
        }
        // Only a cache: one that can't be read or sealed again goes, and Tor starts afresh.
        match self.tor_cache() {
            Ok(Some(data)) if self.write_with(&next, CACHE, &data).is_ok() => {}
            Ok(None) => {}
            _ => self.forget_tor_cache(),
        }
        if !fewer {
            self.reseal_lock_file(first, &next)?;
        }
        // While the secrets of factors going away are still held.
        if !self.old_decoy() && self.spare_fit(target).is_none() {
            self.decoy_lost = true;
        }
        if target & NEEDS_CODE != 0 {
            self.new_code = None;
        }
        if target & NEEDS_CODE == 0 && needs_but(&self.dir, Some(CODE)) & NEEDS_CODE == 0 {
            let _ = std::fs::remove_file(self.dir.join(CODE));
        }
        let still = needs_but(&self.dir, None);
        if target & NEEDS_KEY == 0 && still & NEEDS_KEY == 0 {
            let _ = std::fs::remove_file(self.dir.join(SECKEY));
            self.held.key = None;
        }
        if target & NEEDS_DEVICE == 0 && still & NEEDS_DEVICE == 0 {
            forget_device(&self.dir);
            self.held.device = None;
        }
        if skipped > 0 {
            let (s, verb) = if skipped == 1 { ("is", "it was") } else { ("are", "they were") };
            return Err(SaveError::Failed(format!(
                "{skipped} of its files can't be read (damaged, or sealed some other way), and {s} left as {verb}"
            )));
        }
        Ok(())
    }
}

/// Where a saved signing key came from. A save keeps the number, so new ones go last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrigin {
    /// A new random key.
    Made = 0,
    /// Made from a password on this device.
    Derived = 1,
    /// Read from a key file, which is read again each time the save opens.
    File = 2,
    Pasted = 3,
    /// Made from a password on this device and the nick.
    DerivedNick = 4,
}

/// The signing key a save keeps: the key itself, or for one read from a file, that file's path.
pub struct SavedKey {
    /// [`IdentityKind::Age`] or [`IdentityKind::Pgp`].
    pub kind: IdentityKind,
    pub origin: KeyOrigin,
    /// When a PGP key says it was made (Unix seconds), so its fingerprint stays the same.
    pub pgp_created: u32,
    /// Kept even for a key read from a file, to tell whether the file still holds it.
    pub public: [u8; 32],
    /// The key, unless it's kept as its file's path.
    pub key: Option<IdentityKeypair>,
    pub path: Option<String>,
    /// For a key made with the nick, that nick.
    pub nick: Option<String>,
}

// The key file: its format, kind, origin, whether the secret is a scalar, the PGP creation time and
// the public key; then the secret (and a nick, for one made with it), or a path.
const KEY_FORMAT_KEY: u8 = 1;
const KEY_FORMAT_PATH: u8 = 2;
const KEY_HEAD: usize = 8 + 32;
const KEY_LEN: usize = KEY_HEAD + 64;
const KEY_PATH_MAX: usize = 1024;

impl SavedKey {
    pub fn pack(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(KEY_LEN + KEY_PATH_MAX));
        let path = self
            .path
            .as_deref()
            .filter(|_| self.origin == KeyOrigin::File && self.key.is_none());
        let scalar = self.key.as_ref().is_some_and(|k| k.to_parts().0);
        out.extend_from_slice(&[
            if path.is_some() { KEY_FORMAT_PATH } else { KEY_FORMAT_KEY },
            self.kind.wire(),
            self.origin as u8,
            u8::from(scalar),
        ]);
        out.extend_from_slice(&self.pgp_created.to_be_bytes());
        out.extend_from_slice(&self.public);
        match (path, &self.key) {
            (Some(p), _) => out.extend_from_slice(p.as_bytes()),
            (None, Some(k)) => {
                out.extend_from_slice(&k.to_parts().1[..]);
                if self.origin == KeyOrigin::DerivedNick {
                    out.extend_from_slice(self.nick.as_deref().unwrap_or("").as_bytes());
                }
            }
            (None, None) => {}
        }
        out
    }

    /// None if it isn't a key file chat wrote.
    pub fn unpack(b: &[u8]) -> Option<SavedKey> {
        if b.len() < KEY_HEAD {
            return None;
        }
        let kind = IdentityKind::from_wire(b[1]).filter(|k| *k != IdentityKind::Native)?;
        let origin = [
            KeyOrigin::Made,
            KeyOrigin::Derived,
            KeyOrigin::File,
            KeyOrigin::Pasted,
            KeyOrigin::DerivedNick,
        ]
        .into_iter()
        .find(|o| *o as u8 == b[2])?;
        if b[3] > 1 {
            return None;
        }
        let public: [u8; 32] = b[8..KEY_HEAD].try_into().expect("32 bytes");
        let text = |t: &[u8]| (!t.contains(&0)).then(|| String::from_utf8(t.to_vec()).ok()).flatten();
        let (key, path, nick) = match b[0] {
            KEY_FORMAT_PATH if origin == KeyOrigin::File && b.len() > KEY_HEAD && b.len() < KEY_HEAD + KEY_PATH_MAX => {
                (None, Some(text(&b[KEY_HEAD..])?), None)
            }
            KEY_FORMAT_KEY => {
                let nick_len = b.len().checked_sub(KEY_LEN)?;
                let with_nick = origin == KeyOrigin::DerivedNick;
                if with_nick != (nick_len > 0) || nick_len > crate::protocol::text::MAX_NICK {
                    return None;
                }
                let secret: &[u8; 64] = b[KEY_HEAD..KEY_LEN].try_into().expect("64 bytes");
                let key = IdentityKeypair::from_parts(&public, b[3] == 1, secret)?;
                (Some(key), None, with_nick.then(|| text(&b[KEY_LEN..])).flatten())
            }
            _ => return None,
        };
        if origin == KeyOrigin::DerivedNick && nick.is_none() {
            return None;
        }
        Some(SavedKey {
            kind,
            origin,
            pgp_created: u32::from_be_bytes(b[4..8].try_into().expect("4 bytes")),
            public,
            key,
            path,
            nick,
        })
    }
}

/// RFC 4648 base32, as authenticator apps take a secret.
fn base32(data: &[u8]) -> String {
    const ABC: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0);
    for b in data {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ABC[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ABC[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saves() -> (Saves, PathBuf) {
        let dir = std::env::temp_dir().join(format!("chat-saves-{}", hex::encode(&sodium::random_array::<6>())));
        (Saves::at(dir.join("chat")), dir)
    }

    fn open(s: &Saves, name: &str, pass: &str) -> Result<Save> {
        match s.unlock(name, pass, true, None)? {
            Unlocked::Open(save) => Ok(save),
            Unlocked::Code(_) => panic!("asks for a code"),
        }
    }

    #[test]
    fn saves_and_opens_files() {
        let (s, tmp) = saves();
        let save = s.create("default", "pw", 0, None).unwrap();
        save.set_settings("[profile]\nnick = \"alice\"\n").unwrap();
        save.set_key(b"secret key").unwrap();
        save.set_history(&[7; 16], b"line").unwrap();
        let waiting = vec![
            Queued {
                mid: "0a1b2c3d".into(),
                text: "see you\tat 5".into(),
                at: 1_800_000_000,
            },
            Queued {
                mid: "4e5f6a7b".into(),
                text: "> you: hi\nback".into(),
                at: 1_800_000_060,
            },
        ];
        save.set_outbox(&[7; 16], &waiting).unwrap();
        assert_eq!(
            std::fs::metadata(s.top.join(SETTINGS)).unwrap().len() as usize,
            SETTINGS_PAD + SEAL_OVERHEAD
        );
        let list = s.list();
        assert_eq!((list.len(), list[0].name.as_str(), list[0].key), (1, "default", true));
        let save = open(&s, "default", "pw").unwrap();
        assert_eq!(save.settings().unwrap(), "[profile]\nnick = \"alice\"\n");
        assert_eq!(&save.key().unwrap().unwrap()[..], b"secret key");
        assert_eq!(&save.history(&[7; 16]).unwrap().unwrap()[..], b"line");
        assert!(save.history(&[8; 16]).unwrap().is_none());
        let back = save.outbox(&[7; 16]).unwrap();
        assert_eq!((back[0].text.as_str(), back[1].text.as_str()), ("see you at 5", "> you: hi back"));
        assert_eq!((back[1].mid.as_str(), back[1].at), ("4e5f6a7b", 1_800_000_060));
        assert!(save.outbox(&[8; 16]).unwrap().is_empty());
        // Forgetting histories leaves what waits to go; nothing waiting leaves no file.
        save.forget_history(None);
        assert_eq!(save.outbox(&[7; 16]).unwrap().len(), 2);
        save.set_outbox(&[7; 16], &[]).unwrap();
        assert!(!s.top.join(outbox_file(&[7; 16])).exists());
        assert_eq!(open(&s, "default", "nope").err(), Some(SaveError::Wrong));
        assert!(s.dir("nope/../x", false).is_err());
        s.remove("default").unwrap();
        assert!(s.list().is_empty());
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn destroys_itself_after_wrong_passphrases() {
        let (s, tmp) = saves();
        let save = s.create("work", "pw", 0, None).unwrap();
        // A save always has its settings, written as it's made.
        save.set_settings("").unwrap();
        save.set_destroy_limit(2).unwrap();
        assert_eq!(open(&s, "work", "x").err(), Some(SaveError::Wrong));
        assert_eq!(save.tries_left(), Some(1));
        assert!(open(&s, "work", "pw").is_ok(), "the right one resets the count");
        assert_eq!(save.tries_left(), Some(2));
        assert_eq!(open(&s, "work", "x").err(), Some(SaveError::Wrong));
        assert!(matches!(open(&s, "work", "y").err(), Some(SaveError::Destroyed(_))));
        assert!(s.list().is_empty());
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn the_shadow_passphrase_opens_a_decoy_in_its_place() {
        let (s, tmp) = saves();
        let save = s.create("default", "real", 0, None).unwrap();
        save.set_settings("nick = \"me\"").unwrap();
        save.set_key(b"k").unwrap();
        assert!(!save.has_shadow());
        assert!(save.set_shadow("real").is_err());
        save.set_shadow("decoy").unwrap();
        assert!(save.has_shadow());
        // Opened with its own passphrase, it keeps its decoy.
        let save = open(&s, "default", "real").unwrap();
        assert!(save.has_shadow());
        assert_eq!(save.lock_try("real"), Ok(()));
        assert_eq!(save.lock_try("decoy"), Err(SaveError::Decoy));
        let decoy = open(&s, "default", "decoy").unwrap();
        assert_eq!(decoy.settings().unwrap(), "");
        assert!(decoy.key().unwrap().is_none());
        assert!(!decoy.has_shadow());
        assert_eq!(open(&s, "default", "real").err(), Some(SaveError::Wrong));
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn an_authenticator_code_is_asked_for() {
        let (s, tmp) = saves();
        let mut save = s.create("default", "pw", 0, None).unwrap();
        save.set_settings("x = 1").unwrap();
        let (b32, uri) = save.new_code();
        assert_eq!(b32.len(), 32);
        assert!(uri.starts_with("otpauth://totp/chat:default?secret="));
        assert!(save.set_factor(NEEDS_CODE, true).is_err(), "not until its code came back right");
        let secret = save.new_code.as_ref().unwrap().0.clone();
        let code = |s: &[u8; 20]| format!("{:06}", passlock::totp_code(s, unix_now() / passlock::TOTP_PERIOD));
        save.confirm_code(&code(&secret)).unwrap();
        save.set_factor(NEEDS_CODE, true).unwrap();
        assert_eq!(save.factors(), NEEDS_CODE);
        let Unlocked::Code(pending) = s.unlock("default", "pw", true, None).unwrap() else {
            panic!("no code asked for")
        };
        let save = pending.check(&code(&secret)).map_err(|e| e.1).unwrap();
        assert_eq!(save.settings().unwrap(), "x = 1");
        let mut save = save;
        save.set_factor(NEEDS_CODE, false).unwrap();
        assert!(!s.top.join(CODE).exists());
        assert!(open(&s, "default", "pw").is_ok());
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn base32_is_rfc_4648() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"12345678901234567890"), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }
    #[test]
    fn key_files_round_trip() {
        let k = IdentityKeypair::generate();
        let saved = SavedKey {
            kind: IdentityKind::Pgp,
            origin: KeyOrigin::DerivedNick,
            pgp_created: 7,
            public: k.public,
            key: Some(k.clone()),
            path: None,
            nick: Some("alice".into()),
        };
        let b = saved.pack();
        assert_eq!((b.len(), b[0], b[1], b[2], b[3]), (KEY_LEN + 5, KEY_FORMAT_KEY, 3, 4, 0));
        let back = SavedKey::unpack(&b).unwrap();
        assert_eq!(
            (back.kind, back.origin, back.pgp_created, back.nick.as_deref()),
            (IdentityKind::Pgp, KeyOrigin::DerivedNick, 7, Some("alice"))
        );
        assert_eq!(back.key.unwrap().public, k.public);
        let age = IdentityKeypair::from_x25519(&[9; 32]).unwrap();
        let b = SavedKey {
            kind: IdentityKind::Age,
            origin: KeyOrigin::File,
            pgp_created: 0,
            public: age.public,
            key: None,
            path: Some("/k.txt".into()),
            nick: None,
        }
        .pack();
        assert_eq!((b.len(), b[0]), (KEY_HEAD + 6, KEY_FORMAT_PATH));
        assert_eq!(SavedKey::unpack(&b).unwrap().path.as_deref(), Some("/k.txt"));
        let b = SavedKey {
            kind: IdentityKind::Age,
            origin: KeyOrigin::Made,
            pgp_created: 0,
            public: age.public,
            key: Some(age.clone()),
            path: None,
            nick: None,
        }
        .pack();
        assert_eq!(b[3], 1, "an AGE key's secret is a scalar");
        assert_eq!(SavedKey::unpack(&b).unwrap().key.unwrap().public, age.public);
        let mut bad = b.to_vec();
        bad[8] ^= 1;
        assert!(SavedKey::unpack(&bad).is_none(), "a public key the secret doesn't give");
    }

    #[test]
    fn security_key_files_round_trip() {
        let mut f = KeyFile {
            salt: [3; 32],
            keys: Vec::new(),
        };
        let e = KeyEntry {
            uv: true,
            cred: vec![9; 70],
            wrapped: [0; passlock::WRAP_LEN],
        };
        let w = passlock::secret_wrap(&[1; 32], &f.ad(&e), &[2; 32]);
        f.keys.push(KeyEntry { wrapped: w, ..e });
        let b = f.pack();
        assert_eq!(&b[..4], b"CSK1");
        assert_eq!(b.len(), 4 + 32 + 1 + 3 + 70 + passlock::WRAP_LEN);
        let back = KeyFile::parse(&b).unwrap();
        assert_eq!((back.keys.len(), back.keys[0].uv, back.keys[0].cred.len()), (1, true, 70));
        assert_eq!(
            *passlock::secret_unwrap(&[1; 32], &back.ad(&back.keys[0]), &back.keys[0].wrapped).unwrap(),
            [2; 32]
        );
        assert!(KeyFile::parse(&b[..b.len() - 1]).is_none());
    }
}
