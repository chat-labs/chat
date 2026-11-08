// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Your signing identity: an AGE or PGP key, made here (at random, or from a password with this
//! device's id and your nick), or read from a key file. Peers who verify it once needn't compare
//! codes with you again, in any room, and it's what :call works out a room with.

use chat_core::IdentityKind;
use chat_core::protocol::crypto::{self, identity::IdentityKeypair, pgp};
use chat_core::protocol::hex;

/// Where the key in use came from.
#[derive(Clone)]
pub enum Origin {
    /// Made at random: it lasts until chat exits.
    Made,
    /// Made from a password, with this nick (None: without one).
    Password(Option<String>),
    File(String),
    /// Pasted in: there's no file to point to, so a save seals the key itself.
    Pasted,
}

#[derive(Clone)]
pub struct Ident {
    pub kind: IdentityKind,
    pub kp: IdentityKeypair,
    pub origin: Origin,
    /// A PGP key's creation time, which its fingerprint covers.
    pub created: u32,
}

/// The largest key file read.
const KEY_FILE_MAX: u64 = 16 * 1024;

fn now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs()) as u32
}

impl Ident {
    pub fn made(kind: IdentityKind) -> Self {
        Ident {
            kind,
            kp: IdentityKeypair::generate(),
            origin: Origin::Made,
            created: now(),
        }
    }

    /// From a password, this device's id, and the nick unless it's None: the same every time.
    /// Blocking (Argon2id, 512 MiB): run it off the UI.
    pub fn from_password(kind: IdentityKind, password: &str, nick: Option<&str>) -> Result<Self, String> {
        let device = chat_core::net::device::machine_id()
            .ok_or("this system has no machine id to make the key with - /identity new makes a key for this run")?;
        let kp = IdentityKeypair::from_password(password, &device, nick)
            .map_err(|_| "couldn't make the key - it needs 512 MiB of free memory for a moment")?;
        Ok(Ident {
            kind,
            kp,
            origin: Origin::Password(nick.map(str::to_string)),
            created: pgp::DERIVED_CREATED,
        })
    }

    /// A key of `kind` pasted in: an AGE key's line (or its whole file), or an armored PGP key.
    pub fn from_text(text: &str, kind: IdentityKind) -> Option<Self> {
        let (k, kp) = IdentityKeypair::from_key_text(text).filter(|(k, _)| *k == kind)?;
        Some(Ident {
            kind: k,
            kp,
            origin: Origin::Pasted,
            created: now(),
        })
    }

    /// An AGE key file (as age-keygen writes it) or an unencrypted, armored PGP EdDSA key.
    pub fn from_file(path: &str) -> Result<Self, String> {
        let f = std::fs::File::open(path).map_err(|e| format!("can't read {path}: {e}"))?;
        let mut text = zeroize::Zeroizing::new(String::new());
        use std::io::Read;
        f.take(KEY_FILE_MAX)
            .read_to_string(&mut text)
            .map_err(|_| format!("{path} isn't a key file"))?;
        let (kind, kp) = IdentityKeypair::from_key_text(&text)
            .ok_or_else(|| format!("{path} holds no AGE secret key or unencrypted PGP EdDSA secret key"))?;
        Ok(Ident {
            kind,
            kp,
            origin: Origin::File(path.to_string()),
            created: now(),
        })
    }

    pub fn fingerprint(&self) -> String {
        hex::groups(&crypto::fingerprint(&self.kp.public))
    }

    /// What others use to check it or write to it: an AGE recipient, or a PGP public key.
    pub fn public_text(&self, nick: &str) -> String {
        match self.kind {
            IdentityKind::Pgp => pgp::export_public(&self.kp, nick, self.created).0,
            _ => self.kp.age_strings().map(|(r, _)| r).unwrap_or_default(),
        }
    }

    /// The secret key as a file holds it, and the file's usual name. None for a PGP key read
    /// from a file (its user ids and signatures aren't kept, so only that file has the whole key).
    pub fn secret_file(&self, nick: &str) -> Option<(zeroize::Zeroizing<String>, &'static str)> {
        match (self.kind, &self.origin) {
            (IdentityKind::Pgp, Origin::File(_) | Origin::Pasted) => None,
            (IdentityKind::Pgp, _) => pgp::export_secret(&self.kp, nick, self.created).map(|(s, _)| (s, "pgp-secret-key.asc")),
            _ => {
                let (recipient, secret) = self.kp.age_strings()?;
                Some((
                    zeroize::Zeroizing::new(format!("# public key: {recipient}\n{}\n", secret.as_str())),
                    "age-secret-key.txt",
                ))
            }
        }
    }

    /// The file it's exported as, or None for a PGP key read from a file, which isn't exported.
    pub fn export_name(&self) -> Option<&'static str> {
        match (self.kind, &self.origin) {
            (IdentityKind::Pgp, Origin::File(_) | Origin::Pasted) => None,
            (IdentityKind::Pgp, _) => Some("pgp-secret-key.asc"),
            _ => Some("age-secret-key.txt"),
        }
    }

    /// What /identity says about it.
    pub fn describe(&self) -> Vec<String> {
        let kind = match self.kind {
            IdentityKind::Pgp => "a PGP",
            _ => "an AGE",
        };
        let from = match &self.origin {
            Origin::Made => "made for this run (it's gone when chat exits)".to_string(),
            Origin::Password(Some(n)) => format!("made from your password and the nick {n} on this device"),
            Origin::Password(None) => "made from your password on this device".to_string(),
            Origin::File(p) => format!("from {p}"),
            Origin::Pasted => "pasted in".to_string(),
        };
        let mut lines = vec![
            format!("signing as {kind} key, {from}"),
            format!(
                "its fingerprint: {} - compare it with peers over another channel",
                self.fingerprint()
            ),
        ];
        if self.kind != IdentityKind::Pgp
            && let Some((recipient, _)) = self.kp.age_strings()
        {
            lines.push(format!("AGE recipient (others can age -r encrypt files to you): {recipient}"));
        }
        lines.push("/identity copy copies your public key, /exportkey FOLDER writes the secret one".into());
        lines
    }
}

/// The names a key is exported as, in the order they're tried: "name.ext", "name (2).ext"...
fn export_names(name: &str) -> impl Iterator<Item = String> + '_ {
    let (stem, ext) = name.rsplit_once('.').expect("names have an extension");
    (1..100).map(move |k| if k == 1 { name.to_string() } else { format!("{stem} ({k}).{ext}") })
}

/// The file an export to `dir` would write: the first of its names nothing there has.
pub fn export_path(ident: &Ident, dir: &std::path::Path) -> Option<std::path::PathBuf> {
    export_names(ident.export_name()?)
        .map(|f| dir.join(f))
        .find(|p| std::fs::symlink_metadata(p).is_err())
}

/// Writes the secret key to a new file in `dir`, readable by you alone, never replacing a file.
pub fn export(ident: &Ident, nick: &str, dir: &str) -> Result<String, String> {
    let (text, name) = ident
        .secret_file(nick)
        .ok_or("a PGP key read from a file isn't exported - that file has it, with its user ids")?;
    for file in export_names(name) {
        let path = std::path::Path::new(dir).join(file);
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        match o.open(&path) {
            Ok(mut f) => {
                use std::io::Write;
                if f.write_all(text.as_bytes()).and_then(|_| f.sync_all()).is_err() {
                    let _ = std::fs::remove_file(&path);
                    return Err(format!("couldn't write {}", path.display()));
                }
                return Ok(path.display().to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("couldn't write in {dir}: {e}")),
        }
    }
    Err(format!("{dir} has no free name for the key"))
}
