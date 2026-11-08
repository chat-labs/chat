// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Signing keys the user verified (compared a code with their holder) or ignores, with the nick
//! each had. One list for every room in a client: a peer signing with a verified key needn't
//! compare codes again in any room, and an ignored key is hidden wherever it turns up. The UI
//! keeps the lists (each change bumps [`TrustStore::version`]); nothing here touches a disk.

use crate::protocol::crypto::identity::IdentityKind;
use crate::protocol::{hex, text};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

pub const TRUST_MAX: usize = 128;
pub const IGNORE_MAX: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustEntry {
    pub kind: IdentityKind,
    #[serde(with = "hex32")]
    pub public: [u8; 32],
    pub nick: String,
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::protocol::hex::encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        crate::protocol::hex::decode_array(&s.to_ascii_lowercase()).ok_or_else(|| serde::de::Error::custom("64 hex digits"))
    }
}

#[derive(Default, Debug)]
pub struct TrustStore {
    verified: Vec<TrustEntry>,
    ignored: Vec<TrustEntry>,
    version: u64,
}

pub type SharedTrust = Arc<Mutex<TrustStore>>;

/// How a save names a key's kind.
pub(crate) fn kind_name(kind: IdentityKind) -> &'static str {
    match kind {
        IdentityKind::Native => "key",
        IdentityKind::Age => "age",
        IdentityKind::Pgp => "pgp",
    }
}

pub(crate) fn kind_from_name(name: &str) -> Option<IdentityKind> {
    [IdentityKind::Native, IdentityKind::Age, IdentityKind::Pgp]
        .into_iter()
        .find(|k| kind_name(*k) == name)
}

fn same_skel(e: &TrustEntry, skel: &str) -> bool {
    text::nick_skeleton(&e.nick) == skel
}

fn add_to(list: &mut Vec<TrustEntry>, max: usize, kind: IdentityKind, public: &[u8; 32], nick: &str) -> bool {
    if let Some(e) = list.iter_mut().find(|e| e.public == *public) {
        if e.nick == nick && e.kind == kind {
            return false;
        }
        e.nick = nick.to_string();
        e.kind = kind;
        return true;
    }
    if list.len() >= max {
        list.remove(0);
    }
    list.push(TrustEntry {
        kind,
        public: *public,
        nick: nick.to_string(),
    });
    true
}

impl TrustStore {
    pub fn shared() -> SharedTrust {
        Arc::new(Mutex::new(TrustStore::default()))
    }

    /// Goes up with every change, so a UI can tell when to save the lists again.
    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn verified(&self) -> &[TrustEntry] {
        &self.verified
    }

    pub fn ignored(&self) -> &[TrustEntry] {
        &self.ignored
    }

    pub fn set_verified(&mut self, list: Vec<TrustEntry>) {
        self.verified = list;
        self.verified.truncate(TRUST_MAX);
        self.version += 1;
    }

    pub fn set_ignored(&mut self, list: Vec<TrustEntry>) {
        self.ignored = list;
        self.ignored.truncate(IGNORE_MAX);
        self.version += 1;
    }

    pub fn verified_by_key(&self, public: &[u8; 32]) -> Option<&TrustEntry> {
        self.verified.iter().find(|e| e.public == *public)
    }

    /// A verified entry whose nick looks the same as this skeleton.
    pub fn verified_by_nick(&self, skel: &str) -> Option<&TrustEntry> {
        self.verified.iter().find(|e| same_skel(e, skel))
    }

    /// The verified keys as a save keeps them: a line each, "KIND HEX NICK".
    pub fn verified_text(&self) -> String {
        self.verified
            .iter()
            .map(|e| format!("{} {} {}\n", kind_name(e.kind), hex::encode(&e.public), e.nick))
            .collect()
    }

    /// Adds the keys in `text`, as [`TrustStore::verified_text`] writes it, that aren't verified
    /// already. Returns how many lines couldn't be read.
    pub fn load_verified(&mut self, text: &str) -> usize {
        let mut bad = 0;
        for line in text.split('\n').filter(|l| !l.is_empty()) {
            let mut it = line.splitn(3, ' ');
            let (kind, key, nick) = (it.next(), it.next(), it.next());
            let kind = kind.and_then(kind_from_name);
            let key = key.and_then(hex::decode_array::<32>);
            match (kind, key, nick.filter(|n| !n.is_empty())) {
                (Some(kind), Some(key), Some(nick)) => {
                    if self.verified_by_key(&key).is_none() {
                        self.verify(kind, &key, nick);
                    }
                }
                _ => bad += 1,
            }
        }
        bad
    }

    /// Adds the key, or updates its nick. When full, the oldest goes.
    pub fn verify(&mut self, kind: IdentityKind, public: &[u8; 32], nick: &str) {
        if add_to(&mut self.verified, TRUST_MAX, kind, public, nick) {
            self.version += 1;
        }
    }

    /// Removes every verified key with a nick that looks like this one. Returns how many.
    pub fn forget_nick(&mut self, skel: &str) -> usize {
        let before = self.verified.len();
        self.verified.retain(|e| !same_skel(e, skel));
        let n = before - self.verified.len();
        if n > 0 {
            self.version += 1;
        }
        n
    }

    pub fn ignored_by_key(&self, public: &[u8; 32]) -> Option<&TrustEntry> {
        self.ignored.iter().find(|e| e.public == *public)
    }

    pub fn ignore(&mut self, kind: IdentityKind, public: &[u8; 32], nick: &str) {
        if add_to(&mut self.ignored, IGNORE_MAX, kind, public, nick) {
            self.version += 1;
        }
    }

    pub fn unignore(&mut self, public: &[u8; 32]) -> bool {
        let before = self.ignored.len();
        self.ignored.retain(|e| e.public != *public);
        let changed = self.ignored.len() != before;
        if changed {
            self.version += 1;
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists() {
        let mut t = TrustStore::default();
        t.verify(IdentityKind::Native, &[1; 32], "bob");
        let v = t.version();
        t.verify(IdentityKind::Native, &[1; 32], "bob");
        assert_eq!(t.version(), v);
        t.verify(IdentityKind::Native, &[1; 32], "robert");
        assert_eq!(t.verified().len(), 1);
        assert!(t.verified_by_nick(&text::nick_skeleton("R0BERT")).is_some());
        assert_eq!(t.forget_nick(&text::nick_skeleton("robert")), 1);
        let json = serde_json::to_string(&TrustEntry {
            kind: IdentityKind::Age,
            public: [2; 32],
            nick: "x".into(),
        })
        .unwrap();
        assert!(json.contains("\"kind\":\"age\""));
    }

    #[test]
    fn verified_keys_round_trip_as_text() {
        let mut t = TrustStore::default();
        t.verify(IdentityKind::Age, &[1; 32], "alice");
        t.verify(IdentityKind::Native, &[2; 32], "bob two");
        let text = t.verified_text();
        assert_eq!(text.lines().next().unwrap(), format!("age {} alice", "01".repeat(32)));
        let mut u = TrustStore::default();
        u.verify(IdentityKind::Pgp, &[2; 32], "kept");
        assert_eq!(
            u.load_verified(&format!(
                "{text}bad line
key {} \n",
                "03".repeat(32)
            )),
            2
        );
        assert_eq!(u.verified().len(), 2);
        assert_eq!(u.verified_by_key(&[2; 32]).unwrap().nick, "kept");
        assert_eq!(u.verified_by_key(&[1; 32]).unwrap().nick, "alice");
    }
}
