// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! minisign signatures, which chat's releases are signed with. A peer's "v" sends its release's
//! signed list of binaries, and these keys check it.

use super::sodium;
use crate::protocol::base64;

/// The release key, and its backup.
pub const RELEASE_KEY: &str = "RWSR+ZdG2DibcI2waaAukeezQJcX5D5BcYHmZ2lOzLVATd2FnlS7YEZB";
pub const RELEASE_BACKUP_KEY: &str = "RWSBLoedJe9qDz41AqUhdHq4AySS9e7sB3bnIe1lEAi1mQkN25aD5JCv";

const ALG_LEN: usize = 2;
const KEY_ID_LEN: usize = 8;
const BODY: usize = ALG_LEN + KEY_ID_LEN;

/// A minisign public key: "Ed", its key id, and an Ed25519 key.
#[derive(Clone)]
pub struct PublicKey {
    key_id: [u8; KEY_ID_LEN],
    ed: [u8; 32],
}

impl PublicKey {
    pub fn from_base64(b64: &str) -> Option<Self> {
        let raw = base64::decode_strict(b64.trim())?;
        if raw.len() != BODY + 32 || &raw[..ALG_LEN] != b"Ed" {
            return None;
        }
        Some(PublicKey {
            key_id: raw[ALG_LEN..BODY].try_into().ok()?,
            ed: raw[BODY..].try_into().ok()?,
        })
    }

    /// Checks a signature line over msg: "ED" signs BLAKE2b-512 of it (minisign's default),
    /// "Ed" signs it as it is.
    pub fn verify(&self, msg: &[u8], sig_b64: &str) -> bool {
        self.signature(msg, sig_b64).is_some()
    }

    /// The raw Ed25519 signature of a signature line that checks out over msg.
    fn signature(&self, msg: &[u8], sig_b64: &str) -> Option<[u8; 64]> {
        let raw = base64::decode_strict(sig_b64.trim())?;
        if raw.len() != BODY + 64 || raw[ALG_LEN..BODY] != self.key_id {
            return None;
        }
        let sig: [u8; 64] = raw[BODY..].try_into().expect("64 bytes");
        let ok = match &raw[..ALG_LEN] {
            b"ED" => {
                let mut h = [0u8; 64];
                sodium::blake2b(&mut h, &[], &[msg]);
                sodium::ed25519_verify(&self.ed, &sig, &h)
            }
            b"Ed" => sodium::ed25519_verify(&self.ed, &sig, msg),
            _ => false,
        };
        ok.then_some(sig)
    }

    /// Checks a whole .minisig over msg: its signature line, and its trusted comment, which must
    /// be `trusted` and is signed along with the signature by the last line.
    pub fn verify_minisig(&self, msg: &[u8], minisig: &str, trusted: &str) -> bool {
        let mut lines = minisig.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
        let (Some(_untrusted), Some(sig_line), Some(comment_line), Some(global)) = (lines.next(), lines.next(), lines.next(), lines.next())
        else {
            return false;
        };
        let Some(comment) = comment_line.strip_prefix("trusted comment: ") else {
            return false;
        };
        if comment != trusted {
            return false;
        }
        let Some(global) = base64::decode_strict(global).and_then(|g| <[u8; 64]>::try_from(g).ok()) else {
            return false;
        };
        let Some(sig) = self.signature(msg, sig_line) else {
            return false;
        };
        sodium::ed25519_verify(&self.ed, &global, &[&sig[..], comment.as_bytes()].concat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_keys_parse() {
        assert!(PublicKey::from_base64(RELEASE_KEY).is_some());
        assert!(PublicKey::from_base64(RELEASE_BACKUP_KEY).is_some());
        assert!(PublicKey::from_base64("RWQ").is_none());
    }

    #[test]
    fn a_minisig_holds_only_with_its_own_trusted_comment() {
        let (ed, sk) = sodium::ed25519_seed_keypair(&[7; 32]);
        let key = PublicKey {
            key_id: [1, 2, 3, 4, 5, 6, 7, 8],
            ed,
        };
        let msg = b"0123  chat-linux-x86_64\n";
        let mut h = [0u8; 64];
        sodium::blake2b(&mut h, &[], &[msg]);
        let sig = sodium::ed25519_sign(&sk, &h);
        let line = base64::encode(&[&b"ED"[..], &key.key_id, &sig].concat());
        let minisig = |comment: &str| {
            let global = sodium::ed25519_sign(&sk, &[&sig[..], comment.as_bytes()].concat());
            format!(
                "untrusted comment: x\n{line}\ntrusted comment: {comment}\n{}\n",
                base64::encode(&global)
            )
        };
        assert!(key.verify_minisig(msg, &minisig("chat v0.6.0"), "chat v0.6.0"));
        assert!(!key.verify_minisig(msg, &minisig("chat v0.5.0"), "chat v0.6.0"));
        assert!(!key.verify_minisig(b"other", &minisig("chat v0.6.0"), "chat v0.6.0"));
        // An older release's comment changed to this one's, under the old global signature.
        let swapped = minisig("chat v0.5.0").replace("chat v0.5.0", "chat v0.6.0");
        assert!(!key.verify_minisig(msg, &swapped, "chat v0.6.0"));
    }
}
