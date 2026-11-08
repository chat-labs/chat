// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Secrets kept on disk under one passphrase. A lock is the key Argon2id makes from it with a salt,
//! plus its header (format, limits, salt). XChaCha20-Poly1305 seals each secret under that key,
//! with the header as associated data, so one Argon2id run opens everything sealed under a lock.
//!
//! A lock can also need other factors: a device, a security key, an authenticator app's code. Its
//! header says which, and its key is then the passphrase's key mixed with the device's secret and
//! the security key's. Without them the passphrase opens nothing, and since the header is
//! associated data, it can't be changed to say otherwise. The code adds no secret: it's checked
//! once the files are open.

use super::sodium::{self, AEAD_NONCE_LEN, AEAD_TAG_LEN};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const HEADER_LEN: usize = 32;
pub const SEAL_OVERHEAD: usize = HEADER_LEN + AEAD_NONCE_LEN + AEAD_TAG_LEN;
pub const KEY_LEN: usize = 32;
pub const NEEDS_DEVICE: u8 = 1;
pub const NEEDS_KEY: u8 = 2;
pub const NEEDS_CODE: u8 = 4;
pub const NEEDS_ALL: u8 = 7;

const MAGIC: &[u8; 8] = b"chatkey1";
const DEVICE_MAGIC: &[u8; 8] = b"chatdev1";
const FACTORS_MAGIC: &[u8; 7] = b"chatmfa";
const OPS_AT: usize = 8;
const MEM_AT: usize = 12;
const SALT_AT: usize = 16;
// Limits above these mean a tampered file, which could otherwise ask for any amount of memory.
const OPS_MAX: u32 = 16;
const MEM_KIB_MIN: u32 = 8;
const MEM_KIB_MAX: u32 = 1024 * 1024;
// New locks use a session's limits; chat-core's own unit tests use tiny ones, to run in little memory.
const NEW_OPS: u32 = if cfg!(test) { 1 } else { super::KDF_OPS as u32 };
const NEW_MEM_KIB: u32 = if cfg!(test) { MEM_KIB_MIN } else { (super::KDF_MEM / 1024) as u32 };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassError {
    /// The wrong passphrase, or sealed under another lock, or changed since.
    Wrong,
    /// Not enough free memory for Argon2id.
    NoMemory,
    /// Not something sealed this way.
    Format,
}

/// The factors a header needs, or None if it isn't one of these headers. A device alone is
/// always "chatdev1", so each set of factors has the one header.
fn header_needs(h: &[u8]) -> Option<u8> {
    if h.len() < MAGIC.len() {
        return None;
    }
    if &h[..8] == MAGIC {
        return Some(0);
    }
    if &h[..8] == DEVICE_MAGIC {
        return Some(NEEDS_DEVICE);
    }
    let needs = h[7];
    (&h[..7] == FACTORS_MAGIC && needs & !NEEDS_ALL == 0 && needs & (NEEDS_KEY | NEEDS_CODE) != 0).then_some(needs)
}

fn set_magic(h: &mut [u8; HEADER_LEN], needs: u8) {
    match needs {
        0 => h[..8].copy_from_slice(MAGIC),
        NEEDS_DEVICE => h[..8].copy_from_slice(DEVICE_MAGIC),
        n => {
            h[..7].copy_from_slice(FACTORS_MAGIC);
            h[7] = n;
        }
    }
}

fn new_header() -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    set_magic(&mut h, 0);
    h[OPS_AT..MEM_AT].copy_from_slice(&NEW_OPS.to_be_bytes());
    h[MEM_AT..SALT_AT].copy_from_slice(&NEW_MEM_KIB.to_be_bytes());
    sodium::random(&mut h[SALT_AT..]);
    h
}

/// The factors what was sealed needs; 0 for the passphrase alone (or something else entirely).
pub fn needs_of(sealed: &[u8]) -> u8 {
    header_needs(sealed).unwrap_or(0)
}

/// Random bytes the shape of `plain_len` bytes sealed under a new lock needing `needs`, header and
/// all: without the passphrase, nothing tells them from the real thing.
pub fn chaff(needs: u8, plain_len: usize) -> Vec<u8> {
    let mut h = new_header();
    set_magic(&mut h, needs & NEEDS_ALL);
    let mut out = vec![0u8; SEAL_OVERHEAD + plain_len];
    out[..HEADER_LEN].copy_from_slice(&h);
    sodium::random(&mut out[HEADER_LEN..]);
    out
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PassLock {
    header: [u8; HEADER_LEN],
    key: [u8; KEY_LEN],
    /// The passphrase's key alone.
    base: [u8; KEY_LEN],
    /// The factors `key` has in it.
    needs: u8,
}

impl PassLock {
    /// A new lock with its own salt.
    pub fn new(passphrase: &[u8]) -> Result<Self, PassError> {
        Self::derive(new_header(), passphrase)
    }

    /// The lock `sealed` was sealed under, if `passphrase` is the right one (only `unseal` can
    /// tell). If it needs more factors, nothing opens until `set` gives their secrets.
    pub fn of(passphrase: &[u8], sealed: &[u8]) -> Result<Self, PassError> {
        if sealed.len() < SEAL_OVERHEAD || header_needs(sealed).is_none() {
            return Err(PassError::Format);
        }
        Self::derive(sealed[..HEADER_LEN].try_into().expect("a header"), passphrase)
    }

    /// The lock `passphrase` makes with `like`'s salt: its base is `like`'s only if it's the
    /// passphrase `like` was made from (see [`PassLock::same_passphrase`]).
    pub fn like(passphrase: &[u8], like: &PassLock) -> Result<Self, PassError> {
        Self::derive(like.header, passphrase)
    }

    /// A lock from its header and passphrase key, as kept for a decoy. Its factors still need setting.
    pub fn from_parts(header: [u8; HEADER_LEN], base: [u8; KEY_LEN]) -> Self {
        PassLock {
            header,
            key: [0; KEY_LEN],
            base,
            needs: 0,
        }
    }

    pub fn header(&self) -> &[u8; HEADER_LEN] {
        &self.header
    }

    pub fn base(&self) -> &[u8; KEY_LEN] {
        &self.base
    }

    pub fn needs(&self) -> u8 {
        self.needs
    }

    pub fn same_passphrase(&self, other: &PassLock) -> bool {
        sodium::ct_eq(&self.base, &other.base)
    }

    fn derive(header: [u8; HEADER_LEN], passphrase: &[u8]) -> Result<Self, PassError> {
        let ops = u32::from_be_bytes(header[OPS_AT..MEM_AT].try_into().expect("4 bytes"));
        let mem_kib = u32::from_be_bytes(header[MEM_AT..SALT_AT].try_into().expect("4 bytes"));
        if !(1..=OPS_MAX).contains(&ops) || !(MEM_KIB_MIN..=MEM_KIB_MAX).contains(&mem_kib) {
            return Err(PassError::Format);
        }
        let mut lk = PassLock {
            header,
            key: [0; KEY_LEN],
            base: [0; KEY_LEN],
            needs: 0,
        };
        let salt: &[u8; 16] = header[SALT_AT..].try_into().expect("16 bytes");
        if !sodium::argon2id(&mut lk.base, passphrase, salt, u64::from(ops), mem_kib as usize * 1024) {
            return Err(PassError::NoMemory);
        }
        if &header[..8] == MAGIC {
            lk.key = lk.base;
        }
        Ok(lk)
    }

    /// The same passphrase and salt, needing these factors. `device` and `key` are their secrets,
    /// read only for the factors `needs` has. Keyed with the passphrase's key, so without it or any
    /// of the secrets, the key can't be worked out.
    pub fn set(&mut self, needs: u8, device: &[u8; 32], key: &[u8; 32]) {
        let needs = needs & NEEDS_ALL;
        self.needs = needs;
        set_magic(&mut self.header, needs);
        if needs == 0 {
            self.key = self.base;
            return;
        }
        let mut parts: Vec<&[u8]> = Vec::with_capacity(4);
        if needs == NEEDS_DEVICE {
            // As the device lock was first written, so saves locked then still open.
            parts.extend([&b"chat device lock v1"[..], &self.header[8..]]);
        } else {
            parts.extend([&b"chat factors v1"[..], &self.header[..]]);
        }
        if needs & NEEDS_DEVICE != 0 {
            parts.push(device);
        }
        if needs & NEEDS_KEY != 0 {
            parts.push(key);
        }
        let mut out = [0u8; KEY_LEN];
        sodium::blake2b(&mut out, &self.base, &parts);
        self.key = out;
        out.zeroize();
    }

    /// Ready only once its factors' secrets are in (`set`), as its header says it needs.
    fn ready(&self) -> bool {
        header_needs(&self.header) == Some(self.needs)
    }

    /// The header, a nonce, then `plain` sealed.
    pub fn seal(&self, plain: &[u8]) -> Result<Vec<u8>, PassError> {
        if !self.ready() {
            return Err(PassError::Format);
        }
        let nonce: [u8; AEAD_NONCE_LEN] = sodium::random_array();
        let mut out = Vec::with_capacity(SEAL_OVERHEAD + plain.len());
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sodium::aead_seal(plain, &self.header, &nonce, &self.key));
        Ok(out)
    }

    pub fn unseal(&self, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, PassError> {
        if sealed.len() < SEAL_OVERHEAD || header_needs(sealed).is_none() {
            return Err(PassError::Format);
        }
        if sealed[..HEADER_LEN] != self.header || !self.ready() {
            return Err(PassError::Wrong);
        }
        let nonce: &[u8; AEAD_NONCE_LEN] = sealed[HEADER_LEN..HEADER_LEN + AEAD_NONCE_LEN].try_into().expect("a nonce");
        let mut plain = Zeroizing::new(vec![0u8; sealed.len() - SEAL_OVERHEAD]);
        let n = sodium::aead_open(&mut plain, &sealed[HEADER_LEN + AEAD_NONCE_LEN..], &self.header, nonce, &self.key)
            .ok_or(PassError::Wrong)?;
        plain.truncate(n);
        Ok(plain)
    }
}

pub const WRAP_LEN: usize = AEAD_NONCE_LEN + 32 + AEAD_TAG_LEN;

/// A 32-byte secret sealed under a key from elsewhere (a security key's hmac-secret), with `ad`
/// bound to it: a nonce, then the sealed secret.
pub fn secret_wrap(kek: &[u8; 32], ad: &[u8], secret: &[u8; 32]) -> [u8; WRAP_LEN] {
    let key = Zeroizing::new(super::kh(kek, &[b"chat secret wrap v1"]));
    let nonce: [u8; AEAD_NONCE_LEN] = sodium::random_array();
    let mut out = [0u8; WRAP_LEN];
    out[..AEAD_NONCE_LEN].copy_from_slice(&nonce);
    out[AEAD_NONCE_LEN..].copy_from_slice(&sodium::aead_seal(secret, ad, &nonce, &key));
    out
}

/// The secret, or None for another key or other `ad`.
pub fn secret_unwrap(kek: &[u8; 32], ad: &[u8], wrapped: &[u8; WRAP_LEN]) -> Option<Zeroizing<[u8; 32]>> {
    let key = Zeroizing::new(super::kh(kek, &[b"chat secret wrap v1"]));
    let nonce: &[u8; AEAD_NONCE_LEN] = wrapped[..AEAD_NONCE_LEN].try_into().expect("a nonce");
    let mut out = Zeroizing::new([0u8; 32 + AEAD_TAG_LEN]);
    let n = sodium::aead_open(&mut out[..], &wrapped[AEAD_NONCE_LEN..], ad, nonce, &key)?;
    (n == 32).then(|| Zeroizing::new(out[..32].try_into().expect("32 bytes")))
}

pub const TOTP_SECRET_LEN: usize = 20;
pub const TOTP_PERIOD: u64 = 30;
const TOTP_DIGITS: usize = 6;

/// RFC 6238's code for a time step: HMAC-SHA1, then RFC 4226's dynamic truncation to six digits.
pub fn totp_code(secret: &[u8], step: u64) -> u32 {
    use aws_lc_rs::hmac;
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret), &step.to_be_bytes());
    let mac = tag.as_ref();
    let off = usize::from(mac[19] & 15);
    (u32::from_be_bytes(mac[off..off + 4].try_into().expect("4 bytes")) & 0x7fff_ffff) % 1_000_000
}

/// A typed code: six digits, with any spaces and dashes (as some apps show it) left out.
pub fn parse_code(code: &str) -> Option<u32> {
    let digits: String = code.chars().filter(|c| *c != ' ' && *c != '-').collect();
    (digits.len() == TOTP_DIGITS && digits.bytes().all(|c| c.is_ascii_digit())).then(|| digits.parse().ok())?
}

/// Whether `code` is the one for `unix` seconds, or the step before or after, for a phone's clock
/// that's a little out.
pub fn code_matches(secret: &[u8; TOTP_SECRET_LEN], code: u32, unix: u64) -> bool {
    let step = unix / TOTP_PERIOD;
    [step.wrapping_sub(1), step, step + 1]
        .iter()
        .fold(false, |ok, s| ok | (totp_code(secret, *s) == code))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small(passphrase: &[u8]) -> PassLock {
        PassLock::new(passphrase).unwrap()
    }

    #[test]
    fn seals_and_opens_under_the_passphrase_only() {
        let lk = small(b"correct horse");
        let sealed = lk.seal(b"settings").unwrap();
        assert_eq!(&sealed[..8], MAGIC);
        assert_eq!(sealed.len(), 8 + SEAL_OVERHEAD);
        let again = PassLock::of(b"correct horse", &sealed).unwrap();
        assert_eq!(&again.unseal(&sealed).unwrap()[..], b"settings");
        assert_eq!(
            PassLock::of(b"wrong", &sealed).unwrap().unseal(&sealed).unwrap_err(),
            PassError::Wrong
        );
        assert!(PassLock::like(b"correct horse", &lk).unwrap().same_passphrase(&lk));
        assert!(!PassLock::like(b"wrong", &lk).unwrap().same_passphrase(&lk));
    }

    #[test]
    fn factors_change_the_header_and_need_their_secrets() {
        let mut lk = small(b"pw");
        lk.set(NEEDS_DEVICE | NEEDS_KEY, &[1; 32], &[2; 32]);
        let sealed = lk.seal(b"x").unwrap();
        assert_eq!(&sealed[..7], FACTORS_MAGIC);
        assert_eq!(needs_of(&sealed), NEEDS_DEVICE | NEEDS_KEY);
        let mut other = PassLock::of(b"pw", &sealed).unwrap();
        assert_eq!(
            other.unseal(&sealed).unwrap_err(),
            PassError::Wrong,
            "not ready without the secrets"
        );
        other.set(NEEDS_DEVICE | NEEDS_KEY, &[1; 32], &[9; 32]);
        assert_eq!(other.unseal(&sealed).unwrap_err(), PassError::Wrong, "another security key");
        other.set(NEEDS_DEVICE | NEEDS_KEY, &[1; 32], &[2; 32]);
        assert_eq!(&other.unseal(&sealed).unwrap()[..], b"x");
        lk.set(NEEDS_DEVICE, &[1; 32], &[0; 32]);
        assert_eq!(&lk.seal(b"").unwrap()[..8], DEVICE_MAGIC);
        // A header can't claim a lone code factor's magic without a key or code bit, or extra bits.
        assert_eq!(header_needs(b"chatmfa\x01"), None);
        assert_eq!(header_needs(b"chatmfa\x09"), None);
        assert_eq!(chaff(NEEDS_CODE, 22).len(), 22 + SEAL_OVERHEAD);
        assert_eq!(needs_of(&chaff(NEEDS_CODE, 22)), NEEDS_CODE);
    }

    #[test]
    fn wraps_secrets_and_makes_codes() {
        let w = secret_wrap(&[3; 32], b"ad", &[4; 32]);
        assert_eq!(*secret_unwrap(&[3; 32], b"ad", &w).unwrap(), [4; 32]);
        assert!(secret_unwrap(&[3; 32], b"other", &w).is_none());
        // RFC 6238's SHA-1 test vectors (eight digits there; the last six here).
        let secret = b"12345678901234567890";
        assert_eq!(totp_code(secret, 59 / 30), 287082);
        assert_eq!(totp_code(secret, 1111111109 / 30), 81804);
        assert_eq!(totp_code(secret, 20000000000 / 30), 353130);
        assert!(code_matches(secret, 287082, 59 + 30));
        assert!(!code_matches(secret, 287082, 59 + 90));
        assert_eq!(parse_code("287 082"), Some(287082));
        assert_eq!(parse_code("28-70-82"), Some(287082));
        assert_eq!(parse_code("28708"), None);
        assert_eq!(parse_code("2870821"), None);
    }
}
