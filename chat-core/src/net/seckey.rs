// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! FIDO2 security keys, for a save that needs one (see [`crate::net::saves`]). A key makes a
//! credential with the hmac-secret extension, and from then on gives the same 32-byte secret for the
//! same credential and salt: a touch each time, and its PIN where it needs one. That secret wraps the
//! save's own.
//!
//! On Linux a security key is a HID device whose report descriptor has the FIDO usage page, read and
//! written through /dev/hidrawN in 64-byte reports. udev opens them to the user at the screen, with no
//! group to join. CTAPHID frames each CTAP 2.1 message.

use crate::protocol::crypto::sodium;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use zeroize::Zeroizing;

pub const CRED_MAX: usize = 1024;
pub const SALT_LEN: usize = 32;
pub const RP_ID: &str = "chat";
/// How long a security key is waited for: plugged in, and touched.
const WAIT_SECS: f64 = 60.0;

/// Where a request is, for the screen: [`Wait::LOOKING`] for a key to be plugged in,
/// [`Wait::BUSY`], [`Wait::TOUCH`] while it waits for a touch.
#[derive(Default)]
pub struct Wait {
    pub cancel: AtomicBool,
    pub stage: AtomicU8,
    pub touches: AtomicU8,
}

impl Wait {
    pub const LOOKING: u8 = 0;
    pub const BUSY: u8 = 1;
    pub const TOUCH: u8 = 2;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// It needs its PIN, or that wasn't it.
    Pin(String),
    /// It isn't a key the save was locked with.
    NoCred(String),
    Cancelled,
    Failed(String),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::Pin(w) | KeyError::NoCred(w) | KeyError::Failed(w) => f.write_str(w),
            KeyError::Cancelled => f.write_str("cancelled"),
        }
    }
}

type R<T> = Result<T, KeyError>;
fn fail<T>(why: impl Into<String>) -> R<T> {
    Err(KeyError::Failed(why.into()))
}

/// Whether this system can reach security keys at all.
pub fn usable() -> Result<(), String> {
    #[cfg(windows)]
    return webauthn::usable();
    #[cfg(target_os = "macos")]
    return Err("macOS: chat can't talk to security keys here yet".into());
    #[cfg(not(any(windows, target_os = "macos")))]
    hid::usable()
}

/// Registers the one security key plugged in: a new credential, whether its secret needs the PIN,
/// and its secret for `salt`. Two touches.
pub fn make(salt: &[u8; SALT_LEN], pin: Option<&str>, w: &Wait) -> R<(Vec<u8>, bool, Zeroizing<[u8; 32]>)> {
    usable().map_err(KeyError::Failed)?;
    // Windows' own window asks for the PIN.
    #[cfg(windows)]
    return {
        let _ = pin;
        webauthn::make(salt, w)
    };
    #[cfg(not(windows))]
    hid::make(salt, pin, w)
}

/// The secret for `salt` from whichever key plugged in has one of the credentials (each with whether
/// it needs the PIN): which credential, and the secret.
pub fn secret(creds: &[(Vec<u8>, bool)], salt: &[u8; SALT_LEN], pin: Option<&str>, w: &Wait) -> R<(usize, Zeroizing<[u8; 32]>)> {
    usable().map_err(KeyError::Failed)?;
    #[cfg(windows)]
    return {
        let _ = pin;
        webauthn::secret(creds, salt, w)
    };
    #[cfg(not(windows))]
    hid::secret(creds, salt, pin, w)
}

/// The security keys themselves, over hidraw: CTAPHID frames CTAP 2.1's CBOR messages.
#[cfg(not(windows))]
mod hid {
    use super::*;

    // ---- CBOR, the canonical form CTAP asks for: shortest heads, map keys in order ----

    #[derive(Default)]
    struct Cw(Vec<u8>);

    impl Cw {
        fn head(&mut self, major: u8, v: u64) {
            let m = major << 5;
            match v {
                0..=23 => self.0.push(m | v as u8),
                24..=0xff => self.0.extend_from_slice(&[m | 24, v as u8]),
                0x100..=0xffff => {
                    self.0.push(m | 25);
                    self.0.extend_from_slice(&(v as u16).to_be_bytes());
                }
                _ => {
                    self.0.push(m | 26);
                    self.0.extend_from_slice(&(v as u32).to_be_bytes());
                }
            }
        }
        fn int(&mut self, v: i64) {
            if v >= 0 {
                self.head(0, v as u64)
            } else {
                self.head(1, (-1 - v) as u64)
            }
        }
        fn bytes(&mut self, b: &[u8]) {
            self.head(2, b.len() as u64);
            self.0.extend_from_slice(b);
        }
        fn text(&mut self, t: &str) {
            self.head(3, t.len() as u64);
            self.0.extend_from_slice(t.as_bytes());
        }
        fn array(&mut self, n: usize) {
            self.head(4, n as u64);
        }
        fn map(&mut self, n: usize) {
            self.head(5, n as u64);
        }
        fn bool(&mut self, b: bool) {
            self.0.push(0xe0 | if b { 21 } else { 20 });
        }
    }

    struct Cr<'a>(&'a [u8]);

    impl<'a> Cr<'a> {
        fn head(&mut self) -> Option<(u8, u64)> {
            let (&b, rest) = self.0.split_first()?;
            let (major, ai) = (b >> 5, b & 0x1f);
            let n = match ai {
                0..=23 => return Some((major, (self.0 = rest, u64::from(ai)).1)),
                24 => 1,
                25 => 2,
                26 => 4,
                27 => 8,
                _ => return None,
            };
            let v = rest.get(..n)?.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x));
            self.0 = &rest[n..];
            Some((major, v))
        }
        fn take(&mut self, n: u64) -> Option<&'a [u8]> {
            let n = usize::try_from(n).ok()?;
            let (a, b) = (self.0.get(..n)?, self.0.get(n..)?);
            self.0 = b;
            Some(a)
        }
        fn skip(&mut self, depth: u8) -> Option<()> {
            if depth > 8 {
                return None;
            }
            let (major, v) = self.head()?;
            match major {
                0 | 1 | 7 => {}
                2 | 3 => {
                    self.take(v)?;
                }
                4 => (0..v).try_for_each(|_| self.skip(depth + 1))?,
                5 => (0..v * 2).try_for_each(|_| self.skip(depth + 1))?,
                6 => self.skip(depth + 1)?,
                _ => return None,
            }
            Some(())
        }
        fn int(&mut self) -> Option<i64> {
            match self.head()? {
                (0, v) => i64::try_from(v).ok(),
                (1, v) => i64::try_from(v).ok().map(|v| -1 - v),
                _ => None,
            }
        }
        fn bytes(&mut self) -> Option<&'a [u8]> {
            match self.head()? {
                (2, n) => self.take(n),
                _ => None,
            }
        }
        fn text(&mut self) -> Option<&'a [u8]> {
            match self.head()? {
                (3, n) => self.take(n),
                _ => None,
            }
        }
        fn count(&mut self, major: u8) -> Option<u64> {
            match self.head()? {
                (m, n) if m == major => Some(n),
                _ => None,
            }
        }
        fn bool(&mut self) -> Option<bool> {
            match self.head()? {
                (7, 20) => Some(false),
                (7, 21) => Some(true),
                _ => None,
            }
        }
    }

    // ---- the transport: CTAPHID over hidraw ----

    const REPORT: usize = 64;
    const HID_INIT: u8 = 0x86;
    const HID_CBOR: u8 = 0x90;
    const HID_CANCEL: u8 = 0x91;
    const HID_KEEPALIVE: u8 = 0xbb;
    const HID_ERROR: u8 = 0xbf;
    const BROADCAST: u32 = 0xffff_ffff;

    /// The FIDO usage page (0xf1d0) with usage 1, CTAPHID, somewhere in a HID report descriptor.
    fn is_fido(d: &[u8]) -> bool {
        let (mut i, mut page) = (0, 0u32);
        while i < d.len() {
            let b = d[i];
            if b == 0xfe {
                i += 3 + usize::from(*d.get(i + 1).unwrap_or(&0));
                continue;
            }
            let sz = if b & 3 == 3 { 4 } else { usize::from(b & 3) };
            let Some(v) = d.get(i + 1..i + 1 + sz) else { return false };
            let v = v.iter().rev().fold(0u32, |a, x| (a << 8) | u32::from(*x));
            let (kind, tag) = ((b >> 2) & 3, b >> 4);
            if kind == 1 && tag == 0 {
                page = v;
            } else if kind == 2 && tag == 0 {
                // A 4-byte usage carries its own page in the high half.
                let (pg, usage) = if sz == 4 { (v >> 16, v & 0xffff) } else { (page, v) };
                if pg == 0xf1d0 && usage == 1 {
                    return true;
                }
            }
            i += 1 + sz;
        }
        false
    }

    /// The security keys plugged in.
    fn list_keys() -> Vec<String> {
        let Ok(rd) = std::fs::read_dir("/sys/class/hidraw") else {
            return Vec::new();
        };
        rd.filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.starts_with("hidraw") && n.len() <= 16)
            .filter(|n| std::fs::read(format!("/sys/class/hidraw/{n}/device/report_descriptor")).is_ok_and(|d| is_fido(&d)))
            .map(|n| format!("/dev/{n}"))
            .take(8)
            .collect()
    }

    #[cfg(not(target_os = "macos"))]
    pub(super) fn usable() -> Result<(), String> {
        if cfg!(target_os = "linux") && std::path::Path::new("/sys/class/hidraw").exists() {
            Ok(())
        } else {
            Err("this system has no hidraw devices, which chat reads security keys through".into())
        }
    }

    struct Hid<'w> {
        f: std::fs::File,
        cid: u32,
        w: &'w Wait,
        give_up: std::time::Instant,
    }

    fn now() -> std::time::Instant {
        std::time::Instant::now()
    }

    impl<'w> Hid<'w> {
        fn write(&mut self, pkt: &[u8; REPORT]) -> bool {
            use std::io::Write;
            // FIDO devices have no report ids.
            let mut buf = [0u8; REPORT + 1];
            buf[1..].copy_from_slice(pkt);
            self.f.write_all(&buf).is_ok()
        }

        /// Some(report), None if none came within `ms`; Err if the device went away.
        fn read(&mut self, ms: i32) -> Result<Option<[u8; REPORT]>, ()> {
            use std::io::Read;
            use std::os::fd::AsRawFd;
            let mut p = libc::pollfd {
                fd: self.f.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll reads and writes only the one pollfd it's given.
            let r = unsafe { libc::poll(&mut p, 1, ms) };
            if r < 0 || (r > 0 && p.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0) {
                return Err(());
            }
            if r == 0 {
                return Ok(None);
            }
            let mut pkt = [0u8; REPORT];
            match self.f.read(&mut pkt) {
                Ok(REPORT) => Ok(Some(pkt)),
                _ => Err(()),
            }
        }

        fn send(&mut self, cmd: u8, data: &[u8]) -> bool {
            let mut pkt = [0u8; REPORT];
            pkt[..4].copy_from_slice(&self.cid.to_be_bytes());
            pkt[4] = cmd;
            pkt[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
            let n = data.len().min(REPORT - 7);
            pkt[7..7 + n].copy_from_slice(&data[..n]);
            if !self.write(&pkt) {
                return false;
            }
            for (seq, chunk) in data[n..].chunks(REPORT - 5).enumerate() {
                if seq > 127 {
                    return false;
                }
                pkt = [0u8; REPORT];
                pkt[..4].copy_from_slice(&self.cid.to_be_bytes());
                pkt[4] = seq as u8;
                pkt[5..5 + chunk.len()].copy_from_slice(chunk);
                if !self.write(&pkt) {
                    return false;
                }
            }
            true
        }

        /// The answer to `cmd`. Keepalives say whether it waits for a touch; cancelling sends
        /// CTAPHID_CANCEL, which the key answers by giving the request up.
        fn recv(&mut self, cmd: u8) -> R<Zeroizing<Vec<u8>>> {
            loop {
                if self.w.cancel.load(Ordering::Acquire) {
                    let mut c = [0u8; REPORT];
                    c[..4].copy_from_slice(&self.cid.to_be_bytes());
                    c[4] = HID_CANCEL;
                    self.write(&c);
                    return Err(KeyError::Cancelled);
                }
                if now() > self.give_up {
                    return fail("the security key didn't answer in time");
                }
                let Some(pkt) = self
                    .read(100)
                    .map_err(|()| KeyError::Failed("the security key was unplugged".into()))?
                else {
                    continue;
                };
                if u32::from_be_bytes(pkt[..4].try_into().expect("4 bytes")) != self.cid {
                    continue;
                }
                match pkt[4] {
                    HID_KEEPALIVE => {
                        self.w
                            .stage
                            .store(if pkt[7] == 2 { Wait::TOUCH } else { Wait::BUSY }, Ordering::Release);
                        continue;
                    }
                    HID_ERROR => return fail(format!("the security key's HID error 0x{:02x}", pkt[7])),
                    c if c != cmd => continue,
                    _ => {}
                }
                self.w.stage.store(Wait::BUSY, Ordering::Release);
                let len = usize::from(u16::from_be_bytes([pkt[5], pkt[6]]));
                let mut out = Zeroizing::new(Vec::with_capacity(len));
                out.extend_from_slice(&pkt[7..7 + len.min(REPORT - 7)]);
                let mut seq = 0u8;
                while out.len() < len {
                    let next = loop {
                        match self.read(1000) {
                            Ok(Some(p)) if u32::from_be_bytes(p[..4].try_into().expect("4 bytes")) != self.cid => continue,
                            Ok(Some(p)) if p[4] == seq => break p,
                            _ => return fail("the security key's answer was cut short"),
                        }
                    };
                    let n = (len - out.len()).min(REPORT - 5);
                    out.extend_from_slice(&next[5..5 + n]);
                    seq += 1;
                }
                return Ok(out);
            }
        }

        /// Opens a key and gets a channel of its own on it.
        fn open(path: &str, w: &'w Wait, give_up: std::time::Instant) -> R<Hid<'w>> {
            let f = std::fs::OpenOptions::new().read(true).write(true).open(path).map_err(|e| {
                KeyError::Failed(if e.kind() == std::io::ErrorKind::PermissionDenied {
                    format!(
                        "{path}, the security key, isn't open to you: a udev rule (systemd's for FIDO tokens, or libfido2's \
                     70-u2f.rules) opens security keys to whoever's at the screen"
                    )
                } else {
                    format!("can't open the security key ({e})")
                })
            })?;
            let mut h = Hid {
                f,
                cid: BROADCAST,
                w,
                give_up,
            };
            let nonce: [u8; 8] = sodium::random_array();
            if h.send(HID_INIT, &nonce) {
                let until = now() + std::time::Duration::from_secs(2);
                while now() < until {
                    match h.read(200) {
                        Err(()) => break,
                        Ok(Some(p)) if p[..4] == BROADCAST.to_be_bytes() && p[4] == HID_INIT && p[7..15] == nonce => {
                            if p[23] & 0x04 == 0 {
                                return fail("it's an old U2F security key, without FIDO2");
                            }
                            h.cid = u32::from_be_bytes(p[15..19].try_into().expect("4 bytes"));
                            return Ok(h);
                        }
                        _ => {}
                    }
                }
            }
            fail("the security key didn't answer")
        }

        /// One CTAP command: its status and what follows it.
        fn call(&mut self, msg: &[u8]) -> R<(u8, Zeroizing<Vec<u8>>)> {
            if !self.send(HID_CBOR, msg) {
                return fail("couldn't write to the security key");
            }
            let r = self.recv(HID_CBOR)?;
            let (&st, rest) = r
                .split_first()
                .ok_or(KeyError::Failed("the security key gave an empty answer".into()))?;
            Ok((st, Zeroizing::new(rest.to_vec())))
        }
    }

    // ---- CTAP 2.1 ----

    const CMD_MAKE_CREDENTIAL: u8 = 0x01;
    const CMD_GET_ASSERTION: u8 = 0x02;
    const CMD_GET_INFO: u8 = 0x04;
    const CMD_CLIENT_PIN: u8 = 0x06;

    fn status(st: u8) -> KeyError {
        match st {
            0x2d => KeyError::Cancelled,
            0x2e => KeyError::NoCred("it isn't the security key the save was locked with".into()),
            0x2f => KeyError::Failed("it wasn't touched in time".into()),
            0x27 => KeyError::Failed("the security key refused".into()),
            0x36 | 0x33 => KeyError::Pin("it needs its PIN".into()),
            0x32 => KeyError::Failed(
                "its PIN is blocked after too many wrong ones, and only resetting it (which wipes its credentials) unblocks it".into(),
            ),
            0x34 => KeyError::Failed("it takes no more PINs until it's unplugged and plugged in again".into()),
            0x35 => KeyError::Failed("it wants a PIN, and none is set on it: set one with its own tools first".into()),
            0x37 => KeyError::Pin("that PIN doesn't meet the security key's rules".into()),
            0x3c => KeyError::Failed("its user verification is blocked".into()),
            s => KeyError::Failed(format!("the security key answered with error 0x{s:02x}")),
        }
    }

    #[derive(Default)]
    struct Info {
        hmac_secret: bool,
        protocols: u8,
        always_uv: bool,
        make_needs_pin: bool,
        token_perms: bool,
    }

    fn get_info(h: &mut Hid) -> R<Info> {
        let (st, rsp) = h.call(&[CMD_GET_INFO])?;
        if st != 0 {
            return Err(match status(st) {
                KeyError::Cancelled => KeyError::Cancelled,
                e => KeyError::Failed(e.to_string()),
            });
        }
        let bad = || KeyError::Failed("the security key's description of itself can't be read".into());
        let mut r = Cr(&rsp);
        let mut info = Info::default();
        let (mut pin_set, mut uv_not_rqd) = (false, false);
        for _ in 0..r.count(5).ok_or_else(bad)? {
            match r.int().ok_or_else(bad)? {
                k @ (2 | 6) => {
                    for _ in 0..r.count(4).ok_or_else(bad)? {
                        if k == 6 {
                            let p = r.int().ok_or_else(bad)?;
                            if p == 1 || p == 2 {
                                info.protocols |= 1 << p;
                            }
                        } else if r.text().ok_or_else(bad)? == b"hmac-secret" {
                            info.hmac_secret = true;
                        }
                    }
                }
                4 => {
                    for _ in 0..r.count(5).ok_or_else(bad)? {
                        let (t, b) = (r.text().ok_or_else(bad)?, r.bool().ok_or_else(bad)?);
                        match t {
                            b"clientPin" => pin_set = b,
                            b"alwaysUv" => info.always_uv = b,
                            b"makeCredUvNotRqd" => uv_not_rqd = b,
                            b"pinUvAuthToken" => info.token_perms = b,
                            _ => {}
                        }
                    }
                }
                _ => r.skip(0).ok_or_else(bad)?,
            }
        }
        if info.protocols == 0 {
            info.protocols = 1 << 1;
        }
        info.make_needs_pin = info.always_uv || (pin_set && !uv_not_rqd);
        Ok(info)
    }

    /// The PIN protocol's shared secret: protocol 1's one key, or protocol 2's HMAC key then AES key;
    /// and our half of the key agreement, for the key.
    struct Shared {
        proto: u8,
        key: Zeroizing<[u8; 64]>,
        x: [u8; 32],
        y: [u8; 32],
    }

    fn hkdf_sha256(ikm: &[u8], info: &str) -> Zeroizing<[u8; 32]> {
        let prk = Zeroizing::new(sodium::hmac_sha256(&[0u8; 32], ikm));
        let mut t = info.as_bytes().to_vec();
        t.push(1);
        Zeroizing::new(sodium::hmac_sha256(&prk[..], &t))
    }

    /// AES-256-CBC with no padding, on whole blocks. aws-lc-rs only offers CBC with PKCS#7 padding, so
    /// encrypting drops the padding's block, and decrypting adds one that decrypts to valid padding.
    fn aes_cbc(enc: bool, key: &[u8], iv: [u8; 16], data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        use aws_lc_rs::cipher::{
            AES_256, DecryptionContext, EncryptionContext, PaddedBlockDecryptingKey, PaddedBlockEncryptingKey, UnboundCipherKey,
        };
        use aws_lc_rs::iv::FixedLength;
        if !data.len().is_multiple_of(16) {
            return None;
        }
        let ek = || PaddedBlockEncryptingKey::cbc_pkcs7(UnboundCipherKey::new(&AES_256, key).ok()?).ok();
        let encrypt = |iv: [u8; 16], plain: &[u8]| -> Option<Vec<u8>> {
            let mut buf = plain.to_vec();
            ek()?
                .less_safe_encrypt(&mut buf, EncryptionContext::Iv128(FixedLength::from(iv)))
                .ok()?;
            buf.truncate(plain.len());
            Some(buf)
        };
        if enc {
            return encrypt(iv, data).map(Zeroizing::new);
        }
        if data.is_empty() {
            return Some(Zeroizing::new(Vec::new()));
        }
        let last: [u8; 16] = data[data.len() - 16..].try_into().ok()?;
        let mut buf = data.to_vec();
        buf.extend_from_slice(&encrypt(last, &[16u8; 16])?);
        let dk = PaddedBlockDecryptingKey::cbc_pkcs7(UnboundCipherKey::new(&AES_256, key).ok()?).ok()?;
        let plain = dk.decrypt(&mut buf, DecryptionContext::Iv128(FixedLength::from(iv))).ok()?.to_vec();
        Some(Zeroizing::new(plain))
    }

    impl Shared {
        fn aes_key(&self) -> &[u8] {
            if self.proto == 1 { &self.key[..32] } else { &self.key[32..] }
        }

        fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
            if self.proto == 1 {
                return aes_cbc(true, self.aes_key(), [0; 16], plain).map(|c| c.to_vec());
            }
            let iv: [u8; 16] = sodium::random_array();
            let mut out = iv.to_vec();
            out.extend_from_slice(&aes_cbc(true, self.aes_key(), iv, plain)?);
            Some(out)
        }

        fn decrypt(&self, data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
            if self.proto == 1 {
                return aes_cbc(false, self.aes_key(), [0; 16], data);
            }
            let iv: [u8; 16] = data.get(..16)?.try_into().ok()?;
            aes_cbc(false, self.aes_key(), iv, &data[16..])
        }

        fn cose(&self, w: &mut Cw) {
            w.map(5);
            w.int(1);
            w.int(2);
            w.int(3);
            w.int(-25);
            w.int(-1);
            w.int(1);
            w.int(-2);
            w.bytes(&self.x);
            w.int(-3);
            w.bytes(&self.y);
        }
    }

    /// An authentication: HMAC-SHA256, cut to 16 bytes for protocol 1.
    fn pin_auth(proto: u8, key: &[u8], msg: &[u8]) -> Vec<u8> {
        let mac = sodium::hmac_sha256(key, msg);
        mac[..if proto == 1 { 16 } else { 32 }].to_vec()
    }

    fn pick_protocol(info: &Info) -> u8 {
        if info.protocols & (1 << 2) != 0 { 2 } else { 1 }
    }

    fn key_agreement(h: &mut Hid, proto: u8) -> R<Shared> {
        use aws_lc_rs::agreement::{ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, agree_ephemeral};
        let mut w = Cw(vec![CMD_CLIENT_PIN]);
        w.map(2);
        w.int(1);
        w.int(i64::from(proto));
        w.int(2);
        w.int(2);
        let (st, rsp) = h.call(&w.0)?;
        if st != 0 {
            return Err(status(st));
        }
        let bad = || KeyError::Failed("the security key's key agreement can't be read".into());
        let mut r = Cr(&rsp);
        let mut theirs = None;
        for _ in 0..r.count(5).ok_or_else(bad)? {
            if r.int().ok_or_else(bad)? != 1 {
                r.skip(0).ok_or_else(bad)?;
                continue;
            }
            let (mut x, mut y) = (None, None);
            for _ in 0..r.count(5).ok_or_else(bad)? {
                match r.int().ok_or_else(bad)? {
                    -2 => x = r.bytes().filter(|b| b.len() == 32),
                    -3 => y = r.bytes().filter(|b| b.len() == 32),
                    -1 if r.int() != Some(1) => return Err(bad()),
                    -1 => {}
                    _ => r.skip(0).ok_or_else(bad)?,
                }
            }
            let mut point = vec![4u8];
            point.extend_from_slice(x.ok_or_else(bad)?);
            point.extend_from_slice(y.ok_or_else(bad)?);
            theirs = Some(point);
        }
        let theirs = theirs.ok_or_else(bad)?;
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let mine = EphemeralPrivateKey::generate(&ECDH_P256, &rng).map_err(|_| KeyError::Failed("chat's ECDH failed".into()))?;
        let public = mine
            .compute_public_key()
            .map_err(|_| KeyError::Failed("chat's ECDH failed".into()))?;
        let public = public.as_ref();
        // The key's point is checked to be on the curve before it's used.
        let z = agree_ephemeral(mine, UnparsedPublicKey::new(&ECDH_P256, &theirs), (), |z| {
            Ok(Zeroizing::new(z.to_vec()))
        })
        .map_err(|()| KeyError::Failed("the security key's key agreement key isn't a P-256 point".into()))?;
        let mut key = Zeroizing::new([0u8; 64]);
        if proto == 1 {
            key[..32].copy_from_slice(&sodium::sha256(&[&z]));
        } else {
            key[..32].copy_from_slice(&hkdf_sha256(&z, "CTAP2 HMAC key")[..]);
            key[32..].copy_from_slice(&hkdf_sha256(&z, "CTAP2 AES key")[..]);
        }
        Ok(Shared {
            proto,
            key,
            x: public[1..33].try_into().expect("32 bytes"),
            y: public[33..65].try_into().expect("32 bytes"),
        })
    }

    fn pin_retries(h: &mut Hid, proto: u8) -> Option<i64> {
        let mut w = Cw(vec![CMD_CLIENT_PIN]);
        w.map(2);
        w.int(1);
        w.int(i64::from(proto));
        w.int(2);
        w.int(1);
        let (st, rsp) = h.call(&w.0).ok()?;
        let mut r = Cr(&rsp);
        if st != 0 {
            return None;
        }
        for _ in 0..r.count(5)? {
            if r.int()? == 3 {
                return r.int();
            }
            r.skip(0)?;
        }
        None
    }

    /// A PIN token, and the protocol it's for.
    fn pin_token(h: &mut Hid, info: &Info, pin: &str, perms: i64) -> R<(Zeroizing<Vec<u8>>, u8)> {
        if !(4..=63).contains(&pin.len()) {
            return Err(KeyError::Pin("a security key's PIN is 4 to 63 characters".into()));
        }
        let proto = pick_protocol(info);
        let s = key_agreement(h, proto)?;
        let hash = Zeroizing::new(sodium::sha256(&[pin.as_bytes()]));
        let enc = s.encrypt(&hash[..16]).ok_or(KeyError::Failed("chat's AES failed".into()))?;
        let mut w = Cw(vec![CMD_CLIENT_PIN]);
        w.map(if info.token_perms { 6 } else { 4 });
        w.int(1);
        w.int(i64::from(proto));
        w.int(2);
        w.int(if info.token_perms { 9 } else { 5 });
        w.int(3);
        s.cose(&mut w);
        w.int(6);
        w.bytes(&enc);
        if info.token_perms {
            w.int(9);
            w.int(perms);
            w.int(10);
            w.text(RP_ID);
        }
        let (st, rsp) = h.call(&w.0)?;
        if st == 0x31 {
            return Err(KeyError::Pin(match pin_retries(h, proto) {
                Some(left) => format!(
                    "that isn't its PIN: {left} tr{} left before it's blocked",
                    if left == 1 { "y" } else { "ies" }
                ),
                None => "that isn't its PIN".into(),
            }));
        }
        if st != 0 {
            return Err(status(st));
        }
        let bad = || KeyError::Failed("the security key's PIN token can't be read".into());
        let mut r = Cr(&rsp);
        for _ in 0..r.count(5).ok_or_else(bad)? {
            if r.int().ok_or_else(bad)? != 2 {
                r.skip(0).ok_or_else(bad)?;
                continue;
            }
            let token = s
                .decrypt(r.bytes().ok_or_else(bad)?)
                .filter(|t| (16..=32).contains(&t.len()))
                .ok_or_else(bad)?;
            return Ok((token, proto));
        }
        Err(bad())
    }

    /// What authenticator data holds: the credential id made (with attested data), and the hmac-secret
    /// extension's flag (on a credential made) or output (on an assertion).
    struct AuthData {
        cred: Option<Vec<u8>>,
        hmac_on: bool,
        out: Option<Vec<u8>>,
    }

    fn auth_data(a: &[u8]) -> Option<AuthData> {
        let flags = *a.get(32)?;
        let mut r = Cr(a.get(37..)?);
        let mut cred = None;
        if flags & 0x40 != 0 {
            let head = r.take(18)?;
            let len = u64::from(u16::from_be_bytes([head[16], head[17]]));
            if len == 0 || len > CRED_MAX as u64 {
                return None;
            }
            cred = Some(r.take(len)?.to_vec());
            r.skip(0)?;
        }
        let (mut on, mut out) = (false, None);
        if flags & 0x80 != 0 {
            for _ in 0..r.count(5)? {
                if r.text()? != b"hmac-secret" {
                    r.skip(0)?;
                    continue;
                }
                if r.0.first().is_some_and(|b| b >> 5 == 7) {
                    on = r.bool()?;
                } else {
                    out = Some(r.bytes()?.to_vec());
                }
            }
        }
        Some(AuthData { cred, hmac_on: on, out })
    }

    fn allow_list(w: &mut Cw, creds: &[&[u8]]) {
        w.array(creds.len());
        for c in creds {
            w.map(2);
            w.text("id");
            w.bytes(c);
            w.text("type");
            w.text("public-key");
        }
    }

    fn make_credential(h: &mut Hid, info: &Info, pin: Option<&str>) -> R<Vec<u8>> {
        if !info.hmac_secret {
            return fail("this security key doesn't have the hmac-secret extension, which chat needs");
        }
        if info.make_needs_pin && pin.is_none() {
            return Err(KeyError::Pin("it needs its PIN".into()));
        }
        let token = match pin {
            Some(p) => Some(pin_token(h, info, p, 1)?),
            None => None,
        };
        let cdh: [u8; 32] = sodium::random_array();
        let uid: [u8; 16] = sodium::random_array();
        let mut w = Cw(vec![CMD_MAKE_CREDENTIAL]);
        w.map(if token.is_some() { 7 } else { 5 });
        w.int(1);
        w.bytes(&cdh);
        w.int(2);
        w.map(2);
        w.text("id");
        w.text(RP_ID);
        w.text("name");
        w.text(RP_ID);
        w.int(3);
        w.map(3);
        w.text("id");
        w.bytes(&uid);
        w.text("name");
        w.text("chat");
        w.text("displayName");
        w.text("chat");
        w.int(4);
        w.array(1);
        w.map(2);
        w.text("alg");
        w.int(-7);
        w.text("type");
        w.text("public-key");
        w.int(6);
        w.map(1);
        w.text("hmac-secret");
        w.bool(true);
        if let Some((t, proto)) = &token {
            w.int(8);
            w.bytes(&pin_auth(*proto, t, &cdh));
            w.int(9);
            w.int(i64::from(*proto));
        }
        let (st, rsp) = h.call(&w.0)?;
        if st != 0 {
            return Err(status(st));
        }
        let bad = || KeyError::Failed("the security key's new credential can't be read".into());
        let mut r = Cr(&rsp);
        for _ in 0..r.count(5).ok_or_else(bad)? {
            if r.int().ok_or_else(bad)? != 2 {
                r.skip(0).ok_or_else(bad)?;
                continue;
            }
            let AuthData { cred, hmac_on: on, .. } = auth_data(r.bytes().ok_or_else(bad)?).ok_or_else(bad)?;
            let cred = cred.ok_or_else(bad)?;
            if !on {
                return fail("the security key made the credential without hmac-secret");
            }
            return Ok(cred);
        }
        Err(bad())
    }

    /// Which of `creds` the key's answer names (the only one, if it names none), and the hmac-secret
    /// output in it.
    fn read_assertion(rsp: &[u8], creds: &[&[u8]]) -> Option<(usize, Option<Vec<u8>>)> {
        let mut r = Cr(rsp);
        let mut which = (creds.len() == 1).then_some(0);
        let mut out = None;
        for _ in 0..r.count(5)? {
            match r.int()? {
                1 => {
                    for _ in 0..r.count(5)? {
                        if r.text()? != b"id" {
                            r.skip(0)?;
                            continue;
                        }
                        let id = r.bytes()?;
                        which = creds.iter().position(|c| *c == id);
                    }
                }
                2 => out = auth_data(r.bytes()?)?.out,
                _ => r.skip(0)?,
            }
        }
        Some((which?, out))
    }

    /// Whether the key has one of the credentials, asked without a touch, so only that key blinks.
    /// None if it can't say without one.
    fn probe(h: &mut Hid, creds: &[&[u8]]) -> Option<Option<usize>> {
        let cdh: [u8; 32] = sodium::random_array();
        let mut w = Cw(vec![CMD_GET_ASSERTION]);
        w.map(4);
        w.int(1);
        w.text(RP_ID);
        w.int(2);
        w.bytes(&cdh);
        w.int(3);
        allow_list(&mut w, creds);
        w.int(5);
        w.map(1);
        w.text("up");
        w.bool(false);
        match h.call(&w.0).ok()? {
            (0x2e, _) => Some(None),
            (0, rsp) => read_assertion(&rsp, creds).map(|(which, _)| Some(which)),
            _ => None,
        }
    }

    /// The hmac-secret output for `salt`, from the one credential given.
    fn hmac_secret(h: &mut Hid, info: &Info, cred: &[u8], salt: &[u8; SALT_LEN], uv: bool, pin: Option<&str>) -> R<Zeroizing<[u8; 32]>> {
        if !info.hmac_secret {
            return fail("this security key doesn't have the hmac-secret extension, which chat needs");
        }
        if uv && pin.is_none() {
            return Err(KeyError::Pin("it needs its PIN".into()));
        }
        let token = match (uv, pin) {
            (true, Some(p)) => Some(pin_token(h, info, p, 2)?),
            _ => None,
        };
        let proto = pick_protocol(info);
        let s = key_agreement(h, proto)?;
        let salt_enc = s.encrypt(salt).ok_or(KeyError::Failed("chat's AES failed".into()))?;
        let salt_auth = pin_auth(proto, &s.key[..32], &salt_enc);
        let cdh: [u8; 32] = sodium::random_array();
        let mut w = Cw(vec![CMD_GET_ASSERTION]);
        w.map(if token.is_some() { 6 } else { 4 });
        w.int(1);
        w.text(RP_ID);
        w.int(2);
        w.bytes(&cdh);
        w.int(3);
        allow_list(&mut w, &[cred]);
        w.int(4);
        w.map(1);
        w.text("hmac-secret");
        w.map(if proto == 2 { 4 } else { 3 });
        w.int(1);
        s.cose(&mut w);
        w.int(2);
        w.bytes(&salt_enc);
        w.int(3);
        w.bytes(&salt_auth);
        if proto == 2 {
            w.int(4);
            w.int(2);
        }
        if let Some((t, tproto)) = &token {
            w.int(6);
            w.bytes(&pin_auth(*tproto, t, &cdh));
            w.int(7);
            w.int(i64::from(*tproto));
        }
        let (st, rsp) = h.call(&w.0)?;
        if st != 0 {
            return Err(status(st));
        }
        let plain = read_assertion(&rsp, &[cred])
            .and_then(|(_, out)| s.decrypt(&out?))
            .filter(|p| p.len() == 32);
        let plain = plain.ok_or(KeyError::Failed("the security key's answer has no secret chat can read".into()))?;
        Ok(Zeroizing::new(plain[..].try_into().expect("32 bytes")))
    }

    /// Waits for a security key to be plugged in, up to the deadline.
    fn wait_for_keys(w: &Wait, give_up: std::time::Instant) -> R<Vec<String>> {
        loop {
            let keys = list_keys();
            if !keys.is_empty() {
                return Ok(keys);
            }
            w.stage.store(Wait::LOOKING, Ordering::Release);
            if w.cancel.load(Ordering::Acquire) {
                return Err(KeyError::Cancelled);
            }
            if now() > give_up {
                return fail("no security key was plugged in");
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    fn deadline() -> std::time::Instant {
        now() + std::time::Duration::from_secs_f64(WAIT_SECS)
    }

    /// Registers the one security key plugged in: a new credential, and its secret for `salt`. Two
    /// touches. Whether the secret needs the PIN is the key's choice (alwaysUv), and has to be the same
    /// each time, since it's a different secret with it.
    pub(super) fn make(salt: &[u8; SALT_LEN], pin: Option<&str>, w: &Wait) -> R<(Vec<u8>, bool, Zeroizing<[u8; 32]>)> {
        let give_up = deadline();
        let keys = wait_for_keys(w, give_up)?;
        if keys.len() > 1 {
            return fail("more than one security key is plugged in: unplug all but the one to register");
        }
        let mut h = Hid::open(&keys[0], w, give_up)?;
        w.stage.store(Wait::BUSY, Ordering::Release);
        let info = get_info(&mut h)?;
        let uv = info.always_uv;
        let cred = make_credential(&mut h, &info, pin)?;
        w.touches.fetch_add(1, Ordering::AcqRel);
        let secret = hmac_secret(&mut h, &info, &cred, salt, uv, pin)?;
        w.touches.fetch_add(1, Ordering::AcqRel);
        Ok((cred, uv, secret))
    }

    /// The secret for `salt` from whichever key plugged in has one of the credentials (each with whether
    /// it needs the PIN): which credential, and the secret. Keys are asked without a touch first, so
    /// only the right one blinks; one that can't say is tried after, a credential at a time.
    pub(super) fn secret(creds: &[(Vec<u8>, bool)], salt: &[u8; SALT_LEN], pin: Option<&str>, w: &Wait) -> R<(usize, Zeroizing<[u8; 32]>)> {
        let give_up = deadline();
        let keys = wait_for_keys(w, give_up)?;
        w.stage.store(Wait::BUSY, Ordering::Release);
        let ids: Vec<&[u8]> = creds.iter().map(|(c, _)| c.as_slice()).collect();
        let mut last = KeyError::NoCred("the security key plugged in isn't one the save was locked with".into());
        for pass in 0..2 {
            for path in &keys {
                let mut h = match Hid::open(path, w, give_up) {
                    Ok(h) => h,
                    Err(e) if keys.len() == 1 => return Err(e),
                    Err(_) => continue,
                };
                let info = match get_info(&mut h) {
                    Ok(i) => i,
                    Err(e) if keys.len() == 1 => return Err(e),
                    Err(_) => continue,
                };
                let tries: Vec<usize> = match (probe(&mut h, &ids), pass) {
                    (Some(Some(which)), 0) => vec![which],
                    (None, 1) => (0..creds.len()).collect(),
                    _ => continue,
                };
                for c in tries {
                    match hmac_secret(&mut h, &info, &creds[c].0, salt, creds[c].1, pin) {
                        Ok(s) => {
                            w.touches.fetch_add(1, Ordering::AcqRel);
                            return Ok((c, s));
                        }
                        Err(KeyError::NoCred(why)) => last = KeyError::NoCred(why),
                        Err(e) => return Err(e),
                    }
                }
                if w.cancel.load(Ordering::Acquire) {
                    return Err(KeyError::Cancelled);
                }
            }
        }
        Err(last)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cbor_and_cbc_round_trip() {
            let mut w = Cw::default();
            w.map(2);
            w.int(-25);
            w.bytes(&[1; 300]);
            w.text("hmac-secret");
            w.bool(true);
            let mut r = Cr(&w.0);
            assert_eq!(r.count(5), Some(2));
            assert_eq!(r.int(), Some(-25));
            assert_eq!(r.bytes().map(<[u8]>::len), Some(300));
            assert_eq!(r.text(), Some(&b"hmac-secret"[..]));
            assert_eq!(r.bool(), Some(true));
            let key = [7u8; 32];
            let plain = [9u8; 48];
            let c = aes_cbc(true, &key, [1; 16], &plain).unwrap();
            assert_eq!(c.len(), 48);
            assert_eq!(&aes_cbc(false, &key, [1; 16], &c).unwrap()[..], &plain[..]);
            // FIPS 197's AES-256 vector, as one block of CBC with a zero IV.
            let k: Vec<u8> = (0u8..32).collect();
            let p: Vec<u8> = (0u8..16).map(|i| i * 0x11).collect();
            let c = aes_cbc(true, &k, [0; 16], &p).unwrap();
            assert_eq!(crate::protocol::hex::encode(&c), "8ea2b7ca516745bfeafc49904b496089");
            // The FIDO usage page with usage 1, as security keys describe themselves.
            assert!(is_fido(&[0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01]));
            assert!(!is_fido(&[0x05, 0x01, 0x09, 0x06]));
        }
    }
}

/// Security keys through Windows' WebAuthn API (webauthn.dll): since Windows 10 1903 only
/// administrators can open a security key directly, so Windows' own window takes the PIN and asks
/// for the touch. Reading hmac-secret with a salt of chat's own came in its API version 4. Its
/// functions are looked up as chat runs, so chat still starts on a Windows without them.
#[cfg(windows)]
mod webauthn {
    use super::*;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{HWND, NTE_USER_CANCELLED, S_OK};
    use windows_sys::Win32::Networking::WindowsWebServices::*;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW};
    use windows_sys::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
    use windows_sys::core::{BOOL, GUID, HRESULT, PCWSTR, w};

    const API_FOR_SALTS: u32 = 4;
    /// Authenticator data: the RP id's hash, then the flags.
    const AD_FLAGS_AT: usize = 32;
    const FLAG_UV: u8 = 0x04;
    const USER_ID_LEN: usize = 16;
    const CREDS_MAX: usize = 8;
    /// How often the watcher looks at `cancel`.
    const CANCEL_POLL: std::time::Duration = std::time::Duration::from_millis(100);
    /// HRESULT_FROM_WIN32(ERROR_CANCELLED).
    const CANCELLED: HRESULT = 0x8007_04C7_u32 as HRESULT;
    const NO_DLL: &str = "this Windows has no WebAuthn (webauthn.dll), which chat reads security keys through";

    type MakeFn = unsafe extern "system" fn(
        HWND,
        *const WEBAUTHN_RP_ENTITY_INFORMATION,
        *const WEBAUTHN_USER_ENTITY_INFORMATION,
        *const WEBAUTHN_COSE_CREDENTIAL_PARAMETERS,
        *const WEBAUTHN_CLIENT_DATA,
        *const WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
        *mut *mut WEBAUTHN_CREDENTIAL_ATTESTATION,
    ) -> HRESULT;
    type GetFn = unsafe extern "system" fn(
        HWND,
        PCWSTR,
        *const WEBAUTHN_CLIENT_DATA,
        *const WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
        *mut *mut WEBAUTHN_ASSERTION,
    ) -> HRESULT;

    /// What GetProcAddress gives, before it's given its own type.
    type Proc = unsafe extern "system" fn() -> isize;
    type VersionFn = unsafe extern "system" fn() -> u32;
    type FreeAttFn = unsafe extern "system" fn(*const WEBAUTHN_CREDENTIAL_ATTESTATION);
    type FreeAssertFn = unsafe extern "system" fn(*const WEBAUTHN_ASSERTION);
    type CancelIdFn = unsafe extern "system" fn(*mut GUID) -> HRESULT;
    type CancelFn = unsafe extern "system" fn(*const GUID) -> HRESULT;
    type ErrorNameFn = unsafe extern "system" fn(HRESULT) -> PCWSTR;

    struct Api {
        version: VersionFn,
        make: MakeFn,
        get: GetFn,
        free_att: FreeAttFn,
        free_assert: FreeAssertFn,
        cancel_id: Option<CancelIdFn>,
        cancel: Option<CancelFn>,
        error_name: Option<ErrorNameFn>,
    }

    fn api() -> Option<&'static Api> {
        static API: std::sync::OnceLock<Option<Api>> = std::sync::OnceLock::new();
        API.get_or_init(|| {
            // SAFETY: webauthn.dll from System32 only; each function is looked up by its name, NUL
            // ended, and given the type Microsoft's webauthn.h gives it.
            unsafe {
                let m = LoadLibraryExW(w!("webauthn.dll"), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
                if m.is_null() {
                    return None;
                }
                let f = |name: &[u8]| GetProcAddress(m, name.as_ptr());
                Some(Api {
                    version: std::mem::transmute::<Proc, VersionFn>(f(b"WebAuthNGetApiVersionNumber\0")?),
                    make: std::mem::transmute::<Proc, MakeFn>(f(b"WebAuthNAuthenticatorMakeCredential\0")?),
                    get: std::mem::transmute::<Proc, GetFn>(f(b"WebAuthNAuthenticatorGetAssertion\0")?),
                    free_att: std::mem::transmute::<Proc, FreeAttFn>(f(b"WebAuthNFreeCredentialAttestation\0")?),
                    free_assert: std::mem::transmute::<Proc, FreeAssertFn>(f(b"WebAuthNFreeAssertion\0")?),
                    cancel_id: f(b"WebAuthNGetCancellationId\0").map(|p| std::mem::transmute::<Proc, CancelIdFn>(p)),
                    cancel: f(b"WebAuthNCancelCurrentOperation\0").map(|p| std::mem::transmute::<Proc, CancelFn>(p)),
                    error_name: f(b"WebAuthNGetErrorName\0").map(|p| std::mem::transmute::<Proc, ErrorNameFn>(p)),
                })
            }
        })
        .as_ref()
    }

    pub(super) fn usable() -> Result<(), String> {
        let a = api().ok_or(NO_DLL)?;
        // SAFETY: it takes nothing.
        let v = unsafe { (a.version)() };
        if v < API_FOR_SALTS {
            return Err(format!(
                "this Windows's WebAuthn (version {v}) can't give chat a security key's hmac-secret: version \
                 {API_FOR_SALTS}, in newer releases of Windows 11, can"
            ));
        }
        Ok(())
    }

    /// A NUL-ended UTF-16 string Windows gave.
    unsafe fn wide(p: PCWSTR) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        // SAFETY: the caller's: p is NUL-ended.
        while unsafe { *p.add(n) } != 0 {
            n += 1;
        }
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
    }

    /// `n` bytes Windows gave at `p`, or none.
    unsafe fn bytes<'a>(p: *const u8, n: u32) -> &'a [u8] {
        if p.is_null() || n == 0 {
            &[]
        } else {
            // SAFETY: the caller's: p holds n bytes.
            unsafe { std::slice::from_raw_parts(p, n as usize) }
        }
    }

    fn error(a: &Api, hr: HRESULT, doing: &str) -> KeyError {
        if hr == NTE_USER_CANCELLED || hr == CANCELLED {
            return KeyError::Cancelled;
        }
        // SAFETY: Windows gives a NUL-ended name, or none.
        let name = a.error_name.map(|f| unsafe { wide(f(hr)) }).unwrap_or_default();
        // Windows says NotAllowedError for a closed window, a timeout, and a key without the credential.
        KeyError::Failed(if name == "NotAllowedError" {
            format!(
                "Windows stopped {doing}: its window was closed, it timed out, or the security key isn't the one the save \
                 was locked with"
            )
        } else {
            format!(
                "Windows couldn't {doing} ({}, 0x{:08x})",
                if name.is_empty() { "error" } else { &name },
                hr as u32
            )
        })
    }

    /// Windows' window can't see `w.cancel`, so while `call` runs a thread asks it to close once
    /// that's set. `call` gets the cancellation id to pass, or null.
    fn watched<T>(a: &Api, w: &Wait, call: impl FnOnce(*mut GUID) -> T) -> T {
        // SAFETY: GUID is plain data; the call writes the id into it.
        let mut id: GUID = unsafe { std::mem::zeroed() };
        let have = a.cancel_id.is_some_and(|f| unsafe { f(&mut id) } == S_OK);
        w.stage.store(Wait::TOUCH, Ordering::Release);
        let done = AtomicBool::new(false);
        let copy = id;
        std::thread::scope(|s| {
            if let (true, Some(cancel)) = (have, a.cancel) {
                let done = &done;
                s.spawn(move || {
                    while !done.load(Ordering::Acquire) {
                        if w.cancel.load(Ordering::Acquire) {
                            // SAFETY: the id Windows gave for this call.
                            unsafe { cancel(&copy) };
                            break;
                        }
                        std::thread::sleep(CANCEL_POLL);
                    }
                });
            }
            let r = call(if have { &mut id } else { null_mut() });
            done.store(true, Ordering::Release);
            r
        })
    }

    /// A random challenge in client data Windows only hashes: nothing checks this signature.
    fn client_data(json: &mut String) -> WEBAUTHN_CLIENT_DATA {
        let challenge: [u8; 16] = sodium::random_array();
        *json = format!(
            "{{\"type\":\"chat\",\"challenge\":\"{}\"}}",
            crate::protocol::hex::encode(&challenge)
        );
        WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: json.len() as u32,
            pbClientDataJSON: json.as_ptr() as *mut u8,
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        }
    }

    fn credential(id: &[u8]) -> WEBAUTHN_CREDENTIAL {
        WEBAUTHN_CREDENTIAL {
            dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
            cbId: id.len() as u32,
            pbId: id.as_ptr() as *mut u8,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        }
    }

    /// The hmac-secret for `salt` from whichever credential in `list` the key has: which one, the
    /// secret, and whether the key checked its PIN for it.
    fn get_secret(
        a: &Api,
        list: &mut [WEBAUTHN_CREDENTIAL],
        salt: &[u8; SALT_LEN],
        uv: bool,
        w: &Wait,
    ) -> R<(usize, Zeroizing<[u8; 32]>, bool)> {
        // The salt goes to the key as it is, rather than hashed as WebAuthn's PRF would.
        let mut first = *salt;
        let mut s = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: SALT_LEN as u32,
            pbFirst: first.as_mut_ptr(),
            cbSecond: 0,
            pbSecond: null_mut(),
        };
        let mut values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut s,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: null_mut(),
        };
        let mut json = String::new();
        let cd = client_data(&mut json);
        let mut assertion: *mut WEBAUTHN_ASSERTION = null_mut();
        let hr = watched(a, w, |cancel| {
            let o = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
                dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
                dwTimeoutMilliseconds: (WAIT_SECS * 1000.0) as u32,
                CredentialList: WEBAUTHN_CREDENTIALS {
                    cCredentials: list.len() as u32,
                    pCredentials: list.as_mut_ptr(),
                },
                dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
                dwUserVerificationRequirement: if uv {
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED
                } else {
                    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED
                },
                dwFlags: WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG,
                pCancellationId: cancel,
                pHmacSecretSaltValues: &mut values,
                ..Default::default()
            };
            // SAFETY: every pointer in the options and the client data outlives the call.
            unsafe { (a.get)(GetForegroundWindow(), w!("chat"), &cd, &o, &mut assertion) }
        });
        if hr != S_OK || assertion.is_null() {
            return Err(error(a, hr, "read the security key"));
        }
        // SAFETY: Windows gave the assertion, which stays until it's freed below.
        let out = unsafe {
            let ax = &*assertion;
            let id = bytes(ax.Credential.pbId, ax.Credential.cbId);
            let which = list.iter().position(|c| bytes(c.pbId, c.cbId) == id);
            let hs = (ax.dwVersion >= WEBAUTHN_ASSERTION_VERSION_3 && !ax.pHmacSecret.is_null()).then(|| &*ax.pHmacSecret);
            match (which, hs) {
                (Some(i), Some(h)) if h.cbFirst == 32 && !h.pbFirst.is_null() => {
                    let mut secret = Zeroizing::new([0u8; 32]);
                    secret.copy_from_slice(bytes(h.pbFirst, 32));
                    let used_uv = bytes(ax.pbAuthenticatorData, ax.cbAuthenticatorData)
                        .get(AD_FLAGS_AT)
                        .is_some_and(|f| f & FLAG_UV != 0);
                    Ok((i, secret, used_uv))
                }
                _ => fail("Windows gave back no hmac-secret from the security key"),
            }
        };
        // SAFETY: as above.
        unsafe { (a.free_assert)(assertion) };
        out
    }

    pub(super) fn make(salt: &[u8; SALT_LEN], w: &Wait) -> R<(Vec<u8>, bool, Zeroizing<[u8; 32]>)> {
        let a = api().ok_or_else(|| KeyError::Failed(NO_DLL.into()))?;
        let mut uid: [u8; USER_ID_LEN] = sodium::random_array();
        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: w!("chat"),
            pwszName: w!("chat"),
            pwszIcon: null(),
        };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: USER_ID_LEN as u32,
            pbId: uid.as_mut_ptr(),
            pwszName: w!("chat"),
            pwszIcon: null(),
            pwszDisplayName: w!("chat"),
        };
        let mut alg = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &mut alg,
        };
        let mut on: BOOL = 1;
        let mut ext = WEBAUTHN_EXTENSION {
            pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
            cbExtension: std::mem::size_of::<BOOL>() as u32,
            pvExtension: (&mut on as *mut BOOL).cast(),
        };
        let mut json = String::new();
        let cd = client_data(&mut json);
        let mut att: *mut WEBAUTHN_CREDENTIAL_ATTESTATION = null_mut();
        let hr = watched(a, w, |cancel| {
            let o = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
                dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4,
                dwTimeoutMilliseconds: (WAIT_SECS * 1000.0) as u32,
                Extensions: WEBAUTHN_EXTENSIONS {
                    cExtensions: 1,
                    pExtensions: &mut ext,
                },
                dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
                dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED,
                dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                pCancellationId: cancel,
                ..Default::default()
            };
            // SAFETY: every pointer in the arguments outlives the call.
            unsafe { (a.make)(GetForegroundWindow(), &rp, &user, &params, &cd, &o, &mut att) }
        });
        if hr != S_OK || att.is_null() {
            return Err(error(a, hr, "register the security key"));
        }
        // SAFETY: Windows gave the attestation, which stays until it's freed below.
        let (id, hmac_on, version) = unsafe {
            let at = &*att;
            let exts: &[WEBAUTHN_EXTENSION] =
                if at.dwVersion >= WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_2 && !at.Extensions.pExtensions.is_null() {
                    std::slice::from_raw_parts(at.Extensions.pExtensions, at.Extensions.cExtensions as usize)
                } else {
                    &[]
                };
            let hmac_on = exts.iter().any(|e| {
                wide(e.pwszExtensionIdentifier) == "hmac-secret"
                    && e.cbExtension as usize == std::mem::size_of::<BOOL>()
                    && !e.pvExtension.is_null()
                    && *(e.pvExtension as *const BOOL) != 0
            });
            (bytes(at.pbCredentialId, at.cbCredentialId).to_vec(), hmac_on, at.dwVersion)
        };
        // SAFETY: as above.
        unsafe { (a.free_att)(att) };
        if !(version >= WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3 && !id.is_empty() && id.len() <= CRED_MAX && hmac_on) {
            return fail(if hmac_on {
                "Windows gave back no credential"
            } else {
                "this security key doesn't have hmac-secret, which chat needs"
            });
        }
        w.touches.fetch_add(1, Ordering::AcqRel);
        let (_, secret, uv) = get_secret(a, &mut [credential(&id)], salt, false, w)?;
        w.touches.fetch_add(1, Ordering::AcqRel);
        Ok((id, uv, secret))
    }

    pub(super) fn secret(creds: &[(Vec<u8>, bool)], salt: &[u8; SALT_LEN], w: &Wait) -> R<(usize, Zeroizing<[u8; 32]>)> {
        let a = api().ok_or_else(|| KeyError::Failed(NO_DLL.into()))?;
        let creds = &creds[..creds.len().min(CREDS_MAX)];
        let mut list: Vec<WEBAUTHN_CREDENTIAL> = creds.iter().map(|(c, _)| credential(c)).collect();
        let any_uv = creds.iter().any(|(_, uv)| *uv);
        let (which, secret, _) = get_secret(a, &mut list, salt, any_uv, w)?;
        w.touches.fetch_add(1, Ordering::AcqRel);
        Ok((which, secret))
    }
}
