// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! A secret sealed with a TPM 2.0 that chat speaks to itself, for systems with no systemd
//! credential service (runit, OpenRC, s6, systemd before 256). It's sealed under the TPM's storage
//! key, made again from the owner seed each time (or, where Windows set the TPM up and kept its
//! password, the key Windows keeps at 0x81000001). The secret crosses the bus encrypted, in a
//! session salted to that key, and every answer's HMAC is checked. The sealed form names the key,
//! so a cleared TPM, or something posing as the TPM, is refused.

use aws_lc_rs::{digest, hmac};
use zeroize::Zeroizing;

pub const SECRET_LEN: usize = 32;

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
const CC_CREATE_PRIMARY: u32 = 0x131;
const CC_CREATE: u32 = 0x153;
const CC_LOAD: u32 = 0x157;
const CC_UNSEAL: u32 = 0x15E;
const CC_FLUSH_CONTEXT: u32 = 0x165;
const CC_READ_PUBLIC: u32 = 0x173;
const CC_START_AUTH_SESSION: u32 = 0x176;
const RH_OWNER: u32 = 0x4000_0001;
const RH_NULL: u32 = 0x4000_0007;
const RS_PW: u32 = 0x4000_0009;
const SRK_PERSISTENT: u32 = 0x8100_0001;
const ALG_RSA: u16 = 0x0001;
const ALG_AES: u16 = 0x0006;
const ALG_XOR: u16 = 0x000A;
const ALG_SHA256: u16 = 0x000B;
const ALG_NULL: u16 = 0x0010;
const ALG_ECC: u16 = 0x0023;
const ALG_CFB: u16 = 0x0043;
const ECC_NIST_P256: u16 = 0x0003;
const SE_HMAC: u8 = 0;
const SA_CONTINUE: u8 = 0x01;
const SA_DECRYPT: u8 = 0x20;
const SA_ENCRYPT: u8 = 0x40;
const RC_YIELDED: u32 = 0x908;
const RC_TESTING: u32 = 0x90A;
const RC_LOCKOUT: u32 = 0x921;
const RC_RETRY: u32 = 0x922;
/// fixedTPM, fixedParent, userWithAuth, restricted, decrypt: what a key needs to be a parent.
const STORAGE_ATTRS: u32 = 0x0003_0052;
const HEADER_LEN: usize = 10;
const RETRIES: u32 = 50;
const NAME_LEN: usize = 34;
const NONCE_LEN: usize = 32;
const NONCE_MIN: usize = 16;
const P256_COORD_LEN: usize = 32;
const RSA_LEN: usize = 256;
const AES_BITS: u16 = 128;
const PRIVATE_MAX: usize = 512;
/// The sealed object's public area as the TPM gives it back: the template, and a 32-byte unique.
const SEALED_PUBLIC_LEN: usize = 46;
const FORMAT: u8 = 1;

/// The TCG's storage key template: ECC P-256, SHA-256 names, AES-128-CFB, with fixedTPM,
/// fixedParent, sensitiveDataOrigin, userWithAuth, noDA, restricted and decrypt. The same template
/// always gives the same key, until the TPM is cleared.
const SRK_TEMPLATE: [u8; 26] = [
    0x00, 0x23, 0x00, 0x0B, 0x00, 0x03, 0x04, 0x72, 0x00, 0x00, 0x00, 0x06, 0x00, 0x80, 0x00, 0x43, 0x00, 0x10, 0x00, 0x03, 0x00, 0x10,
    0x00, 0x00, 0x00, 0x00,
];
const SRK_HEAD: usize = 22;

/// Sealed data: a keyed hash object with no scheme, fixedTPM, fixedParent, userWithAuth and noDA,
/// so a wrong password could never count towards the TPM's lockout.
const SEAL_TEMPLATE: [u8; 14] = [0x00, 0x08, 0x00, 0x0B, 0x00, 0x00, 0x04, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00];
const SEAL_HEAD: usize = 12;

/// Sends one command and reads its answer.
pub type Transmit<'a> = &'a mut dyn FnMut(&[u8]) -> Result<Vec<u8>, String>;

#[derive(Default)]
struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn n(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
    /// A TPM2B: its size, then it.
    fn b2(&mut self, b: &[u8]) -> &mut Self {
        self.u16(b.len() as u16).n(b)
    }
    fn command(tag: u16, cc: u32) -> W {
        let mut w = W::default();
        w.u16(tag).u32(0).u32(cc);
        w
    }
    /// The size, filled in once it's known.
    fn done(mut self) -> Zeroizing<Vec<u8>> {
        let n = self.0.len() as u32;
        self.0[2..6].copy_from_slice(&n.to_be_bytes());
        Zeroizing::new(std::mem::take(&mut self.0))
    }
    /// The owner's password, and every key chat makes or uses, is empty.
    fn password_auth(&mut self) -> &mut Self {
        self.u32(9).u32(RS_PW).u16(0).u8(SA_CONTINUE).u16(0)
    }
}

struct R<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> R<'a> {
    fn n(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.i..self.i.checked_add(n)?)?;
        self.i += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.n(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.n(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.n(4)?.try_into().ok()?))
    }
    fn b2(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.n(usize::from(n))
    }
    fn end(&self) -> bool {
        self.i == self.b.len()
    }
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut c = digest::Context::new(&digest::SHA256);
    parts.iter().for_each(|p| c.update(p));
    c.finish().as_ref().try_into().expect("32 bytes")
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut c = hmac::Context::with_key(&k);
    parts.iter().for_each(|p| c.update(p));
    c.sign().as_ref().try_into().expect("32 bytes")
}

/// KDFa (SP 800-108 counter mode, HMAC-SHA256), as TPM 2.0 has it: one zero byte after the label.
fn kdfa(key: &[u8], label: &str, u: &[u8], v: &[u8], out_len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(out_len + 32));
    let bits = (out_len as u32 * 8).to_be_bytes();
    let mut i = 1u32;
    while out.len() < out_len {
        let block = hmac_sha256(key, &[&i.to_be_bytes(), label.as_bytes(), &[0], u, v, &bits]);
        out.extend_from_slice(&block);
        i += 1;
    }
    out.truncate(out_len);
    out
}

/// Parameter encryption with TPM_ALG_XOR: a KDFa stream keyed with the session key, fresh for each
/// command and answer since the nonces are.
fn xor_param(key: &[u8], newer: &[u8], older: &[u8], data: &mut [u8]) {
    let mask = kdfa(key, "XOR", newer, older, data.len());
    data.iter_mut().zip(mask.iter()).for_each(|(d, m)| *d ^= m);
}

/// An object's name: its name algorithm, then the hash of its public area.
fn name_of(public: &[u8]) -> [u8; NAME_LEN] {
    let mut n = [0u8; NAME_LEN];
    n[..2].copy_from_slice(&ALG_SHA256.to_be_bytes());
    n[2..].copy_from_slice(&sha256(&[public]));
    n
}

/// Format one: TPM_RC_BAD_AUTH or TPM_RC_AUTH_FAIL, for any handle or session.
fn auth_error(rc: u32) -> bool {
    rc & 0x80 != 0 && matches!(rc & 0x3F, 0x22 | 0x0E)
}

/// What went wrong: the TPM's answer, or that it didn't answer.
enum Fail {
    Rc(u32),
    Why(String),
}

type Res<T> = Result<T, Fail>;

fn why(s: impl Into<String>) -> Fail {
    Fail::Why(s.into())
}

fn explain(f: Fail, what: &str) -> String {
    match f {
        Fail::Why(w) => w,
        Fail::Rc(RC_LOCKOUT) => format!("{what}: the TPM is locked out after too many wrong passwords, for now"),
        Fail::Rc(rc) if auth_error(rc) => format!("{what}: the TPM wants a password chat doesn't have (0x{rc:x})"),
        Fail::Rc(rc) => format!("{what} (TPM error 0x{rc:x})"),
    }
}

/// Every key chat makes has no password, so the TPM rejecting a session's HMAC means what crossed
/// the bus was changed.
fn explain_session(f: Fail, what: &str) -> String {
    match f {
        Fail::Rc(rc) if auth_error(rc) => {
            format!("{what}: the TPM didn't accept what chat sent, so something between chat and the TPM changed it (0x{rc:x})")
        }
        f => explain(f, what),
    }
}

struct Tpm<'a> {
    io: Transmit<'a>,
}

/// The key everything is sealed under: an ECC P-256 or RSA-2048 storage key with SHA-256 names.
struct Parent {
    handle: u32,
    persistent: bool,
    name: [u8; NAME_LEN],
    key: ParentKey,
}

enum ParentKey {
    Ecc([u8; P256_COORD_LEN], [u8; P256_COORD_LEN]),
    Rsa(Vec<u8>, u32),
}

fn parse_parent(public: &[u8]) -> Option<ParentKey> {
    let mut r = R { b: public, i: 0 };
    let (kind, name_alg, attrs) = (r.u16()?, r.u16()?, r.u32()?);
    r.b2()?;
    let (sym, bits, mode, scheme) = (r.u16()?, r.u16()?, r.u16()?, r.u16()?);
    if name_alg != ALG_SHA256
        || attrs & STORAGE_ATTRS != STORAGE_ATTRS
        || sym != ALG_AES
        || bits != AES_BITS
        || mode != ALG_CFB
        || scheme != ALG_NULL
    {
        return None;
    }
    let key = match kind {
        ALG_ECC => {
            let (curve, kdf) = (r.u16()?, r.u16()?);
            let (x, y) = (r.b2()?, r.b2()?);
            if curve != ECC_NIST_P256 || kdf != ALG_NULL || x.len() != P256_COORD_LEN || y.len() != P256_COORD_LEN {
                return None;
            }
            ParentKey::Ecc(x.try_into().ok()?, y.try_into().ok()?)
        }
        ALG_RSA => {
            let (key_bits, e) = (r.u16()?, r.u32()?);
            let n = r.b2()?;
            if key_bits != 2048 || n.len() != RSA_LEN {
                return None;
            }
            ParentKey::Rsa(n.to_vec(), if e == 0 { 65537 } else { e })
        }
        _ => return None,
    };
    r.end().then_some(key)
}

/// A session: its handle, the key its HMACs and parameter encryption use, and the TPM's nonce.
struct Session {
    handle: u32,
    key: Zeroizing<[u8; 32]>,
    nonce_tpm: Vec<u8>,
}

/// The DER of an RSA public key's SubjectPublicKeyInfo, for aws-lc-rs.
fn rsa_spki(n: &[u8], e: u32) -> Vec<u8> {
    fn len(out: &mut Vec<u8>, n: usize) {
        match n {
            0..=0x7f => out.push(n as u8),
            0x80..=0xff => out.extend([0x81, n as u8]),
            _ => out.extend([0x82, (n >> 8) as u8, n as u8]),
        }
    }
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        len(&mut out, body.len());
        out.extend_from_slice(body);
        out
    }
    let int = |b: &[u8]| {
        let b = &b[b.iter().take_while(|x| **x == 0).count().min(b.len() - 1)..];
        let mut v = if b[0] & 0x80 != 0 { vec![0] } else { Vec::new() };
        v.extend_from_slice(b);
        tlv(0x02, &v)
    };
    let rsa_key = tlv(0x30, &[int(n), int(&e.to_be_bytes())].concat());
    let mut bits = vec![0];
    bits.extend(rsa_key);
    // rsaEncryption, with NULL parameters.
    let alg = tlv(
        0x30,
        &[tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]), vec![0x05, 0x00]].concat(),
    );
    tlv(0x30, &[alg, tlv(0x03, &bits)].concat())
}

/// A session's salt, and the salt encrypted to the parent so only the TPM can read it: RSA-OAEP
/// with the label "SECRET", or ECDH with a fresh key and KDFe, as TPM 2.0 has them.
fn make_salt(p: &ParentKey) -> Option<(Zeroizing<[u8; 32]>, Vec<u8>)> {
    let rng = aws_lc_rs::rand::SystemRandom::new();
    match p {
        ParentKey::Rsa(n, e) => {
            use aws_lc_rs::rsa::{OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey, PublicEncryptingKey};
            let salt = Zeroizing::new(crate::protocol::crypto::sodium::random_array::<32>());
            let key = OaepPublicEncryptingKey::new(PublicEncryptingKey::from_der(&rsa_spki(n, *e)).ok()?).ok()?;
            let mut enc = vec![0u8; key.ciphertext_size()];
            let n = key
                .encrypt(&OAEP_SHA256_MGF1SHA256, &salt[..], &mut enc, Some(b"SECRET\0"))
                .ok()?
                .len();
            enc.truncate(n);
            Some((salt, enc))
        }
        ParentKey::Ecc(x, y) => {
            use aws_lc_rs::agreement::{ECDH_P256, EphemeralPrivateKey, UnparsedPublicKey, agree_ephemeral};
            let mine = EphemeralPrivateKey::generate(&ECDH_P256, &rng).ok()?;
            let point = mine.compute_public_key().ok()?;
            let point = point.as_ref();
            if point.len() != 65 {
                return None;
            }
            let theirs = [&[4u8][..], x, y].concat();
            // KDFe: SHA-256 over a counter, Z, the label and a zero byte, then both x coordinates.
            let salt = agree_ephemeral(mine, UnparsedPublicKey::new(&ECDH_P256, &theirs), (), |z| {
                Ok(Zeroizing::new(sha256(&[&[0, 0, 0, 1], z, b"SECRET", &[0], &point[1..33], x])))
            })
            .ok()?;
            // The encrypted salt is the fresh key's point.
            let mut enc = W::default();
            enc.b2(&point[1..33]).b2(&point[33..]);
            Some((salt, enc.0))
        }
    }
}

impl Tpm<'_> {
    /// Sends a command: Ok with the answer if the TPM ran it, Err(Rc) if it answered with an error.
    /// A TPM that's busy or testing itself hasn't run the command, so it's sent again.
    fn call(&mut self, cmd: &[u8]) -> Res<Vec<u8>> {
        for tries in 0.. {
            let rsp = (self.io)(cmd).map_err(Fail::Why)?;
            if rsp.len() < HEADER_LEN || u32::from_be_bytes(rsp[2..6].try_into().expect("4")) as usize != rsp.len() {
                return Err(why("the TPM didn't answer properly"));
            }
            let rc = u32::from_be_bytes(rsp[6..10].try_into().expect("4"));
            if matches!(rc, RC_RETRY | RC_YIELDED | RC_TESTING) && tries < RETRIES {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
            return if rc == 0 { Ok(rsp) } else { Err(Fail::Rc(rc)) };
        }
        unreachable!()
    }

    fn flush(&mut self, handle: u32) {
        let mut w = W::command(ST_NO_SESSIONS, CC_FLUSH_CONTEXT);
        w.u32(handle);
        let _ = self.call(&w.done());
    }

    fn create_primary(&mut self) -> Res<Parent> {
        let mut w = W::command(ST_SESSIONS, CC_CREATE_PRIMARY);
        // inSensitive: no password, no data; then the template, no outsideInfo, no PCRs.
        w.u32(RH_OWNER).password_auth().u16(4).u16(0).u16(0).b2(&SRK_TEMPLATE).u16(0).u32(0);
        let rsp = self.call(&w.done())?;
        let mut r = R { b: &rsp, i: HEADER_LEN };
        let handle = r.u32().ok_or_else(|| why("the TPM didn't answer properly"))?;
        let public = r.u32().and_then(|_| r.b2());
        match public
            .filter(|p| p.len() >= SRK_HEAD && p[..SRK_HEAD] == SRK_TEMPLATE[..SRK_HEAD])
            .and_then(|p| Some((p, parse_parent(p)?)))
        {
            Some((p, key)) => Ok(Parent {
                handle,
                persistent: false,
                name: name_of(p),
                key,
            }),
            None => {
                self.flush(handle);
                Err(why("the TPM made a storage key other than the one chat asked for"))
            }
        }
    }

    fn read_persistent(&mut self) -> Res<Parent> {
        let mut w = W::command(ST_NO_SESSIONS, CC_READ_PUBLIC);
        w.u32(SRK_PERSISTENT);
        let rsp = self.call(&w.done())?;
        let mut r = R { b: &rsp, i: HEADER_LEN };
        let p = r.b2().ok_or_else(|| why("the TPM didn't answer properly"))?;
        let key = parse_parent(p).ok_or_else(|| why("the TPM's storage key at 0x81000001 isn't one chat can use"))?;
        Ok(Parent {
            handle: SRK_PERSISTENT,
            persistent: true,
            name: name_of(p),
            key,
        })
    }

    fn put_away(&mut self, p: &Parent) {
        if !p.persistent {
            self.flush(p.handle);
        }
    }

    /// Windows sets a random owner password and forgets it, so where it set the TPM up, the owner's
    /// storage key can't be made: the one Windows keeps at 0x81000001 is used instead.
    fn parent(&mut self) -> Result<Parent, String> {
        match self.create_primary() {
            Ok(p) => Ok(p),
            Err(Fail::Rc(rc)) if auth_error(rc) => self.read_persistent().map_err(|f| match f {
                Fail::Rc(rc) => format!(
                    "the TPM's owner hierarchy has a password, and there's no storage key at 0x81000001 to use instead (TPM error 0x{rc:x})"
                ),
                f => explain(f, ""),
            }),
            Err(f) => Err(explain(f, "the TPM couldn't make its storage key")),
        }
    }

    /// An HMAC session salted to the parent, with XOR parameter encryption and SHA-256 throughout.
    fn start_session(&mut self, p: &Parent) -> Result<Session, String> {
        let nonce: [u8; NONCE_LEN] = crate::protocol::crypto::sodium::random_array();
        let (salt, enc) = make_salt(&p.key).ok_or("couldn't make a key to talk to the TPM with")?;
        let mut w = W::command(ST_NO_SESSIONS, CC_START_AUTH_SESSION);
        w.u32(p.handle)
            .u32(RH_NULL)
            .b2(&nonce)
            .b2(&enc)
            .u8(SE_HMAC)
            .u16(ALG_XOR)
            .u16(ALG_SHA256)
            .u16(ALG_SHA256);
        let rsp = self
            .call(&w.done())
            .map_err(|f| explain(f, "the TPM couldn't start an encrypted session"))?;
        let mut r = R { b: &rsp, i: HEADER_LEN };
        let (handle, nt) = (r.u32(), r.b2());
        let (Some(handle), Some(nt)) = (handle, nt.filter(|n| (NONCE_MIN..=NONCE_LEN).contains(&n.len()))) else {
            return Err("the TPM's session didn't make sense".into());
        };
        let key = kdfa(&salt[..], "ATH", nt, &nonce, 32);
        Ok(Session {
            handle,
            key: Zeroizing::new(key[..].try_into().expect("32 bytes")),
            nonce_tpm: nt.to_vec(),
        })
    }

    /// cc for one handle, authorized by s, its first parameter encrypted if attrs has SA_DECRYPT.
    /// The answer's HMAC is checked, then its first parameter decrypted if attrs has SA_ENCRYPT;
    /// the answer's parameters come back.
    fn session_call(
        &mut self,
        s: &mut Session,
        cc: u32,
        handle: u32,
        name: &[u8; NAME_LEN],
        params: &mut [u8],
        attrs: u8,
    ) -> Res<Zeroizing<Vec<u8>>> {
        let nonce: [u8; NONCE_LEN] = crate::protocol::crypto::sodium::random_array();
        if attrs & SA_DECRYPT != 0 {
            let n = params.get(..2).map_or(0, |b| usize::from(u16::from_be_bytes([b[0], b[1]])));
            let Some(first) = params.get_mut(2..2 + n) else {
                return Err(why("couldn't encrypt what goes to the TPM"));
            };
            xor_param(&s.key[..], &nonce, &s.nonce_tpm, first);
        }
        // The HMAC covers the command's parameters as sent, so after they're encrypted.
        let cp = sha256(&[&cc.to_be_bytes(), name, params]);
        let mac = hmac_sha256(&s.key[..], &[&cp, &nonce, &s.nonce_tpm, &[attrs]]);
        let mut w = W::command(ST_SESSIONS, cc);
        w.u32(handle)
            .u32((4 + 2 + NONCE_LEN + 1 + 2 + 32) as u32)
            .u32(s.handle)
            .b2(&nonce)
            .u8(attrs)
            .b2(&mac)
            .n(params);
        let rsp = self.call(&w.done())?;
        let mut r = R { b: &rsp, i: HEADER_LEN };
        let bad = || why("the TPM's answer didn't make sense");
        let psize = r.u32().ok_or_else(bad)? as usize;
        let start = r.i;
        r.n(psize).ok_or_else(bad)?;
        let nt = r.b2().filter(|n| (NONCE_MIN..=NONCE_LEN).contains(&n.len())).ok_or_else(bad)?;
        let rattrs = r.u8().ok_or_else(bad)?;
        let rh = r.b2().filter(|h| h.len() == 32).ok_or_else(bad)?;
        if !r.end() {
            return Err(bad());
        }
        let rp = &rsp[start..start + psize];
        let rph = sha256(&[&[0, 0, 0, 0], &cc.to_be_bytes(), rp]);
        let expect = hmac_sha256(&s.key[..], &[&rph, nt, &nonce, &[rattrs]]);
        if !crate::protocol::crypto::sodium::ct_eq(&expect, rh) {
            return Err(why(
                "the TPM's answer failed its check: something between chat and the TPM changed it",
            ));
        }
        s.nonce_tpm = nt.to_vec();
        let mut out = Zeroizing::new(rp.to_vec());
        if attrs & SA_ENCRYPT != 0 {
            let n = out.get(..2).map_or(0, |b| usize::from(u16::from_be_bytes([b[0], b[1]])));
            let Some(first) = out.get_mut(2..2 + n) else { return Err(bad()) };
            xor_param(&s.key[..], &s.nonce_tpm, &nonce, first);
        }
        Ok(out)
    }
}

/// `secret` sealed under the TPM's storage key: its sealed form.
pub fn seal(io: Transmit, secret: &[u8; SECRET_LEN]) -> Result<Vec<u8>, String> {
    let mut t = Tpm { io };
    let p = t.parent()?;
    let r = (|| {
        let mut s = t.start_session(&p)?;
        let mut params = W::default();
        // inSensitive: no password, the secret as its data; the template; no outsideInfo or PCRs.
        params
            .u16((2 + 2 + SECRET_LEN) as u16)
            .u16(0)
            .b2(secret)
            .b2(&SEAL_TEMPLATE)
            .u16(0)
            .u32(0);
        let mut params = Zeroizing::new(params.0);
        let r = t.session_call(&mut s, CC_CREATE, p.handle, &p.name, &mut params, SA_DECRYPT);
        let rp = match r {
            Ok(rp) => rp,
            Err(f) => {
                // Without a resource manager, a session a failed command didn't use up stays open.
                t.flush(s.handle);
                return Err(explain_session(f, "the TPM couldn't seal it"));
            }
        };
        let mut r = R { b: &rp, i: 0 };
        let (private, public) = (r.b2(), r.b2());
        match (private, public) {
            (Some(v), Some(pb))
                if v.len() <= PRIVATE_MAX && pb.len() == SEALED_PUBLIC_LEN && pb[..SEAL_HEAD] == SEAL_TEMPLATE[..SEAL_HEAD] =>
            {
                let mut o = W::default();
                o.u8(FORMAT).u8(u8::from(p.persistent)).n(&p.name).b2(pb).b2(v);
                Ok(o.0)
            }
            _ => Err("the TPM sealed it in a form chat can't keep".into()),
        }
    })();
    t.put_away(&p);
    r
}

/// The secret a sealed form holds, unsealed by the TPM it was sealed with.
pub fn unseal(io: Transmit, sealed: &[u8]) -> Result<Zeroizing<[u8; SECRET_LEN]>, String> {
    let mut r = R { b: sealed, i: 0 };
    let parsed =
        (|| {
            let (format, persistent, name) = (r.u8()?, r.u8()?, r.n(NAME_LEN)?);
            let (public, private) = (r.b2()?, r.b2()?);
            (r.end() && format == FORMAT && persistent <= 1 && public.len() == SEALED_PUBLIC_LEN && private.len() <= PRIVATE_MAX)
                .then_some((persistent == 1, name, public, private))
        })();
    let (persistent, name, public, private) = parsed.ok_or("it isn't sealed in a way chat knows")?;
    let mut t = Tpm { io };
    let p = if persistent { t.read_persistent() } else { t.create_primary() }.map_err(|f| {
        explain(
            f,
            if persistent {
                "the TPM has no storage key at 0x81000001 any more"
            } else {
                "the TPM couldn't make its storage key"
            },
        )
    })?;
    // Pinned: a TPM cleared since makes another key, and so would anything posing as the TPM.
    if !crate::protocol::crypto::sodium::ct_eq(&p.name, name) {
        t.put_away(&p);
        return Err("this TPM's storage key isn't the one it was sealed under: it was sealed with another TPM, this one has been cleared since, or something is posing as the TPM".into());
    }
    let mut w = W::command(ST_SESSIONS, CC_LOAD);
    w.u32(p.handle).password_auth().b2(private).b2(public);
    let item = match t.call(&w.done()) {
        Ok(rsp) => R { b: &rsp, i: HEADER_LEN }.u32(),
        Err(f) => {
            t.put_away(&p);
            return Err(explain(
                f,
                "the TPM can't load what it sealed: it was sealed with another TPM, or this one has been cleared since",
            ));
        }
    };
    let Some(item) = item else {
        t.put_away(&p);
        return Err("the TPM didn't answer properly".into());
    };
    let r = (|| {
        let mut s = t.start_session(&p)?;
        match t.session_call(&mut s, CC_UNSEAL, item, &name_of(public), &mut [], SA_ENCRYPT) {
            Ok(rp) => {
                let mut r = R { b: &rp, i: 0 };
                match r.b2().filter(|d| d.len() == SECRET_LEN) {
                    Some(d) => Ok(Zeroizing::new(d.try_into().expect("32 bytes"))),
                    None => Err("the TPM unsealed something that isn't chat's".to_string()),
                }
            }
            Err(f) => {
                t.flush(s.handle);
                Err(explain_session(f, "the TPM couldn't unseal it"))
            }
        }
    })();
    t.flush(item);
    t.put_away(&p);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdfa_and_names_are_tpm_shaped() {
        // KDFa's output is as long as asked, and the same for the same inputs.
        let a = kdfa(b"key", "XOR", b"u", b"v", 40);
        assert_eq!(
            (a.len(), &a[..], kdfa(b"key", "XOR", b"u", b"v", 40).as_slice() == &a[..]),
            (40, &a[..], true)
        );
        assert_ne!(&a[..32], &kdfa(b"key", "ATH", b"u", b"v", 32)[..]);
        let n = name_of(&SEAL_TEMPLATE);
        assert_eq!(&n[..2], &[0x00, 0x0B]);
        // The DER aws-lc-rs takes for the parent's RSA key.
        let modulus = [&[0xC1u8][..], &[0x55; 255]].concat();
        assert!(aws_lc_rs::rsa::PublicEncryptingKey::from_der(&rsa_spki(&modulus, 65537)).is_ok());
        assert!(make_salt(&ParentKey::Rsa(modulus, 65537)).is_some_and(|(_, enc)| enc.len() == RSA_LEN));
        assert!(auth_error(0x9a2) && !auth_error(RC_LOCKOUT));
        // A sealed form in another format, or with bytes after it, is refused before the TPM is asked.
        let mut never = |_: &[u8]| -> Result<Vec<u8>, String> { panic!("asked the TPM") };
        assert!(unseal(&mut never, &[2, 0]).is_err());
    }
}
