// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Signing identities as PGP keys (RFC 4880): a v4 EdDSA (Ed25519) key with a user id and its
//! self-signature, armored, for others to `gpg --import`, and an unencrypted armored secret key
//! read back in, with deterministic bytes so the fingerprint is identical.

use super::identity::{IdentityKeypair, SIGN_LEN, SIGN_PUB_LEN};
use super::sodium;
use crate::protocol::base64;
use zeroize::Zeroizing;

pub const FP_LEN: usize = 20;
/// A key made from a password is dated this, the same every time, so its fingerprint (which
/// covers the date) is too.
pub const DERIVED_CREATED: u32 = 1_767_225_600;

pub const PRIVATE_BEGIN: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
pub const PRIVATE_END: &str = "-----END PGP PRIVATE KEY BLOCK-----";
const PUBLIC_BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PUBLIC_END: &str = "-----END PGP PUBLIC KEY BLOCK-----";

const VERSION: u8 = 4;
const EDDSA: u8 = 22;
const SHA256: u8 = 8;
const SIG_POSITIVE_CERT: u8 = 0x13;
const TAG_SIGNATURE: u8 = 2;
const TAG_SECRET_KEY: u8 = 5;
const TAG_PUBLIC_KEY: u8 = 6;
const TAG_USER_ID: u8 = 13;
const SUBPKT_CREATED: u8 = 2;
const SUBPKT_ISSUER: u8 = 16;
const PACKET_BIT: u8 = 0x80;
const NEW_FORMAT_BIT: u8 = 0x40;
const TWO_BYTE_LEN: usize = 192;
const PARTIAL_LEN: usize = 224;
const FOUR_BYTE_LEN: usize = 255;
const HASH_KEY_PREFIX: u8 = 0x99;
const HASH_UID_PREFIX: u8 = 0xb4;
const EDDSA_POINT: u8 = 0x40;
const KEY_ID_LEN: usize = 8;
const ARMOR_LINE: usize = 64;
const ED25519_OID: [u8; 9] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
/// The user id is cut to this many bytes.
const UID_MAX: usize = 63;

/// An MPI: its bit count, then its bytes without leading zeros.
fn put_mpi(out: &mut Vec<u8>, p: &[u8]) {
    let p = &p[p.iter().position(|&b| b != 0).unwrap_or(p.len())..];
    let bits = match p.first() {
        Some(&top) => (p.len() - 1) * 8 + (8 - top.leading_zeros() as usize),
        None => 0,
    };
    out.extend_from_slice(&(bits as u16).to_be_bytes());
    out.extend_from_slice(p);
}

fn put_header(out: &mut Vec<u8>, tag: u8, len: usize) {
    out.push(PACKET_BIT | NEW_FORMAT_BIT | tag);
    if len < TWO_BYTE_LEN {
        out.push(len as u8);
    } else {
        let v = len - TWO_BYTE_LEN;
        out.push((TWO_BYTE_LEN + (v >> 8)) as u8);
        out.push(v as u8);
    }
}

fn pubkey_body(public: &[u8; SIGN_PUB_LEN], created: u32) -> Vec<u8> {
    let mut b = vec![VERSION];
    b.extend_from_slice(&created.to_be_bytes());
    b.push(EDDSA);
    b.push(ED25519_OID.len() as u8);
    b.extend_from_slice(&ED25519_OID);
    let mut point = [0u8; 1 + SIGN_PUB_LEN];
    point[0] = EDDSA_POINT;
    point[1..].copy_from_slice(public);
    put_mpi(&mut b, &point);
    b
}

fn hashed_key(out: &mut Vec<u8>, body: &[u8]) {
    out.push(HASH_KEY_PREFIX);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

fn sha1(data: &[u8]) -> [u8; FP_LEN] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, data);
    d.as_ref().try_into().expect("20 bytes")
}

/// The key's v4 fingerprint, which covers its creation time.
pub fn fingerprint(public: &[u8; SIGN_PUB_LEN], created: u32) -> [u8; FP_LEN] {
    let mut pre = Vec::new();
    hashed_key(&mut pre, &pubkey_body(public, created));
    sha1(&pre)
}

fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xB704CE;
    for &b in data {
        crc ^= u32::from(b) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x100_0000 != 0 {
                crc ^= 0x186_4CFB;
            }
        }
    }
    crc & 0xFF_FFFF
}

/// The key, its user id and its self-signature, armored; with `secret`, the key's packet is the
/// secret one, unencrypted.
fn export(kp: &IdentityKeypair, nick: &str, created: u32, secret: Option<&[u8; 32]>) -> (Zeroizing<String>, [u8; FP_LEN]) {
    let body = pubkey_body(&kp.public, created);
    let fp = fingerprint(&kp.public, created);
    let mut uid = format!("{nick} (chat identity)").into_bytes();
    uid.truncate(UID_MAX);

    // The one hashed subpacket: its length, then the key's creation time.
    let mut hashed = vec![5, SUBPKT_CREATED];
    hashed.extend_from_slice(&created.to_be_bytes());
    let mut trailer = vec![VERSION, SIG_POSITIVE_CERT, EDDSA, SHA256];
    trailer.extend_from_slice(&(hashed.len() as u16).to_be_bytes());
    trailer.extend_from_slice(&hashed);

    let mut pre = Vec::new();
    hashed_key(&mut pre, &body);
    pre.push(HASH_UID_PREFIX);
    pre.extend_from_slice(&(uid.len() as u32).to_be_bytes());
    pre.extend_from_slice(&uid);
    pre.extend_from_slice(&trailer);
    pre.extend_from_slice(&[VERSION, 0xff]);
    pre.extend_from_slice(&(trailer.len() as u32).to_be_bytes());
    let hash = sodium::sha256(&[&pre]);
    let sig: [u8; SIGN_LEN] = kp.sign(&hash);

    let mut unhashed = vec![1 + KEY_ID_LEN as u8, SUBPKT_ISSUER];
    unhashed.extend_from_slice(&fp[FP_LEN - KEY_ID_LEN..]);
    let mut sigbody = trailer.clone();
    sigbody.extend_from_slice(&(unhashed.len() as u16).to_be_bytes());
    sigbody.extend_from_slice(&unhashed);
    sigbody.extend_from_slice(&hash[..2]);
    // R, then S.
    put_mpi(&mut sigbody, &sig[..SIGN_LEN / 2]);
    put_mpi(&mut sigbody, &sig[SIGN_LEN / 2..]);

    let mut doc = Zeroizing::new(Vec::new());
    match secret {
        Some(seed) => {
            // After the public part: S2K usage 0 (in the clear), the seed as an MPI, and the
            // two-byte sum of the MPI's bytes.
            let mut mpi = Zeroizing::new(Vec::new());
            put_mpi(&mut mpi, seed);
            let sum = mpi.iter().fold(0u16, |s, &b| s.wrapping_add(u16::from(b)));
            put_header(&mut doc, TAG_SECRET_KEY, body.len() + 1 + mpi.len() + 2);
            doc.extend_from_slice(&body);
            doc.push(0);
            doc.extend_from_slice(&mpi);
            doc.extend_from_slice(&sum.to_be_bytes());
        }
        None => {
            put_header(&mut doc, TAG_PUBLIC_KEY, body.len());
            doc.extend_from_slice(&body);
        }
    }
    put_header(&mut doc, TAG_USER_ID, uid.len());
    doc.extend_from_slice(&uid);
    put_header(&mut doc, TAG_SIGNATURE, sigbody.len());
    doc.extend_from_slice(&sigbody);

    let b64 = Zeroizing::new(base64::encode(&doc));
    let crc = crc24(&doc).to_be_bytes();
    let (begin, end) = if secret.is_some() {
        (PRIVATE_BEGIN, PRIVATE_END)
    } else {
        (PUBLIC_BEGIN, PUBLIC_END)
    };
    let mut out = Zeroizing::new(format!("{begin}\n\n"));
    for line in b64.as_bytes().chunks(ARMOR_LINE) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("={}\n{end}\n", base64::encode(&crc[1..])));
    (out, fp)
}

/// The key as a PGP public key, armored, with `nick` in its user id. The fingerprint covers
/// `created`, so that has to stay the same for a key.
pub fn export_public(kp: &IdentityKeypair, nick: &str, created: u32) -> (String, [u8; FP_LEN]) {
    let (out, fp) = export(kp, nick, created, None);
    (out.to_string(), fp)
}

/// The same key with its secret, unencrypted, as `gpg --export-secret-keys` writes a key with no
/// passphrase. None for a key with no seed to write (an AGE key's).
pub fn export_secret(kp: &IdentityKeypair, nick: &str, created: u32) -> Option<(Zeroizing<String>, [u8; FP_LEN])> {
    let seed = kp.seed()?;
    Some(export(kp, nick, created, Some(&seed)))
}

fn b64_value(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// The body of an armored block (the text between its BEGIN and END lines): armor headers
/// ("Key: value" lines before the first blank one) are skipped, and the "=XXXX" CRC-24 line is
/// checked when there is one.
fn armor_decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    let (mut q, mut nq, mut done, mut in_headers) = ([0u32; 4], 0usize, false, true);
    let mut crc_want = None;
    for line in text.split('\n') {
        let line = line.trim_end_matches(['\r', ' ', '\t']).as_bytes();
        if line.is_empty() {
            in_headers = false;
            continue;
        }
        if in_headers && line.contains(&b':') {
            continue;
        }
        in_headers = false;
        if line[0] == b'=' && line.len() == 5 {
            let v: Option<Vec<u32>> = line[1..].iter().map(|&c| b64_value(c)).collect();
            let v = v?;
            crc_want = Some(v[0] << 18 | v[1] << 12 | v[2] << 6 | v[3]);
            break;
        }
        let mut i = 0;
        while i < line.len() {
            let c = line[i];
            i += 1;
            if matches!(c, b' ' | b'\t' | b'\r') {
                continue;
            }
            if done {
                return None;
            }
            if c == b'=' {
                // Padding: 2 or 3 characters of the last quartet carry 1 or 2 bytes.
                if nq < 2 {
                    return None;
                }
                let x = q[0] << 18 | q[1] << 12 | if nq > 2 { q[2] << 6 } else { 0 };
                out.push((x >> 16) as u8);
                if nq > 2 {
                    out.push((x >> 8) as u8);
                }
                nq = 0;
                done = true;
                if line[i..].iter().any(|&c| c != b'=' && c != b'\r') {
                    return None;
                }
                break;
            }
            q[nq] = b64_value(c)?;
            nq += 1;
            if nq == 4 {
                let x = q[0] << 18 | q[1] << 12 | q[2] << 6 | q[3];
                out.extend_from_slice(&[(x >> 16) as u8, (x >> 8) as u8, x as u8]);
                nq = 0;
            }
        }
    }
    if nq != 0 || crc_want.is_some_and(|c| c != crc24(&out)) {
        return None;
    }
    Some(out)
}

/// A packet's tag and body, at `pos`, which moves past it.
fn read_packet<'a>(data: &'a [u8], pos: &mut usize) -> Option<(u8, &'a [u8])> {
    let first = *data.get(*pos)?;
    *pos += 1;
    if first & PACKET_BIT == 0 {
        return None;
    }
    let (tag, len) = if first & NEW_FORMAT_BIT != 0 {
        let l0 = usize::from(*data.get(*pos)?);
        *pos += 1;
        let len = if l0 < TWO_BYTE_LEN {
            l0
        } else if l0 < PARTIAL_LEN {
            let l1 = usize::from(*data.get(*pos)?);
            *pos += 1;
            (l0 - TWO_BYTE_LEN) * 256 + l1 + TWO_BYTE_LEN
        } else if l0 == FOUR_BYTE_LEN {
            let b = data.get(*pos..*pos + 4)?;
            *pos += 4;
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize
        } else {
            return None;
        };
        (first & 0x3f, len)
    } else {
        // The old format: the tag, then whether the length takes 1, 2 or 4 bytes.
        let ltype = first & 3;
        if ltype == 3 {
            return None;
        }
        let n = 1usize << ltype;
        let b = data.get(*pos..*pos + n)?;
        *pos += n;
        ((first >> 2) & 0x0f, b.iter().fold(0usize, |v, &x| v << 8 | usize::from(x)))
    };
    let body = data.get(*pos..*pos + len)?;
    *pos += len;
    Some((tag, body))
}

/// A v4 EdDSA (Ed25519) secret-key packet, unencrypted, as a keypair.
fn parse_secret_key(body: &[u8]) -> Option<IdentityKeypair> {
    if body.len() < 7 || body[0] != VERSION || body[5] != EDDSA {
        return None;
    }
    let mut p = 6;
    let oid_len = usize::from(body[p]);
    p += 1;
    if body.get(p..p + oid_len)? != ED25519_OID {
        return None;
    }
    p += oid_len;
    let mpi_bytes = |at: usize| -> Option<usize> {
        let b = body.get(at..at + 2)?;
        Some(usize::from(u16::from_be_bytes([b[0], b[1]])).div_ceil(8))
    };
    // The public point: an MPI of 0x40 and the 32-byte key.
    let pub_bytes = mpi_bytes(p)?;
    p += 2;
    let point = body.get(p..p + pub_bytes)?;
    if pub_bytes != 1 + SIGN_PUB_LEN || point[0] != EDDSA_POINT {
        return None;
    }
    let pgp_pub = &point[1..];
    p += pub_bytes;
    // S2K usage 0: the secret MPI follows in the clear.
    if *body.get(p)? != 0 {
        return None;
    }
    p += 1;
    let sec_start = p;
    let sec_bytes = mpi_bytes(p)?;
    p += 2;
    if sec_bytes > 32 {
        return None;
    }
    let secret = body.get(p..p + sec_bytes)?;
    // The two-byte sum of the secret MPI, its length included.
    let sum = body[sec_start..p + sec_bytes]
        .iter()
        .fold(0u16, |s, &b| s.wrapping_add(u16::from(b)));
    let want = body.get(p + sec_bytes..p + sec_bytes + 2)?;
    if sum != u16::from_be_bytes([want[0], want[1]]) {
        return None;
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed[32 - sec_bytes..].copy_from_slice(secret);
    let kp = IdentityKeypair::from_seed(&seed);
    (kp.public[..] == *pgp_pub).then_some(kp)
}

/// An unencrypted, armored EdDSA/Ed25519 secret key, as `gpg --export-secret-keys --armor`
/// writes one with no passphrase.
pub fn import_secret(text: &str) -> Option<IdentityKeypair> {
    let begin = text.find(PRIVATE_BEGIN)?;
    let after = &text[begin + PRIVATE_BEGIN.len()..];
    let body_start = &after[after.find('\n')? + 1..];
    let end = body_start.find(PRIVATE_END)?;
    let doc = armor_decode(&body_start[..end])?;
    let mut pos = 0;
    while pos < doc.len() {
        let (tag, body) = read_packet(&doc, &mut pos)?;
        if tag == TAG_SECRET_KEY {
            return parse_secret_key(body);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_keys_come_back() {
        let kp = IdentityKeypair::generate();
        let (armored, fp) = export_secret(&kp, "alice", 1_800_000_000).unwrap();
        let back = import_secret(&armored).unwrap();
        assert_eq!(back.public, kp.public);
        assert_eq!(fp, fingerprint(&kp.public, 1_800_000_000));
        // A damaged checksum, or a key that isn't there, is refused.
        let bad = armored.replacen('A', "B", 1);
        assert!(bad == *armored || import_secret(&bad).is_none());
        assert!(import_secret("hello").is_none());
        let (public, _) = export_public(&kp, "alice", 1_800_000_000);
        assert!(public.starts_with(PUBLIC_BEGIN) && import_secret(&public).is_none());
    }
}
