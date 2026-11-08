// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Signing identities: an Ed25519 key that signs each session's keys, so a peer whose key was
//! verified once needn't compare codes again. A key comes from a seed (chat's own, or one made
//! from a password), or from an X25519 secret (an AGE key), which has no seed: that form signs
//! with the scalar directly, as RFC 8032 does once the seed has been hashed.

use super::{ID_LEN, PUB_LEN, sodium};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const SIGN_PUB_LEN: usize = 32;
pub const SIGN_LEN: usize = 64;

/// What kind of key a peer signs with, as "k" numbers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityKind {
    /// chat's own key, made here or from a password.
    Native,
    Age,
    Pgp,
}

impl IdentityKind {
    pub fn wire(self) -> u8 {
        match self {
            IdentityKind::Native => 1,
            IdentityKind::Age => 2,
            IdentityKind::Pgp => 3,
        }
    }
    pub fn from_wire(n: u8) -> Option<Self> {
        match n {
            1 => Some(IdentityKind::Native),
            2 => Some(IdentityKind::Age),
            3 => Some(IdentityKind::Pgp),
            _ => None,
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
enum Secret {
    /// libsodium's secret key: the seed, then the public key.
    Seed([u8; 64]),
    /// The signing scalar (reduced mod L), then the key nonces are made from.
    Scalar([u8; 32], [u8; 32]),
}

#[derive(Clone)]
pub struct IdentityKeypair {
    pub public: [u8; SIGN_PUB_LEN],
    secret: Secret,
}

impl std::fmt::Debug for IdentityKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeypair")
            .field("public", &crate::protocol::hex::encode(&self.public))
            .finish_non_exhaustive()
    }
}

const ID_KDF_LABEL: &[u8] = b"chat-identity-v1";
const ID_NICK_KDF_LABEL: &[u8] = b"chat-identity-nick-v1";

impl IdentityKeypair {
    pub fn generate() -> Self {
        let seed = Zeroizing::new(sodium::random_array::<32>());
        Self::from_seed(&seed)
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (public, sk) = sodium::ed25519_seed_keypair(seed);
        IdentityKeypair {
            public,
            secret: Secret::Seed(sk),
        }
    }

    /// The secret as a saved key keeps it: whether it's a scalar (an AGE key) rather than a seed,
    /// and its 64 bytes (the seed then the public key, or the scalar then the nonce key).
    pub fn to_parts(&self) -> (bool, Zeroizing<[u8; 64]>) {
        let mut out = Zeroizing::new([0u8; 64]);
        match &self.secret {
            Secret::Seed(sk) => out.copy_from_slice(sk),
            Secret::Scalar(s, n) => {
                out[..32].copy_from_slice(s);
                out[32..].copy_from_slice(n);
            }
        }
        (matches!(self.secret, Secret::Scalar(..)), out)
    }

    /// A key from [`IdentityKeypair::to_parts`], if its public half is the one the secret gives.
    pub fn from_parts(public: &[u8; SIGN_PUB_LEN], scalar: bool, secret: &[u8; 64]) -> Option<Self> {
        let kp = if scalar {
            let s: [u8; 32] = secret[..32].try_into().expect("32 bytes");
            IdentityKeypair {
                public: sodium::ed25519_base_noclamp(&s)?,
                secret: Secret::Scalar(s, secret[32..].try_into().expect("32 bytes")),
            }
        } else {
            Self::from_seed(secret[..32].try_into().expect("32 bytes"))
        };
        sodium::ct_eq(&kp.public, public).then_some(kp)
    }

    /// The seed of a key made from one (None for an AGE key, which has none).
    pub fn seed(&self) -> Option<Zeroizing<[u8; 32]>> {
        match &self.secret {
            Secret::Seed(sk) => Some(Zeroizing::new(sk[..32].try_into().expect("32 bytes"))),
            Secret::Scalar(..) => None,
        }
    }

    /// The key a password gives on one device (and with a nick, unless it's None): Argon2id,
    /// as for a room, so each guess is slow. The device id and nick aren't secret.
    pub fn from_password(password: &str, device_id: &str, nick: Option<&str>) -> Result<Self, super::KdfError> {
        let mut salt = [0u8; 16];
        match nick {
            None => sodium::blake2b(&mut salt, &[], &[ID_KDF_LABEL, device_id.as_bytes()]),
            // The device id's NUL goes in too, so no other device id and nick give the same salt.
            Some(n) => sodium::blake2b(&mut salt, &[], &[ID_NICK_KDF_LABEL, device_id.as_bytes(), &[0], n.as_bytes()]),
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        if !sodium::argon2id(&mut seed[..], password.as_bytes(), &salt, super::KDF_OPS, super::KDF_MEM) {
            return Err(super::KdfError);
        }
        Ok(Self::from_seed(&seed))
    }

    /// An X25519 secret (an AGE key's) as a signing key whose public key converts back to the
    /// same X25519 public key, so the AGE recipient shown is the key's own.
    pub fn from_x25519(secret: &[u8; 32]) -> Option<Self> {
        let mut wide = Zeroizing::new([0u8; 64]);
        wide[..32].copy_from_slice(secret);
        clamp(&mut wide[..32]);
        let scalar = sodium::ed25519_scalar_reduce(&wide);
        // Keyed with the secret, over the label (crypto_generichash's input, then its key).
        let mut nonce_key = [0u8; 32];
        sodium::blake2b(&mut nonce_key, secret, &[b"chat identity nonce key"]);
        let public = sodium::ed25519_base_noclamp(&scalar)?;
        let x_pub = sodium::x25519_base(secret);
        let x_from_ed = sodium::ed25519_pk_to_x25519(&public)?;
        if !sodium::ct_eq(&x_pub, &x_from_ed) {
            return None;
        }
        Some(IdentityKeypair {
            public,
            secret: Secret::Scalar(scalar, nonce_key),
        })
    }

    /// The signing scalar for X25519: from a seed, as crypto_sign_ed25519_sk_to_curve25519
    /// makes it; for an AGE key, the reduced scalar, which X25519 clamps to the same point.
    fn scalar(&self) -> Zeroizing<[u8; 32]> {
        match &self.secret {
            Secret::Seed(sk) => Zeroizing::new(sodium::ed25519_sk_to_x25519(sk)),
            Secret::Scalar(s, _) => Zeroizing::new(*s),
        }
    }

    /// The X25519 secret that gives this key back (an AGE secret key's 32 bytes), clamped. From
    /// a seed, it's the one crypto_sign_ed25519_sk_to_curve25519 gives.
    pub fn to_x25519(&self) -> Zeroizing<[u8; 32]> {
        let Secret::Scalar(scalar, _) = &self.secret else {
            return self.scalar();
        };
        // The clamped secret is the scalar plus a multiple of L below 8L: the only one that's a
        // multiple of 8 from 2^254 up to 2^255. All eight are tried, so the time doesn't tell which.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0x10,
        ];
        let mut k = Zeroizing::new(*scalar);
        let mut out = Zeroizing::new([0u8; 32]);
        for _ in 0..8 {
            let ok = u8::from(k[0] & 7 == 0) & u8::from(k[31] >> 6 == 1);
            let mask = 0u8.wrapping_sub(ok);
            for i in 0..32 {
                out[i] |= k[i] & mask;
            }
            let mut carry = 0u16;
            for i in 0..32 {
                carry += u16::from(k[i]) + u16::from(L[i]);
                k[i] = carry as u8;
                carry >>= 8;
            }
        }
        out
    }

    /// The AGE recipient ("age1...") of this key.
    pub fn age_recipient(&self) -> Option<String> {
        Some(crate::protocol::bech32::encode("age", &sodium::ed25519_pk_to_x25519(&self.public)?))
    }

    /// The AGE recipient ("age1...") and secret key ("AGE-SECRET-KEY-1...") of this key.
    pub fn age_strings(&self) -> Option<(String, Zeroizing<String>)> {
        let recipient = self.age_recipient()?;
        let secret = self.to_x25519();
        Some((
            recipient,
            Zeroizing::new(crate::protocol::bech32::encode("AGE-SECRET-KEY-", &secret[..]).to_ascii_uppercase()),
        ))
    }

    /// A secret key as a file or a paste has it: an armored PGP secret key (unencrypted EdDSA), or
    /// an AGE key, alone or in the file age-keygen writes (its comments are skipped).
    pub fn from_key_text(text: &str) -> Option<(IdentityKind, Self)> {
        if text.contains(super::pgp::PRIVATE_BEGIN) {
            return super::pgp::import_secret(text).map(|kp| (IdentityKind::Pgp, kp));
        }
        let line = text
            .split_whitespace()
            .find(|w| w.len() > 16 && w[..16].eq_ignore_ascii_case("AGE-SECRET-KEY-1"))?;
        Self::from_age_secret(line).map(|kp| (IdentityKind::Age, kp))
    }

    /// An AGE secret key, "AGE-SECRET-KEY-1...".
    pub fn from_age_secret(text: &str) -> Option<Self> {
        let (hrp, data) = crate::protocol::bech32::decode(text.trim())?;
        let secret: Zeroizing<[u8; 32]> = Zeroizing::new(data.as_slice().try_into().ok()?);
        (hrp == "age-secret-key-").then(|| Self::from_x25519(&secret)).flatten()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; SIGN_LEN] {
        match &self.secret {
            Secret::Seed(sk) => sodium::ed25519_sign(sk, msg),
            Secret::Scalar(scalar, nonce_key) => sign_with_scalar(scalar, nonce_key, &self.public, msg),
        }
    }

    /// The signature "k" carries: over our session key and id, then theirs.
    pub fn sign_session(
        &self,
        my_pub: &[u8; PUB_LEN],
        my_id: &[u8; ID_LEN],
        their_pub: &[u8; PUB_LEN],
        their_id: &[u8; ID_LEN],
    ) -> [u8; SIGN_LEN] {
        self.sign(&session_message(my_pub, my_id, their_pub, their_id))
    }

    /// The same under :move's label, so neither signature passes for the other.
    pub fn sign_move(
        &self,
        my_pub: &[u8; PUB_LEN],
        my_id: &[u8; ID_LEN],
        their_pub: &[u8; PUB_LEN],
        their_id: &[u8; ID_LEN],
    ) -> [u8; SIGN_LEN] {
        let mut msg = MOVE_LABEL.to_vec();
        msg.extend_from_slice(&session_message(my_pub, my_id, their_pub, their_id));
        self.sign(&msg)
    }

    /// A secret only the holders of this key and theirs can work out, for a call's room: X25519
    /// between the keys taken as points, hashed with a label, both keys (lower first) and the day.
    pub fn contact_secret(&self, their_pub: &[u8; SIGN_PUB_LEN], day: u64) -> Option<Zeroizing<[u8; 64]>> {
        if sodium::ct_eq(&self.public, their_pub) {
            return None;
        }
        let s = self.scalar();
        let q = Zeroizing::new(sodium::ed25519_mul_noclamp(&s, their_pub)?);
        let shared = Zeroizing::new(sodium::ed25519_pk_to_x25519(&q)?);
        let (lo, hi) = if self.public < *their_pub {
            (&self.public, their_pub)
        } else {
            (their_pub, &self.public)
        };
        let mut out = Zeroizing::new([0u8; 64]);
        sodium::blake2b(&mut out[..], &shared[..], &[b"chat-contact-v1", lo, hi, &day.to_be_bytes()]);
        Some(out)
    }
}

const MOVE_LABEL: &[u8] = b"chat move v1";

fn clamp(s: &mut [u8]) {
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

fn session_message(a_pub: &[u8; PUB_LEN], a_id: &[u8; ID_LEN], b_pub: &[u8; PUB_LEN], b_id: &[u8; ID_LEN]) -> [u8; 2 * (PUB_LEN + ID_LEN)] {
    let mut m = [0u8; 2 * (PUB_LEN + ID_LEN)];
    m[..32].copy_from_slice(a_pub);
    m[32..48].copy_from_slice(a_id);
    m[48..80].copy_from_slice(b_pub);
    m[80..].copy_from_slice(b_id);
    m
}

/// RFC 8032's signing from a scalar and a nonce key, where libsodium would derive both from a seed.
fn sign_with_scalar(scalar: &[u8; 32], nonce_key: &[u8; 32], public: &[u8; 32], msg: &[u8]) -> [u8; SIGN_LEN] {
    let h = Zeroizing::new(sodium::sha512(&[nonce_key, msg]));
    let r = Zeroizing::new(sodium::ed25519_scalar_reduce(&h));
    let mut sig = [0u8; SIGN_LEN];
    let Some(big_r) = sodium::ed25519_base_noclamp(&r) else {
        // r is zero (odds 2^-252): no signature rather than one that leaks the scalar.
        return sig;
    };
    sig[..32].copy_from_slice(&big_r);
    let k = sodium::ed25519_scalar_reduce(&sodium::sha512(&[&big_r, public, msg]));
    let ka = Zeroizing::new(sodium::ed25519_scalar_mul(&k, scalar));
    sig[32..].copy_from_slice(&sodium::ed25519_scalar_add(&r, &ka));
    sig
}

/// Checks the signature a peer's "k" carries: over its session key and id, then ours.
pub fn verify_session(
    id_pub: &[u8; SIGN_PUB_LEN],
    sig: &[u8; SIGN_LEN],
    their_pub: &[u8; PUB_LEN],
    their_id: &[u8; ID_LEN],
    my_pub: &[u8; PUB_LEN],
    my_id: &[u8; ID_LEN],
) -> bool {
    sodium::ed25519_verify(id_pub, sig, &session_message(their_pub, their_id, my_pub, my_id))
}

pub fn verify_move(
    pub_key: &[u8; SIGN_PUB_LEN],
    sig: &[u8; SIGN_LEN],
    their_pub: &[u8; PUB_LEN],
    their_id: &[u8; ID_LEN],
    my_pub: &[u8; PUB_LEN],
    my_id: &[u8; ID_LEN],
) -> bool {
    let mut msg = MOVE_LABEL.to_vec();
    msg.extend_from_slice(&session_message(their_pub, their_id, my_pub, my_id));
    sodium::ed25519_verify(pub_key, sig, &msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_and_scalar_keys_sign() {
        let a = IdentityKeypair::generate();
        let sig = a.sign_session(&[1; 32], &[2; 16], &[3; 32], &[4; 16]);
        assert!(verify_session(&a.public, &sig, &[1; 32], &[2; 16], &[3; 32], &[4; 16]));
        assert!(!verify_session(&a.public, &sig, &[3; 32], &[4; 16], &[1; 32], &[2; 16]));

        let age = IdentityKeypair::from_x25519(&[9u8; 32]).unwrap();
        let sig = age.sign(b"hello");
        assert!(sodium::ed25519_verify(&age.public, &sig, b"hello"));
    }

    #[test]
    fn age_keys_export_and_import() {
        let secret = [9u8; 32];
        let a = IdentityKeypair::from_x25519(&secret).unwrap();
        let (recipient, sk) = a.age_strings().unwrap();
        assert!(recipient.starts_with("age1") && sk.starts_with("AGE-SECRET-KEY-1"));
        // The secret comes back clamped, and gives the same key.
        let mut clamped = secret;
        clamp(&mut clamped);
        assert_eq!(*a.to_x25519(), clamped);
        let b = IdentityKeypair::from_age_secret(&sk).unwrap();
        assert_eq!(a.public, b.public);
        // The recipient is X25519 of the secret, as age makes it.
        let (_, x_pub) = crate::protocol::bech32::decode(&recipient).unwrap();
        assert_eq!(x_pub, sodium::x25519_base(&secret).to_vec());
    }

    #[test]
    fn contact_secret_is_shared() {
        let a = IdentityKeypair::generate();
        let b = IdentityKeypair::from_x25519(&[5u8; 32]).unwrap();
        let ab = a.contact_secret(&b.public, 20000).unwrap();
        let ba = b.contact_secret(&a.public, 20000).unwrap();
        assert_eq!(*ab, *ba);
        assert_ne!(*ab, *a.contact_secret(&b.public, 20001).unwrap());
        assert!(a.contact_secret(&a.public, 1).is_none());
    }
}
