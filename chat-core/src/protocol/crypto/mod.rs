// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The protocol's cryptography: what the room derives from its id and password, how frames are
//! sealed, the per-message ratchet, the hybrid X25519 + ML-KEM-768 handshake, and signing
//! identities, down to the bytes on the wire.

pub mod identity;
pub mod kem;
pub mod minisign;
pub mod passlock;
pub mod pgp;
pub mod sodium;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use sodium::{AEAD_NONCE_LEN, AEAD_TAG_LEN};

pub const PUB_LEN: usize = 32;
pub const ID_LEN: usize = 16;
pub const KEY_LEN: usize = 32;
pub const VERIFY_LEN: usize = 16;
pub const COOKIE_LEN: usize = 16;
pub const FINGERPRINT_LEN: usize = 16;
pub const DHT_INFOHASH_LEN: usize = 20;

pub const PAD_BLOCK: usize = 64;
/// Every session frame over UDP is sealed to this size of body (one whole UDP cell).
pub const SESSION_PAD_TARGET: usize = 960;
/// The smallest session body a receiver accepts: what 0.3.1 and older seal to.
pub const SESSION_MIN_BODY: usize = 384;
/// The largest body anything is sealed with or read at: a handshake's two KEM keys plus a little.
pub const SEAL_MAX_BODY: usize = kem::PUB_LEN * 2 + 256;
pub const ROOM_PAD_TARGET: usize = 2560;
pub const SESSION_INDEX_LEN: usize = 4;
pub const SESSION_HEADER_LEN: usize = SESSION_INDEX_LEN + AEAD_NONCE_LEN;
pub const ROOM_HEADER_LEN: usize = AEAD_NONCE_LEN;
/// A chain moves at most this far forward for one frame.
pub const RATCHET_MAX_SKIP: u32 = 200;

/// Argon2id's cost for a room's key: 4 passes over 512 MiB.
pub const KDF_OPS: u64 = 4;
pub const KDF_MEM: usize = 512 * 1024 * 1024;
const KDF_LABEL: &[u8] = b"chat-kdf-v2";

/// A 32-byte secret, wiped when dropped.
pub type Secret = Zeroizing<[u8; KEY_LEN]>;

/// BLAKE2b-256 keyed with `key` over the parts: H(k, x) in the protocol's notation.
pub fn kh(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut out = [0u8; 32];
    sodium::blake2b(&mut out, key, parts);
    out
}

/// `H(k, x)[:N]`: the first N bytes of BLAKE2b-256, which isn't BLAKE2b with an N-byte output.
pub fn kh_trunc<const N: usize>(key: &[u8], parts: &[&[u8]]) -> [u8; N] {
    let full = Zeroizing::new(kh(key, parts));
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}

/// Everything a room shares, from its id and password. Every member has all of these. They keep
/// outsiders out, but can't tell one member from another.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RoomKeys {
    pub master: [u8; KEY_LEN],
    pub room: [u8; KEY_LEN],
    pub udp: [u8; KEY_LEN],
    pub dht: [u8; KEY_LEN],
    pub nostr_tag: [u8; KEY_LEN],
    pub nostr_wrap: [u8; KEY_LEN],
    pub lan_port: u16,
}

#[derive(Debug, thiserror::Error)]
#[error("not enough free memory to derive the room's key (it needs 512 MiB for a few seconds)")]
pub struct KdfError;

impl RoomKeys {
    /// Runs Argon2id (512 MiB, a few seconds) and derives the rest. The password stops at a NUL.
    pub fn derive(room_id: &str, password: &str) -> Result<Self, KdfError> {
        let mut salt = [0u8; 16];
        sodium::blake2b(&mut salt, &[], &[KDF_LABEL, room_id.as_bytes()]);
        let pw = password.as_bytes();
        let pw = &pw[..pw.iter().position(|&b| b == 0).unwrap_or(pw.len())];
        let mut master = Zeroizing::new([0u8; KEY_LEN]);
        if !sodium::argon2id(&mut master[..], pw, &salt, KDF_OPS, KDF_MEM) {
            return Err(KdfError);
        }
        Ok(Self::from_master(&master))
    }

    /// The rest of the keys from a master key (tests use a fixed one to skip Argon2id).
    pub fn from_master(master: &[u8; KEY_LEN]) -> Self {
        let lan: [u8; 2] = kh_trunc(master, &[b"lan-port"]);
        RoomKeys {
            master: *master,
            room: kh(master, &[b"room"]),
            udp: kh(master, &[b"udp-mask"]),
            dht: kh(master, &[b"dht-key"]),
            nostr_tag: kh(master, &[b"nostr-tag"]),
            nostr_wrap: kh(master, &[b"nostr-wrap"]),
            lan_port: 49152 + u16::from_be_bytes(lan) % 16384,
        }
    }

    /// What names the room's history: the same each time it's joined with the same id and
    /// password, and nothing anyone else can work out.
    pub fn history_id(&self) -> [u8; 16] {
        let h = sodium::hmac_sha256(&self.master, b"chat history v1");
        h[..16].try_into().expect("16 bytes")
    }
}

/// The DHT lookup key for one hour.
pub fn dht_infohash(dht_key: &[u8; KEY_LEN], epoch: u64) -> [u8; DHT_INFOHASH_LEN] {
    kh_trunc(dht_key, &[b"dht-epoch", &epoch.to_be_bytes()])
}

/// Masks (or unmasks) a UDP datagram in place: everything but its last 16 bytes is XORed with
/// a keystream those 16 bytes pick. Returns false for one too short to mask.
pub fn udp_mask(key: &[u8; KEY_LEN], d: &mut [u8]) -> bool {
    const IV: usize = 16;
    if d.len() < 2 * IV {
        return false;
    }
    let split = d.len() - IV;
    let mut nonce = [0u8; 24];
    nonce[..IV].copy_from_slice(&d[split..]);
    sodium::xchacha20_xor(&mut d[..split], &nonce, key);
    true
}

fn padded_body(plain_len: usize, min_body: usize) -> usize {
    let mut body = plain_len + 2;
    body += (PAD_BLOCK - body % PAD_BLOCK) % PAD_BLOCK;
    body.max(min_body)
}

/// Whether a frame of this length is one a sealer could make: a body padded to 64, between
/// `min_body` and [`SEAL_MAX_BODY`]. Rejects most junk before any key is touched.
pub fn sealed_len_ok(frame_len: usize, header_len: usize, min_body: usize) -> bool {
    if frame_len < header_len + AEAD_TAG_LEN {
        return false;
    }
    let body = frame_len - header_len - AEAD_TAG_LEN;
    body >= min_body && body <= SEAL_MAX_BODY && body.is_multiple_of(PAD_BLOCK)
}

/// The body: the record's length, the record, then zeros to `min_body` or the next 64.
fn seal_body(data: &[u8], min_body: usize) -> Option<Zeroizing<Vec<u8>>> {
    if data.len() > SEAL_MAX_BODY - 2 {
        return None;
    }
    let body = padded_body(data.len(), min_body);
    if body > SEAL_MAX_BODY {
        return None;
    }
    let mut plain = Zeroizing::new(vec![0u8; body]);
    plain[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
    plain[2..2 + data.len()].copy_from_slice(data);
    Some(plain)
}

fn open_body(key: &[u8; KEY_LEN], ad: &[u8], nonce: &[u8; AEAD_NONCE_LEN], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut plain = Zeroizing::new(vec![0u8; sealed.len().saturating_sub(AEAD_TAG_LEN)]);
    let n = sodium::aead_open(&mut plain, sealed, ad, nonce, key)?;
    if n < 2 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
    if len > n - 2 {
        return None;
    }
    Some(Zeroizing::new(plain[2..2 + len].to_vec()))
}

/// A room frame: a nonce, then the record sealed with the room key, padded to 2560 bytes.
pub fn room_seal(room_key: &[u8; KEY_LEN], data: &[u8]) -> Option<Vec<u8>> {
    let body = seal_body(data, ROOM_PAD_TARGET)?;
    let nonce: [u8; AEAD_NONCE_LEN] = sodium::random_array();
    let mut out = Vec::with_capacity(AEAD_NONCE_LEN + body.len() + AEAD_TAG_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sodium::aead_seal(&body, &[], &nonce, room_key));
    Some(out)
}

pub fn room_open(room_key: &[u8; KEY_LEN], frame: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if !sealed_len_ok(frame.len(), ROOM_HEADER_LEN, ROOM_PAD_TARGET) {
        return None;
    }
    let nonce: [u8; AEAD_NONCE_LEN] = frame[..AEAD_NONCE_LEN].try_into().ok()?;
    open_body(room_key, &[], &nonce, &frame[AEAD_NONCE_LEN..])
}

/// A session frame: the chain index, a nonce, then the records sealed with that index's message
/// key, the index as associated data.
pub fn session_seal(msg_key: &[u8; KEY_LEN], index: u32, data: &[u8], min_body: usize) -> Option<Vec<u8>> {
    let body = seal_body(data, min_body)?;
    let idx = index.to_be_bytes();
    let nonce: [u8; AEAD_NONCE_LEN] = sodium::random_array();
    let mut out = Vec::with_capacity(SESSION_HEADER_LEN + body.len() + AEAD_TAG_LEN);
    out.extend_from_slice(&idx);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sodium::aead_seal(&body, &idx, &nonce, msg_key));
    Some(out)
}

pub fn session_open(msg_key: &[u8; KEY_LEN], index: u32, frame: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if !sealed_len_ok(frame.len(), SESSION_HEADER_LEN, SESSION_MIN_BODY) {
        return None;
    }
    let nonce: [u8; AEAD_NONCE_LEN] = frame[SESSION_INDEX_LEN..SESSION_HEADER_LEN].try_into().ok()?;
    open_body(msg_key, &index.to_be_bytes(), &nonce, &frame[SESSION_HEADER_LEN..])
}

/// The index a session frame says it was sealed at.
pub fn session_index(frame: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(frame.get(..4)?.try_into().ok()?))
}

/// One direction of a session: a chain of keys, each frame's from the one before. Frames can
/// skip ahead (lost ones) but never go back, and no keys are kept for skipped frames: acks and
/// resends cover what's lost.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Ratchet {
    key: [u8; KEY_LEN],
    index: u32,
    started: bool,
}

impl Ratchet {
    pub fn seed(prk: &[u8; KEY_LEN], owner_pub: &[u8; PUB_LEN]) -> Self {
        Ratchet {
            key: kh(prk, &[b"chain", owner_pub]),
            index: 0,
            started: true,
        }
    }

    pub fn started(&self) -> bool {
        self.started
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    /// Whether `target` is a frame index this chain could still open, at most `max_skip` ahead.
    pub fn in_window(&self, target: u32, max_skip: u32) -> bool {
        self.started && target >= self.index && target - self.index <= max_skip
    }

    /// The message key for frame `target`, and the chain moved past it (not applied: the caller
    /// keeps it only once the frame opens).
    pub fn peek(&self, target: u32) -> Option<(Secret, Ratchet)> {
        if !self.started || target < self.index || target - self.index > RATCHET_MAX_SKIP || target == u32::MAX {
            return None;
        }
        let mut cur = Zeroizing::new(self.key);
        let mut msg = Zeroizing::new([0u8; KEY_LEN]);
        for idx in self.index..=target {
            if idx == target {
                *msg = kh(&cur[..], &[b"msg"]);
            }
            *cur = kh(&cur[..], &[b"step"]);
        }
        Some((
            msg,
            Ratchet {
                key: *cur,
                index: target + 1,
                started: true,
            },
        ))
    }

    /// Seals data as this chain's next frame and moves the chain on.
    pub fn seal_next(&mut self, data: &[u8], min_body: usize) -> Option<Vec<u8>> {
        let (mk, next) = self.peek(self.index)?;
        let frame = session_seal(&mk, self.index, data, min_body)?;
        *self = next;
        Some(frame)
    }
}

/// The first half of a session key: X25519 between the two keys, and both sides' keys and ids.
pub fn session_prk_partial(
    master: &[u8; KEY_LEN],
    shared: &[u8; 32],
    my_pub: &[u8; PUB_LEN],
    my_id: &[u8; ID_LEN],
    their_pub: &[u8; PUB_LEN],
    their_id: &[u8; ID_LEN],
) -> Secret {
    let mut mine = [0u8; PUB_LEN + ID_LEN];
    mine[..PUB_LEN].copy_from_slice(my_pub);
    mine[PUB_LEN..].copy_from_slice(my_id);
    let mut theirs = [0u8; PUB_LEN + ID_LEN];
    theirs[..PUB_LEN].copy_from_slice(their_pub);
    theirs[PUB_LEN..].copy_from_slice(their_id);
    let (lo, hi) = if mine <= theirs { (&mine, &theirs) } else { (&theirs, &mine) };
    Zeroizing::new(kh(master, &[shared, lo, hi]))
}

/// The session key: the partial key with ML-KEM's shared secret.
pub fn session_prk(partial: &[u8; KEY_LEN], kem_ss: &[u8; 32]) -> Secret {
    Zeroizing::new(kh(partial, &[kem_ss]))
}

/// The code two members compare to know nobody is between them.
pub fn verify_code(prk: &[u8; KEY_LEN]) -> [u8; VERIFY_LEN] {
    kh_trunc(prk, &[b"vfy"])
}

/// A hello's cookie: only the member that made it checks it, so its layout is ours alone.
pub fn cookie(secret: &[u8; KEY_LEN], addr: &str, peer_id: &[u8; ID_LEN], pub_key: &[u8; PUB_LEN]) -> [u8; COOKIE_LEN] {
    let a = addr.as_bytes();
    let a = &a[..a.len().min(255)];
    let mut out = [0u8; COOKIE_LEN];
    sodium::blake2b(&mut out, secret, &[&[a.len() as u8], a, peer_id, pub_key]);
    out
}

/// An X25519 key pair, made fresh for each session and at each rekey.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519Keypair {
    secret: [u8; 32],
    pub public: [u8; PUB_LEN],
}

impl X25519Keypair {
    pub fn generate() -> Self {
        let secret: [u8; 32] = sodium::random_array();
        let public = sodium::x25519_base(&secret);
        X25519Keypair { secret, public }
    }

    pub fn shared(&self, their_pub: &[u8; PUB_LEN]) -> Option<Secret> {
        sodium::x25519(&self.secret, their_pub).map(Zeroizing::new)
    }
}

/// An identity's fingerprint: BLAKE2b of its public key, the first 16 bytes.
pub fn fingerprint(id_pub: &[u8; 32]) -> [u8; FINGERPRINT_LEN] {
    kh_trunc(&[], &[id_pub])
}

/// The check an invite ends with: it only catches mistakes in copying one.
pub fn invite_check(id: &str, password: &str) -> [u8; 4] {
    let mut full = [0u8; 16];
    sodium::blake2b(&mut full, &[], &[b"chat-invite-v1", id.as_bytes(), &[0], password.as_bytes()]);
    full[..4].try_into().expect("4 bytes")
}

/// What a build's "v" proves: its executable's hash, keyed with both session ids.
pub fn build_proof(exe_sha256: &[u8; 32], from_id: &[u8; ID_LEN], to_id: &[u8; ID_LEN]) -> [u8; 32] {
    let mut out = [0u8; 32];
    sodium::blake2b(&mut out, exe_sha256, &[b"chat build v1", from_id, to_id]);
    out
}

/// Nostr's wrap: sender, recipient, length and datagram, padded with random bytes to this size
/// and sealed under the room's wrap key.
pub const NOSTR_WRAP_PLAIN: usize = 2800;
pub const NOSTR_WRAP_LEN: usize = AEAD_NONCE_LEN + NOSTR_WRAP_PLAIN + AEAD_TAG_LEN;
const NOSTR_WRAP_AD: &[u8] = b"chat nostr wrap v1";

pub fn nostr_wrap(key: &[u8; KEY_LEN], plain: &[u8; NOSTR_WRAP_PLAIN]) -> Vec<u8> {
    let nonce: [u8; AEAD_NONCE_LEN] = sodium::random_array();
    let mut out = Vec::with_capacity(NOSTR_WRAP_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sodium::aead_seal(plain, NOSTR_WRAP_AD, &nonce, key));
    out
}

pub fn nostr_unwrap(key: &[u8; KEY_LEN], wrapped: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if wrapped.len() != NOSTR_WRAP_LEN {
        return None;
    }
    let nonce: [u8; AEAD_NONCE_LEN] = wrapped[..AEAD_NONCE_LEN].try_into().ok()?;
    let mut plain = Zeroizing::new(vec![0u8; NOSTR_WRAP_PLAIN]);
    let n = sodium::aead_open(&mut plain, &wrapped[AEAD_NONCE_LEN..], NOSTR_WRAP_AD, &nonce, key)?;
    (n == NOSTR_WRAP_PLAIN).then_some(plain)
}

/// How many onion services a room has, whose keys every member can derive.
pub const TOR_ROOM_SLOTS: usize = 6;

/// One of the room's onion service keys: the expanded Ed25519 secret (SHA-512 of a seed from the
/// master key, its scalar half clamped), as Tor takes it, and its public key.
pub fn tor_room_key(master: &[u8; KEY_LEN], slot: u8) -> (Zeroizing<[u8; 64]>, [u8; 32]) {
    let seed = Zeroizing::new(kh_trunc::<32>(master, &[b"tor", &[slot]]));
    let mut expanded = Zeroizing::new(sodium::sha512(&[&seed[..]]));
    expanded[0] &= 248;
    expanded[31] &= 127;
    expanded[31] |= 64;
    let scalar: [u8; 32] = expanded[..32].try_into().expect("32 bytes");
    let public = sodium::ed25519_base_noclamp(&scalar).expect("a clamped scalar isn't zero");
    (expanded, public)
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn onion_checksum(public: &[u8; 32]) -> [u8; 2] {
    let d = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA3_256,
        &[b".onion checksum".as_slice(), public, &[3]].concat(),
    );
    [d.as_ref()[0], d.as_ref()[1]]
}

/// A v3 onion address (without ".onion"): the key, a checksum and the version, in base32.
pub fn onion_address(public: &[u8; 32]) -> String {
    let mut raw = public.to_vec();
    raw.extend_from_slice(&onion_checksum(public));
    raw.push(3);
    let (mut acc, mut bits, mut out) = (0u32, 0u32, String::with_capacity(56));
    for b in raw {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    out
}

/// The key a v3 onion address names, if it's one (56 lowercase characters, checksum and all).
pub fn onion_key(s: &str) -> Option<[u8; 32]> {
    if s.len() != 56 {
        return None;
    }
    let (mut acc, mut bits, mut raw) = (0u64, 0u32, Vec::with_capacity(35));
    for c in s.bytes() {
        acc = (acc << 5) | B32.iter().position(|&x| x == c)? as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            raw.push((acc >> bits) as u8);
        }
    }
    let public: [u8; 32] = raw.get(..32)?.try_into().ok()?;
    (raw.len() == 35 && raw[34] == 3 && raw[32..34] == onion_checksum(&public)).then_some(public)
}

/// What a Tor target is called on the wire between the engine and the Tor transport.
pub fn tor_target_id(onion: &str) -> [u8; 16] {
    sodium::sha256(&[onion.as_bytes()])[..16].try_into().expect("16 bytes")
}

/// The tag a room's relay events carry for one ten-minute epoch.
pub fn nostr_tag(tag_key: &[u8; KEY_LEN], epoch: u64) -> String {
    crate::protocol::hex::encode(&sodium::hmac_sha256(tag_key, &epoch.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_targets() {
        assert_eq!(padded_body(0, ROOM_PAD_TARGET), 2560);
        assert_eq!(padded_body(2469, ROOM_PAD_TARGET), 2560);
        assert_eq!(padded_body(2600, ROOM_PAD_TARGET), 2624);
        assert_eq!(padded_body(3, SESSION_PAD_TARGET), 960);
        assert_eq!(padded_body(62, 0), 64);
        assert_eq!(padded_body(63, 0), 128);
    }

    #[test]
    fn frames_round_trip() {
        let key = [7u8; 32];
        let f = room_seal(&key, b"hi\tthere").unwrap();
        assert_eq!(f.len(), 2600);
        assert_eq!(&room_open(&key, &f).unwrap()[..], b"hi\tthere");
        assert!(room_open(&[8u8; 32], &f).is_none());

        let prk = [1u8; 32];
        let mut tx = Ratchet::seed(&prk, &[2u8; 32]);
        let rx = Ratchet::seed(&prk, &[2u8; 32]);
        let f0 = tx.seal_next(b"nop", SESSION_PAD_TARGET).unwrap();
        let f1 = tx.seal_next(b"m\tx", SESSION_PAD_TARGET).unwrap();
        assert_eq!(f1.len(), 1004);
        // The second frame opens first (the first was lost); the first then can't.
        let idx = session_index(&f1).unwrap();
        let (mk, rx2) = rx.peek(idx).unwrap();
        assert_eq!(&session_open(&mk, idx, &f1).unwrap()[..], b"m\tx");
        assert!(rx2.peek(session_index(&f0).unwrap()).is_none());
    }

    #[test]
    fn mask_is_its_own_inverse() {
        let key = [3u8; 32];
        let mut d: Vec<u8> = (0..1004u32).map(|i| i as u8).collect();
        let orig = d.clone();
        assert!(udp_mask(&key, &mut d));
        assert_ne!(d, orig);
        assert_eq!(&d[1004 - 16..], &orig[1004 - 16..]);
        assert!(udp_mask(&key, &mut d));
        assert_eq!(d, orig);
    }
}
