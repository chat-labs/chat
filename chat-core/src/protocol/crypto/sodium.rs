// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Safe wrappers over the libsodium functions chat uses: hashes, keys and seals match byte for byte.

use libsodium_sys as ffi;
use std::ffi::{c_char, c_int, c_ulonglong};
use std::mem::MaybeUninit;
use std::sync::Once;

static INIT: Once = Once::new();

/// C23's memset_explicit, for the Windows build: libsodium's MinGW library wipes memory with it,
/// and the C library that build links (zig's MinGW) doesn't have it yet. Each byte is a volatile
/// write, so a wipe is never optimised away.
///
/// # Safety
/// `dst` is valid for `n` bytes of writes.
#[cfg(all(windows, target_env = "gnu"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset_explicit(dst: *mut std::ffi::c_void, c: c_int, n: usize) -> *mut std::ffi::c_void {
    let p = dst.cast::<u8>();
    for i in 0..n {
        // SAFETY: the caller's.
        unsafe { p.add(i).write_volatile(c as u8) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    dst
}

/// Initializes libsodium once per process. Every wrapper calls it, so callers never need to.
pub fn init() {
    INIT.call_once(|| {
        // SAFETY: sodium_init is safe to call at any time, and only once here.
        if unsafe { ffi::sodium_init() } < 0 {
            panic!("libsodium failed to initialize");
        }
    });
}

/// Fills `buf` with random bytes from the operating system's CSPRNG.
pub fn random(buf: &mut [u8]) {
    init();
    // SAFETY: buf is valid for writes of buf.len() bytes.
    unsafe { ffi::randombytes_buf(buf.as_mut_ptr().cast(), buf.len()) }
}

pub fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    random(&mut out);
    out
}

/// A number below `upper`, each as likely as the next (no modulo bias).
pub fn random_below(upper: u32) -> u32 {
    init();
    if upper < 2 {
        return 0;
    }
    // SAFETY: no pointers involved.
    unsafe { ffi::randombytes_uniform(upper) }
}

/// A float in [0, 1).
pub fn random_unit() -> f64 {
    let r = u32::from_le_bytes(random_array());
    f64::from(r) / (f64::from(u32::MAX) + 1.0)
}

/// BLAKE2b with an output of `out.len()` bytes (1 to 64), keyed with `key` (empty for none,
/// otherwise 16 to 64 bytes), over the parts joined together. This is libsodium's
/// crypto_generichash: a shorter output is a different hash, not a truncation.
pub fn blake2b(out: &mut [u8], key: &[u8], parts: &[&[u8]]) {
    init();
    assert!((1..=64).contains(&out.len()), "BLAKE2b output must be 1 to 64 bytes");
    assert!(
        key.is_empty() || (16..=64).contains(&key.len()),
        "BLAKE2b key must be 16 to 64 bytes"
    );
    let mut st = MaybeUninit::<ffi::crypto_generichash_state>::uninit();
    let key_ptr = if key.is_empty() { std::ptr::null() } else { key.as_ptr() };
    // SAFETY: st is properly aligned (the binding declares align(64)) and sized; all pointers are
    // valid for the lengths given.
    unsafe {
        let rc = ffi::crypto_generichash_init(st.as_mut_ptr(), key_ptr, key.len(), out.len());
        assert_eq!(rc, 0);
        for p in parts {
            ffi::crypto_generichash_update(st.as_mut_ptr(), p.as_ptr(), p.len() as c_ulonglong);
        }
        ffi::crypto_generichash_final(st.as_mut_ptr(), out.as_mut_ptr(), out.len());
        ffi::sodium_memzero(st.as_mut_ptr().cast(), std::mem::size_of::<ffi::crypto_generichash_state>());
    }
}

/// Argon2id v1.3 with libsodium's parameters (one lane), as crypto_pwhash runs it. Returns
/// false when the memory can't be had.
#[must_use]
pub fn argon2id(out: &mut [u8], password: &[u8], salt: &[u8; 16], ops: u64, mem_bytes: usize) -> bool {
    init();
    // SAFETY: all pointers are valid for the lengths given.
    let rc = unsafe {
        ffi::crypto_pwhash(
            out.as_mut_ptr(),
            out.len() as c_ulonglong,
            password.as_ptr().cast::<c_char>(),
            password.len() as c_ulonglong,
            salt.as_ptr(),
            ops as c_ulonglong,
            mem_bytes,
            ffi::crypto_pwhash_ALG_ARGON2ID13 as c_int,
        )
    };
    rc == 0
}

pub const AEAD_NONCE_LEN: usize = 24;
pub const AEAD_TAG_LEN: usize = 16;

/// XChaCha20-Poly1305 (IETF): `out` gets the ciphertext and its tag, `plain.len() + 16` bytes.
pub fn aead_seal(plain: &[u8], ad: &[u8], nonce: &[u8; AEAD_NONCE_LEN], key: &[u8; 32]) -> Vec<u8> {
    init();
    let mut out = vec![0u8; plain.len() + AEAD_TAG_LEN];
    let mut clen: c_ulonglong = 0;
    // SAFETY: out has room for the ciphertext and tag; the rest are valid for their lengths.
    unsafe {
        ffi::crypto_aead_xchacha20poly1305_ietf_encrypt(
            out.as_mut_ptr(),
            &mut clen,
            plain.as_ptr(),
            plain.len() as c_ulonglong,
            if ad.is_empty() { std::ptr::null() } else { ad.as_ptr() },
            ad.len() as c_ulonglong,
            std::ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        );
    }
    out.truncate(clen as usize);
    out
}

/// Opens what [`aead_seal`] sealed into `out` (which needs `sealed.len() - 16` bytes). Returns
/// the plaintext's length, or `None` if it doesn't open.
pub fn aead_open(out: &mut [u8], sealed: &[u8], ad: &[u8], nonce: &[u8; AEAD_NONCE_LEN], key: &[u8; 32]) -> Option<usize> {
    init();
    if sealed.len() < AEAD_TAG_LEN || out.len() < sealed.len() - AEAD_TAG_LEN {
        return None;
    }
    let mut mlen: c_ulonglong = 0;
    // SAFETY: out has room for the plaintext; the rest are valid for their lengths.
    let rc = unsafe {
        ffi::crypto_aead_xchacha20poly1305_ietf_decrypt(
            out.as_mut_ptr(),
            &mut mlen,
            std::ptr::null_mut(),
            sealed.as_ptr(),
            sealed.len() as c_ulonglong,
            if ad.is_empty() { std::ptr::null() } else { ad.as_ptr() },
            ad.len() as c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    (rc == 0).then_some(mlen as usize)
}

/// XORs `data` in place with the XChaCha20 keystream for this key and nonce.
pub fn xchacha20_xor(data: &mut [u8], nonce: &[u8; 24], key: &[u8; 32]) {
    init();
    // SAFETY: libsodium allows the input and output to be the same buffer.
    unsafe {
        ffi::crypto_stream_xchacha20_xor(
            data.as_mut_ptr(),
            data.as_ptr(),
            data.len() as c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        );
    }
}

/// X25519's public key for a secret.
pub fn x25519_base(secret: &[u8; 32]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    // SAFETY: both buffers are 32 bytes.
    unsafe { ffi::crypto_scalarmult_base(out.as_mut_ptr(), secret.as_ptr()) };
    out
}

/// X25519 between our secret and their public key. `None` for a point that gives all zeros.
pub fn x25519(secret: &[u8; 32], their_pub: &[u8; 32]) -> Option<[u8; 32]> {
    init();
    let mut out = [0u8; 32];
    // SAFETY: all buffers are 32 bytes.
    let rc = unsafe { ffi::crypto_scalarmult(out.as_mut_ptr(), secret.as_ptr(), their_pub.as_ptr()) };
    (rc == 0).then_some(out)
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    init();
    let mut st = MaybeUninit::<ffi::crypto_hash_sha256_state>::uninit();
    let mut out = [0u8; 32];
    // SAFETY: the state is sized and aligned by its binding; pointers are valid.
    unsafe {
        ffi::crypto_hash_sha256_init(st.as_mut_ptr());
        for p in parts {
            ffi::crypto_hash_sha256_update(st.as_mut_ptr(), p.as_ptr(), p.len() as c_ulonglong);
        }
        ffi::crypto_hash_sha256_final(st.as_mut_ptr(), out.as_mut_ptr());
    }
    out
}

/// SHA-256 fed a piece at a time, for files.
pub struct Sha256 {
    st: Box<ffi::crypto_hash_sha256_state>,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        init();
        // SAFETY: an all-zero state is a valid place for init to write into.
        let mut st: Box<ffi::crypto_hash_sha256_state> = Box::new(unsafe { std::mem::zeroed() });
        // SAFETY: st is a valid state.
        unsafe { ffi::crypto_hash_sha256_init(&mut *st) };
        Self { st }
    }
    pub fn update(&mut self, data: &[u8]) {
        // SAFETY: st is initialized; data is valid for its length.
        unsafe { ffi::crypto_hash_sha256_update(&mut *self.st, data.as_ptr(), data.len() as c_ulonglong) };
    }
    pub fn finish(mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        // SAFETY: st is initialized; out is 32 bytes.
        unsafe { ffi::crypto_hash_sha256_final(&mut *self.st, out.as_mut_ptr()) };
        out
    }
}

pub fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    init();
    let mut st = MaybeUninit::<ffi::crypto_hash_sha512_state>::uninit();
    let mut out = [0u8; 64];
    // SAFETY: the state is sized and aligned by its binding; pointers are valid.
    unsafe {
        ffi::crypto_hash_sha512_init(st.as_mut_ptr());
        for p in parts {
            ffi::crypto_hash_sha512_update(st.as_mut_ptr(), p.as_ptr(), p.len() as c_ulonglong);
        }
        ffi::crypto_hash_sha512_final(st.as_mut_ptr(), out.as_mut_ptr());
        ffi::sodium_memzero(st.as_mut_ptr().cast(), std::mem::size_of::<ffi::crypto_hash_sha512_state>());
    }
    out
}

/// HMAC-SHA-256 with a key of any length.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    init();
    let mut st = MaybeUninit::<ffi::crypto_auth_hmacsha256_state>::uninit();
    let mut out = [0u8; 32];
    // SAFETY: the state is sized by its binding; pointers are valid for their lengths.
    unsafe {
        ffi::crypto_auth_hmacsha256_init(st.as_mut_ptr(), key.as_ptr(), key.len());
        ffi::crypto_auth_hmacsha256_update(st.as_mut_ptr(), data.as_ptr(), data.len() as c_ulonglong);
        ffi::crypto_auth_hmacsha256_final(st.as_mut_ptr(), out.as_mut_ptr());
        ffi::sodium_memzero(st.as_mut_ptr().cast(), std::mem::size_of::<ffi::crypto_auth_hmacsha256_state>());
    }
    out
}

/// Constant-time equality.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    init();
    // SAFETY: both are valid for the length compared.
    a.len() == b.len() && unsafe { ffi::sodium_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) } == 0
}

// ---- Ed25519 ----

/// A key pair from a 32-byte seed: (public key, secret key as seed then public key).
pub fn ed25519_seed_keypair(seed: &[u8; 32]) -> ([u8; 32], [u8; 64]) {
    init();
    let mut pk = [0u8; 32];
    let mut sk = [0u8; 64];
    // SAFETY: buffers sized as libsodium requires.
    unsafe { ffi::crypto_sign_seed_keypair(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr()) };
    (pk, sk)
}

pub fn ed25519_sign(sk: &[u8; 64], msg: &[u8]) -> [u8; 64] {
    init();
    let mut sig = [0u8; 64];
    // SAFETY: buffers sized as libsodium requires.
    unsafe {
        ffi::crypto_sign_detached(
            sig.as_mut_ptr(),
            std::ptr::null_mut(),
            msg.as_ptr(),
            msg.len() as c_ulonglong,
            sk.as_ptr(),
        );
    }
    sig
}

pub fn ed25519_verify(pk: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> bool {
    init();
    // SAFETY: buffers sized as libsodium requires.
    unsafe { ffi::crypto_sign_verify_detached(sig.as_ptr(), msg.as_ptr(), msg.len() as c_ulonglong, pk.as_ptr()) == 0 }
}

/// The X25519 secret an Ed25519 secret key converts to (the scalar half of SHA-512 of its
/// seed, clamped).
pub fn ed25519_sk_to_x25519(sk: &[u8; 64]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    // SAFETY: buffers sized as libsodium requires.
    unsafe { ffi::crypto_sign_ed25519_sk_to_curve25519(out.as_mut_ptr(), sk.as_ptr()) };
    out
}

/// The X25519 public key an Ed25519 public key converts to, or `None` for a bad point.
pub fn ed25519_pk_to_x25519(pk: &[u8; 32]) -> Option<[u8; 32]> {
    init();
    let mut out = [0u8; 32];
    // SAFETY: buffers sized as libsodium requires.
    let rc = unsafe { ffi::crypto_sign_ed25519_pk_to_curve25519(out.as_mut_ptr(), pk.as_ptr()) };
    (rc == 0).then_some(out)
}

/// `[scalar]B` on Ed25519 without clamping. `None` if the scalar is zero.
pub fn ed25519_base_noclamp(scalar: &[u8; 32]) -> Option<[u8; 32]> {
    init();
    let mut out = [0u8; 32];
    // SAFETY: buffers sized as libsodium requires.
    let rc = unsafe { ffi::crypto_scalarmult_ed25519_base_noclamp(out.as_mut_ptr(), scalar.as_ptr()) };
    (rc == 0).then_some(out)
}

/// `[scalar]P` on Ed25519 without clamping. `None` for a bad point or a result of the identity.
pub fn ed25519_mul_noclamp(scalar: &[u8; 32], point: &[u8; 32]) -> Option<[u8; 32]> {
    init();
    let mut out = [0u8; 32];
    // SAFETY: buffers sized as libsodium requires.
    let rc = unsafe { ffi::crypto_scalarmult_ed25519_noclamp(out.as_mut_ptr(), scalar.as_ptr(), point.as_ptr()) };
    (rc == 0).then_some(out)
}

/// A 64-byte number reduced mod L, the order of Ed25519's base point.
pub fn ed25519_scalar_reduce(wide: &[u8; 64]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    // SAFETY: buffers sized as libsodium requires.
    unsafe { ffi::crypto_core_ed25519_scalar_reduce(out.as_mut_ptr(), wide.as_ptr()) };
    out
}

pub fn ed25519_scalar_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    // SAFETY: buffers sized as libsodium requires.
    unsafe { ffi::crypto_core_ed25519_scalar_mul(out.as_mut_ptr(), a.as_ptr(), b.as_ptr()) };
    out
}

pub fn ed25519_scalar_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    init();
    let mut out = [0u8; 32];
    // SAFETY: buffers sized as libsodium requires.
    unsafe { ffi::crypto_core_ed25519_scalar_add(out.as_mut_ptr(), a.as_ptr(), b.as_ptr()) };
    out
}
