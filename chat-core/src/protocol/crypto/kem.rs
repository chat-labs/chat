// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! ML-KEM-768 (FIPS 203), from AWS-LC: a FIPS 140-3 validated module whose ML-KEM comes from
//! mlkem-native, which is formally verified. FIPS 203 fixes the encodings for keys and ciphertexts.

use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use zeroize::Zeroizing;

pub const PUB_LEN: usize = 1184;
pub const CT_LEN: usize = 1088;
pub const SS_LEN: usize = 32;

/// Our ML-KEM key pair. The decapsulation key never leaves AWS-LC.
pub struct KemKeypair {
    dk: DecapsulationKey,
    public: Box<[u8; PUB_LEN]>,
}

impl KemKeypair {
    pub fn generate() -> Self {
        let dk = DecapsulationKey::generate(&ML_KEM_768).expect("ML-KEM-768 key generation");
        let ek = dk.encapsulation_key().expect("ML-KEM-768 encapsulation key");
        let bytes = ek.key_bytes().expect("ML-KEM-768 public key bytes");
        let mut public = Box::new([0u8; PUB_LEN]);
        public.copy_from_slice(bytes.as_ref());
        KemKeypair { dk, public }
    }

    pub fn public(&self) -> &[u8; PUB_LEN] {
        &self.public
    }

    /// The shared secret in a ciphertext made for our key. A ciphertext that wasn't gives a
    /// pseudorandom secret (FIPS 203's implicit rejection), so it only shows when frames don't open.
    pub fn decapsulate(&self, ct: &[u8; CT_LEN]) -> Option<Zeroizing<[u8; SS_LEN]>> {
        let ss = self.dk.decapsulate(Ciphertext::from(&ct[..])).ok()?;
        let mut out = Zeroizing::new([0u8; SS_LEN]);
        out.copy_from_slice(ss.as_ref());
        Some(out)
    }
}

/// A ciphertext, and the shared secret in it.
pub type Encapsulated = (Box<[u8; CT_LEN]>, Zeroizing<[u8; SS_LEN]>);

/// A ciphertext for their key, and the shared secret in it. `None` if their key isn't valid.
pub fn encapsulate(their_pub: &[u8; PUB_LEN]) -> Option<Encapsulated> {
    let ek = EncapsulationKey::new(&ML_KEM_768, their_pub).ok()?;
    let (ct, ss) = ek.encapsulate().ok()?;
    let mut ct_out = Box::new([0u8; CT_LEN]);
    ct_out.copy_from_slice(ct.as_ref());
    let mut ss_out = Zeroizing::new([0u8; SS_LEN]);
    ss_out.copy_from_slice(ss.as_ref());
    Some((ct_out, ss_out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let kp = KemKeypair::generate();
        let (ct, ss) = encapsulate(kp.public()).unwrap();
        assert_eq!(*kp.decapsulate(&ct).unwrap(), *ss);
        let mut bad = *ct;
        bad[0] ^= 1;
        assert_ne!(*kp.decapsulate(&bad).unwrap(), *ss);
    }
}
