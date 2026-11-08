// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The picture cleaner: pictures, cleaned with the same seed, produce deterministic outputs.
//! The pictures are made by tests/data/pictures/make.py (Pillow).
//! The pictures are made by tests/data/pictures/make.py (Pillow); the hashes verify what
//! image_clean produces.

use chat_core::protocol::crypto::sodium;
use chat_core::protocol::picture;

// (file, noise, what was taken out, the start of the cleaned picture's SHA-256)
const KAT: &[(&str, bool, u32, &str)] = &[
    ("anim.gif", false, 0, "71b392a8786feb9b"),
    ("anim.gif", true, 0, "71b392a8786feb9b"),
    ("exif420.jpg", false, 19, "859dae7f3954f309"),
    ("exif420.jpg", true, 275, "cc4632967a630080"),
    ("gray.jpg", false, 0, "41fbb2959b8822cd"),
    ("gray.jpg", true, 256, "49d5e58eb788b05c"),
    ("opt.jpg", false, 0, "90dda9bc5ac7a4b5"),
    ("opt.jpg", true, 256, "fb1d84ae2548134f"),
    ("pal.gif", false, 16, "668b4b356da26ebd"),
    ("pal.gif", true, 16, "668b4b356da26ebd"),
    ("prog.jpg", false, 3, "439020930c36f17d"),
    ("prog.jpg", true, 3, "439020930c36f17d"),
    ("q444.jpg", false, 0, "8add1731b6c6e7b4"),
    ("q444.jpg", true, 256, "4b124fc4430e6cf3"),
    ("rst.jpg", false, 0, "3a31d596e95de213"),
    ("rst.jpg", true, 256, "cf114fa468dd0c0c"),
    ("text.png", false, 20, "06d7a1e8edad98b8"),
    ("text.png", true, 20, "06d7a1e8edad98b8"),
];

#[test]
fn cleans_deterministically() {
    let seed: [u8; 16] = std::array::from_fn(|i| (i * 37 + 1) as u8);
    let dir = "tests/data/pictures";
    for &(name, noise, took, sha) in KAT {
        let data = std::fs::read(format!("{dir}/{name}")).unwrap();
        let (out, got) = picture::clean(&data, noise, &seed).unwrap_or_else(|| panic!("{name} didn't clean"));
        let hash = chat_core::protocol::hex::encode(&sodium::sha256(&[&out]));
        assert_eq!((got, &hash[..16]), (took, sha), "{name}, noise {noise}");
    }
}

#[test]
fn damaged_pictures_fail() {
    let dir = "tests/data/pictures";
    for name in ["exif420.jpg", "text.png", "pal.gif"] {
        let data = std::fs::read(format!("{dir}/{name}")).unwrap();
        // Every cut either fails or cleans: none panics or reads past the end.
        for cut in (0..data.len()).step_by(97) {
            let _ = picture::clean(&data[..cut], true, &[7; 16]);
        }
        let mut bad = data.clone();
        for i in (20..bad.len()).step_by(13) {
            bad[i] ^= 0x5A;
        }
        let _ = picture::clean(&bad, true, &[7; 16]);
    }
}
