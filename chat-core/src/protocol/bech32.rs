// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Bech32 (BIP-173), as AGE writes its keys: "age1..." recipients and "AGE-SECRET-KEY-1..."
//! secret keys. AGE keys are longer than BIP-173's 90 characters, so there's no length limit.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn polymod(values: &[u8]) -> u32 {
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.iter().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.iter().map(|c| c & 31));
    v
}

fn convert(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let (mut acc, mut bits) = (0u32, 0u32);
    let mut out = Vec::new();
    let maxv = (1u32 << to) - 1;
    for &d in data {
        if u32::from(d) >> from != 0 {
            return None;
        }
        acc = (acc << from) | u32::from(d);
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

/// Bytes as Bech32 under a human-readable part, in lower case.
pub fn encode(hrp: &str, data: &[u8]) -> String {
    let hrp = hrp.to_ascii_lowercase();
    let five = convert(data, 8, 5, true).expect("8-bit input");
    let mut values = hrp_expand(hrp.as_bytes());
    values.extend(&five);
    values.extend([0u8; 6]);
    let m = polymod(&values) ^ 1;
    let mut s = hrp;
    s.push('1');
    for d in five.iter().copied().chain((0..6).map(|i| ((m >> (5 * (5 - i))) & 31) as u8)) {
        s.push(CHARSET[usize::from(d)] as char);
    }
    s
}

/// The human-readable part and the bytes, if the checksum holds. All one case.
pub fn decode(s: &str) -> Option<(String, Vec<u8>)> {
    let has_lower = s.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = s.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper || !s.is_ascii() {
        return None;
    }
    let s = s.to_ascii_lowercase();
    let sep = s.rfind('1')?;
    if sep == 0 || sep + 7 > s.len() {
        return None;
    }
    let (hrp, rest) = (&s[..sep], &s[sep + 1..]);
    let data: Vec<u8> = rest
        .bytes()
        .map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8))
        .collect::<Option<_>>()?;
    let mut values = hrp_expand(hrp.as_bytes());
    values.extend(&data);
    if polymod(&values) != 1 {
        return None;
    }
    Some((hrp.to_string(), convert(&data[..data.len() - 6], 5, 8, false)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip173_vectors() {
        // Valid strings from BIP-173.
        for v in [
            "A12UEL5L",
            "a12uel5l",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        ] {
            assert!(decode(v).is_some(), "{v}");
        }
        // A changed character, mixed case, and no separator.
        for v in ["abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxx", "A12uEL5L", "pzry9x0s0muk"] {
            assert!(decode(v).is_none(), "{v}");
        }
        assert_eq!(decode("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw").unwrap().0, "abcdef");
    }

    #[test]
    fn age_keys_round_trip() {
        let secret = [0x42u8; 32];
        let sk = encode("AGE-SECRET-KEY-", &secret).to_ascii_uppercase();
        assert!(sk.starts_with("AGE-SECRET-KEY-1GFPYYSJZ"));
        let (hrp, data) = decode(&sk).unwrap();
        assert_eq!((hrp.as_str(), data.as_slice()), ("age-secret-key-", &secret[..]));
        let mut bad = sk.into_bytes();
        bad[20] = if bad[20] == b'Q' { b'P' } else { b'Q' };
        assert!(decode(std::str::from_utf8(&bad).unwrap()).is_none());
    }
}
