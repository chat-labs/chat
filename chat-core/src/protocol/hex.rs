// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Lowercase hex, as the protocol writes it. Decoding takes lowercase only, so a value has one
//! spelling on the wire.

const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 15)] as char);
    }
    s
}

fn lower(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Exactly N bytes of lowercase hex.
pub fn decode_array<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (lower(b[2 * i])? << 4) | lower(b[2 * i + 1])?;
    }
    Some(out)
}

pub fn decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks(2).map(|p| Some((lower(p[0])? << 4) | lower(p[1])?)).collect()
}

/// Hex in groups of four digits, "a1b2 c3d4 ...", for codes people read out to each other.
pub fn groups(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2 + data.len() / 2);
    for (i, &b) in data.iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            s.push(' ');
        }
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 15)] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    #[test]
    fn round_trip() {
        assert_eq!(super::encode(&[0xab, 0x01]), "ab01");
        assert_eq!(super::decode_array::<2>("ab01"), Some([0xab, 0x01]));
        assert_eq!(super::decode_array::<2>("AB01"), None);
        assert_eq!(super::groups(&[1, 2, 3, 4, 5]), "0102 0304 05");
    }
}
