// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Standard, padded base64. Decoding is strict, so a value has one spelling.

const CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(data.len()));
    for chunk in data.chunks(3) {
        let v = (u32::from(chunk[0]) << 16) | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8) | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(CHARS[(v >> 18 & 63) as usize] as char);
        out.push(CHARS[(v >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            CHARS[(v >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { CHARS[(v & 63) as usize] as char } else { '=' });
    }
    out
}

fn value(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// Padded standard alphabet only, with padding only at the end.
pub fn decode_strict(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (q, quad) in b.chunks(4).enumerate() {
        let last = (q + 1) * 4 == b.len();
        let pad = match (quad[2], quad[3]) {
            (b'=', b'=') if last => 2,
            (_, b'=') if last => 1,
            _ => 0,
        };
        let mut v = 0u32;
        for (k, &c) in quad.iter().enumerate() {
            if k >= 4 - pad {
                v <<= 6;
            } else {
                v = (v << 6) | value(c)?;
            }
        }
        for k in 0..3 - pad {
            out.push((v >> (16 - 8 * k)) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for n in 0..10 {
            let data: Vec<u8> = (0..n).map(|i: u32| (i * 37) as u8).collect();
            assert_eq!(decode_strict(&encode(&data)).unwrap(), data);
        }
        assert_eq!(encode(b"hi"), "aGk=");
        assert!(decode_strict("aGk").is_none());
        assert!(decode_strict("a=k=").is_none());
        assert!(decode_strict("aGk=aGk=").is_none());
    }
}
