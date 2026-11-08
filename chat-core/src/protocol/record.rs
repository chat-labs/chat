// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Records: one line of tab-separated fields, its name first ("hi", "m", "a"...). A frame
//! carries one record, or several joined by newlines for a peer that reads them ("b").

/// At most this many fields; the last keeps any tabs after it.
pub const MAX_FIELDS: usize = 8;

/// The records in a frame's plaintext. A NUL ends it.
pub fn records(plain: &[u8]) -> impl Iterator<Item = &[u8]> {
    let end = plain.iter().position(|&b| b == 0).unwrap_or(plain.len());
    plain[..end].split(|&b| b == b'\n')
}

/// A record's fields.
pub fn fields(rec: &[u8]) -> Vec<&[u8]> {
    rec.splitn(MAX_FIELDS, |&b| b == b'\t').collect()
}

/// A field as text, if it's valid UTF-8 (hex, numbers and names always are).
pub fn str_field<'a>(f: &[&'a [u8]], i: usize) -> Option<&'a str> {
    std::str::from_utf8(f.get(i)?).ok()
}

/// Joins fields into a record.
pub fn join(fields: &[&str]) -> String {
    fields.join("\t")
}

/// A decimal number with no sign, at most 19 digits (so any fits in a u64).
pub fn parse_u64(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 19 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_records() {
        let f = fields(b"m\t0a0b0c0d\tid\tnick\ttext");
        assert_eq!(f.len(), 5);
        assert_eq!(f[4], b"text");
        let many = fields(b"a\tb\tc\td\te\tf\tg\th\ti\tj");
        assert_eq!(many.len(), MAX_FIELDS);
        assert_eq!(many[7], b"h\ti\tj");
        assert_eq!(records(b"nop\na\t1\0junk").collect::<Vec<_>>(), vec![&b"nop"[..], &b"a\t1"[..]]);
        assert_eq!(parse_u64("123"), Some(123));
        assert_eq!(parse_u64("+1"), None);
    }
}
