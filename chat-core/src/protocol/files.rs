// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Files: the names, sizes and limits the transfer uses, and the storage it reads and writes
//! through.
//!
//! A file is offered to the room ("fo"). Nothing else is sent until someone fetches it: they ask
//! for a window of chunks at a time ("fg"), and the sender sends them in the slots that would
//! otherwise carry a nop ("fd"), so a transfer looks the same as any other traffic. Each window
//! is written in order and hashed, and the file is only kept if the hash matches the offer.
//!
//! The engine does no I/O of its own. It reads our files through a [`Source`] and saves fetched
//! ones through a [`Disk`]: the filesystem in the runtime, memory in tests, or whatever a phone
//! provides.

/// The largest file offered or fetched.
pub const FILE_HARD_MAX: u64 = 1024 * 1024 * 1024;
/// Offers bigger than this need "anyway" to be fetched, unless the user sets another limit.
pub const FILE_CAP_DEFAULT: u64 = 8 * 1024 * 1024;
/// A file fetched to be shown rather than saved is held in memory, up to this size.
pub const FILE_VIEW_MAX: u64 = 64 * 1024 * 1024;
/// Pictures that were shown stay in memory, up to this much in all (the oldest go first).
pub const FILE_CACHE_MAX: u64 = 128 * 1024 * 1024;
/// The longest file name shown and saved, in bytes.
pub const FILE_NAME_MAX: usize = 100;

/// Where one of our offered files is read from: the file opened when it was offered (so a file
/// changed since then no longer matches its hash, and nothing else is sent in its place), or a
/// cleaned picture in memory.
pub trait Source: Send {
    /// Fills buf from offset off. False if it can't (the file shrank or went away).
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> bool;
}

impl Source for zeroize::Zeroizing<Vec<u8>> {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> bool {
        let Ok(off) = usize::try_from(off) else {
            return false;
        };
        match self.get(off..off + buf.len()) {
            Some(b) => {
                buf.copy_from_slice(b);
                true
            }
            None => false,
        }
    }
}

/// A file being saved: written in order, then kept under its name, or removed if it's dropped
/// without being kept.
pub trait Part: Send {
    fn write(&mut self, data: &[u8]) -> bool;
    /// Gives it `name` in its folder, or "name (2).ext" and so on if that's taken. The path it was
    /// saved as, or None if it couldn't be (the part is removed).
    fn keep(self: Box<Self>, name: &str) -> Option<String>;
}

/// Where fetched files are saved.
pub trait Disk: Send {
    /// A new, empty part file in `dir`, or in the Downloads folder without one. Err: why not.
    fn create(&mut self, dir: Option<&str>) -> Result<Box<dyn Part>, String>;
    /// A file saved before, to check that it's still what was offered: its size, and its bytes.
    fn open(&mut self, path: &str) -> Option<(u64, Box<dyn Source>)>;
    /// The folder as messages name it: the one given, or "Downloads".
    fn folder_name(&self, dir: Option<&str>) -> String {
        dir.unwrap_or("Downloads").to_string()
    }
}

/// The last part of a path, as the name a file is offered under.
pub fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn bad_char(ch: char) -> bool {
    ch < ' ' || ch == '\x7f' || "/\\:*?\"<>|".contains(ch)
}

/// Windows treats these as devices whatever comes after a dot: "nul.txt" is NUL.
fn device_name(s: &str) -> bool {
    let stem = s.split('.').next().unwrap_or("").trim_end_matches(' ');
    let up = stem.to_ascii_uppercase();
    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&up.as_str()) {
        return true;
    }
    let Some(rest) = up.strip_prefix("COM").or_else(|| up.strip_prefix("LPT")) else {
        return false;
    };
    // COM1-9 and LPT1-9, and the superscript digits Windows also takes.
    matches!(
        rest,
        "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "\u{b9}" | "\u{b2}" | "\u{b3}"
    )
}

/// A name from a peer, made safe to show and to save under: no folders, nothing the terminal or
/// the filesystem would read as more than a name (control and bidi characters, / \ : * ? " < > |),
/// no leading dots (a hidden file) or trailing dots and spaces, not a Windows device name (CON,
/// NUL, COM1, ...), and never empty.
pub fn clean_name(raw: &[u8]) -> String {
    let clean = crate::protocol::text::clean(raw, 4 * FILE_NAME_MAX);
    let mut out = String::new();
    for ch in basename(&clean).chars() {
        let ch = if bad_char(ch) { '_' } else { ch };
        if out.len() + ch.len_utf8() > FILE_NAME_MAX {
            break;
        }
        out.push(ch);
    }
    let out = out.trim_start_matches(['.', ' ']).trim_end_matches(['.', ' ']);
    if out.is_empty() {
        return "file".into();
    }
    if device_name(out) {
        let mut s = format!("_{out}");
        while s.len() > FILE_NAME_MAX {
            s.pop();
        }
        return s;
    }
    out.to_string()
}

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

/// "8M", "512K", "2G", "1048576" or "8 MB": bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let digits = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if digits == 0 {
        return None;
    }
    let whole: u64 = s[..digits].parse().ok()?;
    let mut rest = &s[digits..];
    let (mut frac, mut frac_div) = (0u64, 1u64);
    if let Some(r) = rest.strip_prefix('.') {
        let n = r.find(|c: char| !c.is_ascii_digit()).unwrap_or(r.len());
        for d in r[..n].bytes().take(6) {
            frac = frac * 10 + u64::from(d - b'0');
            frac_div *= 10;
        }
        rest = &r[n..];
    }
    let mut rest = rest.trim_start();
    let mult = match rest.chars().next().map(|c| c.to_ascii_uppercase()) {
        Some('K') => KIB,
        Some('M') => MIB,
        Some('G') => GIB,
        _ => 1,
    };
    if mult > 1 {
        rest = &rest[1..];
    }
    if rest.starts_with(['b', 'B']) {
        rest = &rest[1..];
    }
    if !rest.trim().is_empty() {
        return None;
    }
    whole.checked_mul(mult)?.checked_add(frac * mult / frac_div)
}

/// "230 KB", "8.0 MB".
pub fn format_size(n: u64) -> String {
    let f = n as f64;
    if n < KIB {
        format!("{n} bytes")
    } else if n < MIB {
        format!("{:.0} KB", f / KIB as f64)
    } else if n < GIB {
        format!("{:.1} MB", f / MIB as f64)
    } else {
        format!("{:.1} GB", f / GIB as f64)
    }
}

/// The size as [`parse_size`] takes it, exactly: "8M", "512K", "1G", else in bytes.
pub fn format_size_exact(n: u64) -> String {
    for (per, unit) in [(GIB, "G"), (MIB, "M"), (KIB, "K")] {
        if n > 0 && n.is_multiple_of(per) {
            return format!("{}{unit}", n / per);
        }
    }
    n.to_string()
}

/// How long something takes, roughly: "under a minute", "about 6 min", "about 2 h 10 min".
pub fn format_duration(seconds: f64) -> String {
    const HOUR: i64 = 60;
    const DAY: i64 = 24 * HOUR;
    let seconds = if seconds < 60.0 * DAY as f64 * 365.0 {
        seconds
    } else {
        60.0 * DAY as f64 * 365.0
    };
    let min = (seconds / 60.0 + 0.5) as i64;
    if seconds < 60.0 {
        "under a minute".into()
    } else if min < HOUR {
        format!("about {min} min")
    } else if min >= 2 * DAY {
        format!("about {} days", (min + DAY / 2) / DAY)
    } else if min % HOUR == 0 || min >= 10 * HOUR {
        format!("about {} h", (min + HOUR / 2) / HOUR)
    } else {
        format!("about {} h {} min", min / HOUR, min % HOUR)
    }
}

/// A path typed in a command: trailing spaces and the quotes file managers copy paths with are
/// removed, and a leading ~ is the home folder.
pub fn typed_path(input: &str, home: Option<&str>) -> String {
    let mut p = input.trim_matches(' ').to_string();
    let b = p.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        p = p[1..p.len() - 1].to_string();
    }
    if let Some(home) = home
        && (p == "~" || p.starts_with("~/"))
    {
        p = format!("{home}{}", &p[1..]);
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(clean_name(b"../../etc/passwd"), "passwd");
        assert_eq!(clean_name(b"..hidden. "), "hidden");
        assert_eq!(clean_name(b"a:b*c?.txt"), "a_b_c_.txt");
        assert_eq!(clean_name(b"nul.txt"), "_nul.txt");
        assert_eq!(clean_name(b"COM1"), "_COM1");
        assert_eq!(clean_name(b"COM10"), "COM10");
        assert_eq!(clean_name(b"..."), "file");
        assert_eq!(clean_name(b"txt\xe2\x80\xaeexe.txt"), "txtexe.txt");
        assert!(clean_name(&[b'x'; 300]).len() == FILE_NAME_MAX);
        assert_eq!(basename("C:\\photos\\a.jpg"), "a.jpg");
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("8M"), Some(8 * MIB));
        assert_eq!(parse_size("8 MB"), Some(8 * MIB));
        assert_eq!(parse_size("1.5k"), Some(1536));
        assert_eq!(parse_size("1048576"), Some(MIB));
        assert_eq!(parse_size("x"), None);
        assert_eq!(parse_size("5 Q"), None);
        assert_eq!(format_size(512), "512 bytes");
        assert_eq!(format_size(230 * KIB), "230 KB");
        assert_eq!(format_size(8 * MIB), "8.0 MB");
        assert_eq!(format_size_exact(8 * MIB), "8M");
        assert_eq!(format_size_exact(1000), "1000");
        assert_eq!(format_duration(30.0), "under a minute");
        assert_eq!(format_duration(360.0), "about 6 min");
        assert_eq!(format_duration(130.0 * 60.0), "about 2 h 10 min");
        assert_eq!(format_duration(3.0 * 86400.0), "about 3 days");
        assert_eq!(typed_path(" '~/a b.png' ", Some("/home/x")), "/home/x/a b.png");
    }
}
