// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! A room's history, as a save keeps it (see [`crate::net::saves`]): a line for each line of its
//! chat, "WHEN\tCOLOUR\tLEN\tMENTION\tTEXT". WHEN is local time ("2026-11-06 14:05"), COLOUR the
//! colour of the line's head (its sender, up to the colon) as hex or "-", LEN that head's length in
//! bytes, MENTION 1 if it mentions you, and TEXT the line as shown ("@ alice: hi"). Up to 256 KB
//! are kept, the oldest lines going first.

use crate::net::saves::HISTORY_MAX;
use crate::protocol::hex;
use zeroize::Zeroizing;

/// A line read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// "YYYY-MM-DD HH:MM", local time.
    pub when: String,
    pub colour: Option<[u8; 3]>,
    /// How many bytes of `text` are its head, drawn in `colour`.
    pub head: usize,
    pub mention: bool,
    pub text: String,
}

impl Line {
    pub fn day(&self) -> &str {
        &self.when[..10]
    }

    pub fn hhmm(&self) -> &str {
        &self.when[11..]
    }
}

const STAMP_LEN: usize = 16;

/// "YYYY-MM-DD HH:MM" for a Unix time, in local time.
pub fn stamp(unix: u64) -> String {
    #[cfg(unix)]
    {
        // SAFETY: localtime_r only writes into the struct it's given.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let tt = unix as libc::time_t;
        if !unsafe { libc::localtime_r(&tt, &mut tm) }.is_null() {
            return format!(
                "{:04}-{:02}-{:02} {:02}:{:02}",
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min
            );
        }
    }
    // shortcut: UTC where there's no localtime_r (Windows); use the platform's local time there.
    let (days, secs) = ((unix / 86400) as i64, unix % 86400);
    // Days to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", secs / 3600, secs / 60 % 60)
}

/// One room's history while it's kept.
#[derive(Default)]
pub struct History {
    buf: Zeroizing<Vec<u8>>,
    /// Changed since it was last written.
    pub dirty: bool,
}

impl History {
    /// What a save had, or nothing.
    pub fn from_saved(saved: Option<&[u8]>) -> History {
        History {
            buf: Zeroizing::new(saved.unwrap_or_default().to_vec()),
            dirty: false,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// A line of the chat, as shown: its head is its first `head` bytes.
    pub fn add(&mut self, unix: u64, colour: Option<[u8; 3]>, head: usize, mention: bool, text: &str) {
        let text = text.replace(['\t', '\n', '\r'], " ");
        let col = colour.map_or("-".to_string(), |c| hex::encode(&c));
        let line = format!("{}\t{col}\t{head}\t{}\t{text}\n", stamp(unix), u8::from(mention));
        if line.len() > HISTORY_MAX {
            return;
        }
        // The oldest lines make room.
        while self.buf.len() + line.len() > HISTORY_MAX {
            let cut = self.buf.iter().position(|b| *b == b'\n').map_or(self.buf.len(), |i| i + 1);
            self.buf.drain(..cut);
        }
        self.buf.extend_from_slice(line.as_bytes());
        self.dirty = true;
    }

    /// Lines from before the room's message timer go too.
    pub fn expire(&mut self, seconds: u32, now: u64) {
        let cutoff = stamp(now.saturating_sub(u64::from(seconds)));
        let mut cut = 0;
        while self.buf.len() - cut >= STAMP_LEN && self.buf[cut..cut + STAMP_LEN] < *cutoff.as_bytes() {
            cut = self.buf[cut..]
                .iter()
                .position(|b| *b == b'\n')
                .map_or(self.buf.len(), |i| cut + i + 1);
        }
        if cut > 0 {
            self.buf.drain(..cut);
            self.dirty = true;
        }
    }

    /// The lines kept, skipping any that can't be read.
    pub fn lines(&self) -> Vec<Line> {
        String::from_utf8_lossy(&self.buf)
            .split('\n')
            .filter_map(|l| {
                let mut f = l.splitn(5, '\t');
                let (when, col, head, mention, text) = (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
                (when.len() == STAMP_LEN).then(|| Line {
                    when: when.to_string(),
                    colour: hex::decode_array::<3>(col),
                    head: head.parse().unwrap_or(0).min(text.len()),
                    mention: mention == "1",
                    text: text.to_string(),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_lines_and_drops_the_oldest() {
        let mut h = History::default();
        h.add(1_700_000_000, Some([1, 2, 3]), 6, false, "alice: hi\tthere");
        h.add(1_700_000_060, None, 0, true, "@ bob: you");
        let l = h.lines();
        assert_eq!(l.len(), 2);
        assert_eq!(
            (l[0].colour, l[0].head, l[0].mention, l[0].text.as_str()),
            (Some([1, 2, 3]), 6, false, "alice: hi there")
        );
        assert_eq!((l[1].colour, l[1].mention), (None, true));
        assert_eq!(l[0].when.len(), 16);
        let big = "x".repeat(1000);
        for i in 0..400 {
            h.add(1_700_000_100 + i, None, 0, false, &big);
        }
        assert!(h.bytes().len() <= HISTORY_MAX);
        assert!(h.lines().iter().all(|l| l.text == big), "the oldest went first");
        h.expire(60, 1_700_000_100 + 400 + 3600);
        assert!(h.lines().is_empty());
    }
}
