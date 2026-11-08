// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Styled text wrapped to a width, and the time of day.

use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// "HH:MM", local time.
pub fn hhmm(unix: u64) -> String {
    #[cfg(unix)]
    {
        // SAFETY: localtime_r only writes into the struct it's given.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        let t = unix as libc::time_t;
        if !unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
            return format!("{:02}:{:02}", tm.tm_hour, tm.tm_min);
        }
    }
    format!("{:02}:{:02}", (unix / 3600) % 24, (unix / 60) % 60)
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Display width, with control characters (which the engine already strips) counted as one.
pub fn width(s: &str) -> usize {
    UnicodeWidthStr::width(s)
}

/// Wraps styled pieces of text to `width` columns, breaking between words where it can.
/// Lines after the first start with `indent` spaces.
pub fn wrap(pieces: &[(String, Style)], width: usize, indent: usize) -> Vec<Line<'static>> {
    let width = width.max(indent + 8);
    // Runs of spaces and of everything else, each keeping its style.
    let mut tokens: Vec<(String, Style, bool)> = Vec::new();
    for (text, style) in pieces {
        let mut cur = String::new();
        let mut cur_space = false;
        for ch in text.chars() {
            let ch = if ch == '\n' || ch == '\t' { ' ' } else { ch };
            let space = ch == ' ';
            if !cur.is_empty() && space != cur_space {
                tokens.push((std::mem::take(&mut cur), *style, cur_space));
            }
            cur_space = space;
            cur.push(ch);
        }
        if !cur.is_empty() {
            tokens.push((cur, *style, cur_space));
        }
    }
    let mut lines = Vec::new();
    let mut line: Vec<Span<'static>> = Vec::new();
    let mut used = 0;
    let new_line = |lines: &mut Vec<Line<'static>>, line: &mut Vec<Span<'static>>, used: &mut usize| {
        // The spaces a line breaks at don't stay at its end.
        while line.last().is_some_and(|s| s.content.trim_end().is_empty() && line.len() > 1) {
            line.pop();
        }
        lines.push(Line::from(std::mem::take(line)));
        line.push(Span::raw(" ".repeat(indent)));
        *used = indent;
    };
    for (tok, style, space) in tokens {
        let w = self::width(&tok);
        if used + w <= width {
            line.push(Span::styled(tok, style));
            used += w;
            continue;
        }
        if space {
            // Spaces at a break are dropped.
            new_line(&mut lines, &mut line, &mut used);
            continue;
        }
        if w <= width - indent && used > indent {
            new_line(&mut lines, &mut line, &mut used);
            line.push(Span::styled(tok, style));
            used += w;
            continue;
        }
        // A word longer than a line: broken wherever it has to be.
        let mut part = String::new();
        for ch in tok.chars() {
            let cw = ch.width().unwrap_or(1);
            if used + cw > width {
                line.push(Span::styled(std::mem::take(&mut part), style));
                new_line(&mut lines, &mut line, &mut used);
            }
            part.push(ch);
            used += cw;
        }
        line.push(Span::styled(part, style));
    }
    lines.push(Line::from(line));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(lines: &[Line]) -> Vec<String> {
        lines.iter().map(|l| l.spans.iter().map(|s| s.content.as_ref()).collect()).collect()
    }

    #[test]
    fn wraps_between_words() {
        let l = wrap(&[("hello there general kenobi".into(), Style::default())], 12, 2);
        assert_eq!(plain(&l), vec!["hello there", "  general", "  kenobi"]);
    }

    #[test]
    fn breaks_long_words() {
        let l = wrap(&[("abcdefghijklmnopqrstuvwxyz".into(), Style::default())], 10, 0);
        assert_eq!(plain(&l), vec!["abcdefghij", "klmnopqrst", "uvwxyz"]);
    }

    #[test]
    fn wide_characters_count_twice() {
        let l = wrap(&[("日本語のテキスト".into(), Style::default())], 10, 0);
        assert!(plain(&l).iter().all(|s| width(s) <= 10));
    }
}
