// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Text from the network: cleaned of what a terminal or a bidi algorithm would act on, nicks
//! that can't fake what the UI puts around them, and the rules for telling lookalike nicks
//! apart, so messages display consistently.

/// The length of the character a byte starts, or 0 if it can't start one.
fn lead_len(c: u8) -> usize {
    if c < 0x80 {
        1
    } else if c & 0xe0 == 0xc0 {
        2
    } else if c & 0xf0 == 0xe0 {
        3
    } else if c & 0xf8 == 0xf0 {
        4
    } else {
        0
    }
}

fn is_cont(c: u8) -> bool {
    c & 0xc0 == 0x80
}

fn is_scalar(cp: u32) -> bool {
    cp <= 0x10ffff && !(0xd800..=0xdfff).contains(&cp)
}

/// The code point at `s[i]`, strictly: an overlong form, a surrogate or anything past U+10FFFF is
/// malformed, and comes back as its first byte with a length of 1.
pub fn decode_at(s: &[u8], i: usize) -> (u32, usize) {
    const MIN_CP: [u32; 5] = [0, 0, 0x80, 0x800, 0x10000];
    let c = s[i];
    let len = lead_len(c);
    if len <= 1 || i + len > s.len() {
        return (u32::from(c), 1);
    }
    let mut cp = u32::from(c & (0x7f >> len));
    for k in 1..len {
        let cc = s[i + k];
        if !is_cont(cc) {
            return (u32::from(c), 1);
        }
        cp = (cp << 6) | u32::from(cc & 0x3f);
    }
    if cp < MIN_CP[len] || !is_scalar(cp) {
        return (u32::from(c), 1);
    }
    (cp, len)
}

fn is_control(cp: u32) -> bool {
    cp < 0x20 || cp == 0x7f || (0x80..=0x9f).contains(&cp)
}

/// Controls (C0, C1, DEL) and the marks that reorder text.
fn is_stripped(cp: u32) -> bool {
    is_control(cp) || cp == 0x61c || cp == 0x200e || cp == 0x200f || (0x202a..=0x202e).contains(&cp) || (0x2066..=0x2069).contains(&cp)
}

/// Text made safe to show: malformed UTF-8, controls and bidi marks dropped, at most `max_len`
/// bytes (stopping before a character that doesn't fit), and spaces trimmed from both ends.
pub fn clean(input: &[u8], max_len: usize) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(input.len().min(max_len));
    let mut i = 0;
    while i < input.len() {
        let (cp, adv) = decode_at(input, i);
        if !is_stripped(cp) && !(adv == 1 && cp >= 0x80) {
            if out.len() + adv > max_len {
                break;
            }
            out.extend_from_slice(&input[i..i + adv]);
        }
        i += adv;
    }
    let is_space = |c: &u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r');
    let end = out.iter().rposition(|c| !is_space(c)).map_or(0, |p| p + 1);
    let start = out[..end].iter().position(|c| !is_space(c)).unwrap_or(end);
    // Only whole, valid characters were copied.
    String::from_utf8(out[start..end].to_vec()).unwrap_or_default()
}

pub fn clean_str(input: &str, max_len: usize) -> String {
    clean(input.as_bytes(), max_len)
}

/// Characters that render as nothing, or next to nothing.
fn is_invisible(cp: u32) -> bool {
    matches!(
        cp,
        0xad | 0x34f | 0x61c | 0x115f | 0x1160 | 0x17b4 | 0x17b5 | 0x180e | 0x3164 | 0xfeff | 0xffa0
    ) || (0x200b..=0x200d).contains(&cp)
        || (0x2060..=0x2064).contains(&cp)
        || (0xfe00..=0xfe0f).contains(&cp)
        || (0xe0000..=0xe007f).contains(&cp)
}

/// Fullwidth ASCII, and brackets and marks that look like the ones the UI uses, as plain ASCII.
fn fold_punct(cp: u32) -> u32 {
    if (0xff01..=0xff5e).contains(&cp) {
        return cp - 0xff01 + 0x21;
    }
    match cp {
        0x207d | 0x208d | 0x2768 | 0x276a | 0x27ee | 0x2985 | 0xfe59 | 0xff5f => '(' as u32,
        0x207e | 0x208e | 0x2769 | 0x276b | 0x27ef | 0x2986 | 0xfe5a | 0xff60 => ')' as u32,
        0xfe5f => '#' as u32,
        0x2d0 | 0x2236 | 0xa789 | 0xfe13 | 0xfe55 => ':' as u32,
        0xfe6b => '@' as u32,
        _ => cp,
    }
}

/// Letters from other scripts that look like Latin ones.
const LOOKALIKES: &[(u32, u8)] = &[
    (0x0131, b'i'),
    (0x0261, b'g'),
    (0x0391, b'A'),
    (0x0392, b'B'),
    (0x0395, b'E'),
    (0x0396, b'Z'),
    (0x0397, b'H'),
    (0x0399, b'I'),
    (0x039a, b'K'),
    (0x039c, b'M'),
    (0x039d, b'N'),
    (0x039f, b'O'),
    (0x03a1, b'P'),
    (0x03a4, b'T'),
    (0x03a5, b'Y'),
    (0x03a7, b'X'),
    (0x03b1, b'a'),
    (0x03b9, b'i'),
    (0x03ba, b'k'),
    (0x03bd, b'v'),
    (0x03bf, b'o'),
    (0x03c1, b'p'),
    (0x03c5, b'u'),
    (0x0405, b'S'),
    (0x0406, b'I'),
    (0x0408, b'J'),
    (0x0410, b'A'),
    (0x0412, b'B'),
    (0x0415, b'E'),
    (0x041a, b'K'),
    (0x041c, b'M'),
    (0x041d, b'H'),
    (0x041e, b'O'),
    (0x0420, b'P'),
    (0x0421, b'C'),
    (0x0422, b'T'),
    (0x0425, b'X'),
    (0x0430, b'a'),
    (0x0435, b'e'),
    (0x043a, b'k'),
    (0x043e, b'o'),
    (0x0440, b'p'),
    (0x0441, b'c'),
    (0x0443, b'y'),
    (0x0445, b'x'),
    (0x0455, b's'),
    (0x0456, b'i'),
    (0x0458, b'j'),
    (0x04ae, b'Y'),
    (0x04bb, b'h'),
    (0x04c0, b'I'),
    (0x0501, b'd'),
    (0x051b, b'q'),
    (0x051d, b'w'),
    (0x217c, b'l'),
];

pub const MAX_NICK: usize = 24;

fn push_cp(out: &mut Vec<u8>, cp: u32) {
    let mut buf = [0u8; 4];
    match char::from_u32(cp) {
        Some(ch) => out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes()),
        // A lone byte decode_at gave back: kept as a byte.
        None => out.push(cp as u8),
    }
}

/// A nick cleaned of what the UI puts around nicks ("(verified)", "#id", "name:"), lookalikes of
/// those included, and of invisible characters, so no nick can fake them. Never empty.
pub fn clean_nick(input: &[u8]) -> String {
    let tmp = clean(input, MAX_NICK);
    let t = tmp.as_bytes();
    let mut kept = Vec::with_capacity(t.len());
    let mut i = 0;
    while i < t.len() {
        let (cp, adv) = decode_at(t, i);
        let f = fold_punct(cp);
        let banned = f < 0x80 && b"()#:@".contains(&(f as u8));
        if !is_invisible(cp) && !banned {
            if f != cp {
                kept.push(f as u8);
            } else {
                kept.extend_from_slice(&t[i..i + adv]);
            }
        }
        i += adv;
    }
    let out = clean(&kept, MAX_NICK);
    if out.is_empty() { "anon".to_string() } else { out }
}

/// A nick normalised for comparing: lookalikes mapped to Latin, i/I/1/| to l, 0 to o, case and
/// invisible characters ignored. Two nicks with the same skeleton look the same.
pub fn nick_skeleton(nick: &str) -> String {
    const CAP: usize = 4 * MAX_NICK + 1;
    let s = nick.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let (raw, adv) = decode_at(s, i);
        i += adv;
        let mut cp = fold_punct(raw);
        if is_invisible(cp) {
            continue;
        }
        if let Some(&(_, ascii)) = LOOKALIKES.iter().find(|(c, _)| *c == cp) {
            cp = u32::from(ascii);
        }
        if cp < 0x80 {
            cp = u32::from((cp as u8).to_ascii_lowercase());
        }
        if cp == 'i' as u32 || cp == '|' as u32 || cp == '1' as u32 {
            cp = 'l' as u32;
        } else if cp == '0' as u32 {
            cp = 'o' as u32;
        }
        let before = out.len();
        push_cp(&mut out, cp);
        if out.len() >= CAP {
            out.truncate(before);
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether two nicks are the same, ignoring ASCII case.
pub fn nick_eq_ignore_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// The length of an @mention of `nick` at the start of s, or 0: any case, and not run on into a
/// longer name, so "@ann," names ann but "@anna" and "@ann-2" don't.
pub fn mention_len(s: &[u8], nick: &str) -> usize {
    let n = nick.as_bytes();
    if s.first() != Some(&b'@') || n.is_empty() || s.len() < 1 + n.len() {
        return 0;
    }
    if !s[1..1 + n.len()].eq_ignore_ascii_case(n) {
        return 0;
    }
    let rest = &s[1 + n.len()..];
    if rest.is_empty() {
        return 1 + n.len();
    }
    let (cp, _) = decode_at(rest, 0);
    // Accented Latin letters go on a name too; other scripts, symbols and emoji end it.
    let name = if cp < 0x80 {
        (cp as u8).is_ascii_alphanumeric() || cp == '-' as u32 || cp == '_' as u32
    } else {
        (0xc0..=0x24f).contains(&cp) && cp != 0xd7 && cp != 0xf7
    };
    if name { 0 } else { 1 + n.len() }
}

/// Whether text @mentions nick anywhere.
pub fn has_mention(text: &str, nick: &str) -> bool {
    let b = text.as_bytes();
    b.iter().enumerate().any(|(i, &c)| c == b'@' && mention_len(&b[i..], nick) > 0)
}

/// How much of text goes in a part of at most `max` bytes: up to a space in its second half if
/// there's one, so a word isn't split, otherwise to the end of a character.
pub fn part_len(text: &[u8], max: usize) -> usize {
    if text.len() <= max {
        return text.len();
    }
    let mut cut = max;
    while cut > 0 && is_cont(text[cut]) {
        cut -= 1;
    }
    let mut i = cut;
    while i > max / 2 {
        if text[i] == b' ' {
            return i;
        }
        i -= 1;
    }
    cut
}

/// The start of text, at most `max` bytes on a character boundary, with "…" if it was cut.
pub fn quote(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut n = max;
    while n > 0 && !text.is_char_boundary(n) {
        n -= 1;
    }
    format!("{}\u{2026}", &text[..n])
}

// ---- links ----

/// The longest address a link opens.
pub const LINK_URL_MAX: usize = 1024;

fn ascii_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// What a link holds past its host: anything printable but a space and what RFC 3986 never leaves
/// unencoded, and the bytes of characters past ASCII.
fn link_byte(c: u8) -> bool {
    c >= 0x80 || (c > b' ' && c < 0x7f && !b"\"<>\\^`{|}".contains(&c))
}

fn scheme_len(s: &[u8]) -> usize {
    for p in [&b"https://"[..], b"http://"] {
        if s.len() >= p.len() && s[..p.len()].eq_ignore_ascii_case(p) {
            return p.len();
        }
    }
    0
}

/// Two or more labels of letters, digits and '-' (not first or last), the last of them two or more
/// letters in one case, so "e.g", "v1.2.3" and "end.Next" aren't names. Its length, or 0.
fn domain_len(s: &[u8]) -> usize {
    let (mut i, mut last, mut end, mut labels) = (0, 0, 0, 0);
    loop {
        let st = i;
        while i < s.len() && (ascii_alnum(s[i]) || s[i] == b'-') {
            i += 1;
        }
        if i == st || s[st] == b'-' || s[i - 1] == b'-' {
            break;
        }
        labels += 1;
        last = st;
        end = i;
        if i + 1 < s.len() && s[i] == b'.' && ascii_alnum(s[i + 1]) {
            i += 1;
        } else {
            break;
        }
    }
    if labels < 2 || end - last < 2 {
        return 0;
    }
    let tld = &s[last..end];
    let (lower, upper) = (tld.iter().all(u8::is_ascii_lowercase), tld.iter().all(u8::is_ascii_uppercase));
    if lower || upper { end } else { 0 }
}

/// A name starts a link only where it isn't the rest of a word, a path, an address or another
/// link ("ida@ieji.de", "~/notes.md"). Past ASCII, the character before could be a letter.
fn name_starts(s: &[u8], i: usize) -> bool {
    i == 0 || (s[i - 1] < 0x80 && !ascii_alnum(s[i - 1]) && !b"-_.@/\\:~#$%&+=".contains(&s[i - 1]))
}

fn name_ends(s: &[u8], e: usize) -> bool {
    if e >= s.len() {
        return true;
    }
    if b"@_-".contains(&s[e]) {
        return false;
    }
    !(s[e] == b'.' && e + 1 < s.len() && (ascii_alnum(s[e + 1]) || b"_-".contains(&s[e + 1])))
}

/// Leaves off what's around a link rather than in it: a sentence's punctuation after it, and a
/// bracket it didn't open, as in "(see example.com)". Never before `min`.
fn link_trim(s: &[u8], start: usize, mut end: usize, min: usize) -> usize {
    const CLOSERS: [&str; 6] = ["\u{201d}", "\u{2019}", "\u{bb}", "\u{2026}", "\u{3002}", "\u{ff09}"];
    loop {
        if end <= min {
            return end;
        }
        let c = s[end - 1];
        if b".,;:!?'*".contains(&c) {
            end -= 1;
            continue;
        }
        if c == b')' || c == b']' {
            let open = if c == b')' { b'(' } else { b'[' };
            let depth: i32 = s[start..end]
                .iter()
                .map(|k| {
                    if *k == open {
                        1
                    } else if *k == c {
                        -1
                    } else {
                        0
                    }
                })
                .sum();
            if depth < 0 {
                end -= 1;
                continue;
            }
        }
        match CLOSERS.iter().find(|cl| end - min >= cl.len() && s[..end].ends_with(cl.as_bytes())) {
            Some(cl) => end -= cl.len(),
            None => return end,
        }
    }
}

/// What the address a link opens %-encodes: bytes past ASCII, and what a shell reads inside quotes.
fn target_encodes(c: u8) -> bool {
    c >= 0x80 || c == b'$' || c == b'\''
}

fn target_len(link: &[u8]) -> usize {
    let scheme = if scheme_len(link) > 0 { 0 } else { "https://".len() };
    scheme + link.iter().map(|c| if target_encodes(*c) { 3 } else { 1 }).sum::<usize>()
}

/// The links in text, as (start, length) in bytes: "https://..." and "http://...", and names like
/// "example.com/page", in the order they come.
pub fn links(text: &str) -> Vec<(usize, usize)> {
    let s = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let sl = scheme_len(&s[i..]);
        let e = if sl > 0 && (i == 0 || !ascii_alnum(s[i - 1])) && i + sl < s.len() && (ascii_alnum(s[i + sl]) || s[i + sl] == b'[') {
            let mut e = i + sl;
            while e < s.len() && link_byte(s[e]) {
                e += 1;
            }
            link_trim(s, i, e, i + sl + 1)
        } else if ascii_alnum(s[i]) && name_starts(s, i) {
            let d = domain_len(&s[i..]);
            if d == 0 || !name_ends(s, i + d) {
                i += 1;
                continue;
            }
            let mut e = i + d;
            if e < s.len() && b"/?#".contains(&s[e]) {
                let mut p = e;
                while p < s.len() && link_byte(s[p]) {
                    p += 1;
                }
                e = link_trim(s, i, p, e);
            }
            e
        } else {
            i += 1;
            continue;
        };
        if target_len(&s[i..e]) < LINK_URL_MAX && text.is_char_boundary(i) && text.is_char_boundary(e) {
            out.push((i, e - i));
        }
        i = e.max(i + 1);
    }
    out
}

/// The address a link opens: "https://" before a bare name, and bytes past ASCII, '$' and '\''
/// %-encoded, since a browser launcher can pass it through a shell.
pub fn link_target(link: &str) -> String {
    let b = link.as_bytes();
    let mut out = String::with_capacity(target_len(b));
    if scheme_len(b) == 0 {
        out.push_str("https://");
    }
    for c in b {
        if target_encodes(*c) {
            out.push_str(&format!("%{c:02X}"));
        } else {
            out.push(*c as char);
        }
    }
    out
}

/// What a part of a line of chat's own text (a note, or the network's log) is, for an interface to
/// highlight it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    /// The part of chat a line comes from, which it starts with: "tor:", "nostr:", "joining:".
    Source,
    /// The "warning:" a line starts with.
    Warning,
    /// A command to type: "/invite".
    Command,
    /// Where a peer or a server is: "192.0.2.7:5000", "[2001:db8::1]:5000", "abc...xyz.onion",
    /// "relay.example.net".
    Address,
    /// A file or folder: "~/Downloads/a.png".
    Path,
    /// A count, a size, a share, an id or a group of hex: "3", "2/5", "45%", "f838687f".
    Number,
    /// An invite to a room, password and all.
    Invite,
    /// A verify code's words, to read out.
    Code,
    /// What went right: "connected", "joined", "verified".
    Good,
    /// What's under way: "connecting", "waiting", "retrying".
    Busy,
    /// What went wrong: "failed", "can't", "refused".
    Bad,
    /// One of the names asked about (the room's, yours, a peer's), by its place among them.
    Name(usize),
}

const GOOD: &[&str] = &[
    "answered",
    "back",
    "compared",
    "connected",
    "delivered",
    "done",
    "found",
    "hosting",
    "joined",
    "kept",
    "mapped",
    "match",
    "open",
    "opened",
    "published",
    "reached",
    "ready",
    "saved",
    "sent",
    "up",
    "verified",
];
const BUSY: &[&str] = &[
    "asking",
    "checking",
    "connecting",
    "deriving",
    "downloading",
    "fetching",
    "finding",
    "joining",
    "looking",
    "making",
    "opening",
    "publishing",
    "queued",
    "reconnecting",
    "retrying",
    "sealing",
    "sending",
    "starting",
    "trying",
    "waiting",
];
const BAD: &[&str] = &[
    "can't",
    "cannot",
    "couldn't",
    "denied",
    "differ",
    "error",
    "failed",
    "invalid",
    "lost",
    "missed",
    "quiet",
    "refused",
    "timed",
    "unexpected",
    "unreachable",
    "wrong",
];

/// The parts of a line of chat's own text to highlight, as (start, length, what) in bytes, in
/// order, with `names` (the room's, yours, peers') marked where a word is one of them. Each is a
/// whole word, without the brackets or punctuation around it. Peers' messages aren't read this
/// way: they're theirs, and anything in them could look like anything.
// shortcut: words split at spaces, so a path with a space is marked up to it, "/tmp" alone reads as
// a command and "a.png" as a host; mark from the line's own parts if notes ever carry them.
pub fn console_marks(text: &str, names: &[&str]) -> Vec<(usize, usize, Mark)> {
    let mut out = Vec::new();
    // The source it starts with: one lowercase word and a colon.
    let mut from = 0;
    if let Some((tag, _)) = text.split_once(": ")
        && !tag.is_empty()
        && tag.bytes().all(|c| c.is_ascii_lowercase())
    {
        out.push((0, tag.len() + 1, if tag == "warning" { Mark::Warning } else { Mark::Source }));
        from = tag.len() + 1;
    }
    // A verify code: its words, from the colon before them to its hex.
    let code = text
        .find(" (in hex ")
        .and_then(|end| text[..end].rfind(": ").map(|start| start + 2..end));
    let mut at = 0;
    for word in text.split(' ') {
        let start = at;
        at += word.len() + 1;
        let lead = word.len() - word.trim_start_matches(['(', '"', '\'']).len();
        let w = word[lead..].trim_end_matches([')', '"', '\'', ',', '.', ';', ':', '!', '?']);
        if start < from || w.is_empty() {
            continue;
        }
        let m = match &code {
            Some(c) if c.contains(&start) && w != "\u{b7}" => Some(Mark::Code),
            _ => word_mark(w, names),
        };
        if let Some(m) = m {
            out.push((start + lead, w.len(), m));
        }
    }
    out
}

fn word_mark(w: &str, names: &[&str]) -> Option<Mark> {
    let b = w.as_bytes();
    let first = *b.first()?;
    let lower = w.to_ascii_lowercase();
    let host = w
        .rsplit_once(':')
        .filter(|(_, port)| port.parse::<u16>().is_ok())
        .map_or(w, |(h, _)| h);
    if let Some(i) = names
        .iter()
        .position(|n| !n.is_empty() && (*n == w || w.strip_suffix("'s") == Some(n)))
    {
        Some(Mark::Name(i))
    } else if first == b'/' && b.len() > 1 && b[1..].iter().all(u8::is_ascii_lowercase) {
        Some(Mark::Command)
    } else if w.len() > "chat:".len() && crate::protocol::names::is_invite(w) {
        Some(Mark::Invite)
    } else if w.parse::<std::net::SocketAddr>().is_ok()
        || w.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().is_ok()
        || host.len() > ".onion".len() && host.ends_with(".onion")
        || !host.is_empty() && domain_len(host.as_bytes()) == host.len()
    {
        Some(Mark::Address)
    } else if w.starts_with("~/") || w.starts_with("./") || first == b'/' && w[1..].contains('/') {
        Some(Mark::Path)
    } else if first.is_ascii_digit() && b.iter().all(|c| c.is_ascii_digit() || b".,/%".contains(c))
        || b.len() >= 4 && b.iter().all(u8::is_ascii_hexdigit) && b.iter().any(u8::is_ascii_digit)
    {
        Some(Mark::Number)
    } else if GOOD.contains(&lower.as_str()) {
        Some(Mark::Good)
    } else if BUSY.contains(&lower.as_str()) {
        Some(Mark::Busy)
    } else if BAD.contains(&lower.as_str()) {
        Some(Mark::Bad)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_console_lines() {
        let marks = |t: &'static str| -> Vec<(&str, Mark)> {
            console_marks(t, &["vin-moe-party", "ida", "Gemma"])
                .into_iter()
                .map(|(a, n, m)| (&t[a..a + n], m))
                .collect()
        };
        assert_eq!(
            marks("nostr: connected to relay.snort.social"),
            [
                ("nostr:", Mark::Source),
                ("connected", Mark::Good),
                ("relay.snort.social", Mark::Address)
            ]
        );
        assert_eq!(
            marks("joining: peer f838687f - connected, waiting for its nick"),
            [
                ("joining:", Mark::Source),
                ("f838687f", Mark::Number),
                ("connected", Mark::Good),
                ("waiting", Mark::Busy)
            ]
        );
        assert_eq!(
            marks("Gemma (verified) joined (2 online)"),
            [
                ("Gemma", Mark::Name(2)),
                ("verified", Mark::Good),
                ("joined", Mark::Good),
                ("2", Mark::Number)
            ]
        );
        // A verify code's words, and its hex all alike.
        assert_eq!(
            marks("verify code with Gemma: city holy \u{b7} curl easy (in hex 1a5e 4684) - compare it"),
            [
                ("Gemma", Mark::Name(2)),
                ("city", Mark::Code),
                ("holy", Mark::Code),
                ("curl", Mark::Code),
                ("easy", Mark::Code),
                ("1a5e", Mark::Number),
                ("4684", Mark::Number),
            ]
        );
        assert_eq!(
            marks("hi to ida's peer (192.0.2.7:5000, try 2/5) failed"),
            [
                ("ida's", Mark::Name(1)),
                ("192.0.2.7:5000", Mark::Address),
                ("2/5", Mark::Number),
                ("failed", Mark::Bad)
            ]
        );
        assert_eq!(marks("warning: bob no longer signs"), [("warning:", Mark::Warning)]);
        assert_eq!(
            marks("room vin-moe-party is ready. /invite copies it (/verify NAME)."),
            [
                ("vin-moe-party", Mark::Name(0)),
                ("ready", Mark::Good),
                ("/invite", Mark::Command),
                ("/verify", Mark::Command)
            ]
        );
        assert_eq!(
            marks("saved file 3 to ~/Downloads/a.png."),
            [("saved", Mark::Good), ("3", Mark::Number), ("~/Downloads/a.png", Mark::Path)]
        );
        assert_eq!(
            marks("from [2001:db8::1]:5000 and abcdefgh.onion:80"),
            [("[2001:db8::1]:5000", Mark::Address), ("abcdefgh.onion:80", Mark::Address)]
        );
        assert_eq!(marks("share this invite: chat:room:pw:x"), [("chat:room:pw:x", Mark::Invite)]);
        // Words that only have digits or hex letters in them, and plain words: nothing.
        assert!(marks("hi2 cafe 8a1 udp/1234 tor said chat").is_empty());
    }

    #[test]
    fn cleans_text() {
        assert_eq!(clean(b"  hi\x1b[31m there \x07", 100), "hi[31m there");
        assert_eq!(clean(b"a\xc0\x80b", 100), "ab");
        assert_eq!(clean(b"a\xed\xa0\x80b", 100), "ab");
        assert_eq!(clean("caf\u{e9}".as_bytes(), 4), "caf");
        assert_eq!(clean("x\u{202e}y".as_bytes(), 10), "xy");
    }

    #[test]
    fn nicks() {
        assert_eq!(clean_nick(b"bob (verified)"), "bob verified");
        assert_eq!(clean_nick("\u{ff21}lice".as_bytes()), "Alice");
        assert_eq!(clean_nick(b"@#:"), "anon");
        assert_eq!(nick_skeleton("B0b"), nick_skeleton("bob"));
        assert_eq!(nick_skeleton("\u{0430}lice"), nick_skeleton("alice"));
        assert_eq!(nick_skeleton("Il1|"), "llll");
    }

    #[test]
    fn mentions() {
        assert!(has_mention("hey @Ann, look", "ann"));
        assert!(has_mention("hey @ann", "ann"));
        assert!(!has_mention("hey @anna", "ann"));
        assert!(!has_mention("hey @ann-2", "ann"));
        assert!(!has_mention("hey @ann\u{e9}", "ann"));
        assert!(has_mention("@ann\u{4e16}", "ann"));
    }

    #[test]
    fn parts_split_on_spaces() {
        let t = b"aaaa bbbb cccc";
        assert_eq!(part_len(t, 7), 4);
        assert_eq!(part_len(t, 100), 14);
        let u = "\u{e9}\u{e9}\u{e9}".as_bytes();
        assert_eq!(part_len(u, 3), 2);
    }

    #[test]
    fn finds_links_like_people_write_them() {
        let found = |t: &str| links(t).iter().map(|(a, n)| t[*a..a + n].to_string()).collect::<Vec<_>>();
        assert_eq!(found("see https://example.com/a?b=1."), ["https://example.com/a?b=1"]);
        assert_eq!(found("(see example.com/page) and ida@ieji.de, e.g. v1.2.3"), ["example.com/page"]);
        assert_eq!(found("end.Next and ~/notes.md and x.co"), ["x.co"]);
        assert_eq!(
            found("wiki https://en.wikipedia.org/wiki/Foo_(bar) ok"),
            ["https://en.wikipedia.org/wiki/Foo_(bar)"]
        );
        assert_eq!(link_target("example.com/caf\u{e9}'$"), "https://example.com/caf%C3%A9%27%24");
        assert_eq!(link_target("HTTP://x.org"), "HTTP://x.org");
    }
}
