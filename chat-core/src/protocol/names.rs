// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Names and other text the protocol and the UIs share: colours, room ids and passwords,
//! invites, message timers, and verify codes in words.

use crate::protocol::crypto::{invite_check, sodium};
use crate::protocol::hex;
use serde::{Deserialize, Serialize};

/// A colour, written "#rrggbb" in the API and "rrggbb" on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Colour(pub [u8; 3]);

impl Colour {
    pub fn hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// "#rrggbb" or "rrggbb" in either case, or a palette colour's name.
    pub fn parse(text: &str) -> Option<Colour> {
        let h = text.strip_prefix('#').unwrap_or(text);
        if h.len() == 6 && h.is_ascii() {
            let lower = h.to_ascii_lowercase();
            if let Some(rgb) = hex::decode_array::<3>(&lower) {
                return Some(Colour(rgb));
            }
        }
        PALETTE.iter().find(|(name, _)| name.eq_ignore_ascii_case(text)).map(|(_, c)| *c)
    }

    pub fn random() -> Colour {
        PALETTE[sodium::random_below(PALETTE.len() as u32) as usize].1
    }
}

impl std::fmt::Display for Colour {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.hex())
    }
}

impl Serialize for Colour {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Colour {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Colour::parse(&s).ok_or_else(|| serde::de::Error::custom("a colour: #rrggbb or a name"))
    }
}

pub const PALETTE: &[(&str, Colour)] = &[
    ("red", Colour([0xE5, 0x48, 0x4D])),
    ("orange", Colour([0xF7, 0x6B, 0x15])),
    ("yellow", Colour([0xF5, 0xD9, 0x0A])),
    ("green", Colour([0x30, 0xA4, 0x6C])),
    ("teal", Colour([0x12, 0xA5, 0x94])),
    ("cyan", Colour([0x00, 0xA2, 0xC7])),
    ("blue", Colour([0x00, 0x90, 0xFF])),
    ("indigo", Colour([0x3E, 0x63, 0xDD])),
    ("purple", Colour([0x8E, 0x4E, 0xC6])),
    ("pink", Colour([0xD6, 0x40, 0x9F])),
    ("brown", Colour([0xAD, 0x7F, 0x58])),
    ("gray", Colour([0x8B, 0x8D, 0x98])),
];

const ROOM_ID_ALPHABET: &[u8; 30] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const ROOM_ID_LEN: usize = 10;
pub const MAX_ROOM_ID: usize = 64;
pub const MAX_PASSWORD: usize = 255;

/// A new room's id: ten characters that can't be misread for one another.
pub fn random_room_id() -> String {
    (0..ROOM_ID_LEN)
        .map(|_| ROOM_ID_ALPHABET[sodium::random_below(30) as usize] as char)
        .collect()
}

/// The room only two signing keys can work out, for one day (UTC): its id and password. Both
/// open it with :call, each with their own key and the other's. None for a key that isn't a
/// usable point, or our own.
pub fn contact_room(mine: &crate::protocol::crypto::identity::IdentityKeypair, theirs: &[u8; 32], day: u64) -> Option<(String, String)> {
    let k = mine.contact_secret(theirs, day)?;
    let n = u64::from_be_bytes(k[..8].try_into().expect("8 bytes"));
    Some((room_id_from(n), crate::protocol::hex::encode(&k[32..])))
}

/// The day a call's room is for: days since 1970, UTC.
pub fn contact_day(unix: u64) -> u64 {
    unix / 86_400
}

/// A room id worked out rather than made up (a call's).
pub fn room_id_from(mut n: u64) -> String {
    (0..ROOM_ID_LEN)
        .map(|_| {
            let c = ROOM_ID_ALPHABET[(n % 30) as usize] as char;
            n /= 30;
            c
        })
        .collect()
}

/// A new room's password: eight random bytes as words.
/// Names as a sentence: "bob", "bob and carol", "bob, carol and dave", naming six at most and
/// counting the rest.
pub fn list(names: &[String]) -> String {
    const NAMED: usize = 6;
    let n = names.len();
    let shown = if n <= NAMED { n } else { NAMED - 1 };
    let mut out = String::new();
    for (i, name) in names[..shown].iter().enumerate() {
        if i > 0 {
            out += if i == n - 1 { " and " } else { ", " };
        }
        out += name;
    }
    if shown < n {
        out += &format!(" and {} others", n - shown);
    }
    out
}

pub fn random_password() -> String {
    bytewords_plain(&sodium::random_array::<8>())
}

const NICK_ADJ: &[&str] = &[
    "swift", "quiet", "brave", "lucky", "quick", "calm", "bright", "bold", "gentle", "sharp", "steady", "sunny", "clever", "mellow", "sly",
    "eager", "plucky", "spry", "vivid", "wry", "keen", "amber", "cosmic", "rustic",
];
const NICK_NOUN: &[&str] = &[
    "otter", "falcon", "maple", "comet", "heron", "lynx", "willow", "badger", "raven", "cedar", "ember", "sparrow", "harbor", "meadow",
    "gecko", "juniper", "pixel", "quartz", "tundra", "wren", "yonder", "zephyr", "canyon", "delta",
];

pub fn random_nick() -> String {
    format!(
        "{}-{}{}",
        NICK_ADJ[sodium::random_below(NICK_ADJ.len() as u32) as usize],
        NICK_NOUN[sodium::random_below(NICK_NOUN.len() as u32) as usize],
        sodium::random_below(100)
    )
}

// ---- verify codes in words (Bytewords, BCR-2020-012, (C) 2019 Blockchain Commons, BSD-2-Clause Plus Patent) ----

const WORDS: &[u8; 1024] = b"ableacidalsoapexaquaarchatomaunt\
awayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcash\
catschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdeli\
dicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepicevenexam\
exiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuel\
fundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhang\
hardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyinto\
irisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokept\
keyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlist\
logoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmiss\
monknailnavyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowls\
paidpartpeckplaypluspoempoolposepuffpumapurrquadquizracerampreal\
redorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslot\
soapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoys\
triptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoid\
vowswallwandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyell\
yogayurtzapszerozestzinczonezoom";

fn word(b: u8) -> &'static str {
    let i = usize::from(b) * 4;
    std::str::from_utf8(&WORDS[i..i + 4]).expect("ASCII")
}

/// Bytes as words, in groups of four ("able acid also apex · aqua ..."), as verify codes show.
pub fn bytewords(data: &[u8]) -> String {
    let mut s = String::new();
    for (i, &b) in data.iter().enumerate() {
        if i > 0 {
            s.push_str(if i % 4 == 0 { " \u{b7} " } else { " " });
        }
        s.push_str(word(b));
    }
    s
}

/// Bytes as words separated by spaces, as a new room's password.
pub fn bytewords_plain(data: &[u8]) -> String {
    data.iter().map(|&b| word(b)).collect::<Vec<_>>().join(" ")
}

// ---- invites ----

const INVITE_PREFIX: &str = "chat:";

/// A room's id and password as one string to pass on: "chat:ID:PASSWORD:CHECK". The password
/// can hold ':', since the id ends at the first and the check starts after the last.
pub fn invite(id: &str, password: &str) -> Option<String> {
    if id.is_empty() || id.contains(':') || id.len() > MAX_ROOM_ID || password.len() > MAX_PASSWORD {
        return None;
    }
    Some(format!(
        "{INVITE_PREFIX}{id}:{password}:{}",
        hex::encode(&invite_check(id, password))
    ))
}

pub fn is_invite(text: &str) -> bool {
    let t = text.trim_start_matches(' ');
    t.len() >= INVITE_PREFIX.len() && t.as_bytes()[..INVITE_PREFIX.len()].eq_ignore_ascii_case(INVITE_PREFIX.as_bytes())
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    #[error("that isn't an invite")]
    NotAnInvite,
    #[error("that invite is mistyped or cut off: its check doesn't match")]
    BadCheck,
}

/// An invite's id and password. Spaces around it and the case of "chat:" don't count.
pub fn parse_invite(text: &str) -> Result<(String, String), InviteError> {
    if !is_invite(text) {
        return Err(InviteError::NotAnInvite);
    }
    let body = text.trim_matches(' ');
    let body = &body[INVITE_PREFIX.len()..];
    let first = body.find(':').ok_or(InviteError::BadCheck)?;
    let last = body.rfind(':').ok_or(InviteError::BadCheck)?;
    if last <= first {
        return Err(InviteError::BadCheck);
    }
    let (id, password, check) = (&body[..first], &body[first + 1..last], &body[last + 1..]);
    if id.is_empty() || id.len() > MAX_ROOM_ID || password.len() > MAX_PASSWORD || check.len() != 8 {
        return Err(InviteError::BadCheck);
    }
    let given = hex::decode_array::<4>(&check.to_ascii_lowercase()).ok_or(InviteError::BadCheck)?;
    if given != invite_check(id, password) {
        return Err(InviteError::BadCheck);
    }
    Ok((id.to_string(), password.to_string()))
}

// ---- message timers ----

pub const TIMER_MIN: u32 = 60;
pub const TIMER_MAX: u32 = 7 * 24 * 3600;

/// "10m", "2h", "1d", "90s", or "off".
pub fn format_timer(seconds: u32) -> String {
    match seconds {
        0 => "off".into(),
        s if s % 86400 == 0 => format!("{}d", s / 86400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// The other way: "off" or "0" is 0; otherwise a number and a unit, a minute to a week.
pub fn parse_timer(s: &str) -> Option<u32> {
    if s == "off" || s == "0" {
        return Some(0);
    }
    let unit = match s.chars().last()? {
        's' => 1u64,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return None,
    };
    let digits = &s[..s.len() - 1];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    let total = n.checked_mul(unit)?;
    (u64::from(TIMER_MIN)..=u64::from(TIMER_MAX))
        .contains(&total)
        .then_some(total as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invites_round_trip() {
        let inv = invite("NH7Q5KS2ZX", "a:b c").unwrap();
        assert_eq!(
            parse_invite(&format!("  {}  ", inv.replacen("chat:", "CHAT:", 1))).unwrap(),
            ("NH7Q5KS2ZX".into(), "a:b c".into())
        );
        let bad = inv.replace("a:b", "a:c");
        assert_eq!(parse_invite(&bad), Err(InviteError::BadCheck));
        assert_eq!(parse_invite("hello"), Err(InviteError::NotAnInvite));
        assert!(invite("a:b", "x").is_none());
    }

    #[test]
    fn timers() {
        assert_eq!(format_timer(600), "10m");
        assert_eq!(format_timer(7200), "2h");
        assert_eq!(format_timer(86400), "1d");
        assert_eq!(format_timer(90), "90s");
        assert_eq!(parse_timer("10m"), Some(600));
        assert_eq!(parse_timer("59s"), None);
        assert_eq!(parse_timer("8d"), None);
        assert_eq!(parse_timer("off"), Some(0));
    }

    #[test]
    fn words_and_colours() {
        assert_eq!(bytewords(&[0, 1, 2, 3, 255]), "able acid also apex \u{b7} zoom");
        assert_eq!(bytewords_plain(&[0, 255]), "able zoom");
        assert_eq!(Colour::parse("Blue"), Some(Colour([0, 0x90, 0xff])));
        assert_eq!(Colour::parse("#00FF00"), Some(Colour([0, 255, 0])));
        assert_eq!(room_id_from(0), "2222222222");
    }
}
