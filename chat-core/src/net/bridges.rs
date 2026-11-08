// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Tor bridges, for a network that blocks Tor or where using it stands out. With any set, Tor
//! reaches the Tor network only through them.
//!
//! obfs4, webtunnel and meek_lite bridges need lyrebird (obfs4proxy works too, but has no
//! webtunnel), and snowflake ones need snowflake-client. They're looked for in the folder given for
//! them, or else on PATH and in the usual folders, and only programs only root or we can change
//! are run. A bridge line is never shown: only how many there are, and their transports.

use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use std::path::{Path, PathBuf};

const LYREBIRD: &str = "lyrebird";
const OBFS4PROXY: &str = "obfs4proxy";
const SNOWFLAKE: &str = "snowflake-client";
/// Each transport, and the program that carries it.
const TRANSPORTS: [(&str, &str); 6] = [
    ("obfs4", LYREBIRD),
    ("webtunnel", LYREBIRD),
    ("meek_lite", LYREBIRD),
    ("obfs3", LYREBIRD),
    ("scramblesuit", LYREBIRD),
    ("snowflake", SNOWFLAKE),
];
const USUAL: [&str; 7] = [
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
    "/opt/homebrew/bin",
];

/// The bridges Tor is given, and where their transport programs are.
#[derive(Clone, Default)]
pub struct Bridges {
    lines: Vec<String>,
    /// The folder with the transport programs; None: PATH and the usual folders.
    transports: Option<PathBuf>,
}

/// A bridge's transport from its first word: "plain" for one without (it starts with IP:PORT).
fn kind(word: &str) -> Option<&'static str> {
    if word.starts_with('[') || (word.starts_with(|c: char| c.is_ascii_digit()) && word.contains(':')) {
        return Some("plain");
    }
    TRANSPORTS.iter().find(|t| t.0 == word).map(|t| t.0)
}

fn first_word(line: &str) -> &str {
    line.split(' ').next().unwrap_or("")
}

impl Bridges {
    /// Bridge lines as typed, separated by ';' (or new lines, if a paste kept them); a line may
    /// start with "Bridge", as in a torrc. An error says which line, never what's in it.
    pub fn set_lines(&mut self, typed: &str) -> Result<(), String> {
        let mut lines = Vec::new();
        for raw in typed.split([';', '\r', '\n']) {
            let line = raw.trim_matches([' ', '\t']).replace('\t', " ");
            if line.is_empty() {
                continue;
            }
            let n = lines.len() + 1;
            let l = match line.get(..7) {
                Some(p) if p.eq_ignore_ascii_case("Bridge ") => line[7..].trim_start_matches(' '),
                _ => line.as_str(),
            };
            if l.bytes().any(|c| !(b' '..=b'~').contains(&c) || c == b'"' || c == b'\\') {
                return Err(format!("bridge {n} has a character bridge lines never have"));
            }
            let word = first_word(l);
            match kind(word) {
                Some("plain") => {}
                Some(_) if !l.contains(' ') => return Err(format!("bridge {n} has no address after its transport")),
                Some(_) => {}
                // The first word is only shown if it looks like a transport's name, not an address.
                None if word.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_') => {
                    return Err(format!(
                        "bridge {n}: chat doesn't know the transport {word:.20} - it knows obfs4, webtunnel, \
                         meek_lite, obfs3, scramblesuit and snowflake, or IP:PORT starts a plain bridge"
                    ));
                }
                None => return Err(format!("bridge {n} starts with neither a transport nor an IP:PORT address")),
            }
            // Tor's own reading of it, whose errors quote the line: only which one is said.
            if l.parse::<BridgeConfigBuilder>().is_err() {
                return Err(format!(
                    "bridge {n} isn't one Tor can read: check its address, fingerprint and settings"
                ));
            }
            lines.push(l.to_string());
        }
        self.lines = lines;
        Ok(())
    }

    /// The folder with lyrebird and snowflake-client; None looks on PATH and in the usual folders.
    pub fn set_transports(&mut self, dir: Option<PathBuf>) -> Result<(), String> {
        self.transports = match dir {
            Some(d) => Some(std::path::absolute(&d).map_err(|e| format!("{}: {e}", d.display()))?),
            None => None,
        };
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// How many there are and their transports, as "2 (obfs4, plain)", or "none".
    pub fn describe(&self) -> String {
        if self.lines.is_empty() {
            return "none".into();
        }
        let mut kinds: Vec<&str> = Vec::new();
        for k in self.lines.iter().filter_map(|l| kind(first_word(l))) {
            if !kinds.contains(&k) {
                kinds.push(k);
            }
        }
        format!("{} ({})", self.lines.len(), kinds.join(", "))
    }

    /// Where the transport programs are looked for, and which were found.
    pub fn describe_transports(&self) -> String {
        let place = self.transports.as_ref().map_or("on PATH".into(), |d| d.display().to_string());
        let lyre = self
            .find(LYREBIRD)
            .map(|_| LYREBIRD)
            .or_else(|| self.find(OBFS4PROXY).map(|_| OBFS4PROXY));
        let found: Vec<&str> = lyre.into_iter().chain(self.find(SNOWFLAKE).map(|_| SNOWFLAKE)).collect();
        if found.is_empty() {
            format!("{place}: neither lyrebird nor snowflake-client found")
        } else {
            format!("{place}: {} found", found.join(" and "))
        }
    }

    /// The transport programs there are, for the sandbox to let run.
    pub fn programs(&self) -> Vec<PathBuf> {
        [LYREBIRD, OBFS4PROXY, SNOWFLAKE].iter().filter_map(|p| self.find(p)).collect()
    }

    /// A transport program, in the folder given or else on PATH and in the usual folders.
    fn find(&self, name: &str) -> Option<PathBuf> {
        match &self.transports {
            Some(d) => program_ok(&d.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))),
            None => find_program(name),
        }
    }

    /// What a started tor is given over its control port for the bridges: UseBridges, a Bridge for
    /// each line, and a ClientTransportPlugin for each program they need. None without bridges.
    pub(crate) fn setconf(&self) -> Result<Option<String>, String> {
        if self.lines.is_empty() {
            return Ok(None);
        }
        let quoted = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
        let mut conf = String::from("UseBridges=1");
        let mut need: Vec<&str> = Vec::new();
        for l in &self.lines {
            conf.push_str(&format!(" Bridge={}", quoted(l)));
            if let Some(t) = TRANSPORTS.iter().find(|t| t.0 == first_word(l))
                && !need.contains(&t.1)
            {
                need.push(t.1);
            }
        }
        let webtunnel = self.lines.iter().any(|l| first_word(l) == "webtunnel");
        for program in need {
            let (path, old) = match (self.find(program), program == LYREBIRD) {
                (Some(p), _) => (p, false),
                (None, true) => (self.find(OBFS4PROXY).ok_or(
                    "obfs4, webtunnel and meek_lite bridges need lyrebird (or obfs4proxy), which isn't on PATH or in the transports folder",
                )?, true),
                (None, false) => {
                    return Err("snowflake bridges need snowflake-client, which isn't on PATH or in the transports folder".into());
                }
            };
            if old && webtunnel {
                return Err("webtunnel bridges need lyrebird: obfs4proxy, found instead, doesn't have them".into());
            }
            let path = path.to_string_lossy();
            if path.contains(' ') {
                return Err(format!(
                    "tor can't run {program} from a folder with a space in its path - copy it to one without and set transports to that"
                ));
            }
            let names: Vec<&str> = TRANSPORTS
                .iter()
                .filter(|t| t.1 == program && !(old && t.0 == "webtunnel"))
                .map(|t| t.0)
                .collect();
            conf.push_str(&format!(
                " ClientTransportPlugin={}",
                quoted(&format!("{} exec {path}", names.join(",")))
            ));
        }
        Ok(Some(conf))
    }

    /// Gives Tor the bridges, and a transport for each program they need. An error if one is
    /// missing, so Tor never starts without them.
    pub(crate) fn apply(&self, b: &mut TorClientConfigBuilder) -> Result<(), String> {
        let mut need: Vec<&str> = Vec::new();
        for l in &self.lines {
            b.bridges()
                .bridges()
                .push(l.parse().map_err(|_| "a bridge Tor can't read".to_string())?);
            if let Some(t) = TRANSPORTS.iter().find(|t| t.0 == first_word(l))
                && !need.contains(&t.1)
            {
                need.push(t.1);
            }
        }
        let webtunnel = self.lines.iter().any(|l| first_word(l) == "webtunnel");
        for program in need {
            let (path, old) = match (self.find(program), program == LYREBIRD) {
                (Some(p), _) => (p, false),
                (None, true) => (self.find(OBFS4PROXY).ok_or(
                    "obfs4, webtunnel and meek_lite bridges need lyrebird (or obfs4proxy), which isn't on PATH or in the transports folder",
                )?, true),
                (None, false) => {
                    return Err("snowflake bridges need snowflake-client, which isn't on PATH or in the transports folder".into());
                }
            };
            if old && webtunnel {
                return Err("webtunnel bridges need lyrebird: obfs4proxy, found instead, doesn't have them".into());
            }
            let protocols = TRANSPORTS
                .iter()
                .filter(|t| t.1 == program && !(old && t.0 == "webtunnel"))
                .map(|t| t.0.parse().expect("a transport name"))
                .collect();
            let mut t = TransportConfigBuilder::default();
            t.protocols(protocols).path(CfgPath::new_literal(path)).run_on_startup(false);
            b.bridges().transports().push(t);
        }
        Ok(())
    }
}

/// A program by its name, on PATH or in the usual folders.
pub(crate) fn find_program(name: &str) -> Option<PathBuf> {
    let exe = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    let path = std::env::var_os("PATH").unwrap_or_default();
    // A relative entry ("." or "bin") would run whatever is in the current folder.
    std::env::split_paths(&path)
        .filter(|d| d.is_absolute())
        .chain(USUAL.iter().map(PathBuf::from))
        .find_map(|d| program_ok(&d.join(&exe)))
}

/// A program we'll run: a regular, executable file nobody else can replace, in a folder nobody
/// else can write to.
#[cfg(unix)]
pub(crate) fn program_ok(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: neither call can fail or touches memory.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    let only_ours = |m: &std::fs::Metadata| {
        (m.uid() == 0 || m.uid() == uid) && m.mode() & 0o002 == 0 && (m.mode() & 0o020 == 0 || m.gid() == 0 || m.gid() == gid)
    };
    let real = std::fs::canonicalize(path).ok()?;
    let m = std::fs::metadata(&real).ok()?;
    let dir = std::fs::metadata(real.parent()?).ok()?;
    (m.is_file() && m.mode() & 0o111 != 0 && only_ours(&m) && only_ours(&dir)).then_some(real)
}

// shortcut: no owner check off Unix, only that the file is there; add one with the Windows ACLs if
// a Windows build ships.
#[cfg(not(unix))]
pub(crate) fn program_ok(path: &Path) -> Option<PathBuf> {
    path.is_file().then(|| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBFS4: &str = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0";
    const PLAIN: &str = "192.0.2.66:443 7DD62766BF2052432051D7B7E08A22F7E34A4543";

    #[test]
    fn reads_bridge_lines() {
        let mut b = Bridges::default();
        b.set_lines(&format!(" Bridge {OBFS4} ;\n{PLAIN}\t; ;bridge {PLAIN}")).unwrap();
        assert_eq!(b.describe(), "3 (obfs4, plain)");
        assert_eq!(b.lines[0], OBFS4);
        b.set_lines("").unwrap();
        assert_eq!(b.describe(), "none");
    }

    #[test]
    fn says_which_line_is_wrong_but_not_what_is_in_it() {
        let mut b = Bridges::default();
        let e = b.set_lines(&format!("{PLAIN}; frob 1.2.3.4:5")).unwrap_err();
        assert!(e.starts_with("bridge 2: chat doesn't know the transport frob"), "{e}");
        let e = b.set_lines("obfs4").unwrap_err();
        assert_eq!(e, "bridge 1 has no address after its transport");
        let e = b.set_lines("Secret.Host 1.2.3.4").unwrap_err();
        assert_eq!(e, "bridge 1 starts with neither a transport nor an IP:PORT address");
        let e = b.set_lines("obfs4 192.0.2.1:1 SECRETFP").unwrap_err();
        assert!(!e.contains("SECRET"), "{e}");
        assert!(b.set_lines("192.0.2.1:1 \"x\"").is_err());
        // A failed set keeps what was there.
        assert_eq!(b.describe(), "none");
    }
}
