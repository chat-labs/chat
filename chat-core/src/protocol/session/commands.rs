// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! What a UI asks of a session.

use super::peer::{CodeOk, TrustMatch};
use super::*;
use crate::protocol::names::{TIMER_MAX, TIMER_MIN, format_timer};

impl Session {
    pub(super) fn run_command(&mut self, cmd: Command) -> Result<Outcome, CommandError> {
        if self.left {
            return Err(CommandError::Invalid("this session has ended".into()));
        }
        match cmd {
            Command::Send { text } => self.send_text(&text, None),
            Command::Reply { mid, text } => {
                if self.recent_find(&mid).is_none() {
                    return Err(CommandError::NoSuchMessage);
                }
                self.send_text(&text, Some(mid))
            }
            Command::Dm { peer, text } => self.send_direct(peer, &text),
            Command::Verify { peer, same } => self.verify(peer, same),
            Command::Ignore { peer, on } => self.ignore(peer, on),
            Command::SetNick { nick } => {
                self.nick = crate::protocol::text::clean_nick(nick.as_bytes());
                self.skel = crate::protocol::text::nick_skeleton(&self.nick);
                self.note(format!("your nickname is now {}", self.nick));
                let msg = format!("n\t{}", self.nick);
                self.send_to_live(&msg);
                for slot in self.live() {
                    self.peer_changed(slot);
                }
                Ok(Outcome::Done)
            }
            Command::SetColour { colour } => {
                self.colour = colour;
                self.note(format!("your colour is now {colour}"));
                let msg = format!("c\t{}", colour.hex());
                self.send_to_live(&msg);
                Ok(Outcome::Done)
            }
            Command::SetTimer { seconds } => self.set_timer(seconds),
            Command::SetHistory { on } => {
                if self.persist != on {
                    self.persist = on;
                    for slot in self.live() {
                        self.send_k_now(slot);
                    }
                    if self.live_count() > 0 {
                        self.note(if on {
                            "everyone here is told you keep a history of this chat now"
                        } else {
                            "everyone here is told you stopped keeping a history of it"
                        });
                    }
                }
                Ok(Outcome::Done)
            }
            Command::SetVerifyRequired { on } => {
                self.verify_required = on;
                for slot in self.live() {
                    self.peer_changed(slot);
                }
                Ok(Outcome::Done)
            }
            Command::SetNetLog { level } => {
                self.net_log = level;
                Ok(Outcome::Done)
            }
            Command::SetComingBack { on } => {
                self.coming_back = on;
                Ok(Outcome::Done)
            }
            Command::Fetch { num, show, anyway, dir } => self.fetch(num, show, anyway, dir),
            Command::Cancel { num } => self.cancel_file(num),
            Command::Offer { .. } => Err(CommandError::Invalid(
                "a file is read by the runtime, which then offers it with offer_file".into(),
            )),
            Command::SetFileOptions { limit, fast } => {
                self.set_file_options(limit, fast);
                Ok(Outcome::Done)
            }
            Command::Move { answer: None } => Ok(Outcome::MovePlan(self.move_plan())),
            Command::Move { answer: Some(false) } => self.move_no(),
            Command::Move { answer: Some(true) } => Err(CommandError::Invalid(
                "moving opens a new room, which the runtime does: Room::answer_move".into(),
            )),
            Command::NetReport => {
                self.net_report();
                Ok(Outcome::Done)
            }
            Command::Leave => {
                self.leave_now();
                Ok(Outcome::Done)
            }
        }
    }

    fn live_slot(&self, peer: PeerId) -> Result<usize, CommandError> {
        self.find_peer(&peer.0).filter(|&s| self.peer(s).ok).ok_or(CommandError::NoSuchPeer)
    }

    /// The user compared a peer's verify code over another channel.
    fn verify(&mut self, peer: PeerId, same: bool) -> Result<Outcome, CommandError> {
        let slot = self.live_slot(peer)?;
        let name = self.peer_name(slot);
        let trusted_before = self.trusted(self.peer(slot));
        if !same {
            self.peer_mut(slot).code_ok = CodeOk::Different;
            self.warn(format!(
                "{name}: the codes differ - someone with this room's password may be between you. Nothing you send goes to \
                 them now. Leave this room and start a new one, with a new password shared over a channel you trust"
            ));
        } else {
            let p = self.peer_mut(slot);
            let replaced = p.trust == TrustMatch::OtherKey;
            p.code_ok = CodeOk::Same;
            // Its signing key is verified from now on, in every room: the user compared codes
            // with whoever holds it. One that had the nick of another verified key replaces it.
            let signed = p
                .ident
                .as_ref()
                .filter(|i| i.state == SignatureState::Verified)
                .map(|i| (i.kind, i.public));
            let (nick, skel) = (p.nick.clone(), p.skel.clone());
            if let Some((kind, public)) = signed {
                p.trust = TrustMatch::Key;
                let mut t = self.trust.lock().expect("trust lock");
                if replaced {
                    t.forget_nick(&skel);
                }
                t.verify(kind, &public, &nick);
                self.trust_seen = t.version();
            }
            self.note(format!(
                "{name}: verify code confirmed - what you send reaches them{}{}",
                if signed.is_some() {
                    ". Their signing key counts as verified in every room now"
                } else {
                    ". They have no valid signing key, so this lasts for this session only"
                },
                if replaced && signed.is_some() {
                    ". It replaces the key verified for this nick before"
                } else {
                    ""
                }
            ));
        }
        if !trusted_before && self.trusted(self.peer(slot)) {
            self.file_offer_all(slot);
        }
        self.peer_changed(slot);
        self.emit_timer_if_changed();
        Ok(Outcome::Done)
    }

    /// Hides what a peer says, here and (if it signs) wherever its key turns up. Nothing is sent,
    /// so nobody can tell, and what it says still goes on to everyone else.
    fn ignore(&mut self, peer: PeerId, on: bool) -> Result<Outcome, CommandError> {
        let slot = self.live_slot(peer)?;
        let name = self.peer_name(slot);
        let p = self.peer(slot);
        let signed = p
            .ident
            .as_ref()
            .filter(|i| i.state == SignatureState::Verified)
            .map(|i| (i.kind, i.public));
        let (id, nick) = (p.id, p.nick.clone());
        self.set_ignored(&id, on);
        {
            let mut t = self.trust.lock().expect("trust lock");
            if let Some((kind, public)) = signed {
                if on {
                    t.ignore(kind, &public, &nick);
                } else {
                    t.unignore(&public);
                }
            }
            self.trust_seen = t.version();
        }
        if on {
            self.note(format!(
                "{name} is ignored: what they say or send you doesn't show. Nothing tells them, and what they say still goes \
                 on to everyone else{}",
                if signed.is_some() {
                    ". Their signing key is ignored in every room too"
                } else {
                    ". This lasts for this session only"
                }
            ));
        } else {
            self.note(format!("{name} isn't ignored any more - what they say shows from now on"));
        }
        self.peer_changed(slot);
        Ok(Outcome::Done)
    }

    fn set_timer(&mut self, seconds: u32) -> Result<Outcome, CommandError> {
        if seconds != 0 && !(TIMER_MIN..=TIMER_MAX).contains(&seconds) {
            return Err(CommandError::Invalid(
                "a message timer is from a minute to a week, or 0 for none".into(),
            ));
        }
        if seconds == self.timer {
            return Ok(Outcome::Done);
        }
        self.timer = seconds;
        let mut deaf = false;
        for slot in self.live() {
            self.send_k_now(slot);
            deaf |= !self.peer(slot).caps.can_timer;
        }
        if seconds > 0 {
            self.note(format!(
                "messages here go after {} from now: off the screen and out of memory, here and on every chat here that keeps to \
                 it (a modified chat, or a screenshot, can keep anything){}",
                format_timer(seconds),
                if deaf { ". Some here run a chat too old to keep to it" } else { "" }
            ));
        } else {
            match self.timer() {
                (t, Some(who)) if t > 0 => self.note(format!("you stopped asking for messages here to go - {who} still asks")),
                _ => self.note("you stopped asking for messages here to go"),
            }
        }
        self.emit_timer_if_changed();
        Ok(Outcome::Done)
    }
}
