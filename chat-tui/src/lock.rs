// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The lock screen and the panic key. Locked, chat draws nothing but a box for the open save's
//! passphrase (or, with no save open, a PIN kept only as an Argon2id key in memory); rooms carry on
//! behind it. The panic key quits at once, from anywhere, saving nothing.

use crate::app::{App, Input, Modal, Msg, PromptKind};
use crate::saved::SaveMsg;
use chat_core::net::saves::{Save, SaveError};
use chat_core::protocol::crypto::passlock::PassLock;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct Lock {
    pub input: Input,
    /// A try is being checked (Argon2id takes a second or two).
    pub busy: bool,
    pub why: Option<String>,
}

/// Whether `k` is the key a lockkey or panickey row names ("ctrl+l", "f9", "off"...).
pub fn is_key(k: &KeyEvent, name: &str) -> bool {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    match name {
        "ctrl+\\" => ctrl && matches!(k.code, KeyCode::Char('\\' | '4')),
        "f9" => k.code == KeyCode::F(9),
        "f12" => k.code == KeyCode::F(12),
        n => n
            .strip_prefix("ctrl+")
            .and_then(|c| c.chars().next())
            .is_some_and(|c| ctrl && k.code == KeyCode::Char(c)),
    }
}

impl App {
    /// Locks the screen: with a save open, its passphrase unlocks it; without, a PIN, asked for
    /// first if there's none yet.
    pub fn lock_now(&mut self) {
        if self.save.is_none() && self.pin.is_none() {
            let hint = "No save is open, so the lock needs a PIN: chat keeps it hashed in memory until it exits.".into();
            self.modal = Some(Modal::Prompt {
                kind: PromptKind::SetPin,
                title: "LOCK SCREEN \u{b7} PIN".into(),
                hint,
                input: Input::default(),
            });
            return;
        }
        // What's open stays as it was under the lock.
        self.locked = Some(Lock::default());
    }

    pub fn set_pin(&mut self, pin: &str) {
        if pin.is_empty() {
            return self.fail("no PIN, so the screen doesn't lock");
        }
        let (pin, tx) = (Zeroizing::new(pin.to_string()), self.tx.clone());
        self.say("setting the PIN...");
        tokio::spawn(async move {
            let r = tokio::task::spawn_blocking(move || PassLock::new(pin.as_bytes()).ok())
                .await
                .ok()
                .flatten();
            let _ = tx.send(Msg::Save(SaveMsg::PinSet(r)));
        });
    }

    pub fn pin_set(&mut self, lock: Option<PassLock>) {
        match lock {
            Some(l) => {
                self.pin = Some(l);
                self.lock_now();
            }
            None => self.fail("there isn't enough free memory to keep a PIN (it needs 512 MiB for a moment)"),
        }
    }

    /// A key while locked: only the passphrase box takes it.
    pub fn lock_key(&mut self, k: KeyEvent) {
        let Some(lock) = self.locked.as_mut() else { return };
        if lock.busy {
            return;
        }
        if k.code != KeyCode::Enter {
            lock.input.edit(&k);
            return;
        }
        let text = Zeroizing::new(lock.input.text());
        lock.input = Input::default();
        if text.is_empty() {
            return;
        }
        lock.busy = true;
        lock.why = None;
        let tx = self.tx.clone();
        match (self.save.take(), self.pin.clone()) {
            (Some(save), _) => {
                tokio::spawn(async move {
                    let r = tokio::task::spawn_blocking(move || {
                        let r = save.lock_try(&text);
                        (Box::new(save), r)
                    })
                    .await;
                    let _ = tx.send(Msg::Save(SaveMsg::LockTried(r.ok())));
                });
            }
            (None, Some(pin)) => {
                tokio::spawn(async move {
                    let ok =
                        tokio::task::spawn_blocking(move || PassLock::like(text.as_bytes(), &pin).is_ok_and(|l| l.same_passphrase(&pin)))
                            .await
                            .unwrap_or(false);
                    let _ = tx.send(Msg::Save(SaveMsg::PinTried(ok)));
                });
            }
            (None, None) => self.locked = None,
        }
    }

    pub fn lock_tried(&mut self, r: Option<(Box<Save>, Result<(), SaveError>)>) {
        let Some((save, r)) = r else { return self.panic() };
        match r {
            Ok(()) => {
                self.save = Some(*save);
                self.locked = None;
            }
            // The shadow passphrase panics, leaving the decoy in the save's place; one wrong
            // passphrase too many has deleted the save.
            Err(SaveError::Decoy | SaveError::Destroyed(_)) => self.panic(),
            Err(e) => {
                self.save = Some(*save);
                if let Some(l) = self.locked.as_mut() {
                    l.busy = false;
                    let left = self.save.as_ref().and_then(|s| s.tries_left());
                    l.why = Some(match left {
                        Some(n) => format!("{e} ({n} more and the save is deleted)"),
                        None => e.to_string(),
                    });
                }
            }
        }
    }

    pub fn pin_tried(&mut self, ok: bool) {
        if ok {
            self.locked = None;
        } else if let Some(l) = self.locked.as_mut() {
            l.busy = false;
            l.why = Some("that's not the PIN".into());
        }
    }

    /// Quits at once, saving nothing; with /set panicwipe on, the open save is deleted too.
    pub fn panic(&mut self) {
        if self.settings.on("panicwipe")
            && let (Some(saves), Some(name)) = (&self.saves, self.save.as_ref().map(|s| s.name().to_string()))
        {
            let _ = saves.remove(&name);
        }
        self.save = None;
        self.pin = None;
        self.locked = None;
        self.panicked = true;
        self.quit = true;
    }
}
