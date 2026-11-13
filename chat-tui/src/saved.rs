// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Saves in the terminal: opening one as chat starts, /install, /save, /uninstall, /keep and /set,
//! and autosave. chat-core does the sealing; this asks for passphrases and applies what's saved.

use crate::app::Input;
use crate::app::{App, Modal, Msg, PromptKind};
use crate::identity::{Ident, Origin};
use chat_core::net::history::History;
use chat_core::net::saves::{KeyOrigin, PendingCode, Save, SaveError, SavedKey, Unlocked};
use chat_core::net::settings::{KeptRoom, ROOM_LABEL_MAX, ROOMS_MAX, Settings};
use chat_core::{Colour, Command, IdentityKind, Level, Message, PeerInfo};
use zeroize::Zeroizing;

/// What a save's work off the UI's thread comes back with.
pub enum SaveMsg {
    Opened(String, Result<Unlocked, SaveError>),
    /// None if checking it failed outright.
    Code(Option<Result<Save, (Box<PendingCode>, SaveError)>>),
    Created(Result<Save, SaveError>),
    /// A save's security key gave its secret, or didn't.
    KeySecret(String, Result<Zeroizing<[u8; 32]>, SaveError>),
    /// A security key registered for the open save, with the save back.
    KeyRegistered(Option<(Box<Save>, Result<(), SaveError>)>),
    /// The lock screen's passphrase checked, with the save back (None if checking failed outright).
    LockTried(Option<(Box<Save>, Result<(), SaveError>)>),
    PinSet(Option<chat_core::protocol::crypto::passlock::PassLock>),
    PinTried(bool),
}

/// Where /install is.
pub enum Installing {
    Name,
    Pass(String),
    Again(String, Zeroizing<String>),
}

impl App {
    fn prompt(&mut self, kind: PromptKind, title: &str, hint: String) {
        self.modal = Some(Modal::Prompt {
            kind,
            title: title.into(),
            hint,
            input: Input::default(),
        });
    }

    /// As chat starts: the save --save names, the only one there is, or one picked from a list.
    /// The passphrase comes from CHAT_INSTALL_PASSWORD if it's set; Esc starts without the save.
    pub fn open_at_start(&mut self, name: Option<String>) {
        let Some(saves) = self.saves.clone() else {
            return self.begin_start(false);
        };
        let list = saves.list();
        let name = match name {
            Some(n) if list.iter().any(|s| s.name == n) => n,
            Some(n) => {
                self.fail(format!(
                    "there's no save called {n} yet: chat starts from its defaults, and /install makes it"
                ));
                return self.begin_start(false);
            }
            None if list.len() == 1 => list[0].name.clone(),
            None if list.is_empty() => return self.begin_start(false),
            None => {
                let names = list.into_iter().map(|s| s.name).collect();
                return self.modal = Some(Modal::PickSave { names, sel: 0 });
            }
        };
        if let Ok(pass) = std::env::var("CHAT_INSTALL_PASSWORD") {
            return self.unlock(name, Zeroizing::new(pass));
        }
        self.ask_passphrase(name);
    }

    fn ask_passphrase(&mut self, name: String) {
        if self.overwriting {
            let hint = format!(
                "Its passphrase opens {name}, and what's in use now is saved over it under the same one. Forgot it? Esc goes \
                 back, and /uninstall {name} deletes it."
            );
            return self.prompt(PromptKind::Unlock(name), " INSTALL \u{b7} PASSPHRASE ", hint);
        }
        let hint = format!(
            "The passphrase for {} ({}). Esc starts with chat's defaults instead, and saves nothing.",
            name,
            self.saves.as_ref().map(|s| s.shown_dir(&name)).unwrap_or_default()
        );
        self.prompt(PromptKind::Unlock(name), "UNLOCK", hint);
    }

    /// Enter asks for the passphrase of the save picked; Esc opens none.
    pub fn pick_save_key(&mut self, names: Vec<String>, sel: usize, k: crossterm::event::KeyEvent) {
        use crate::settings_page::{ListKey, list_key};
        let sel = match list_key(&k) {
            ListKey::Choose | ListKey::Right => return self.ask_passphrase(names[sel].clone()),
            ListKey::Left | ListKey::Back | ListKey::Close => return self.unlock_skipped(),
            ListKey::Up => sel.saturating_sub(1),
            ListKey::Down => (sel + 1).min(names.len() - 1),
            ListKey::First => 0,
            ListKey::Last => names.len() - 1,
            _ => sel,
        };
        self.modal = Some(Modal::PickSave { names, sel });
    }

    /// Esc while a save is being opened: as chat starts, it goes on with its defaults; later, from
    /// /install, nothing opens.
    pub fn unlock_skipped(&mut self) {
        self.pending_code = None;
        if self.start.is_none() {
            self.pending_factor = None;
            self.overwriting = false;
            return self.say("nothing was opened");
        }
        self.say("started without the save: chat's defaults, and nothing you change is saved");
        self.begin_start(false);
    }

    /// Argon2id takes seconds and 512 MiB, off the UI's thread.
    pub fn unlock(&mut self, name: String, pass: Zeroizing<String>) {
        let Some(saves) = self.saves.clone() else { return };
        let tx = self.tx.clone();
        self.pending_pass = Some((name.clone(), pass.clone()));
        let key = self.pending_key.clone();
        self.say(format!("opening {name}..."));
        tokio::spawn(async move {
            let n = name.clone();
            let r = tokio::task::spawn_blocking(move || saves.unlock(&n, &pass, true, key.as_deref()))
                .await
                .unwrap_or(Err(SaveError::Failed("couldn't open it".into())));
            let _ = tx.send(Msg::Save(SaveMsg::Opened(name, r)));
        });
    }

    pub fn check_code(&mut self, code: String) {
        let Some(pending) = self.pending_code.take() else { return };
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let r = tokio::task::spawn_blocking(move || pending.check(&code)).await.ok();
            let _ = tx.send(Msg::Save(SaveMsg::Code(r)));
        });
    }

    pub fn on_save(&mut self, m: SaveMsg) {
        match m {
            SaveMsg::Opened(_, Ok(Unlocked::Open(save))) => self.use_save(save),
            SaveMsg::Opened(name, Ok(Unlocked::Code(p))) => {
                self.pending_code = Some(Box::new(p));
                let hint = format!("{name} asks for your authenticator app's code too. Esc starts without the save.");
                self.prompt(PromptKind::Code, "UNLOCK \u{b7} CODE", hint);
            }
            SaveMsg::Opened(name, Err(SaveError::Key)) if self.pending_key.is_none() => self.key_open(name, None),
            SaveMsg::KeySecret(name, r) => {
                self.key_wait = None;
                match r {
                    Ok(secret) => {
                        self.pending_key = Some(secret);
                        if let Some((n, pass)) = self.pending_pass.take() {
                            self.unlock(n, pass);
                        }
                    }
                    Err(SaveError::KeyPin(why)) => {
                        let hint = format!("{why}. Esc starts without the save.");
                        self.prompt(PromptKind::KeyPin(Some(name)), "SECURITY KEY \u{b7} PIN", hint);
                    }
                    Err(e) => {
                        self.pending_pass = None;
                        self.fail(format!("the save didn't open: {e} - chat starts from its defaults"));
                        self.begin_start(false);
                    }
                }
            }
            SaveMsg::KeyRegistered(r) => {
                self.key_wait = None;
                match r {
                    Some((save, Ok(()))) => {
                        self.save = Some(*save);
                        self.say("the save needs your security key from now on: a touch each time, and its PIN where it asks");
                    }
                    Some((save, Err(SaveError::KeyPin(why)))) => {
                        self.save = Some(*save);
                        self.prompt(
                            PromptKind::KeyPin(None),
                            "SECURITY KEY \u{b7} PIN",
                            format!("{why}. Esc registers none."),
                        );
                    }
                    Some((save, Err(e))) => {
                        self.save = Some(*save);
                        self.fail(format!("no security key was registered: {e}"));
                    }
                    None => self.fail("registering the security key failed"),
                }
            }
            SaveMsg::Opened(name, Err(SaveError::Wrong)) => {
                self.fail("that's not the passphrase");
                self.ask_passphrase(name);
            }
            SaveMsg::Opened(_, Err(e)) => {
                self.fail(format!("the save didn't open: {e} - chat starts from its defaults"));
                self.begin_start(false);
            }
            SaveMsg::Code(Some(Ok(save))) => self.use_save(save),
            SaveMsg::Code(None) => {
                self.fail("the code couldn't be checked - chat starts from its defaults");
                self.begin_start(false);
            }
            SaveMsg::Code(Some(Err((p, e)))) => {
                self.pending_code = Some(p);
                self.fail(format!("{e}"));
                self.prompt(
                    PromptKind::Code,
                    "UNLOCK \u{b7} CODE",
                    "Try the code again. Esc starts without the save.".into(),
                );
            }
            SaveMsg::Created(Ok(save)) => {
                let name = save.name().to_string();
                self.save = Some(save);
                match self.save_all() {
                    Ok(()) => self.say(format!(
                        "saved in {}: your settings, signing key and verified keys - /set autosave on keeps them saved as they change",
                        self.saves.as_ref().map(|s| s.shown_dir(&name)).unwrap_or_default()
                    )),
                    Err(e) => self.fail(e),
                }
                self.factor_after_install();
            }
            SaveMsg::Created(Err(e)) => {
                self.pending_factor = None;
                self.fail(format!("nothing was saved: {e}"));
            }
            SaveMsg::LockTried(r) => self.lock_tried(r),
            SaveMsg::PinSet(l) => self.pin_set(l),
            SaveMsg::PinTried(ok) => self.pin_tried(ok),
        }
    }

    /// What's saved, in use: its settings (the command line's options still win for this run), its
    /// signing key, verified and ignored keys, kept rooms, and the sessions to reopen.
    /// The save's security key asked for its secret, off the UI's thread: plugged in, touched, and its
    /// PIN where it needs one.
    pub fn key_open(&mut self, name: String, pin: Option<Zeroizing<String>>) {
        let Some(saves) = self.saves.clone() else { return };
        let wait = std::sync::Arc::new(chat_core::net::seckey::Wait::default());
        self.key_wait = Some(wait.clone());
        self.key_save = Some(name.clone());
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let n = name.clone();
            let r = tokio::task::spawn_blocking(move || saves.key_secret(&n, pin.as_deref().map(|p| p.as_str()), &wait))
                .await
                .unwrap_or(Err(SaveError::Failed("the security key couldn't be asked".into())));
            let _ = tx.send(Msg::Save(SaveMsg::KeySecret(name, r)));
        });
    }

    /// Registers the security key plugged in for the open save, off the UI's thread.
    pub fn register_key(&mut self, pin: Option<Zeroizing<String>>) {
        let Some(mut save) = self.save.take() else {
            return self.fail("no save is open - /install makes one");
        };
        let wait = std::sync::Arc::new(chat_core::net::seckey::Wait::default());
        self.key_wait = Some(wait.clone());
        self.key_save = None;
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let r = tokio::task::spawn_blocking(move || {
                let r = save.register_key(pin.as_deref().map(|p| p.as_str()), &wait);
                (Box::new(save), r)
            })
            .await
            .ok();
            let _ = tx.send(Msg::Save(SaveMsg::KeyRegistered(r)));
        });
    }

    fn use_save(&mut self, mut save: Save) {
        self.pending_pass = None;
        self.pending_key = None;
        if std::mem::take(&mut self.overwriting) {
            return self.overwrite_into(save);
        }
        let (relocked, decoy_lost) = save.news();
        // A save with settings starts chat at once; one without starts on the settings page.
        let (mut settings, notes, had_settings) = match save.settings() {
            Ok(t) if t.is_empty() => (Settings::default(), Vec::new(), false),
            Ok(t) => {
                let (s, n) = Settings::from_toml(&t);
                (s, n, true)
            }
            Err(e) => (
                Settings::default(),
                vec![format!("its settings can't be read ({e}) - chat's defaults are used")],
                true,
            ),
        };
        for (name, value) in &self.overrides {
            let _ = settings.set(name, value);
        }
        for n in notes {
            self.fail(format!("{}: {n}", save.name()));
        }
        // Tor starts from the guards and directory the save kept, unless --tor-dir gave it a folder.
        if settings.on("torguards")
            && self.tor_dir.is_none()
            && let Ok(Some(state)) = save.tor_cache()
        {
            self.client = std::mem::take(&mut self.client).with_tor_state(&state);
        }
        match save.key() {
            Ok(Some(b)) => match SavedKey::unpack(&b) {
                Some(k) => self.use_saved_key(k),
                None => self.fail("your saved signing key can't be read - /identity picks one"),
            },
            Ok(None) => {}
            Err(e) => self.fail(format!("your saved signing key can't be read: {e}")),
        }
        if let Ok(mut t) = self.client.trust().lock() {
            if let Ok(text) = save.verified()
                && t.load_verified(&text) > 0
            {
                self.status = Some(("some saved verified keys couldn't be read".into(), true, std::time::Instant::now()));
            }
            let mut ignored = t.ignored().to_vec();
            ignored.extend(
                settings
                    .ignored
                    .iter()
                    .filter(|e| !ignored.iter().any(|i| i.public == e.public))
                    .cloned()
                    .collect::<Vec<_>>(),
            );
            t.set_ignored(ignored);
        }
        if relocked == Some(false) {
            self.fail("the save was being changed when chat last stopped, and it couldn't be finished");
        }
        if decoy_lost {
            self.fail("its shadow passphrase couldn't be kept - set it again with /set shadow");
        }
        let name = save.name().to_string();
        self.save = Some(save);
        self.settings = settings;
        self.apply_settings();
        self.say(format!("opened {name}"));
        self.begin_start(had_settings);
        self.factor_after_install();
    }

    fn use_saved_key(&mut self, k: SavedKey) {
        let origin = match k.origin {
            KeyOrigin::Derived => Origin::Password(None),
            KeyOrigin::DerivedNick => Origin::Password(k.nick.clone()),
            KeyOrigin::File => Origin::File(k.path.clone().unwrap_or_default()),
            KeyOrigin::Pasted => Origin::Pasted,
            KeyOrigin::Made => Origin::Made,
        };
        let ident = match (k.key, &k.path) {
            (Some(kp), _) => Ident {
                kind: k.kind,
                kp,
                origin,
                created: k.pgp_created,
            },
            (None, Some(path)) => match Ident::from_file(path) {
                Ok(i) if i.kp.public == k.public => i,
                Ok(i) => {
                    self.fail(format!(
                        "{path} holds a different key from the one /install saved - chat signs with it"
                    ));
                    i
                }
                Err(_) => {
                    return self.fail(format!(
                        "your saved signing key's file {path} can't be read, or no longer holds the key - /identity picks one"
                    ));
                }
            },
            (None, None) => return,
        };
        self.base.identity = Some((ident.kind, ident.kp.clone()));
        self.ident = Some(ident);
    }

    /// The rows applied: routing and files for rooms opened from now on, the rest where they act.
    pub fn apply_settings(&mut self) {
        let s = &self.settings;
        let peers = std::mem::take(&mut self.base.route.peers);
        self.base.route = s.route();
        self.base.route.peers = peers;
        self.base.verify_required = s.get("verify") == "required";
        self.base.net_log = Some(s.net_log());
        self.base.files.fast = s.on("fastfiles");
        self.base.files.noise = s.on("noise");
        self.base.files.limit = s.file_limit();
        self.base.history = s.on("history") && self.save.is_some();
        if !s.get("nick").is_empty() {
            self.nick = s.get("nick").to_string();
        }
        if let Some(c) = Colour::parse(s.get("colour")) {
            self.colour = Some(c);
            self.base.colour = Some(c);
        }
        self.client.set_tor_use(s.tor_use(&self.tor_password));
        chat_core::net::update::helper_enable(s.on("updater"));
        let (bridges, transports) = (s.get("bridges").to_string(), s.get("transports").to_string());
        let client = self.client.clone();
        tokio::spawn(async move {
            let _ = client.set_transports((!transports.is_empty()).then(|| transports.into())).await;
            let _ = client.set_bridges(&bridges).await;
        });
    }

    /// A row changed by its own command (/nick, /route...): kept, and saved with autosave on.
    pub fn setting_changed(&mut self, name: &str, value: &str) {
        if self.settings.set(name, value).is_ok() {
            self.autosave();
        }
    }

    /// With autosave on, the settings go to the open save straight away; otherwise they wait for
    /// /save, and the reply says so.
    pub(crate) fn autosave(&mut self) {
        if self.save.is_none() {
            return;
        }
        if !self.settings.on("autosave") {
            if let Some((text, bad, at)) = self.status.take() {
                self.status = Some((format!("{text} \u{b7} not saved (autosave is off)"), bad, at));
            }
            return;
        }
        if let Err(e) = self.write_settings() {
            self.fail(e);
        }
    }

    pub(crate) fn write_settings(&mut self) -> Result<(), String> {
        let save = self.save.as_ref().ok_or("no save is open - /install makes one")?;
        if let Ok(t) = self.client.trust().lock() {
            self.settings.ignored = t.ignored().to_vec();
        }
        save.set_settings(&self.settings.to_toml())
            .map_err(|e| format!("couldn't save the settings: {e}"))
    }

    /// /save: the settings, the signing key and the verified keys, to the open save.
    fn save_all(&mut self) -> Result<(), String> {
        self.write_settings()?;
        let save = self.save.as_ref().ok_or("no save is open")?;
        if let Some(i) = &self.ident {
            let (origin, path, nick) = match &i.origin {
                Origin::Made => (KeyOrigin::Made, None, None),
                Origin::Password(None) => (KeyOrigin::Derived, None, None),
                Origin::Password(Some(n)) => (KeyOrigin::DerivedNick, None, Some(n.clone())),
                Origin::File(p) => (KeyOrigin::File, Some(p.clone()), None),
                Origin::Pasted => (KeyOrigin::Pasted, None, None),
            };
            // A key from a file is saved as its path, and read again each start.
            let key = path.is_none().then(|| i.kp.clone());
            let k = SavedKey {
                kind: i.kind,
                origin,
                pgp_created: i.created,
                public: i.kp.public,
                key,
                path,
                nick,
            };
            save.set_key(&k.pack()).map_err(|e| format!("couldn't save the signing key: {e}"))?;
        }
        let verified = self.client.trust().lock().map(|t| t.verified_text()).unwrap_or_default();
        save.set_verified(&verified)
            .map_err(|e| format!("couldn't save the verified keys: {e}"))
    }

    /// `/install [NAME]`: a new save, with its own passphrase, typed twice.
    pub fn install_command(&mut self, arg: &str) -> Result<(), String> {
        let Some(saves) = self.saves.clone() else {
            return Err("there's nowhere to install to - no home folder".into());
        };
        let name = arg.trim();
        if !name.is_empty() && !chat_core::net::saves::name_ok(name) && name != "default" {
            return Err("a save's name is 1 to 32 letters, digits, - and _".into());
        }
        let list = saves.list();
        let exists = |n: &str| list.iter().any(|s| s.name == n);
        if let Some(save) = &self.save {
            let current = save.name().to_string();
            // The open save is saved to after the usual question.
            if name.is_empty() || name == current {
                self.ask(crate::app::Ask::Install(current));
            } else if exists(name) {
                // Another one that's there needs its passphrase to be saved over.
                self.ask(crate::app::Ask::Overwrite(name.to_string()));
            } else {
                self.ask(crate::app::Ask::Install(name.to_string()));
            }
            return Ok(());
        }
        // Nothing is open: the saves there are offered before a new one is made.
        match name {
            "" if list.len() == 1 => self.ask(crate::app::Ask::UseSave(Some(list[0].name.clone()))),
            "" if !list.is_empty() => self.ask(crate::app::Ask::UseSave(None)),
            "" => self.install_new(),
            n if exists(n) => self.ask(crate::app::Ask::UseSave(Some(n.to_string()))),
            n => self.ask(crate::app::Ask::Install(n.to_string())),
        }
        Ok(())
    }

    /// Why what was typed in a field can't be used, if it can't.
    pub(crate) fn refused(&self, kind: &PromptKind, text: &str) -> Option<String> {
        let t = text.trim();
        match kind {
            PromptKind::JoinId if t.is_empty() => Some("type the room's id - or Esc to cancel".into()),
            PromptKind::Install(Installing::Name) if !t.is_empty() && !chat_core::net::saves::name_ok(t) && t != "default" => {
                Some("a save's name is letters, digits, - and _ (up to 32)".into())
            }
            PromptKind::Install(Installing::Name) if self.saves.as_ref().is_some_and(|s| s.list().iter().any(|i| i.name == t)) => {
                Some(format!("there's a save called {t} already - /uninstall {t} deletes it"))
            }
            PromptKind::Install(Installing::Pass(_)) if text.is_empty() => {
                Some("what's saved needs a passphrase - or Esc to cancel".into())
            }
            _ => None,
        }
    }

    pub fn install_name(&mut self, name: &str) {
        let name = match name.trim() {
            "" => chat_core::protocol::names::random_nick(),
            n => n.to_string(),
        };
        // The random name too: a save is never made over another.
        if self.saves.as_ref().is_some_and(|s| s.list().iter().any(|i| i.name == name)) {
            return self.fail(format!("there's a save called {name} already - /uninstall {name} deletes it"));
        }
        self.ask(crate::app::Ask::Install(name));
    }

    pub fn install_pass(&mut self, name: String, pass: &str) {
        let hint = "The passphrase again.".to_string();
        self.prompt(
            PromptKind::Install(Installing::Again(name, Zeroizing::new(pass.into()))),
            "INSTALL \u{b7} PASSPHRASE",
            hint,
        );
    }

    pub fn install_again(&mut self, name: String, first: Zeroizing<String>, again: &str) {
        if *first != again {
            self.fail("the two passphrases differ - nothing was saved");
            return self.install_name(&name);
        }
        let (Some(saves), tx) = (self.saves.clone(), self.tx.clone()) else {
            return;
        };
        self.say(format!("sealing {name}..."));
        tokio::spawn(async move {
            let r = tokio::task::spawn_blocking(move || saves.create(&name, &first, 0, None))
                .await
                .unwrap_or(Err(SaveError::Failed("couldn't make it".into())));
            let _ = tx.send(Msg::Save(SaveMsg::Created(r)));
        });
    }

    /// /save.
    pub fn save_command(&mut self) -> Result<(), String> {
        if self.save.is_none() {
            return self.install_command("");
        }
        self.save_all()?;
        self.say("saved");
        Ok(())
    }

    /// `/uninstall [NAME]`: asks first.
    pub fn uninstall_command(&mut self, arg: &str) -> Result<(), String> {
        let name = match arg.trim() {
            "" => self
                .save
                .as_ref()
                .map(|s| s.name().to_string())
                .ok_or("no save is open - /uninstall NAME deletes one")?,
            n => n.to_string(),
        };
        let hint = format!(
            "Type yes to delete {name} and everything in it. Deleting isn't erasing: the disk and backups can still \
             have it. Esc keeps it."
        );
        self.prompt(PromptKind::Uninstall(name), "UNINSTALL", hint);
        Ok(())
    }

    pub fn uninstall(&mut self, name: String, answer: &str) {
        if answer.trim() != "yes" {
            return self.say(format!("{name} is kept"));
        }
        let Some(saves) = &self.saves else { return };
        match saves.remove(&name) {
            Ok(()) => {
                if self.save.as_ref().is_some_and(|s| s.name() == name) {
                    self.save = None;
                }
                self.say(format!("{name} is deleted"));
            }
            Err(e) => self.fail(format!("{name} wasn't all deleted: {e}")),
        }
    }

    /// /keep [LABEL|forget]: this room kept in the save, to join again with /join LABEL.
    pub fn keep_command(&mut self, arg: &str) -> Result<(), String> {
        let info = self.room().and_then(|r| r.info.clone()).ok_or("no room is open here")?;
        let rooms = &mut self.settings.rooms;
        let at = rooms.iter().position(|k| k.id == info.room);
        if arg == "forget" {
            let i = at.ok_or("this room isn't kept")?;
            rooms.remove(i);
            self.say("this room isn't kept any more");
        } else {
            let label: String = match arg.trim() {
                "" => info.room.clone(),
                l => l.chars().take(ROOM_LABEL_MAX).collect(),
            };
            match at {
                Some(i) => rooms[i].label = label.clone(),
                None if rooms.len() >= ROOMS_MAX => return Err(format!("{ROOMS_MAX} rooms are kept already")),
                None => rooms.push(KeptRoom {
                    label: label.clone(),
                    id: info.room.clone(),
                    password: info.password.clone(),
                    at_start: false,
                }),
            }
            self.say(format!("kept as {label} - /join {label} opens it again"));
        }
        if self.save.is_none() {
            self.fail("no save is open, so it's kept until chat exits - /install makes one");
        }
        self.autosave();
        Ok(())
    }

    /// With /set reopen on, the rooms open now are the ones opened again next time.
    pub fn remember_open(&mut self) {
        if !self.settings.on("reopen") {
            return;
        }
        let open: Vec<(String, String)> = self
            .rooms
            .iter()
            .filter(|r| r.room().is_some() && r.call.is_none())
            .filter_map(|r| r.info.as_ref().map(|i| (i.room.clone(), i.password.clone())))
            .take(chat_core::net::settings::ROOMS_MAX)
            .collect();
        // A call by the key it's with: it opens that day's room.
        let calls: Vec<[u8; 32]> = self
            .rooms
            .iter()
            .filter(|r| r.room().is_some())
            .filter_map(|r| r.call.as_ref().map(|c| c.0))
            .take(chat_core::net::settings::ROOMS_MAX)
            .collect();
        if open != self.settings.reopen || calls != self.settings.calls {
            self.settings.reopen = open;
            self.settings.calls = calls;
            self.autosave();
        }
    }

    /// As chat starts: the kept rooms joined at the start, and with reopen on, the rooms open last time.
    pub(crate) fn join_saved_rooms(&mut self) {
        let mut joins: Vec<String> = self
            .settings
            .rooms
            .iter()
            .filter(|k| k.at_start)
            .map(|k| format!("{} {}", k.id, k.password))
            .collect();
        if self.settings.on("reopen") {
            for (id, pw) in self.settings.reopen.clone() {
                let j = format!("{id} {pw}");
                if !joins.contains(&j) {
                    joins.push(j);
                }
            }
        }
        for j in joins {
            self.join(&j);
        }
        if self.settings.on("reopen") {
            self.reopen_calls();
        }
    }

    /// The calls open last time, with keys still verified: each opens today's room.
    fn reopen_calls(&mut self) {
        let keys = self.settings.calls.clone();
        if keys.is_empty() {
            return;
        }
        let Some(ident) = self.ident.clone() else {
            return self.fail("the calls kept to reopen need your signing identity - /identity, then /call");
        };
        let day = chat_core::protocol::names::contact_day(crate::text::unix_now());
        for public in keys {
            if self.rooms.iter().any(|r| r.call.as_ref().is_some_and(|c| c.0 == public)) {
                continue;
            }
            let nick = match self.client.trust().lock() {
                Ok(t) => t.verified().iter().find(|e| e.public == public).map(|e| e.nick.clone()),
                Err(_) => None,
            };
            if let Some(nick) = nick
                && let Err(e) = self.open_call(&ident, public, nick, day, None)
            {
                self.fail(e);
            }
        }
    }

    /// What waits to go to a call's peer, as the open save keeps it.
    pub(crate) fn kept_outbox(&mut self, ident: &Ident, public: &[u8; 32], nick: &str) -> Vec<chat_core::Queued> {
        let (Some(save), Some(id)) = (&self.save, ident.kp.contact_id(public)) else {
            return Vec::new();
        };
        match save.outbox(&id) {
            Ok(o) => o,
            Err(_) => {
                self.fail(format!("what waits to go to {nick} can't be read from your save"));
                Vec::new()
            }
        }
    }

    /// With history on and a save open, a room's history kept from before is shown above its new
    /// messages, and it's kept from here.
    pub(crate) fn start_history(&mut self, id: usize) {
        if !self.settings.on("history") {
            return;
        }
        let Some(save) = &self.save else { return };
        let Some(r) = self.rooms.iter_mut().find(|r| r.id == id) else {
            return;
        };
        let Some(info) = &r.info else { return };
        if r.history.is_some() {
            return;
        }
        let saved = match save.history(&info.history_id) {
            Ok(h) => h,
            Err(_) => {
                r.note(
                    Level::Warn,
                    "this room's history in the save can't be read - it's kept again from here",
                );
                None
            }
        };
        let h = History::from_saved(saved.as_deref().map(|v| &v[..]));
        let lines = h.lines();
        if !lines.is_empty() {
            r.note(Level::Note, "kept from before, sealed in your save (/history forget deletes it):");
            let mut day = String::new();
            for l in &lines {
                if l.day() != day {
                    day = l.day().to_string();
                    r.note(Level::Note, day.clone());
                }
                r.note(Level::Note, format!("{} {}", l.hhmm(), l.text));
            }
            r.note(Level::Note, "new from here");
        }
        r.history = Some(h);
    }

    /// A room's history written to the save, if it changed; `stop` stops keeping it. False if the
    /// save refused it.
    pub(crate) fn write_history(&mut self, id: usize, stop: bool) -> bool {
        let Some(r) = self.rooms.iter_mut().find(|r| r.id == id) else {
            return true;
        };
        let (Some(info), Some(h)) = (&r.info, r.history.as_mut()) else {
            return true;
        };
        let mut failed = false;
        if h.dirty {
            match &self.save {
                Some(save) if save.set_history(&info.history_id, h.bytes()).is_ok() => h.dirty = false,
                Some(_) => failed = true,
                None => {}
            }
        }
        if failed {
            r.note(
                Level::Warn,
                "couldn't write this room's history to the save - it's tried again in a moment",
            );
        }
        if stop {
            r.history = None;
        }
        !failed
    }

    /// `/history [forget [all]]`.
    pub(crate) fn history_command(&mut self, arg: &str) -> Result<(), String> {
        let r = self.room().ok_or("no room is open here")?;
        let id = r.id;
        let hid = r.info.as_ref().map(|i| i.history_id);
        match arg.trim() {
            "" => {
                let kept = r.history.is_some();
                self.say(match (kept, self.save.is_some()) {
                    (true, _) => "this room's history is kept, sealed in your save - /history forget deletes it",
                    (false, true) => "this room's history isn't kept - /set history on keeps every room's",
                    (false, false) => "no history is kept: it needs a save (/install) and /set history on",
                });
            }
            "forget" => {
                let (save, hid) = (self.save.as_ref().ok_or("no save is open")?, hid.ok_or("this room isn't open yet")?);
                save.forget_history(Some(&hid));
                if let Some(r) = self.rooms.iter_mut().find(|r| r.id == id)
                    && r.history.is_some()
                {
                    r.history = Some(History::default());
                }
                self.say("this room's history is deleted");
            }
            "forget all" => {
                let save = self.save.as_ref().ok_or("no save is open")?;
                save.forget_history(None);
                for r in &mut self.rooms {
                    if r.history.is_some() {
                        r.history = Some(History::default());
                    }
                }
                self.say("every room's history is deleted");
            }
            _ => return Err("/history, /history forget, or /history forget all".into()),
        }
        Ok(())
    }

    /// /set history on or off: every room told, and its history kept or written and stopped.
    async fn history_changed(&mut self) {
        let on = self.settings.on("history") && self.save.is_some();
        let ids: Vec<usize> = self.rooms.iter().map(|r| r.id).collect();
        for id in ids {
            if on {
                self.start_history(id);
            } else {
                self.write_history(id, true);
            }
        }
        for r in &self.rooms {
            if let Some(room) = r.room() {
                let _ = room.command(Command::SetHistory { on }).await;
            }
        }
        if self.settings.on("history") && self.save.is_none() {
            self.fail("history needs a save to be kept in - /install makes one");
        }
    }

    /// At exit: with torguards on, Tor's guards and directory sealed into the save for next time;
    /// with it off, any kept there deleted.
    pub(crate) fn keep_tor_state(&mut self) {
        let Some(save) = &self.save else { return };
        if !self.settings.on("torguards") {
            save.forget_tor_cache();
        } else if let Some(state) = self.client.tor_state().filter(|s| !s.is_empty())
            && save.set_tor_cache(&state).is_err()
        {
            self.fail("couldn't keep Tor's guards in the save");
        }
    }

    /// A kept room's id and password by its label.
    pub fn kept(&self, label: &str) -> Option<String> {
        self.settings
            .rooms
            .iter()
            .find(|k| k.label == label)
            .map(|k| format!("{} {}", k.id, k.password))
    }

    /// `/set [NAME [VALUE]]`.
    /// /set opens the settings page, /set NAME opens it on that row, and /set NAME VALUE sets it.
    pub async fn set_command(&mut self, arg: &str) -> Result<(), String> {
        use chat_core::net::settings::{self as st, RowKind};
        let (name, value) = arg.split_once(' ').map_or((arg, ""), |(n, v)| (n, v.trim()));
        let name = if name == "color" { "colour" } else { name };
        if name.is_empty() {
            self.open_settings(None);
            return Ok(());
        }
        let Some(row) = st::PAGE.iter().find(|r| r.name == name) else {
            return Err(format!("no setting called {name} - /set opens the page with all of them"));
        };
        if value.is_empty() {
            self.open_settings(Some(name));
            return Ok(());
        }
        // Typed after /set, a secret would be on screen; the page's box hides it.
        if st::row_kind(name) == RowKind::Secret {
            self.open_settings(Some(name));
            if let Some(Modal::Settings(p)) = self.modal.take() {
                self.begin_edit(p, row.name);
            }
            self.say(format!("type the {} here instead, where it's hidden", row.label));
            return Ok(());
        }
        self.set_value(row.name, value).await
    }

    /// Sets a row, from /set NAME VALUE or the settings page.
    pub async fn set_value(&mut self, name: &str, value: &str) -> Result<(), String> {
        // Keeping Tor's guards asks first; off deletes them from the save at once.
        if name == "torguards" {
            let on = match value {
                "on" => true,
                "off" => false,
                _ => return Err("it takes on or off".into()),
            };
            if !on {
                let _ = self.settings.set(name, "off");
                if let Some(s) = &self.save {
                    s.forget_tor_cache();
                }
                self.autosave();
                self.say(format!(
                    "Keep tor's guards: off{}",
                    if self.save.is_some() { " - deleted from the save" } else { "" }
                ));
                return Ok(());
            }
            if self.save.is_none() {
                return Err("Keep tor's guards: it needs a save to keep them in - /install makes one".into());
            }
            if self.settings.on(name) {
                self.say("Keep tor's guards: on already");
                return Ok(());
            }
            self.ask(crate::app::Ask::TorGuards);
            return Ok(());
        }
        if name == "sign" {
            let cmd = match value {
                "off" => "identity off".to_string(),
                "age" | "pgp" => format!("identity {value}"),
                "age-nonick" => "identity age nonick".into(),
                "pgp-nonick" => "identity pgp nonick".into(),
                // age:PATH or pgp:PATH: a key file, like --identity takes.
                v if (v.starts_with("age:") || v.starts_with("pgp:")) && v.len() > 4 => {
                    let kind = if v.starts_with("age:") {
                        IdentityKind::Age
                    } else {
                        IdentityKind::Pgp
                    };
                    self.load_key(kind, &chat_core::net::files::typed_path_here(&v[4..]));
                    return Ok(());
                }
                _ => return Err("sign takes off|age|pgp|age-nonick|pgp-nonick|age:PATH|pgp:PATH".into()),
            };
            self.run(&cmd).await;
            return Ok(());
        }
        // The control password is never saved: it's kept in memory, for this run.
        if name == "torpassword" {
            self.tor_password = Zeroizing::new(value.to_string());
            self.apply_settings();
            self.say(if value.is_empty() {
                "torpassword: not set"
            } else {
                "torpassword: set"
            });
            return Ok(());
        }
        if let Some(r) = self.save_row(name, value) {
            return r;
        }
        self.settings.set(name, value)?;
        let now = self.settings.get(name).to_string();
        match name {
            "nick" => self.set_nick(&now).await,
            "colour" => {
                let c = Colour::parse(&now);
                self.colour = c;
                self.base.colour = c;
                for r in &self.rooms {
                    if let (Some(room), Some(c)) = (r.room(), c) {
                        let _ = room.command(Command::SetColour { colour: c }).await;
                    }
                }
            }
            "bridges" => {
                let r = self.client.set_bridges(&now).await;
                if let Err(e) = r {
                    return Err(format!("bridges: {e}"));
                }
            }
            "transports" => {
                let r = self.client.set_transports((!now.is_empty()).then(|| now.clone().into())).await;
                if let Err(e) = r {
                    return Err(format!("transport programs: {e}"));
                }
            }
            "net" => {
                let log = self.settings.net_log();
                for r in &self.rooms {
                    if let Some(room) = r.room() {
                        let _ = room.command(Command::SetNetLog { level: log }).await;
                    }
                }
            }
            "history" => {
                self.apply_settings();
                self.history_changed().await;
            }
            // It goes up at Start chatting, and can't come down once it's up.
            "sandbox" if !self.onboarding => {
                self.say(format!("sandbox: {now} - from the next start"));
                self.autosave();
                return Ok(());
            }
            "fastfiles" | "noise" | "filelimit" => {
                self.apply_settings();
                self.push_file_options().await;
            }
            "lock" if now != "off" && self.save.is_none() && self.pin.is_none() => {
                self.modal = Some(Modal::Prompt {
                    kind: PromptKind::SetPin,
                    title: "LOCK SCREEN \u{b7} PIN".into(),
                    hint: "No save is open, so the lock needs a PIN: chat keeps it hashed in memory until it exits.".into(),
                    input: Input::default(),
                });
            }
            _ => self.apply_settings(),
        }
        let shown = if name == "bridges" {
            self.settings
                .get(name)
                .split(';')
                .filter(|l| !l.trim().is_empty())
                .count()
                .to_string()
        } else {
            now
        };
        self.say(format!("{name}: {shown}"));
        self.autosave();
        Ok(())
    }

    /// The rows that are how the open save is locked, not settings in it.
    fn save_row(&mut self, name: &str, value: &str) -> Option<Result<(), String>> {
        use chat_core::protocol::crypto::passlock::{NEEDS_CODE, NEEDS_DEVICE, NEEDS_KEY};
        let rows = ["destroy", "shadow", "authenticator", "devicelock", "securitykey"];
        if !rows.contains(&name) {
            return None;
        }
        let Some(save) = self.save.as_mut() else {
            // It's for a save, so a box asks to /install first, and sets it up on the save that makes.
            if value == "on"
                && let Some(f) = ["devicelock", "securitykey", "authenticator"].into_iter().find(|f| *f == name)
            {
                self.ask(crate::app::Ask::InstallFirst(f));
                return Some(Ok(()));
            }
            return Some(Err(format!("{name} needs a save open - /install makes one")));
        };
        let on = match value {
            "on" => true,
            "off" => false,
            _ if name == "destroy" => false,
            _ => return Some(Err("it takes on or off".into())),
        };
        let r = match name {
            "destroy" => {
                let limit = match value {
                    "off" => 0,
                    "3" | "5" | "10" => value.parse().unwrap_or(0),
                    _ => return Some(Err("it takes off, 3, 5 or 10".into())),
                };
                save.set_destroy_limit(limit).map_err(|e| e.to_string()).map(|()| {
                    if limit > 0 {
                        format!("the save is deleted after {limit} wrong passphrases in a row")
                    } else {
                        "wrong passphrases don't delete the save".into()
                    }
                })
            }
            "shadow" if on => {
                let hint = "A second passphrase: typed instead of the save's own, it opens an empty decoy in the save's place, \
                            for good. Not the save's own passphrase."
                    .into();
                self.modal = Some(Modal::Prompt {
                    kind: PromptKind::Shadow(None),
                    title: "SHADOW PASSWORD".into(),
                    hint,
                    input: Input::default(),
                });
                return Some(Ok(()));
            }
            "shadow" => save
                .clear_shadow()
                .map_err(|e| e.to_string())
                .map(|()| "no shadow passphrase any more".into()),
            "authenticator" if on => {
                let (b32, uri) = save.new_code();
                let note = "scan it with your authenticator app (or type the secret in), then any key for its code".to_string();
                self.modal = Some(match chat_core::protocol::qr::encode(&uri) {
                    Some(qr) => Modal::Qr { invite: b32, qr, note },
                    None => Modal::Info {
                        title: "AUTHENTICATOR APP".into(),
                        lines: vec![b32, note],
                    },
                });
                self.prompt_after_info = true;
                return Some(Ok(()));
            }
            "authenticator" if save.factors() & NEEDS_CODE == 0 => Ok("the save doesn't ask for a code".into()),
            "authenticator" => {
                self.ask(crate::app::Ask::Factor("authenticator", false));
                return Some(Ok(()));
            }
            // A box says what would lose the save for good, first.
            "devicelock" if on && save.factors() & NEEDS_DEVICE != 0 => Ok("the save is locked to this device already".into()),
            "devicelock" if !on && save.factors() & NEEDS_DEVICE == 0 => Ok("the save isn't locked to this device".into()),
            "devicelock" => match chat_core::net::device::lock::available() {
                Err(why) if on => Err(format!("can't lock it to this device: {why}")),
                _ => {
                    self.ask(crate::app::Ask::DeviceLock(on));
                    return Some(Ok(()));
                }
            },
            "securitykey" if !on && save.factors() & NEEDS_KEY == 0 => Ok("the save doesn't need a security key".into()),
            // A box says what it means, and what would lose the save, first.
            _ => {
                self.ask(crate::app::Ask::Factor("securitykey", on));
                return Some(Ok(()));
            }
        };
        Some(r.map(|text| self.say(text)))
    }

    /// What's in use, saved over a save just opened, which is the save in use from then on: the
    /// keys verified there are added to the ones in use, and the rest of it is replaced.
    fn overwrite_into(&mut self, save: Save) {
        let name = save.name().to_string();
        if let Ok(text) = save.verified()
            && let Ok(mut t) = self.client.trust().lock()
        {
            t.load_verified(&text);
        }
        self.save = Some(save);
        match self.save_all() {
            Ok(()) => self.say(format!("saved over {name}, which is the save in use from now on")),
            Err(e) => self.fail(e),
        }
    }

    /// The device lock, once its box has said what it means.
    fn device_lock_now(&mut self, on: bool) {
        use chat_core::protocol::crypto::passlock::NEEDS_DEVICE;
        let Some(save) = self.save.as_mut() else { return };
        match save.set_factor(NEEDS_DEVICE, on) {
            Ok(()) if on => self.say("the save only opens on this device from now on"),
            Ok(()) => self.say("the save opens on any device again"),
            Err(e) => self.fail(e.to_string()),
        }
    }

    /// A box that asks before it does something.
    pub(crate) fn ask(&mut self, then: crate::app::Ask) {
        use crate::app::Ask;
        let shown = |s: &Self, name: &str| s.saves.as_ref().map(|v| v.shown_dir(name)).unwrap_or_default();
        let (title, paras, keys) = match &then {
            // The files page builds its own boxes.
            Ask::File(..) | Ask::Move | Ask::MoveAsked(_) => return,
            Ask::Overwrite(name) => {
                let what = match &self.ident {
                    None => "not your signing key (signing is off),",
                    Some(i) if matches!(i.origin, Origin::File(_)) => {
                        "the path to your signing key's file in place of the key saved there,"
                    }
                    Some(_) => "your signing key in place of the one saved there,",
                };
                (
                    "INSTALL",
                    vec![format!(
                        "{name} is another save, in {}, sealed with its own passphrase. Save what's in use now over it? \
                         That's your settings, {what} and the keys you verified, which are added to the ones saved there. \
                         Its passphrase is asked for next, and from then on {name} is the save in use. To use what's saved \
                         there as it is, start chat with --save {name}. /install NEWNAME makes a new save instead.",
                        shown(self, name)
                    )],
                    "y overwrite \u{b7} n cancel",
                )
            }
            Ask::TorGuards => {
                let name = self.save.as_ref().map(|s| s.name().to_string()).unwrap_or_default();
                (
                    "TOR GUARDS",
                    vec![
                        format!(
                            "When chat's own tor stops, its entry guards and its copy of the Tor directory are sealed into \
                             the save {name}, and the next one starts from them: the same guards from run to run, as \
                             Tor's design expects, and connected in seconds instead of a minute or more."
                        ),
                        "It adds to the save:\n\u{2022} which guards you use, for anyone who can open it\n\u{2022} tens of \
                         MB, mostly the directory, in a file called cache"
                            .into(),
                        "Its decoy gets none. /set torguards off deletes them from the save.".into(),
                    ],
                    "y keep them \u{b7} n cancel",
                )
            }
            Ask::Factor(f, on) => {
                let name = self.save.as_ref().map(|s| s.name().to_string()).unwrap_or_default();
                match (*f, *on) {
                    ("authenticator", _) => (
                        "AUTHENTICATOR APP",
                        vec![format!(
                            "This stops the save {name} asking for the code your authenticator app shows. Its \
                             authenticator file is deleted, and with it the secret the codes come from: delete the save's \
                             entry from the app too. /set authenticator on sets up a new one."
                        )],
                        "y turn off \u{b7} n cancel",
                    ),
                    (_, false) => (
                        "SECURITY KEY",
                        vec![format!(
                            "This seals the save {name} again without the security key, as if it had never needed one: a \
                             copy of its files opens with what else it needs. Its securitykey file is deleted. The security \
                             key keeps nothing for it, so there's nothing to delete from the key."
                        )],
                        "y turn off \u{b7} n cancel",
                    ),
                    _ => {
                        let key_inside = self.ident.as_ref().is_some_and(|i| !matches!(i.origin, Origin::File(_)));
                        (
                            "SECURITY KEY",
                            vec![
                                format!(
                                    "This makes the save {name} need your security key as well as its passphrase: a FIDO2 \
                                     key with hmac-secret, which most have (YubiKey 5, Nitrokey 3, SoloKey 2, Google \
                                     Titan...). Each time it opens, chat asks you to touch the key, which gives back a \
                                     secret that goes into the key the files are sealed with. Without the security key, \
                                     the passphrase opens nothing, wherever the files are copied."
                                ),
                                format!(
                                    "The save is gone for good{}, with no way back, if:\n\u{2022} the security key is lost \
                                     or broken\n\u{2022} it's reset: a FIDO reset (from its maker's app, or ykman fido \
                                     reset) wipes what it needs to give the secret back\n\u{2022} its securitykey file is \
                                     deleted: a backup it's restored from needs that file too",
                                    if key_inside { ", and the signing key only saved in it" } else { "" }
                                ),
                                "Before you reset it or stop using it, /set securitykey off first.".into(),
                                "Registering it takes two touches, one after the other: plug it in now. chat asks for its \
                                 PIN only if the key wants it."
                                    .into(),
                            ],
                            "y register \u{b7} n cancel",
                        )
                    }
                }
            }
            Ask::Install(name) => {
                let open = self.save.as_ref().is_some_and(|s| s.name() == name);
                let paras = self.install_paras(name, open);
                if open {
                    ("SAVE", paras, "y save \u{b7} n cancel")
                } else {
                    ("INSTALL", paras, "y install \u{b7} n cancel")
                }
            }
            Ask::UseSave(Some(name)) => (
                "INSTALL",
                vec![format!(
                    "There's a save here already: {name}, in {}, sealed with its own passphrase and not open in this run. \
                     Use it? Yes asks for its passphrase, and what's saved there is used from then on. No makes a new \
                     save, with a name and a passphrase of its own.",
                    shown(self, name)
                )],
                "y use it \u{b7} n new save \u{b7} esc cancel",
            ),
            Ask::UseSave(None) => (
                "INSTALL",
                vec![format!(
                    "There are {} saves here already, each sealed with its own passphrase, and none is open in this run. \
                     Use one of them? Yes asks which, then its passphrase, and what's saved there is used from then \
                     on. No makes a new save, with a name and a passphrase of its own.",
                    self.saves.as_ref().map_or(0, |s| s.list().len())
                )],
                "y use one \u{b7} n new save \u{b7} esc cancel",
            ),
            Ask::InstallFirst(f) => {
                let (title, what, then) = match *f {
                    "devicelock" => ("DEVICE LOCK", "The device lock", "locks it to this device"),
                    "securitykey" => (
                        "SECURITY KEY",
                        "A security key",
                        "registers your security key for it, with two touches",
                    ),
                    _ => (
                        "AUTHENTICATOR APP",
                        "An authenticator app",
                        "shows a QR code that adds it to your authenticator app",
                    ),
                };
                let text = if self.saves.as_ref().is_some_and(|s| !s.list().is_empty()) {
                    format!(
                        "{what} needs a save open first, and none is. Install now? Yes goes through /install, which opens \
                         a save here or makes a new one, and {then}."
                    )
                } else {
                    format!(
                        "{what} needs chat installed first. Until /install saves your settings, sealed with a passphrase, \
                         chat keeps nothing on disk. Install now? Yes goes through /install, which makes a save and {then}."
                    )
                };
                (title, vec![text], "y install \u{b7} n cancel")
            }
            Ask::DeviceLock(on) => {
                let name = self.save.as_ref().map(|s| s.name().to_string()).unwrap_or_default();
                if *on {
                    let key_inside = self.ident.as_ref().is_some_and(|i| !matches!(i.origin, Origin::File(_)));
                    let mut paras = vec![
                        format!(
                            "This locks the save {name} to this device: it only opens here, with its passphrase. A copy of its \
                             files anywhere else, from a backup or from the disk itself, can't be opened, even with the passphrase."
                        ),
                        format!(
                            "The save is gone for good{}, with no way back, if:",
                            if key_inside { ", and the signing key only saved in it" } else { "" }
                        ),
                    ];
                    let mut losses: Vec<String> = chat_core::net::device::lock::losses()
                        .into_iter()
                        .map(|l| format!("\u{2022} {l}"))
                        .collect();
                    losses.push("\u{2022} its device file is deleted: a backup it's restored from needs that file too".into());
                    losses.push("\u{2022} this computer breaks or is lost".into());
                    paras.push(losses.join("\n"));
                    paras.push(
                        "Before one of those you can see coming, like a firmware update or a reinstall, /set devicelock \
                         off here first, then lock it again after."
                            .into(),
                    );
                    if let Ok(uses) = chat_core::net::device::lock::available() {
                        paras.push(format!("It uses {uses}."));
                    }
                    ("DEVICE LOCK", paras, "y lock \u{b7} n cancel")
                } else {
                    let text = format!(
                        "This seals the save {name} again with its passphrase alone: its files open wherever they're copied, \
                         for anyone with the passphrase, as if it had never been locked. /set devicelock on locks it again."
                    );
                    ("DEVICE LOCK", vec![text], "y unlock \u{b7} n cancel")
                }
            }
        };
        self.modal = Some(Modal::Ask { title, paras, keys, then });
    }

    /// What /install saves, where, and how: the INSTALL box (SAVE for the save that's open).
    fn install_paras(&self, name: &str, open: bool) -> Vec<String> {
        use chat_core::protocol::crypto::passlock::NEEDS_DEVICE;
        let saves = self.saves.as_ref();
        let place = saves.map(|s| s.shown_dir(name)).unwrap_or_default();
        let others = saves.map_or(0, |s| s.list().iter().filter(|i| i.name != name).count());
        let trail = "they tell anyone who can read this disk (an admin, malware, a backup, forensics) that chat is used here.";
        let intro = if open {
            format!("{name} is already installed, in {place}, and open. Save what's in use now to it, in place of what's saved there:")
        } else if others > 0 || self.save.is_some() {
            format!(
                "This makes a new save, {name}, next to what /install saved already, with its own passphrase. When there's \
                 more than one save, chat asks which one to open when it starts, or --save NAME picks it. The files are a \
                 trail: {trail}"
            )
        } else {
            format!("Until you install, chat keeps nothing on disk. Installing leaves a trail: files that {trail}")
        };
        let key = match &self.ident {
            None => "No signing key: signing is off. One you choose later (/set sign) is kept by /install again, under the \
                     same passphrase."
                .to_string(),
            Some(i) => match &i.origin {
                Origin::File(p) => format!(
                    "{place}/key: the path to your signing key, {}. The key itself isn't copied: chat reads the file each \
                     time it starts.",
                    crate::browser::tilde(std::path::Path::new(p))
                ),
                _ => format!("{place}/key: your signing key."),
            },
        };
        let verified = self.client.trust().lock().map_or(0, |t| t.verified().len());
        let mut paras = vec![
            intro,
            [
                format!(
                    "\u{2022} {place}/settings: the settings you've changed - your nickname, colour, routing, relays and the \
                     like. Never the Tor control password."
                ),
                format!("\u{2022} {key}"),
                format!(
                    "\u{2022} {place}/verified: the signing keys of peers whose verify code you compared (/verify NICK), with \
                     their nicks, so they don't need comparing again ({verified} now). /verified lists them."
                ),
            ]
            .join("\n"),
            if open {
                "It's all sealed (Argon2id, XChaCha20-Poly1305) with the passphrase it's sealed with now: there's nothing to type."
            } else {
                "It's all sealed (Argon2id, XChaCha20-Poly1305) with one passphrase you choose next, which chat asks for when it \
                 starts."
            }
            .into(),
        ];
        let device = chat_core::net::device::lock::available();
        let device = match (open, self.pending_factor) {
            (true, _) if self.save.as_ref().is_some_and(|s| s.factors() & NEEDS_DEVICE != 0) => {
                Some("It stays locked to this device.".to_string())
            }
            (true, _) => None,
            (false, Some("devicelock")) => Some(
                "Locked to this device as well: its files won't open anywhere else, even with the passphrase. The next box \
                 says what would lose it for good."
                    .into(),
            ),
            (false, _) => Some(match device {
                Ok(_) => "Not locked to this device: a copy of the files opens anywhere with the passphrase. /set devicelock \
                          on locks it to this device as well, once it's installed."
                    .into(),
                Err(why) => format!("Not locked to this device, which can't lock a save to it: {why}."),
            }),
        };
        paras.extend(device);
        match (open, self.pending_factor) {
            (false, Some("securitykey")) => {
                paras.push("It needs your security key as well: a box registers it next, with two touches.".into())
            }
            (false, Some("authenticator")) => {
                paras.push("It asks for an authenticator code as well: a box shows a QR code to scan.".into())
            }
            _ => {}
        }
        paras.push(format!(
            "{} Never saved: rooms, their passwords, messages or files. /uninstall deletes it all - but a disk and its \
             backups can keep traces of deleted files.",
            if self.settings.on("autosave") {
                "Settings and verified keys you change from then on are saved as you change them (/set autosave off stops that)."
            } else {
                "Autosave is off: what you change from then on lasts until you /save again (/set autosave on saves it as you go)."
            }
        ));
        paras
    }

    /// y, n or (None) Esc on a box that asked.
    pub(crate) fn answer(&mut self, then: crate::app::Ask, yes: Option<bool>) {
        use crate::app::Ask;
        match (then, yes) {
            (Ask::Install(name), Some(true)) => {
                if self.save.as_ref().is_some_and(|s| s.name() == name) {
                    match self.save_all() {
                        Ok(()) => self.say("saved"),
                        Err(e) => self.fail(e),
                    }
                } else {
                    let hint = format!("A passphrase for {name}: long, since it's all that protects what's saved.");
                    self.prompt(PromptKind::Install(Installing::Pass(name)), "INSTALL \u{b7} PASSPHRASE", hint);
                }
            }
            (Ask::Install(name), _) => {
                let open = self.save.as_ref().is_some_and(|s| s.name() == name);
                self.install_cancelled(if open {
                    "not saved - nothing was written"
                } else {
                    "not installed - nothing was written"
                });
            }
            (Ask::UseSave(Some(name)), Some(true)) => self.ask_passphrase(name),
            (Ask::UseSave(None), Some(true)) => {
                let names: Vec<String> = self
                    .saves
                    .as_ref()
                    .map_or(Vec::new(), |s| s.list().into_iter().map(|i| i.name).collect());
                if !names.is_empty() {
                    self.modal = Some(Modal::PickSave { names, sel: 0 });
                }
            }
            (Ask::UseSave(_), Some(false)) => self.install_new(),
            (Ask::UseSave(_), None) => self.install_cancelled("not installed - nothing was written"),
            (Ask::InstallFirst(f), Some(true)) => {
                self.pending_factor = Some(f);
                if let Err(e) = self.install_command("") {
                    self.install_cancelled(&e);
                }
            }
            (Ask::InstallFirst(f), _) => {
                let label = chat_core::net::settings::PAGE.iter().find(|r| r.name == f).map_or(f, |r| r.label);
                self.say(format!("{label}: off - nothing was installed"));
            }
            (Ask::DeviceLock(on), Some(true)) => self.device_lock_now(on),
            (Ask::DeviceLock(_), _) => self.say("the device lock is as it was"),
            (Ask::File(..) | Ask::Move | Ask::MoveAsked(_), _) => {}
            (Ask::Overwrite(name), Some(true)) => {
                self.overwriting = true;
                self.ask_passphrase(name);
            }
            (Ask::Overwrite(_), _) => self.say("not saved - nothing was written"),
            (Ask::TorGuards, Some(true)) => {
                let _ = self.settings.set("torguards", "on");
                self.autosave();
                self.say("Keep tor's guards: on - kept in the save once chat's own tor has connected, from when it stops");
            }
            (Ask::TorGuards, _) => self.say("Keep tor's guards: off"),
            (Ask::Factor("securitykey", true), Some(true)) => self.register_key(None),
            (Ask::Factor(f, _), Some(true)) => {
                use chat_core::protocol::crypto::passlock::{NEEDS_CODE, NEEDS_KEY};
                let (flag, done) = if f == "authenticator" {
                    (NEEDS_CODE, "the save doesn't ask for a code any more")
                } else {
                    (NEEDS_KEY, "the save doesn't need the security key any more")
                };
                match self.save.as_mut().map(|s| s.set_factor(flag, false)) {
                    Some(Ok(())) => self.say(done),
                    Some(Err(e)) => self.fail(e.to_string()),
                    None => self.fail("no save is open"),
                }
            }
            (Ask::Factor(f, _), _) => {
                let label = chat_core::net::settings::PAGE.iter().find(|r| r.name == f).map_or(f, |r| r.label);
                self.say(format!("{label}: as it was"));
            }
        }
    }

    fn install_cancelled(&mut self, why: &str) {
        self.pending_factor = None;
        self.say(why.to_string());
    }

    /// A new save: its name, then the INSTALL box.
    fn install_new(&mut self) {
        let hint = "A name for the new save: letters, digits, - and _ (up to 32), or Enter for one picked at random. It \
                    goes in saves/NAME in chat's folder (default is the folder itself), and anyone who can read the disk \
                    can see the folder's name."
            .to_string();
        self.prompt(PromptKind::Install(Installing::Name), "INSTALL \u{b7} NEW SAVE", hint);
    }

    /// The factor /install was for, set up on the save it made or opened.
    fn factor_after_install(&mut self) {
        if let Some(f) = self.pending_factor.take()
            && let Some(Err(e)) = self.save_row(f, "on")
        {
            self.fail(format!("{f}: {e}"));
        }
    }

    pub fn shadow_pass(&mut self, first: Option<Zeroizing<String>>, pass: &str) {
        let Some(first) = first else {
            if pass.is_empty() {
                return self.say("no shadow passphrase was set");
            }
            let input = Input::default();
            let kind = PromptKind::Shadow(Some(Zeroizing::new(pass.to_string())));
            self.modal = Some(Modal::Prompt {
                kind,
                title: "SHADOW PASSWORD".into(),
                hint: "The shadow passphrase again.".into(),
                input,
            });
            return;
        };
        if *first != pass {
            return self.fail("the two differ - no shadow passphrase was set");
        }
        let Some(save) = &self.save else { return };
        // Argon2id runs twice here, a few seconds; it's rare enough to wait for.
        match save.set_shadow(pass) {
            Ok(()) => self.say("shadow passphrase set: typed instead of the save's own, it opens a decoy in its place"),
            Err(e) => self.fail(format!("no shadow passphrase was set: {e}")),
        }
    }

    /// After the authenticator's QR code: its code, typed back.
    pub fn ask_new_code(&mut self) {
        let hint = "The code your authenticator app shows now.".into();
        self.modal = Some(Modal::Prompt {
            kind: PromptKind::NewCode,
            title: "AUTHENTICATOR APP".into(),
            hint,
            input: Input::default(),
        });
    }

    pub fn new_code_typed(&mut self, code: &str) {
        use chat_core::protocol::crypto::passlock::NEEDS_CODE;
        let Some(save) = self.save.as_mut() else { return };
        let r = save.confirm_code(code).and_then(|()| save.set_factor(NEEDS_CODE, true));
        match r {
            Ok(()) => self.say("the save asks for your authenticator app's code as well as its passphrase from now on"),
            Err(e) => {
                self.fail(format!("not turned on: {e}"));
                self.ask_new_code();
            }
        }
    }
}

/// A message as its history line: `[@ ]NAME: TEXT`, with how many bytes are its head (up to the colon).
pub fn history_text(m: &Message, nick: &str, peers: &[PeerInfo]) -> (String, usize) {
    let peer = || {
        peers
            .iter()
            .find(|p| Some(p.id) == m.peer)
            .map_or_else(|| "someone".to_string(), |p| p.name.clone())
    };
    let who = match (m.direct, m.mine) {
        (true, true) => format!("you \u{2192} {}", peer()),
        (true, false) => format!("{} \u{2192} you", m.name),
        (false, true) => nick.to_string(),
        (false, false) => m.name.clone(),
    };
    let head = format!("{}{who}:", if m.mention && !m.direct && !m.mine { "@ " } else { "" });
    (format!("{head} {}", m.body()), head.len())
}
