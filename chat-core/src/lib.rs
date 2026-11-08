// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! chat's core: end-to-end encrypted rooms with no server and no accounts. A UI (the TUI, a GUI,
//! a phone app) needs nothing else.
//!
//! - [`protocol`]: the engine. Rooms, handshakes, encryption, messages and DMs, with no I/O, so
//!   it's deterministic and testable. It speaks chat's wire protocol.
//! - [`net`]: the runtime. It runs the engine over Tor (the default), the Nostr relays, and for
//!   direct routing UDP, the LAN and the DHT.
//!
//! Plugging a UI in takes three things: a [`Client`], [`Client::join`] for a [`Room`] and its
//! [`RoomEvents`], and [`Command`]s. Everything that crosses this boundary serializes, so another
//! language can drive the same API over JSON (the `chat-json` binary) or FFI.
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let client = chat_core::Client::new();
//! let (room, mut events) = client.join(chat_core::RoomConfig::create("alice")).await?;
//! println!("invite: {}", room.info().invite.as_deref().unwrap_or(""));
//! room.send("hello").await?;
//! while let Some(event) = events.recv().await {
//!     println!("{event:?}");
//! }
//! # Ok(()) }
//! ```

pub mod ffi;
pub mod json;
pub mod net;
pub mod protocol;

pub use net::{Client, FileOptions, JoinError, Room, RoomConfig, RoomEvents, RoomInfo, Route, harden_process};
pub use protocol::api::*;
pub use protocol::crypto::identity::{IdentityKeypair, IdentityKind};
pub use protocol::names::Colour;
pub use protocol::trust::{SharedTrust, TrustEntry, TrustStore};
