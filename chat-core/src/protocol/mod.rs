// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The protocol engine, with no I/O of its own.
//!
//! A [`Session`] is one member in one room. It's driven from outside: the caller hands it
//! datagrams as they arrive ([`Session::handle_udp`], [`Session::handle_relayed`]), the time ([`Session::tick`]) and
//! what the user asks for ([`Session::command`]), and takes back what to send
//! ([`Session::poll_transmit`]) and what happened ([`Session::poll_event`]). It never reads a
//! clock or a socket itself, so the same engine runs under any runtime, in a test with a
//! simulated network, or behind an FFI boundary on a phone.

pub mod api;
pub mod base64;
pub mod bech32;
pub mod crypto;
pub mod dht;
pub mod files;
pub mod hex;
pub mod names;
pub mod picture;
pub mod qr;
pub mod record;
pub mod session;
pub mod text;
pub mod trust;
pub mod wire;

pub use api::*;
pub use session::{MoveTo, OwnFile, Session, SessionConfig, Transmit};
