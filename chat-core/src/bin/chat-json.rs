// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! chat-json: one room, driven by another program over JSON Lines (see [`chat_core::json`]).

/// What handles secrets allocates where it can't be swapped out.
#[global_allocator]
static ALLOC: chat_core::net::memlock::LockedAlloc = chat_core::net::memlock::LockedAlloc;

fn main() {
    chat_core::harden_process();
    // This thread runs the room's interface: its allocations are locked too.
    chat_core::net::memlock::lock_this_thread();
    if std::env::args().any(|a| a == "--version") {
        println!("chat-json {}, JSON interface v1", env!("CARGO_PKG_VERSION"));
        return;
    }
    // Before any thread starts, so it binds them all.
    if !std::env::args().any(|a| a == "--nosandbox") {
        let run = chat_core::net::Bridges::default().programs();
        let _ = chat_core::net::sandbox::up(&run, &[]);
    }
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("a runtime");
    rt.block_on(chat_core::json::serve());
}
