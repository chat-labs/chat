// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The JSON interface in-process, for an app that runs chat inside its own process (a phone's)
//! rather than as `chat-json`: the same JSON Lines, a room a handle, through a C ABI. The header is
//! `include/chat.h`.
//!
//! The app's process isn't hardened here ([`crate::harden_process`] would lock all of its memory,
//! a whole JVM's included): an app does what its platform allows for that.

use std::ffi::{CStr, CString, c_char, c_int};
use std::sync::mpsc;
use zeroize::Zeroize;

/// One room being served, on a thread and runtime of its own.
pub struct ChatRoom {
    commands: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    events: mpsc::Receiver<String>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// A room to drive, as `chat-json` serves one: its first event is "hello". NULL if no thread or
/// runtime could be started.
#[unsafe(no_mangle)]
pub extern "C" fn chat_open() -> *mut ChatRoom {
    let (commands, lines) = tokio::sync::mpsc::unbounded_channel();
    let (out, events) = mpsc::channel();
    let thread = std::thread::Builder::new().name("chat".into()).spawn(move || {
        if let Ok(rt) = tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            rt.block_on(crate::json::serve_on(lines, out));
        }
    });
    match thread {
        Ok(t) => Box::into_raw(Box::new(ChatRoom {
            commands: Some(commands),
            events,
            thread: Some(t),
        })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// A command: one JSON object, or several a line each, in UTF-8 ending in NUL. 0, or -1 if it
/// isn't UTF-8 or the room has ended.
///
/// # Safety
/// `room` is from [`chat_open`] and not closed; `line` is NUL-ended.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chat_send(room: *mut ChatRoom, line: *const c_char) -> c_int {
    if room.is_null() || line.is_null() {
        return -1;
    }
    // SAFETY: the caller's.
    let (room, line) = unsafe { (&*room, CStr::from_ptr(line)) };
    let (Ok(text), Some(commands)) = (line.to_str(), room.commands.as_ref()) else {
        return -1;
    };
    for l in text.lines().filter(|l| !l.trim().is_empty()) {
        if commands.send(l.to_string()).is_err() {
            return -1;
        }
    }
    0
}

/// The next event, a JSON object in UTF-8 ending in NUL, waited for up to `timeout_ms` (below 0:
/// however long it takes). NULL if none came in time, or once the room has ended (its last event
/// is "bye"). Each is given back with [`chat_free`].
///
/// # Safety
/// `room` is from [`chat_open`] and not closed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chat_recv(room: *mut ChatRoom, timeout_ms: c_int) -> *mut c_char {
    if room.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: the caller's.
    let room = unsafe { &*room };
    let line = match u64::try_from(timeout_ms) {
        Ok(ms) => room.events.recv_timeout(std::time::Duration::from_millis(ms)).ok(),
        Err(_) => room.events.recv().ok(),
    };
    // A JSON line has no NUL in it: serde_json writes one as \u0000.
    line.and_then(|l| CString::new(l).ok())
        .map_or(std::ptr::null_mut(), CString::into_raw)
}

/// An event from [`chat_recv`], wiped (it can hold messages and keys) and freed.
///
/// # Safety
/// `line` is from [`chat_recv`], or NULL, and isn't used after.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chat_free(line: *mut c_char) {
    if !line.is_null() {
        // SAFETY: the caller's: it came from CString::into_raw.
        unsafe { CString::from_raw(line) }.into_bytes().zeroize();
    }
}

/// Leaves the room, as "quit" does, waits for it to end, and frees the handle.
///
/// # Safety
/// `room` is from [`chat_open`], or NULL, and isn't used after.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn chat_close(room: *mut ChatRoom) {
    if room.is_null() {
        return;
    }
    // SAFETY: the caller's: it came from Box::into_raw.
    let mut room = unsafe { Box::from_raw(room) };
    // No more commands: the room is left, as when chat-json's stdin ends.
    room.commands = None;
    if let Some(t) = room.thread.take() {
        let _ = t.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_the_json_interface_in_process() {
        let room = chat_open();
        assert!(!room.is_null());
        // SAFETY: the handle and the lines are this test's own.
        unsafe {
            let hello = chat_recv(room, 10_000);
            assert!(!hello.is_null());
            let v: serde_json::Value = serde_json::from_str(CStr::from_ptr(hello).to_str().unwrap()).unwrap();
            assert_eq!((v["t"].as_str(), v["v"].as_i64()), (Some("hello"), Some(1)));
            chat_free(hello);
            assert_eq!(chat_send(room, c"{\"cmd\":\"quit\"}".as_ptr()), 0);
            let bye = chat_recv(room, 10_000);
            assert_eq!(CStr::from_ptr(bye).to_str(), Ok("{\"t\":\"bye\"}"));
            chat_free(bye);
            assert!(chat_recv(room, 100).is_null());
            chat_close(room);
        }
    }
}
