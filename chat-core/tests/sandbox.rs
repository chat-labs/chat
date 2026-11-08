// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The sandbox binds threads already running when it goes up, not only the one putting it up. It's
//! put up on this test's own process, so this file holds this one test alone.

#[cfg(target_os = "linux")]
#[test]
fn binds_threads_started_before_it() {
    use std::sync::mpsc;
    // Somewhere the sandbox doesn't let chat write, that this user can write to without it.
    let outside = std::path::PathBuf::from(format!("/var/tmp/chat-sandbox-test-{}", std::process::id()));
    if std::fs::write(&outside, b"").is_err() {
        eprintln!("skipped: /var/tmp can't be written here");
        return;
    }
    let _ = std::fs::remove_file(&outside);
    let (go, wait) = mpsc::channel::<()>();
    let (tell, told) = mpsc::channel();
    let path = outside.clone();
    let before = std::thread::spawn(move || {
        wait.recv().unwrap();
        tell.send(std::fs::write(&path, b"").map_err(|e| e.kind())).unwrap();
    });
    let s = chat_core::net::sandbox::up(&[], &[]);
    if !s.files {
        eprintln!("skipped: no Landlock here ({:?})", s.why);
        return;
    }
    go.send(()).unwrap();
    let from_before = told.recv().unwrap();
    before.join().unwrap();
    let from_here = std::fs::write(&outside, b"").map_err(|e| e.kind());
    let _ = std::fs::remove_file(&outside);
    assert_eq!(from_before, Err(std::io::ErrorKind::PermissionDenied));
    assert_eq!(from_here, Err(std::io::ErrorKind::PermissionDenied));
    // A thread started after has it too, and a narrower layer goes up on every thread as well.
    let after = std::thread::spawn(move || std::fs::write(&outside, b"").map_err(|e| e.kind()));
    assert_eq!(after.join().unwrap(), Err(std::io::ErrorKind::PermissionDenied));
    chat_core::net::sandbox::narrow();
}
