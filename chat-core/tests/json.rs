// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! chat-json's `start`, served in-process: a route's `tor` is the tor the room uses.

use serde_json::{Value, json};
use std::time::Duration;

/// Serves `commands`, and gives back what came out up to "bye".
async fn serve(commands: &[Value]) -> Vec<Value> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    for c in commands {
        tx.send(c.to_string()).unwrap();
    }
    let (out, lines) = std::sync::mpsc::channel();
    tokio::time::timeout(Duration::from_secs(60), chat_core::json::serve_on(rx, out))
        .await
        .expect("chat-json to answer");
    lines.try_iter().map(|l| serde_json::from_str(&l).unwrap()).collect()
}

fn error_of(out: &[Value]) -> String {
    let e = out.iter().find(|v| v["t"] == "error").expect("an error");
    assert_eq!(out.last().unwrap()["t"], "bye");
    e["text"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn start_checks_the_route_tor() {
    let out = serve(&[json!({"cmd": "start", "route": {"mode": "tor", "tor": {"launch": "sometimes"}}})]).await;
    assert_eq!(error_of(&out), "tor \"launch\" is auto, always or never");
    let out = serve(&[json!({"cmd": "start", "route": {"mode": "tor", "tor": {"socks": "9050"}}})]).await;
    assert_eq!(error_of(&out), "tor \"socks\" and \"control\" are host:port");
}

#[tokio::test(flavor = "multi_thread")]
async fn start_uses_the_route_tor() {
    // A port nothing listens on: with launch never, the room fails there instead of starting a tor.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string();
    let tor = json!({"socks": closed, "control": closed, "launch": "never"});
    let out = serve(&[json!({"cmd": "start", "create": true, "route": {"mode": "tor", "tor": tor}})]).await;
    assert!(error_of(&out).contains("torlaunch never"), "{out:?}");
}
