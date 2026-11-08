// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Two rooms that can only meet through a Nostr relay: a small one in this test, over a plain
//! websocket, that does what public relays do with chat's events (REQ, EVENT, OK).

use chat_core::{Client, Event, NostrMode, RoomConfig, Route, RouteMode};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

type Subs = Arc<Mutex<HashMap<usize, (mpsc::UnboundedSender<String>, Vec<(String, Vec<String>)>)>>>;

/// A relay: every event goes to every subscription whose "#e" filter has one of its "e" tags.
async fn relay() -> (String, Arc<Mutex<usize>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let subs: Subs = Arc::default();
    let events = Arc::new(Mutex::new(0usize));
    let ev_count = events.clone();
    tokio::spawn(async move {
        let mut next = 0usize;
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let id = next;
            next += 1;
            let subs = subs.clone();
            let ev_count = ev_count.clone();
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(tcp).await else {
                    return;
                };
                let (mut tx, mut rx) = ws.split();
                let (out_tx, mut out_rx) = mpsc::unbounded_channel::<String>();
                subs.lock().unwrap().insert(id, (out_tx.clone(), Vec::new()));
                tokio::spawn(async move {
                    while let Some(m) = out_rx.recv().await {
                        if tx.send(Message::text(m)).await.is_err() {
                            break;
                        }
                    }
                });
                while let Some(Ok(msg)) = rx.next().await {
                    let Message::Text(t) = msg else { continue };
                    let v: Value = serde_json::from_str(&t).unwrap();
                    match v[0].as_str() {
                        Some("REQ") => {
                            let tags = v[2]["#e"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|x| x.as_str().unwrap().to_string())
                                .collect();
                            subs.lock()
                                .unwrap()
                                .get_mut(&id)
                                .unwrap()
                                .1
                                .push((v[1].as_str().unwrap().to_string(), tags));
                        }
                        Some("EVENT") => {
                            let ev = &v[1];
                            *ev_count.lock().unwrap() += 1;
                            let _ = out_tx.send(json!(["OK", ev["id"], true, ""]).to_string());
                            let etags: Vec<String> = ev["tags"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .filter(|t| t[0] == "e")
                                .map(|t| t[1].as_str().unwrap().to_string())
                                .collect();
                            for (tx, filters) in subs.lock().unwrap().values() {
                                for (sub, tags) in filters {
                                    if tags.iter().any(|t| etags.contains(t)) {
                                        let _ = tx.send(json!(["EVENT", sub, ev]).to_string());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                subs.lock().unwrap().remove(&id);
            });
        }
    });
    (url, events)
}

fn relay_only(url: &str) -> Route {
    Route {
        mode: RouteMode::Direct,
        port: 0,
        peers: vec![],
        dht: false,
        ipv6: false,
        lan: false,
        portmap: false,
        nostr: NostrMode::Always,
        relays: vec![url.to_string()],
    }
}

async fn until<T>(events: &mut chat_core::RoomEvents, what: &str, mut f: impl FnMut(&Event) -> Option<T>) -> T {
    let mut seen = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let e = events.recv().await.expect("the room closed");
            if let Some(t) = f(&e) {
                return t;
            }
            seen.push(e);
        }
    })
    .await;
    match r {
        Ok(t) => t,
        Err(_) => {
            for e in &seen {
                eprintln!("  {e:?}");
            }
            panic!("timed out waiting for {what}")
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn rooms_meet_and_talk_through_a_relay() {
    let (url, relayed) = relay().await;
    let alice = Client::new();
    let bob = Client::new();
    let mut a_cfg = RoomConfig::create("alice");
    a_cfg.route = relay_only(&url);
    a_cfg.net_log = Some(chat_core::NetLog::Verbose);
    let (a, mut a_ev) = alice.join(a_cfg).await.unwrap();
    let invite = a.info().invite.clone().unwrap();
    let mut b_cfg = RoomConfig::invite(&invite, "bob");
    b_cfg.route = relay_only(&url);
    b_cfg.net_log = Some(chat_core::NetLog::Verbose);
    let (b, mut b_ev) = bob.join(b_cfg).await.unwrap();

    until(&mut a_ev, "bob to join", |e| {
        matches!(e, Event::PeerJoined(p) if p.nick == "bob").then_some(())
    })
    .await;
    until(&mut b_ev, "alice to join", |e| {
        matches!(e, Event::PeerJoined(p) if p.nick == "alice").then_some(())
    })
    .await;
    let peers = a.peers().await;
    assert_eq!(peers[0].path, chat_core::protocol::PathKind::Relays);

    a.send("over the relay").await.unwrap();
    let m = until(&mut b_ev, "the message", |e| match e {
        Event::Message(m) if !m.mine => Some(m.clone()),
        _ => None,
    })
    .await;
    assert_eq!(m.text, "over the relay");
    b.dm(a.info().me, "and back, directly").await.unwrap();
    let m = until(&mut a_ev, "the dm", |e| match e {
        Event::Message(m) if !m.mine && m.direct => Some(m.clone()),
        _ => None,
    })
    .await;
    assert_eq!(m.text, "and back, directly");
    assert!(*relayed.lock().unwrap() > 0);

    b.leave().await;
    until(&mut a_ev, "bob to leave", |e| matches!(e, Event::PeerLeft { .. }).then_some(())).await;
}
