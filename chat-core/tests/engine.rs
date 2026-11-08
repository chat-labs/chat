// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Sessions against each other over the simulated network.

mod sim;

use chat_core::{Command, Delivery, Event, LeaveReason, Outcome};
use sim::{Net, config};

/// Two nodes in one room, the second given the first's address.
fn pair(net: &mut Net) -> (usize, usize) {
    let mut a = config("alice");
    a.created = true;
    let a = net.add(a);
    let mut b = config("bob");
    b.static_peers = vec![net.nodes[a].addr()];
    let b = net.add(b);
    net.run_until(30.0, "a and b connect", |n| n.connected(a, b) && n.connected(b, a));
    (a, b)
}

fn sent_own(o: Outcome) -> u64 {
    match o {
        Outcome::Sent { own, .. } => own,
        other => panic!("not sent: {other:?}"),
    }
}

#[test]
fn two_peers_connect_and_talk() {
    let mut net = Net::new();
    let (a, b) = pair(&mut net);
    // Both see the same verify code.
    let code_ab = net.nodes[a].s.peers()[0].code.clone().unwrap();
    let code_ba = net.nodes[b].s.peers()[0].code.clone().unwrap();
    assert_eq!(code_ab, code_ba);
    assert_eq!(net.nodes[a].s.peers()[0].nick, "bob");
    assert_eq!(net.nodes[b].s.peers()[0].nick, "alice");
    assert!(net.nodes[b].events.contains(&Event::Opened));

    let own = sent_own(net.send(a, Command::Send { text: "hello bob".into() }).unwrap());
    net.send(b, Command::Send { text: "hi @alice".into() }).unwrap();
    net.run_until(10.0, "messages arrive", |n| {
        n.nodes[b].received("hello bob").is_some() && n.nodes[a].received("hi @alice").is_some()
    });
    let m = net.nodes[b].received("hello bob").unwrap();
    assert_eq!(m.nick, "alice");
    assert_eq!(m.from, net.nodes[a].id());
    assert!(!m.relayed && !m.direct && !m.mention);
    assert!(net.nodes[a].received("hi @alice").unwrap().mention);

    // Alice hears bob has it, then that it's settled.
    net.run_until(10.0, "delivery", |n| {
        n.nodes[a]
            .events
            .iter()
            .any(|e| matches!(e, Event::Delivery { own: o, delivery: Delivery::Settled } if *o == own))
    });
    let delivered = net.nodes[a]
        .events
        .iter()
        .any(|e| matches!(e, Event::Delivery { own: o, delivery: Delivery::Delivered { name, .. } } if *o == own && name == "bob"));
    assert!(delivered);
}

#[test]
fn a_message_is_shown_once() {
    let mut net = Net::new();
    let (a, b) = pair(&mut net);
    net.send(a, Command::Send { text: "once".into() }).unwrap();
    net.run(20.0);
    assert_eq!(net.nodes[b].messages().iter().filter(|m| m.body() == "once").count(), 1);
}

#[test]
fn messages_pass_through_a_peer_in_the_middle() {
    let mut net = Net::new();
    let mut a = config("alice");
    a.created = true;
    let a = net.add(a);
    let mut b = config("bob");
    b.static_peers = vec![net.nodes[a].addr()];
    let b = net.add(b);
    let mut c = config("carol");
    c.static_peers = vec![net.nodes[b].addr()];
    let c = net.add(c);
    // Alice and carol can't reach each other: everything between them goes through bob.
    net.cut_link(a, c);
    net.run_until(40.0, "a-b and b-c connect", |n| {
        n.connected(a, b) && n.connected(b, c) && n.connected(c, b)
    });
    assert!(!net.connected(a, c));
    net.send(a, Command::Send { text: "via bob".into() }).unwrap();
    net.run_until(15.0, "carol hears alice through bob", |n| n.nodes[c].received("via bob").is_some());
    let m = net.nodes[c].received("via bob").unwrap();
    assert!(m.relayed);
    assert_eq!(m.from, net.nodes[a].id());
    assert_eq!(m.peer, Some(net.nodes[b].id()));
    assert!(m.name.starts_with("alice#"));
}

#[test]
fn direct_messages_reach_only_their_peer() {
    let mut net = Net::new();
    let mut a = config("alice");
    a.created = true;
    let a = net.add(a);
    let mut b = config("bob");
    b.static_peers = vec![net.nodes[a].addr()];
    let b = net.add(b);
    let mut c = config("carol");
    c.static_peers = vec![net.nodes[a].addr()];
    let c = net.add(c);
    net.run_until(40.0, "everyone connects", |n| n.all_connected());
    let bob = net.nodes[b].id();
    let own = sent_own(
        net.send(
            a,
            Command::Dm {
                peer: bob,
                text: "just for you".into(),
            },
        )
        .unwrap(),
    );
    net.run_until(10.0, "bob gets it", |n| n.nodes[b].received("just for you").is_some());
    let m = net.nodes[b].received("just for you").unwrap();
    assert!(m.direct && m.mention);
    net.run(5.0);
    assert!(net.nodes[c].received("just for you").is_none());
    assert!(
        net.nodes[a]
            .events
            .iter()
            .any(|e| matches!(e, Event::Delivery { own: o, delivery: Delivery::Delivered { .. } } if *o == own))
    );
    // An unknown peer, and an empty message, are refused.
    assert!(
        net.send(
            a,
            Command::Dm {
                peer: chat_core::PeerId([9; 16]),
                text: "x".into()
            }
        )
        .is_err()
    );
    assert!(
        net.send(
            a,
            Command::Dm {
                peer: bob,
                text: "   ".into()
            }
        )
        .is_err()
    );
}

#[test]
fn replies_quote_what_they_answer() {
    let mut net = Net::new();
    let (a, b) = pair(&mut net);
    net.send(
        a,
        Command::Send {
            text: "lunch at noon?".into(),
        },
    )
    .unwrap();
    net.run_until(10.0, "bob gets it", |n| n.nodes[b].received("lunch at noon?").is_some());
    let mid = net.nodes[b].received("lunch at noon?").unwrap().mid.clone();
    net.send(
        b,
        Command::Reply {
            mid: mid.clone(),
            text: "yes".into(),
        },
    )
    .unwrap();
    net.run_until(10.0, "alice gets the reply", |n| n.nodes[a].received("yes").is_some());
    let r = net.nodes[a].received("yes").unwrap();
    assert_eq!(r.reply_to.as_deref(), Some(mid.as_str()));
    assert!(r.text.starts_with("\u{21aa} alice: lunch at noon?"));
    assert!(r.mention, "a reply to us is a mention");
    assert!(
        net.send(
            b,
            Command::Reply {
                mid: "00000000".into(),
                text: "x".into()
            }
        )
        .is_err()
    );
}

#[test]
fn rekeys_keep_the_session_and_its_code() {
    let mut net = Net::new();
    let (a, b) = pair(&mut net);
    net.send(
        a,
        Command::SetNetLog {
            level: chat_core::NetLog::Verbose,
        },
    )
    .unwrap();
    let code = net.nodes[a].s.peers()[0].code.clone();
    // Past two rekeys (every 300-360 s), talking all along.
    for i in 0..8 {
        net.send(a, Command::Send { text: format!("tick {i}") }).unwrap();
        net.run(100.0);
        assert!(
            net.nodes[b].received(&format!("tick {i}")).is_some(),
            "message {i} after {:.0}s",
            net.now
        );
    }
    assert!(net.connected(a, b) && net.connected(b, a));
    assert_eq!(net.nodes[a].s.peers()[0].code, code);
    assert!(!net.nodes[a].events.iter().any(|e| matches!(e, Event::PeerLeft { .. })));
    let rekeys = net.nodes[a]
        .events
        .iter()
        .filter(|e| matches!(e, Event::Log { text } if text.starts_with("rekey:")))
        .count();
    assert!(rekeys >= 2, "only {rekeys} rekeys in {:.0}s", net.now - 1000.0);
}

#[test]
fn rekeys_barely_delay_messages() {
    // Both sides rekey every 120-144 s (2.5 times the protocol's rate), and talk every 2 s.
    let mut net = Net::new();
    let mut a = config("alice");
    a.created = true;
    a.rekey_interval = 120.0;
    a.net_log = chat_core::NetLog::Verbose;
    let a = net.add(a);
    let mut b = config("bob");
    b.static_peers = vec![net.nodes[a].addr()];
    b.rekey_interval = 120.0;
    let b = net.add(b);
    net.run_until(30.0, "connect", |n| n.connected(a, b) && n.connected(b, a));
    let mut sent = Vec::new();
    for i in 0..600 {
        net.send(a, Command::Send { text: format!("a{i}") }).unwrap();
        net.send(b, Command::Send { text: format!("b{i}") }).unwrap();
        sent.push((i, net.now));
        net.run(2.0);
    }
    net.run(40.0);
    let mut worst = (0.0f64, String::new());
    for (i, at) in sent {
        for (to, tag) in [(b, "a"), (a, "b")] {
            let text = format!("{tag}{i}");
            let got = net.nodes[to].arrived_at(&text).unwrap_or_else(|| panic!("{text} never arrived"));
            if got - at > worst.0 {
                worst = (got - at, text);
            }
        }
    }
    let rekeys = net.nodes[a]
        .events
        .iter()
        .filter(|e| matches!(e, Event::Log { text } if text.starts_with("rekey:")))
        .count();
    println!("worst delivery {:.1}s ({}); rekeys seen by alice's log: {rekeys}", worst.0, worst.1);
    assert!(worst.0 < 15.0, "{} took {:.1}s", worst.1, worst.0);
    assert!(!net.nodes[a].events.iter().chain(&net.nodes[b].events).any(|e| matches!(
        e,
        Event::PeerLeft { .. }
            | Event::Delivery {
                delivery: Delivery::Missed { .. },
                ..
            }
    )));
}

#[test]
fn lossy_links_still_deliver_everything() {
    let mut net = Net::new();
    let (a, b) = pair(&mut net);
    net.loss = 0.3;
    for i in 0..10 {
        net.send(
            a,
            Command::Send {
                text: format!("lossy {i}"),
            },
        )
        .unwrap();
        net.send(b, Command::Send { text: format!("back {i}") }).unwrap();
        net.run(1.0);
    }
    net.run_until(120.0, "everything arrives despite 30% loss", |n| {
        (0..10).all(|i| n.nodes[b].received(&format!("lossy {i}")).is_some() && n.nodes[a].received(&format!("back {i}")).is_some())
    });
}

#[test]
fn verify_required_holds_messages_until_compared() {
    let mut net = Net::new();
    let mut a = config("alice");
    a.created = true;
    a.verify_required = true;
    let a = net.add(a);
    let mut b = config("bob");
    b.static_peers = vec![net.nodes[a].addr()];
    let b = net.add(b);
    net.run_until(30.0, "connect", |n| n.connected(a, b) && n.connected(b, a));
    match net.send(a, Command::Send { text: "secret".into() }).unwrap() {
        Outcome::Sent { to, held, .. } => assert_eq!((to, held), (0, 1)),
        o => panic!("{o:?}"),
    }
    net.run(10.0);
    assert!(net.nodes[b].received("secret").is_none());
    let bob = net.nodes[b].id();
    assert!(
        net.send(
            a,
            Command::Dm {
                peer: bob,
                text: "x".into()
            }
        )
        .is_err()
    );
    net.send(a, Command::Verify { peer: bob, same: true }).unwrap();
    net.send(
        a,
        Command::Send {
            text: "now you can read it".into(),
        },
    )
    .unwrap();
    net.run_until(10.0, "after verifying", |n| n.nodes[b].received("now you can read it").is_some());
}

#[test]
fn a_peer_that_drops_and_comes_back_gets_what_it_missed() {
    let mut net = Net::new();
    let (a, b) = pair(&mut net);
    // Bob vanishes (a train tunnel); alice sends while he's gone.
    net.nodes[b].down = true;
    net.send(
        a,
        Command::Send {
            text: "while you were out".into(),
        },
    )
    .unwrap();
    net.run_until(120.0, "alice times bob out", |n| {
        n.nodes[a].events.iter().any(|e| {
            matches!(
                e,
                Event::PeerLeft {
                    reason: LeaveReason::TimedOut,
                    ..
                }
            )
        })
    });
    assert!(net.nodes[b].received("while you were out").is_none());
    // He's back, with the same session: they find each other again, and he gets it.
    net.nodes[b].down = false;
    net.run_until(180.0, "bob gets it after coming back", |n| {
        n.nodes[b].received("while you were out").is_some()
    });
    assert!(!net.nodes[a].events.iter().any(|e| matches!(
        e,
        Event::Delivery {
            delivery: Delivery::Missed { .. },
            ..
        }
    )));
}

#[test]
fn leaving_tells_everyone() {
    let mut net = Net::new();
    let (a, b) = pair(&mut net);
    net.send(b, Command::Leave).unwrap();
    net.run_until(5.0, "alice hears bob left", |n| {
        n.nodes[a].events.iter().any(|e| {
            matches!(
                e,
                Event::PeerLeft {
                    reason: LeaveReason::Left,
                    ..
                }
            )
        })
    });
    assert!(net.nodes[a].s.peers().is_empty());
}

#[test]
fn nicks_colours_and_timers_reach_peers() {
    let mut net = Net::new();
    let (a, b) = pair(&mut net);
    net.send(a, Command::SetNick { nick: "alicia".into() }).unwrap();
    net.send(
        a,
        Command::SetColour {
            colour: chat_core::protocol::names::Colour([1, 2, 3]),
        },
    )
    .unwrap();
    net.send(a, Command::SetTimer { seconds: 600 }).unwrap();
    net.run(10.0);
    let p = &net.nodes[b].s.peers()[0];
    assert_eq!(p.nick, "alicia");
    assert_eq!(p.colour, chat_core::protocol::names::Colour([1, 2, 3]));
    // Bob keeps to a timer once alice is trusted (comparing isn't required here).
    assert_eq!(net.nodes[b].s.timer().0, 600);
    assert!(net.nodes[b].events.iter().any(|e| matches!(e, Event::Timer { seconds: 600, .. })));
}

#[test]
fn lan_beacons_find_peers() {
    let mut net = Net::new();
    let mut a = config("alice");
    a.created = true;
    a.lan = true;
    let a = net.add(a);
    let mut b = config("bob");
    b.lan = true;
    let b = net.add(b);
    net.run_until(30.0, "found over the LAN", |n| n.connected(a, b) && n.connected(b, a));
}

#[test]
fn relays_carry_peers_that_cant_reach_each_other() {
    let mut net = Net::new();
    net.relay = true;
    let mut a = config("alice");
    a.created = true;
    a.nostr = chat_core::NostrMode::Fallback;
    a.relays = 3;
    let a = net.add(a);
    let mut b = config("bob");
    b.nostr = chat_core::NostrMode::Fallback;
    b.relays = 3;
    let b = net.add(b);
    net.nodes[a].s.set_relays_up(3);
    net.nodes[b].s.set_relays_up(3);
    // No UDP between them at all: only the relays.
    net.cut_link(a, b);
    net.run_until(90.0, "connected through the relays", |n| n.connected(a, b) && n.connected(b, a));
    assert_eq!(net.nodes[a].s.peers()[0].path, chat_core::PathKind::Relays);
    net.send(a, Command::Send { text: "over nostr".into() }).unwrap();
    net.run_until(30.0, "message through the relays", |n| n.nodes[b].received("over nostr").is_some());
}

#[test]
fn tor_rooms_meet_through_their_onion_services() {
    // The default: no UDP at all. The maker hosts the room's first onion service; the others knock
    // on it, then learn each other's onions ("px") and connect to them directly.
    let mut net = Net::new();
    let mut a = sim::tor_config("alice");
    a.created = true;
    let a = net.add(a);
    let b = net.add(sim::tor_config("bob"));
    let c = net.add(sim::tor_config("carol"));
    net.run_until(60.0, "all three connect through Tor", |n| n.all_connected());
    for n in &net.nodes {
        assert!(n.s.peers().iter().all(|p| p.path == chat_core::PathKind::Tor));
    }
    assert_eq!(net.nodes[a].s.mode(), chat_core::RouteMode::Tor);
    net.send(
        b,
        Command::Send {
            text: "hello over onions".into(),
        },
    )
    .unwrap();
    let carol = net.nodes[c].id();
    net.send(
        a,
        Command::Dm {
            peer: carol,
            text: "just you".into(),
        },
    )
    .unwrap();
    net.run_until(20.0, "messages through Tor", |n| {
        n.nodes[a].received("hello over onions").is_some()
            && n.nodes[c].received("hello over onions").is_some()
            && n.nodes[c].received("just you").is_some()
    });
    // Bob and carol reached each other directly, not through alice.
    let m = net.nodes[c].received("hello over onions").unwrap();
    assert!(!m.relayed);
}

#[test]
fn moving_takes_compared_peers_to_a_new_room() {
    use chat_core::{CodeState, MovePlan};
    let mut net = Net::new();
    let mut c = config("alice");
    c.created = true;
    let a = net.add(c);
    let mut c = config("bob");
    c.static_peers = vec![net.nodes[a].addr()];
    let b = net.add(c);
    let mut c = config("carol");
    c.static_peers = vec![net.nodes[a].addr()];
    let carol = net.add(c);
    net.run_until(40.0, "all three connect", |n| {
        n.all_connected() && (0..3).all(|i| n.nodes[i].joined() == 2)
    });
    // Alice and bob compare codes; carol doesn't.
    let (ida, idb) = (net.nodes[a].id(), net.nodes[b].id());
    net.send(a, Command::Verify { peer: idb, same: true }).unwrap();
    net.send(b, Command::Verify { peer: ida, same: true }).unwrap();
    let plan = match net.send(a, Command::Move { answer: None }).unwrap() {
        Outcome::MovePlan(p) => p,
        o => panic!("{o:?}"),
    };
    assert_eq!(
        plan,
        MovePlan {
            coming: vec!["bob".into()],
            left: vec!["carol (code not compared)".into()]
        }
    );

    // Alice moves the room: the new one opens, then bob is asked along.
    let now = net.time();
    let to = net.nodes[a].s.move_yes(now).unwrap();
    assert!(to.created && to.room != "SIMROOM234");
    let mut c = config("alice");
    c.created = true;
    c.moved = Some(to.key.clone());
    let a2 = net.add_in(c, [7; 32]);
    net.move_links.insert(a, a2);
    net.nodes[a].s.move_go(&to, now);
    net.run_until(20.0, "bob is asked", |n| {
        n.nodes[b]
            .events
            .iter()
            .any(|e| matches!(e, Event::MoveAsked { ask: Some(k) } if k.from.starts_with("alice") && k.coming.is_empty()))
    });

    // Alice's old room has bob's key now, so it closes, before bob has even answered: bob still
    // takes her key along.
    net.run_until(20.0, "alice's old room has done its part", |n| n.nodes[a].s.move_finished());
    let now = net.time();
    net.nodes[a].s.leave(now);
    net.run_until(10.0, "bob sees alice leave the old room", |n| {
        n.nodes[b].s.peers().iter().all(|p| p.nick != "alice")
    });

    // Bob goes.
    let now = net.time();
    let tob = net.nodes[b].s.move_yes(now).unwrap();
    assert!(!tob.created && (tob.room.as_str(), tob.password.as_str()) == (to.room.as_str(), to.password.as_str()));
    let mut c = config("bob");
    c.static_peers = vec![net.nodes[a2].addr()];
    c.moved = Some(tob.key.clone());
    let b2 = net.add_in(c, [7; 32]);
    net.move_links.insert(b, b2);
    net.nodes[b].s.move_go(&tob, now);

    // In the new room, each counts as compared, from the keys they showed in the old one.
    net.run_until(40.0, "they meet in the new room, compared", |n| {
        let compared = |i: usize| n.nodes[i].s.peers().first().is_some_and(|p| p.code_state == CodeState::Compared);
        n.nodes[a2].joined() == 1 && n.nodes[b2].joined() == 1 && compared(a2) && compared(b2)
    });
    assert!(
        net.nodes[b2]
            .notices()
            .iter()
            .any(|t| t.contains("came along from the room you moved from"))
    );
    net.run_until(30.0, "bob's old room has done its part", |n| n.nodes[b].s.move_finished());
    // Carol was never asked, and the new room is nothing to her.
    assert!(!net.nodes[carol].events.iter().any(|e| matches!(e, Event::MoveAsked { .. })));
    assert_eq!(net.nodes[carol].s.peers().len(), 1);
}
