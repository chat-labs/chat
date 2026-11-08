// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! A diagnostic, not a check: two peers talking every 2 s through fast rekeys, with every
//! network note, delivery and handshake state printed. Run it when re-handshakes misbehave:
//!
//!     cargo test -p chat-core --test trace_rekey -- --ignored --nocapture

mod sim;
use chat_core::{Command, Event};
use sim::{Net, config};

#[test]
#[ignore]
fn trace() {
    let mut net = Net::new();
    let mut a = config("alice");
    a.created = true;
    a.rekey_interval = 120.0;
    a.net_log = chat_core::NetLog::Verbose;
    let a = net.add(a);
    let mut b = config("bob");
    b.static_peers = vec![net.nodes[a].addr()];
    b.rekey_interval = 120.0;
    b.net_log = chat_core::NetLog::Verbose;
    let b = net.add(b);
    net.run_until(30.0, "connect", |n| n.connected(a, b) && n.connected(b, a));
    let t0 = net.now;
    let (mut la, mut lb) = (0, 0);
    for i in 0..400 {
        net.send(b, Command::Send { text: format!("b{i}") }).unwrap();
        net.send(a, Command::Send { text: format!("a{i}") }).unwrap();
        for _ in 0..4 {
            net.run(0.5);
            for (n, l, tag) in [(a, &mut la, "A"), (b, &mut lb, "B")] {
                for (k, e) in net.nodes[n].events.iter().enumerate().skip(*l) {
                    let at = net.nodes[n].event_times[k] - t0;
                    match e {
                        Event::Log { text } => println!("{at:6.1} {tag} log {text}"),
                        Event::Message(m) if !m.mine => println!("{at:6.1} {tag} got {}", m.text),
                        Event::Delivery { own, delivery } => println!("{at:6.1} {tag} delivery {own} {delivery:?}"),
                        _ => {}
                    }
                }
                *l = net.nodes[n].events.len();
            }
        }
        println!(
            "{:6.1} A {}\n{:6.1} B {}",
            net.now - t0,
            net.nodes[a].s.debug_state(),
            net.now - t0,
            net.nodes[b].s.debug_state()
        );
    }
}
