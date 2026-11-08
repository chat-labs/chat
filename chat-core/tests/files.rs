// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Files between sessions over the simulated network, saved to a disk in memory.

mod sim;

use chat_core::protocol::OwnFile;
use chat_core::protocol::crypto::sodium;
use chat_core::protocol::files::{Disk, Part, Source};
use chat_core::{Command, Event, FileInfo, FileState, Outcome};
use sim::{Net, config};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

type Saved = Arc<Mutex<HashMap<String, Vec<u8>>>>;

struct MemDisk(Saved);
struct MemPart(Saved, String, Vec<u8>);

impl Disk for MemDisk {
    fn create(&mut self, dir: Option<&str>) -> Result<Box<dyn Part>, String> {
        Ok(Box::new(MemPart(self.0.clone(), dir.unwrap_or("Downloads").into(), Vec::new())))
    }
    fn open(&mut self, path: &str) -> Option<(u64, Box<dyn Source>)> {
        let d = self.0.lock().unwrap().get(path)?.clone();
        Some((d.len() as u64, Box::new(Zeroizing::new(d))))
    }
}

impl Part for MemPart {
    fn write(&mut self, data: &[u8]) -> bool {
        self.2.extend_from_slice(data);
        true
    }
    fn keep(self: Box<Self>, name: &str) -> Option<String> {
        let mut saved = self.0.lock().unwrap();
        let path = (1..)
            .map(|k| {
                if k == 1 {
                    format!("{}/{name}", self.1)
                } else {
                    format!("{}/{name} ({k})", self.1)
                }
            })
            .find(|p| !saved.contains_key(p))?;
        saved.insert(path.clone(), self.2.clone());
        Some(path)
    }
}

/// A source that gives other bytes than were hashed: a file changed after it was offered.
struct Changed(Vec<u8>);

impl Source for Changed {
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> bool {
        let off = off as usize;
        buf.copy_from_slice(&self.0[off..off + buf.len()]);
        buf[0] ^= 1;
        true
    }
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    sodium::random(&mut v);
    v
}

fn own_file(name: &str, data: &[u8], image: bool) -> OwnFile {
    OwnFile {
        name: name.into(),
        size: data.len() as u64,
        sha: sodium::sha256(&[data]),
        image,
        source: Box::new(Zeroizing::new(data.to_vec())),
        picture: image.then(|| Zeroizing::new(data.to_vec())),
        cleaned: None,
        cannot: None,
    }
}

/// Alice and bob connected, each saving to a disk of their own. `fast`: alice's transfers are.
fn pair(net: &mut Net, fast: bool, verify_required: bool) -> (usize, usize, Saved) {
    let mut a = config("alice");
    a.created = true;
    a.fast_files = fast;
    a.verify_required = verify_required;
    let a = net.add(a);
    let mut b = config("bob");
    b.static_peers = vec![net.nodes[a].addr()];
    b.verify_required = verify_required;
    let b = net.add(b);
    let saved: Saved = Default::default();
    net.nodes[b].s.set_disk(Box::new(MemDisk(saved.clone())));
    net.nodes[a].s.set_disk(Box::new(MemDisk(Default::default())));
    net.run_until(30.0, "a and b connect", |n| n.connected(a, b) && n.connected(b, a));
    net.run_until(10.0, "they announce each other", |n| {
        n.nodes[a].joined() > 0 && n.nodes[b].joined() > 0
    });
    (a, b, saved)
}

fn offer(net: &mut Net, i: usize, f: OwnFile) -> u32 {
    let now = net.time();
    match net.nodes[i].s.offer_file(f, now).unwrap() {
        Outcome::Offered { num } => num,
        o => panic!("not offered: {o:?}"),
    }
}

/// The number bob has the offer of `name` under, once it has come.
fn offered(net: &mut Net, b: usize, name: &str) -> u32 {
    net.run_until(30.0, "the offer arrives", |n| n.nodes[b].s.files().iter().any(|f| f.name == name));
    net.nodes[b].s.files().iter().find(|f| f.name == name).unwrap().num
}

fn info(net: &Net, i: usize, num: u32) -> FileInfo {
    net.nodes[i].s.files().into_iter().find(|f| f.num == num).unwrap()
}

fn fetch(net: &mut Net, b: usize, num: u32, show: bool) {
    net.send(
        b,
        Command::Fetch {
            num,
            show,
            anyway: false,
            dir: None,
        },
    )
    .unwrap();
}

#[test]
fn a_file_is_fetched_and_saved() {
    let mut net = Net::new();
    let (a, b, saved) = pair(&mut net, false, false);
    let data = random_bytes(5000);
    offer(&mut net, a, own_file("notes.txt", &data, false));
    let num = offered(&mut net, b, "notes.txt");
    // The offer is shown as a line of its own, with the file's number.
    assert!(
        net.nodes[b]
            .messages()
            .iter()
            .any(|m| m.file == Some(num) && m.text.contains("notes.txt"))
    );
    assert!(matches!(info(&net, b, num).state, FileState::Offered));
    fetch(&mut net, b, num, false);
    // 8 chunks, one a slot.
    net.run_until(60.0, "the file is saved", |n| matches!(info(n, b, num).state, FileState::Done));
    let f = info(&net, b, num);
    assert_eq!(f.saved.as_deref(), Some("Downloads/notes.txt"));
    assert_eq!(saved.lock().unwrap()["Downloads/notes.txt"], data);
    net.run(2.0);
    let mine = &net.nodes[a].s.files()[0];
    assert_eq!(mine.sent_to, vec!["bob".to_string()]);
    assert!(net.nodes[a].notices().iter().any(|n| n.contains("sent all of file")));
    // Fetched again, it's already there.
    fetch(&mut net, b, num, false);
    net.run(0.1);
    assert!(net.nodes[b].notices().iter().any(|n| n.contains("already saved")));
}

#[test]
fn fast_transfers_survive_loss_and_rekeys() {
    let mut net = Net::new();
    let mut a = config("alice");
    a.created = true;
    a.fast_files = true;
    a.rekey_interval = 15.0;
    let a = net.add(a);
    let mut b = config("bob");
    b.static_peers = vec![net.nodes[a].addr()];
    b.rekey_interval = 15.0;
    let b = net.add(b);
    let saved: Saved = Default::default();
    net.nodes[b].s.set_disk(Box::new(MemDisk(saved.clone())));
    net.run_until(30.0, "a and b connect", |n| n.connected(a, b) && n.connected(b, a));
    net.run_until(10.0, "joined", |n| n.nodes[b].joined() > 0);
    let data = random_bytes(300_000);
    offer(&mut net, a, own_file("big.bin", &data, false));
    let num = offered(&mut net, b, "big.bin");
    net.loss = 0.1;
    net.send(
        b,
        Command::Fetch {
            num,
            show: false,
            anyway: false,
            dir: Some("/tmp/x".into()),
        },
    )
    .unwrap();
    let start = net.now;
    net.run_until(600.0, "the big file is saved despite loss and rekeys", |n| {
        matches!(info(n, b, num).state, FileState::Done)
    });
    eprintln!("300 KB at 10% loss, rekeying every 15 s: {:.0} s", net.now - start);
    assert_eq!(saved.lock().unwrap()["/tmp/x/big.bin"], data);
}

#[test]
fn a_transfer_continues_through_rekeys() {
    let mut net = Net::new();
    let mut a = config("alice");
    a.created = true;
    a.rekey_interval = 90.0;
    let a = net.add(a);
    let mut b = config("bob");
    b.static_peers = vec![net.nodes[a].addr()];
    b.rekey_interval = 90.0;
    let b = net.add(b);
    let saved: Saved = Default::default();
    net.nodes[b].s.set_disk(Box::new(MemDisk(saved.clone())));
    net.run_until(30.0, "a and b connect", |n| n.connected(a, b) && n.connected(b, a));
    net.run_until(10.0, "joined", |n| n.nodes[b].joined() > 0);
    // 60 chunks at a slot each: about 100 s, through a rekey or two.
    let data = random_bytes(60 * 690 - 100);
    offer(&mut net, a, own_file("slow.bin", &data, false));
    let num = offered(&mut net, b, "slow.bin");
    fetch(&mut net, b, num, false);
    let start = net.now;
    // Each re-handshake holds chunks up while its frames go (about 21 cells, a slot each).
    net.run_until(600.0, "it's saved", |n| matches!(info(n, b, num).state, FileState::Done));
    eprintln!("60 chunks, rekeying every 90 s: {:.0} s", net.now - start);
    assert_eq!(saved.lock().unwrap()["Downloads/slow.bin"], data);
}

#[test]
fn a_picture_is_shown_and_then_saved_without_fetching_again() {
    let mut net = Net::new();
    let (a, b, saved) = pair(&mut net, true, false);
    let data = random_bytes(3000);
    offer(&mut net, a, own_file("cat.png", &data, true));
    net.run(0.1);
    // Ours is shown here at once.
    assert!(
        net.nodes[a]
            .events
            .iter()
            .any(|e| matches!(e, Event::Picture { data: d, .. } if *d == data))
    );
    let num = offered(&mut net, b, "cat.png");
    assert!(info(&net, b, num).image);
    fetch(&mut net, b, num, true);
    net.run_until(30.0, "the picture arrives", |n| {
        n.nodes[b]
            .events
            .iter()
            .any(|e| matches!(e, Event::Picture { num: k, .. } if *k == num))
    });
    let pic = net.nodes[b].events.iter().find_map(|e| match e {
        Event::Picture { data, .. } => Some(data.clone()),
        _ => None,
    });
    assert_eq!(pic.unwrap(), data);
    let f = info(&net, b, num);
    assert!(f.shown && f.saved.is_none());
    // Saved from the copy here: nothing more comes from alice.
    let sent_before = net.nodes[a].s.files()[0].sent_count;
    fetch(&mut net, b, num, false);
    net.run(0.1);
    assert_eq!(saved.lock().unwrap()["Downloads/cat.png"], data);
    assert!(net.nodes[b].notices().iter().any(|n| n.contains("from the copy already here")));
    net.run(3.0);
    assert_eq!(net.nodes[a].s.files()[0].sent_count, sent_before);
}

#[test]
fn a_file_that_changed_is_thrown_away() {
    let mut net = Net::new();
    let (a, b, saved) = pair(&mut net, true, false);
    let data = random_bytes(2000);
    let mut f = own_file("changed.txt", &data, false);
    f.source = Box::new(Changed(data.clone()));
    offer(&mut net, a, f);
    let num = offered(&mut net, b, "changed.txt");
    fetch(&mut net, b, num, false);
    net.run_until(30.0, "it fails", |n| matches!(info(n, b, num).state, FileState::Failed { .. }));
    assert!(saved.lock().unwrap().is_empty());
    assert!(net.nodes[b].notices().iter().any(|n| n.contains("didn't match what was offered")));
}

#[test]
fn a_withdrawn_file_stops_coming() {
    let mut net = Net::new();
    let (a, b, _) = pair(&mut net, false, false);
    let data = random_bytes(30_000);
    let mine = offer(&mut net, a, own_file("gone.bin", &data, false));
    let num = offered(&mut net, b, "gone.bin");
    fetch(&mut net, b, num, false);
    net.run_until(
        30.0,
        "it starts coming",
        |n| matches!(info(n, b, num).state, FileState::Fetching { got, .. } if got > 0),
    );
    net.send(a, Command::Cancel { num: mine }).unwrap();
    assert!(matches!(info(&net, a, mine).state, FileState::Withdrawn));
    net.run_until(60.0, "bob hears it's gone", |n| {
        matches!(info(n, b, num).state, FileState::Failed { .. })
    });
    assert!(net.nodes[b].notices().iter().any(|n| n.contains("no longer offers")));
}

#[test]
fn one_file_at_a_time_from_each_sender() {
    let mut net = Net::new();
    let (a, b, saved) = pair(&mut net, true, false);
    let (d1, d2) = (random_bytes(20_000), random_bytes(10_000));
    offer(&mut net, a, own_file("one.bin", &d1, false));
    offer(&mut net, a, own_file("two.bin", &d2, false));
    let n1 = offered(&mut net, b, "one.bin");
    let n2 = offered(&mut net, b, "two.bin");
    fetch(&mut net, b, n1, false);
    fetch(&mut net, b, n2, false);
    assert_eq!(info(&net, b, n2).state, FileState::Queued { after: Some(n1) });
    net.run_until(60.0, "both are saved", |n| {
        matches!(info(n, b, n1).state, FileState::Done) && matches!(info(n, b, n2).state, FileState::Done)
    });
    let s = saved.lock().unwrap();
    assert_eq!((&s["Downloads/one.bin"], &s["Downloads/two.bin"]), (&d1, &d2));
}

#[test]
fn big_files_need_anyway() {
    let mut net = Net::new();
    let (a, b, _) = pair(&mut net, false, false);
    net.send(b, Command::SetFileOptions { limit: 1000, fast: false }).unwrap();
    offer(&mut net, a, own_file("big.bin", &random_bytes(2000), false));
    let num = offered(&mut net, b, "big.bin");
    let r = net.send(
        b,
        Command::Fetch {
            num,
            show: false,
            anyway: false,
            dir: None,
        },
    );
    assert!(r.unwrap_err().to_string().contains("over your 1000 bytes limit"));
    net.send(
        b,
        Command::Fetch {
            num,
            show: false,
            anyway: true,
            dir: None,
        },
    )
    .unwrap();
    assert!(matches!(info(&net, b, num).state, FileState::Fetching { .. }));
}

#[test]
fn offers_wait_for_compared_codes_when_required() {
    let mut net = Net::new();
    let (a, b, saved) = pair(&mut net, true, true);
    let data = random_bytes(1500);
    offer(&mut net, a, own_file("secret.txt", &data, false));
    net.run(10.0);
    assert!(net.nodes[b].s.files().is_empty());
    assert!(net.nodes[a].notices().iter().any(|n| n.contains("not offered to 1 peer")));
    // Alice compares bob's code: bob gets the offer, and once he compares hers he can fetch it.
    let (ida, idb) = (net.nodes[a].id(), net.nodes[b].id());
    net.send(a, Command::Verify { peer: idb, same: true }).unwrap();
    let num = offered(&mut net, b, "secret.txt");
    let r = net.send(
        b,
        Command::Fetch {
            num,
            show: false,
            anyway: false,
            dir: None,
        },
    );
    assert!(r.unwrap_err().to_string().contains("compare verify codes"));
    net.send(b, Command::Verify { peer: ida, same: true }).unwrap();
    fetch(&mut net, b, num, false);
    net.run_until(30.0, "saved", |n| matches!(info(n, b, num).state, FileState::Done));
    assert_eq!(saved.lock().unwrap()["Downloads/secret.txt"], data);
}

#[test]
fn file_events_list_the_files() {
    let mut net = Net::new();
    let (a, b, _) = pair(&mut net, true, false);
    offer(&mut net, a, own_file("x.txt", b"hello", false));
    let num = offered(&mut net, b, "x.txt");
    net.run(1.0);
    let listed = net.nodes[b].events.iter().rev().find_map(|e| match e {
        Event::Files { list } => Some(list.clone()),
        _ => None,
    });
    let list = listed.expect("a files event");
    assert_eq!(list.len(), 1);
    assert_eq!((list[0].num, list[0].size, list[0].from_name.as_str()), (num, 5, "alice"));
    // It serializes, for the JSON interface.
    let json = serde_json::to_string(&Event::Files { list }).unwrap();
    assert!(json.contains("\"state\":\"offered\""));
}
