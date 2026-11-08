# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
"""Two chat-json processes in one room over loopback UDP, for some rounds: each round a new pair,
taking turns to make the room, so both handshake roles come up.

usage: interop.py SCRATCH ALICE BOB [ROUNDS]   where ALICE and BOB are chat-json executables
"""
import sys
sys.path.insert(0, sys.argv[1])
from harness import Peer, check, message, results

ALICE, BOB = sys.argv[2], sys.argv[3]
rounds = int(sys.argv[4]) if len(sys.argv) > 4 else 3
route = {"mode": "udp", "dht": False, "lan": False, "portmap": False, "nostr": "off"}

roles = {"alice initiates": 0, "bob initiates": 0}
for rnd in range(rounds):
    port_a, port_b = 47200 + 2 * rnd, 47201 + 2 * rnd
    room = f"INTEROP{rnd:03d}"
    alice_creates = rnd % 2 == 0
    a = Peer("alice", ALICE)
    b = Peer("bob", BOB)
    try:
        a.send(cmd="start", create=alice_creates, room=room, password="pw", nick="alice", port=port_a,
               peers=[] if alice_creates else [f"127.0.0.1:{port_b}"], route=route)
        b.send(cmd="start", create=not alice_creates, room=room, password="pw", nick="bob", port=port_b,
               peers=[f"127.0.0.1:{port_a}"] if alice_creates else [], route=route)
        ra = a.wait(lambda o: o["t"] == "ready", 30, "ready")
        rb = b.wait(lambda o: o["t"] == "ready", 30, "ready")
        initiator = "alice initiates" if bytes.fromhex(ra["me"]["id"]) < bytes.fromhex(rb["me"]["id"]) else "bob initiates"
        roles[initiator] += 1
        tag = f"round {rnd} ({'alice' if alice_creates else 'bob'} creates, {initiator})"

        def connect():
            a.wait(lambda o: o["t"] == "peers" and any(p["nick"] == "bob" for p in o["list"]), 40, "bob in peers")
            b.wait(lambda o: o["t"] == "peers" and any(p["nick"] == "alice" for p in o["list"]), 40, "alice in peers")
            pa = [o for o in a.seen if o["t"] == "peers" and o["list"]][-1]["list"][0]
            pb = [o for o in b.seen if o["t"] == "peers" and o["list"]][-1]["list"][0]
            assert pa["code"]["hex"] == pb["code"]["hex"], (pa["code"], pb["code"])
            print(f"    bob's build as alice sees it: {pa['build']['label']}; alice's as bob sees it: {pb['build']['label']}", flush=True)
        check(f"{tag}: handshake, same verify code", connect)

        def talk():
            a.send(cmd="send", text="hello from alice")
            b.wait(message("hello from alice"), 20, "alice's message")
            b.send(cmd="send", text="hello from bob @alice")
            m = a.wait(message("hello from bob @alice"), 20, "bob's message")
            assert m.get("mention"), m
            a.wait(lambda o: o["t"] == "delivery" and o.get("settled"), 20, "settled")
            b.wait(lambda o: o["t"] == "delivery" and o.get("settled"), 20, "settled")
        check(f"{tag}: messages both ways, acked", talk)

        def dms():
            a.send(cmd="dm", peer=rb["me"]["id"], text="dm to bob")
            m = b.wait(message("dm to bob"), 20, "dm")
            assert m.get("direct"), m
            b.send(cmd="dm", peer=ra["me"]["id"], text="dm to alice")
            m = a.wait(message("dm to alice"), 20, "dm")
            assert m.get("direct") and m.get("mention"), m
        check(f"{tag}: direct messages both ways", dms)

        def replies():
            mid = [o for o in b.seen if o.get("t") == "line" and o.get("text") == "hello from alice"][0]["mid"]
            b.send(cmd="reply", mid=mid, text="bob answers")
            m = a.wait(message("bob answers"), 20, "reply")
            assert m.get("quote", 0) > 0, m
            mid2 = [o for o in a.seen if o.get("t") == "line" and o.get("text") == "hello from bob @alice"][0]["mid"]
            a.send(cmd="reply", mid=mid2, text="alice answers")
            m = b.wait(message("alice answers"), 20, "reply")
            assert m.get("quote", 0) > 0, m
        check(f"{tag}: replies both ways", replies)

        def long_text():
            t = "word " * 150 + "end"
            a.send(cmd="send", text=t)
            b.wait(lambda o: o.get("t") == "line" and o.get("text") == t.strip(), 20, "long message")
        check(f"{tag}: long message", long_text)

        def changes():
            a.send(cmd="settings", nick="alice2", colour="#112233")
            b.wait(lambda o: o["t"] == "peers" and any(p["nick"] == "alice2" and p["colour"] == "#112233" for p in o["list"]), 20, "rename")
            b.send(cmd="timer", seconds=600)
            a.wait(lambda o: o["t"] == "timer" and o["seconds"] == 600, 20, "timer")
        check(f"{tag}: nick, colour, timer", changes)

        def leave():
            b.send(cmd="quit")
            a.wait(lambda o: o["t"] == "line" and "bob left" in o.get("text", ""), 15, "bob left")
        check(f"{tag}: leave", leave)
    finally:
        a.close()
        b.close()
print("roles covered:", roles)
print("passed" if all(x[1] for x in results) else "FAILED")
sys.exit(0 if all(x[1] for x in results) else 1)
