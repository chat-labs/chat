# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
""":move between two chat-json processes over loopback UDP: each moves the room and the other
follows, and in the new room their codes count as compared already.

usage: move.py SCRATCH ALICE BOB   where ALICE and BOB are chat-json executables
"""
import sys
sys.path.insert(0, sys.argv[1])
from harness import Peer, check, message, results

ALICE, BOB = sys.argv[2], sys.argv[3]
# LAN beacons on: the new room's members find each other through them.
route = {"mode": "udp", "dht": False, "lan": True, "portmap": False, "nostr": "off"}


def peers_with(p, nick, pred=lambda q: True):
    return lambda o: o.get("t") == "peers" and any(q["nick"] == nick and pred(q) for q in o["list"])


def compared(q):
    return q["code"]["state"] == "compared"


def since(p, o):
    """Forget what p said before o, so waits only match what came after."""
    p.seen = p.seen[p.seen.index(o) + 1:]


for mover in ("alice", "bob"):
    alice, bob = Peer("alice", ALICE), Peer("bob", BOB)
    try:
        room = f"MOVEFROM{mover.upper()}"
        alice.send(cmd="start", create=True, room=room, password="pw", nick="alice", port=47400, route=route)
        bob.send(cmd="start", room=room, password="pw", nick="bob", port=47401, peers=["127.0.0.1:47400"], route=route)
        ready_alice = alice.wait(lambda o: o["t"] == "ready", 30, "ready")
        ready_bob = bob.wait(lambda o: o["t"] == "ready", 30, "ready")
        alice.wait(peers_with(alice, "bob"), 40, "bob in peers")
        bob.wait(peers_with(bob, "alice"), 40, "alice in peers")
        alice.send(cmd="verify", peer=ready_bob["me"]["id"], same=True)
        bob.send(cmd="verify", peer=ready_alice["me"]["id"], same=True)
        alice.wait(peers_with(alice, "bob", compared), 20, "bob compared")
        bob.wait(peers_with(bob, "alice", compared), 20, "alice compared")
        a, b, b_nick = (alice, bob, "alice") if mover == "alice" else (bob, alice, "bob")
        other = "bob" if mover == "alice" else "alice"

        def plan():
            a.send(cmd="move")
            p = a.wait(lambda o: o.get("t") == "move_plan", 10, "a move plan")
            assert p["coming"] == 1 and other in p["coming_names"] and p["left"] == 0, p
        check(f"{mover} moves: the plan names who comes", plan)

        def go():
            a.send(cmd="move", answer=True)
            moved_a = a.wait(lambda o: o.get("t") == "moved", 60, "moved")
            since(a, moved_a)
            assert moved_a["room"] != room and moved_a.get("from") == room, moved_a
            ask = b.wait(lambda o: o.get("t") == "move" and o.get("seq", 0) > 0, 30, "the request to move")
            assert b_nick in ask["from"], ask
            b.send(cmd="move", answer=True)
            moved_b = b.wait(lambda o: o.get("t") == "moved", 60, "moved")
            since(b, moved_b)
            assert moved_b["room"] == moved_a["room"] and moved_b["password"] == moved_a["password"], (moved_a, moved_b)
            # In the new room their codes count as compared: nobody compares them again.
            a.wait(peers_with(a, other, compared), 90, f"{other} compared in the new room")
            b.wait(peers_with(b, b_nick, compared), 90, f"{b_nick} compared in the new room")
        check(f"{mover} moves, the other follows, codes still compared", go)

        def talk():
            a.send(cmd="send", text=f"hello in the new room from {mover}")
            b.wait(message(f"hello in the new room from {mover}"), 30, "the message")
            b.send(cmd="send", text="and back")
            a.wait(message("and back"), 30, "the answer")
        check(f"{mover} moves: messages in the new room", talk)
        if not results[-1][1]:
            for who in (a, b):
                who.drain()
                for o in who.seen[-25:]:
                    if o.get("t") in ("line", "moved", "peers", "error", "stderr", "delivery"):
                        print("   ", who.name, {k: v for k, v in o.items() if k not in ("_rx", "qr", "list")} if o["t"] != "peers" else [(q["nick"], q["code"]["state"]) for q in o["list"]])
    finally:
        alice.close()
        bob.close()
print("passed" if all(x[1] for x in results) else "FAILED")
sys.exit(0 if all(x[1] for x in results) else 1)
