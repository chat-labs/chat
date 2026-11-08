# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
"""Two chat-json processes meeting over the live Tor network, through onion services only."""
import sys, time
sys.path.insert(0, sys.argv[1])
from harness import Peer, check, message, results

BIN = sys.argv[2]
nostr = sys.argv[3] if len(sys.argv) > 3 else "off"
route = {"mode": "tor", "nostr": nostr}
t0 = time.time()
a = Peer("alice", BIN)
b = Peer("bob", BIN)
try:
    a.send(cmd="start", create=True, room="TORPAIR234", password="pw", nick="alice", route=route, net_log="verbose")
    b.send(cmd="start", room="TORPAIR234", password="pw", nick="bob", route=route, net_log="verbose")
    ra = a.wait(lambda o: o["t"] == "ready", 60, "ready")
    rb = b.wait(lambda o: o["t"] == "ready", 60, "ready")
    print(f"ready after {time.time() - t0:.0f}s, route {ra['route']}", flush=True)

    def connect():
        b.wait(lambda o: o["t"] == "peers" and any(p["nick"] == "alice" for p in o["list"]), 600, "alice in peers")
        a.wait(lambda o: o["t"] == "peers" and any(p["nick"] == "bob" for p in o["list"]), 120, "bob in peers")
        print(f"    connected after {time.time() - t0:.0f}s", flush=True)
    check("meet through onion services", connect)

    def talk():
        a.send(cmd="send", text="hello over tor")
        b.wait(message("hello over tor"), 120, "message")
        b.send(cmd="dm", peer=ra["me"]["id"], text="dm over tor")
        m = a.wait(message("dm over tor"), 120, "dm")
        assert m.get("direct"), m
        print(f"    talked after {time.time() - t0:.0f}s", flush=True)
    check("messages and DMs over Tor", talk)

    def newtor():
        # Bob takes new circuits and a new onion: alice is told it, and messages keep coming.
        b.send(cmd="newtor")
        b.wait(lambda o: o.get("t") == "log" and "new Tor circuits" in o.get("text", ""), 10, "newtor")
        time.sleep(30)
        b.send(cmd="send", text="after newtor")
        a.wait(message("after newtor"), 300, "message after newtor")
        a.send(cmd="send", text="and back")
        b.wait(message("and back"), 300, "answer after newtor")
        print(f"    after newtor at {time.time() - t0:.0f}s", flush=True)
    check("new circuits and onion, still talking", newtor)
finally:
    for p, n in ((a, "alice"), (b, "bob")):
        p.drain()
        for o in p.seen:
            if o.get("t") == "line" and ("tor:" in o.get("text", "") or "joined" in o.get("text", "")):
                print(f"  {n}: {o['text'][:140]}")
    a.close()
    b.close()
print("passed" if all(r[1] for r in results) else "FAILED")
sys.exit(0 if all(r[1] for r in results) else 1)
