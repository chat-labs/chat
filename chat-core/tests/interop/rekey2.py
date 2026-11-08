# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
"""Two chat-json processes talking through rekeys every 30 s; reports delivery latency.

usage: rekey2.py SCRATCH ALICE BOB SECONDS   where ALICE and BOB are chat-json executables
"""
import sys, time
sys.path.insert(0, sys.argv[1])
from harness import Peer, message

route = {"mode": "udp", "dht": False, "lan": False, "portmap": False, "nostr": "off"}
seconds = int(sys.argv[4])


def make(name, path):
    return Peer(name, path, env={"CHAT_TEST_REKEY_SECONDS": "30"})


a, b = make("a", sys.argv[2]), make("b", sys.argv[3])
lat = []
try:
    a.send(cmd="start", create=True, room="REKEYTEST3", password="pw", nick="aa", port=47401, route=route, net_log="verbose")
    b.send(cmd="start", room="REKEYTEST3", password="pw", nick="bb", port=47402, peers=["127.0.0.1:47401"], route=route, net_log="verbose")
    a.wait(lambda o: o["t"] == "peers" and o["list"], 40, "connect")
    b.wait(lambda o: o["t"] == "peers" and o["list"], 40, "connect")
    start = time.time()
    i = 0
    lost = []
    while time.time() - start < seconds:
        for src, dst, tag in ((a, b, "a"), (b, a, "b")):
            src.send(cmd="send", text=f"{tag}{i}")
        for src, dst, tag in ((a, b, "a"), (b, a, "b")):
            t0 = time.time()
            try:
                dst.wait(message(f"{tag}{i}"), 45, f"{tag}{i}")
                o = [x for x in dst.seen if x.get("t") == "line" and x.get("text") == f"{tag}{i}" and not x.get("mine")][0]
                own = src.wait(lambda x: x.get("t") == "line" and x.get("text") == f"{tag}{i}" and x.get("mine"), 10, "own line")
                _unused = [x for x in src.seen if x.get("t") == "line" and x.get("text") == f"{tag}{i}" and x.get("mine")]
                lat.append((o["_rx"] - own["_rx"], f"{tag}{i}@{own['_rx'] - start:.0f}s"))
            except TimeoutError:
                lost.append(f"{tag}{i}")
        i += 1
        time.sleep(3)
    a.drain(); b.drain()
    rk = [sum(1 for o in p.seen if o.get("t") == "line" and "rekey: fresh session keys" in o.get("text", "")) for p in (a, b)]
    missed = [o for p in (a, b) for o in p.seen if o.get("t") == "delivery" and o.get("missed")]
    lat.sort()
    print(f"{len(lat)} delivered, lost {lost}, missed {len(missed)}, rekeys {rk}")
    print("  median %.2fs, p90 %.2fs, slowest %s" % (lat[len(lat) // 2][0], lat[int(len(lat) * 0.9)][0], [f"{k}:{v:.1f}s" for v, k in lat[-5:]]))
finally:
    a.close()
    b.close()
# Rekeys lose nothing: every message arrived, and none was reported missed.
sys.exit(1 if lost or missed else 0)
