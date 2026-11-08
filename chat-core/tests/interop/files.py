# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
"""Files between two chat-json processes over loopback UDP: offers, fetches to save and to show,
cleaned pictures, transfers at the normal rate and fast, and withdrawals.

usage: files.py SCRATCH ALICE BOB PICTURES   where ALICE and BOB are chat-json executables
"""
import hashlib, os, sys, tempfile
sys.path.insert(0, sys.argv[1])
from harness import Peer, check, results

ALICE, BOB, PICTURES = sys.argv[2], sys.argv[3], sys.argv[4]
route = {"mode": "udp", "dht": False, "lan": False, "portmap": False, "nostr": "off"}
work = tempfile.mkdtemp(prefix="chat-files-")
dirs = {k: os.path.join(work, k) for k in ("alice-in", "bob-in", "out")}
for d in dirs.values():
    os.makedirs(d)


def blob(name, size):
    path = os.path.join(dirs["out"], name)
    with open(path, "wb") as f:
        f.write(os.urandom(size))
    return path


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def offer_line(p, name):
    return p.wait(lambda o: o.get("t") == "line" and o.get("file") and name in o.get("text", "") and not o.get("mine"), 30,
                  f"the offer of {name}")


def file_state(p, num, state, timeout, what):
    def done(o):
        return o.get("t") == "files" and any(f["num"] == num and f["state"] == state for f in o["list"])
    o = p.wait(done, timeout, what)
    return next(f for f in o["list"] if f["num"] == num)


alice = Peer("alice", ALICE)
bob = Peer("bob", BOB)
try:
    alice.send(cmd="start", create=True, room="FILESROOM1", password="pw", nick="alice", port=47300, route=route,
               files={"dir": dirs["alice-in"], "fast": True})
    bob.send(cmd="start", room="FILESROOM1", password="pw", nick="bob", port=47301, peers=["127.0.0.1:47300"],
             route=route, files={"dir": dirs["bob-in"], "fast": True})
    alice.wait(lambda o: o["t"] == "ready", 30, "ready")
    bob.wait(lambda o: o["t"] == "ready", 30, "ready")
    alice.wait(lambda o: o["t"] == "peers" and any(p["nick"] == "bob" for p in o["list"]), 40, "bob in peers")
    bob.wait(lambda o: o["t"] == "peers" and any(p["nick"] == "alice" for p in o["list"]), 40, "alice in peers")
    alice.wait(lambda o: o.get("t") == "line" and "bob" in o.get("text", "") and "joined" in o.get("text", ""), 20, "join")
    bob.wait(lambda o: o.get("t") == "line" and "alice" in o.get("text", "") and "joined" in o.get("text", ""), 20, "join")

    def alice_to_bob():
        path = blob("from-alice.bin", 300_000)
        alice.send(cmd="offer", path=path)
        num = offer_line(bob, "from-alice.bin")["file"]
        bob.send(cmd="fetch", num=num)
        f = file_state(bob, num, "done", 120, "from-alice.bin saved")
        assert sha(f["saved"]) == sha(path), "bob saved something else"
        alice.wait(lambda o: o.get("t") == "files" and any(x.get("sent_to") == "bob" for x in o["list"]), 20, "sent to bob")
    check("alice offers 300 KB, bob fetches it (fast)", alice_to_bob)

    def bob_to_alice():
        path = blob("from-bob.bin", 250_000)
        bob.send(cmd="offer", path=path)
        num = offer_line(alice, "from-bob.bin")["file"]
        alice.send(cmd="fetch", num=num)
        f = file_state(alice, num, "done", 120, "from-bob.bin saved")
        assert sha(f["saved"]) == sha(path), "alice saved something else"
    check("bob offers 250 KB, alice fetches it (fast)", bob_to_alice)

    def normal_rate():
        # Fast transfers off on both sides: a chunk a slot, as everything else goes.
        alice.send(cmd="settings", files={"fast": False})
        bob.send(cmd="settings", files={"fast": False})
        a, b = blob("slow-alice.bin", 9000), blob("slow-bob.bin", 7000)
        alice.send(cmd="offer", path=a)
        bob.send(cmd="offer", path=b)
        na, nb = offer_line(bob, "slow-alice.bin")["file"], offer_line(alice, "slow-bob.bin")["file"]
        bob.send(cmd="fetch", num=na)
        alice.send(cmd="fetch", num=nb)
        fa = file_state(bob, na, "done", 90, "slow-alice.bin saved")
        fb = file_state(alice, nb, "done", 90, "slow-bob.bin saved")
        assert sha(fa["saved"]) == sha(a) and sha(fb["saved"]) == sha(b)
        alice.send(cmd="settings", files={"fast": True})
        bob.send(cmd="settings", files={"fast": True})
    check("both ways at the normal rate", normal_rate)

    def alice_picture():
        alice.send(cmd="offer", path=os.path.join(PICTURES, "exif420.jpg"))
        alice.wait(lambda o: o.get("t") == "line" and "took out" in o.get("text", ""), 20, "what was taken out")
        num = offer_line(bob, "exif420.jpg")["file"]
        bob.send(cmd="fetch", num=num, show=True)
        pic = bob.wait(lambda o: o.get("t") == "picture" and o.get("num") == num, 60, "the picture")
        # src_w and src_h are the picture as stored, before it's turned upright; the Orientation is
        # kept for other viewers either way.
        assert "error" not in pic and (pic["src_w"], pic["src_h"]) == (333, 211), {k: pic[k] for k in pic if k != "rgb"}
        bob.send(cmd="fetch", num=num)
        f = file_state(bob, num, "done", 30, "the picture saved")
        data = open(f["saved"], "rb").read()
        for secret in (b"Camera Maker", b"Model X", b"secret comment"):
            assert secret not in data, f"{secret} is still in it"
    check("alice offers a photo cleaned, bob shows it and saves it", alice_picture)

    def bob_picture():
        bob.send(cmd="offer", path=os.path.join(PICTURES, "text.png"))
        num = offer_line(alice, "text.png")["file"]
        alice.send(cmd="fetch", num=num, show=True)
        pic = alice.wait(lambda o: o.get("t") == "picture" and o.get("num") == num, 60, "the picture")
        assert "error" not in pic and (pic["w"], pic["h"]) == (333, 211), pic
        assert len(pic["rgb"]) == 4 * ((333 * 211 * 3 + 2) // 3)
        alice.send(cmd="fetch", num=num)
        f = file_state(alice, num, "done", 30, "the picture saved, from the copy here")
        assert b"secret" not in open(f["saved"], "rb").read()
    check("bob offers a picture cleaned, alice shows it and saves it", bob_picture)

    def withdrawn():
        bob.send(cmd="settings", files={"fast": False})
        path = blob("withdrawn.bin", 60_000)
        bob.send(cmd="offer", path=path)
        num = offer_line(alice, "withdrawn.bin")["file"]
        alice.send(cmd="fetch", num=num)
        alice.wait(lambda o: o.get("t") == "files" and any(f["num"] == num and f.get("got", 0) > 0 for f in o["list"]), 30,
                   "it starts coming")
        mine = bob.wait(lambda o: o.get("t") == "line" and o.get("file") and o.get("mine") and "withdrawn.bin" in o.get("text", ""),
                        10, "our offer line")
        bob.send(cmd="cancel", num=mine["file"])
        f = file_state(alice, num, "failed", 60, "the fetch failing")
        assert "offered" in f.get("why", ""), f
    check("bob withdraws a file alice is fetching", withdrawn)
finally:
    alice.close()
    bob.close()
print("passed" if all(x[1] for x in results) else "FAILED")
sys.exit(0 if all(x[1] for x in results) else 1)
