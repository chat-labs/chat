# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 finlay@tuta.com
"""Drive chat-json processes and wait on what they say."""
import json, os, queue, shlex, subprocess, sys, threading, time


class Peer:
    # argv: the program and its arguments, or one command line ("../target/debug/chat --json").
    def __init__(self, name, argv, env=None):
        self.name = name
        if isinstance(argv, str):
            argv = shlex.split(argv)
        e = dict(os.environ)
        e.update(env or {})
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e, text=True, bufsize=1)
        self.q = queue.Queue()
        self.seen = []
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._err, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            try:
                o = json.loads(line)
                o["_rx"] = time.time()
                self.q.put(o)
            except ValueError:
                self.q.put({"t": "raw", "text": line.rstrip()})

    def _err(self):
        for line in self.p.stderr:
            self.q.put({"t": "stderr", "text": line.rstrip()})

    def send(self, **cmd):
        self.p.stdin.write(json.dumps(cmd) + "\n")
        self.p.stdin.flush()

    def drain(self):
        while True:
            try:
                self.seen.append(self.q.get_nowait())
            except queue.Empty:
                return

    def wait(self, pred, timeout=60, what="something"):
        end = time.time() + timeout
        for o in self.seen:
            if pred(o):
                return o
        while time.time() < end:
            try:
                o = self.q.get(timeout=0.2)
            except queue.Empty:
                continue
            self.seen.append(o)
            if pred(o):
                return o
        raise TimeoutError(f"{self.name}: no {what} within {timeout}s")

    def lines(self, kind=None):
        self.drain()
        return [o for o in self.seen if o.get("t") == "line" and (kind is None or o.get("kind") == kind)]

    def close(self):
        try:
            self.send(cmd="quit")
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


def message(text, mine=False):
    return lambda o: o.get("t") == "line" and o.get("kind") == "message" and o.get("text", "").endswith(text) and bool(o.get("mine")) == mine


results = []


def check(name, fn):
    try:
        fn()
        results.append((name, True, ""))
        print(f"ok   {name}", flush=True)
    except Exception as e:  # noqa: BLE001
        results.append((name, False, str(e)))
        print(f"FAIL {name}: {e}", flush=True)
