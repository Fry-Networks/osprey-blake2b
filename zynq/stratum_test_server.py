#!/usr/bin/env python3
"""A local Sia-dialect Stratum v1 server, used as a deterministic test fixture.

Why this exists. The pool the Osprey is configured for pins share difficulty at
4096 and will not negotiate: passwords `x`, `d=0.001`, `d=1`, `diff=1`, `,d=1`
and `mining.suggest_difficulty` at 1 and 0.01 were all tried, and every one came
back `set_difficulty 4096`. At 4096 a 220 MH/s miner expects one share every
~22 hours (4096 * 2**32 / 2.2e8), so "submit a share and see it accepted" is not
a test anyone can run -- not in CI, not in a bring-up session, not ever on
demand. Without a fixture, the submit path would ship unproven and the first
evidence of a bug would be a silent zero-share miner.

So this serves the same dialect at a difficulty a CPU can hit in seconds, and
grades submissions with zynq/sia_reference.py as an oracle. The oracle is not
the code under test: the C miner reimplements the same rules independently in
miner/sia_stratum.c, and the point of the exercise is to make those two agree.

The dialect it speaks is the one the live pool speaks, verified against it:
    * mining.notify's ntime is 64-bit (16 hex chars), not Bitcoin's 32
    * the arbitrary transaction hashes as blake2b(0x00 || arbtx)
    * it is the RIGHTMOST merkle leaf; branch steps are blake2b(0x01 || br || acc)
    * the share compare value is the digest BYTE-REVERSED (the Knots rule),
      so leading zeros live in digest[31..24] -- word H[3], not H[0]
    * a rejected share comes back as [23, "LowDifficultyShare", None]

Template sources. `gbt` drives real work from ATLAS00's Knots node, which is
what makes an end-to-end run meaningful. `synthetic` needs no node at all, and
--selftest uses it deliberately so the fixture can never fail because a host on
the other side of a Tailscale link was down.
"""

import argparse
import hashlib
import json
import os
import random
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sia_reference import (                     # noqa: E402
    arbitrary_tx,
    arbtx_leaf,
    build_header,
    difficulty_to_target,
    merkle_root_from_branches,
    pow_compare_value,
    prevhash_from_block_hash,
    sia_compare_value,
)

CHAIN_ID_PS1 = r"C:\tmp\osprey-chain-id.ps1"
TEMPLATE_MAX_AGE_S = 30

# The live pool's constants, reproduced so a client cannot tell this apart from
# the real thing by inspecting a job.
POOL_NBITS = "d4c20319"
POOL_NTIME = "00" * 8
EXTRANONCE2_SIZE = 8


# --------------------------------------------------------------- templates

class TemplateSource:
    """Supplies (prevhash, coinb1) pairs.

    coinb1 is always 39 bytes, because 1 + 39 + 4 + 8 == 52 and 52 is the
    stage-3 message length baked into the bitstream as kStage3MsgLen. A source
    that produced any other length would be serving work this hardware cannot
    mine, so the arithmetic is asserted here rather than discovered downstream.
    """

    def __init__(self, kind: str, seed: int = 0xB2B) -> None:
        self.kind = kind
        self.rng = random.Random(seed)
        self.cached = None
        self.cached_at = 0.0
        self.height = 0

    def _synthetic(self):
        self.height += 1
        block_hash = bytes(self.rng.getrandbits(8) for _ in range(32))
        prevhash = prevhash_from_block_hash(block_hash)
        pseudo_h2 = hashlib.sha256(
            bytes(self.rng.getrandbits(8) for _ in range(16))).digest()
        coinb1 = bytes(3) + pseudo_h2 + bytes(self.rng.getrandbits(8) for _ in range(4))
        return prevhash, coinb1, self.height

    def _gbt(self):
        out = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", CHAIN_ID_PS1],
            capture_output=True, text=True, timeout=180)
        tip = None
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("{"):
                tip = json.loads(line)
                break
        if tip is None:
            raise RuntimeError("chain-id helper produced no JSON: "
                               + (out.stdout + out.stderr)[:400])
        prevhash = prevhash_from_block_hash(bytes.fromhex(tip["previousblockhash"]))
        # The real coinb1's middle 32 bytes are h2_hash, a value only the pool
        # can compute. A stand-in keyed to the height is fine here: nothing
        # downstream interprets it, and using the real one would require
        # reimplementing stages 1 and 2 for no test value.
        pseudo_h2 = hashlib.sha256(
            f"osprey-fixture-{tip['height']}".encode()).digest()
        coinb1 = bytes(3) + pseudo_h2 + struct.pack("<I", tip["height"] & 0xFFFFFFFF)
        return prevhash, coinb1, tip["height"]

    def get(self):
        now = time.time()
        if self.cached is not None and (now - self.cached_at) < TEMPLATE_MAX_AGE_S:
            return self.cached
        prevhash, coinb1, height = (
            self._synthetic() if self.kind == "synthetic" else self._gbt())
        assert len(prevhash) == 32, f"prevhash is {len(prevhash)} bytes"
        assert len(coinb1) == 39, (
            f"coinb1 is {len(coinb1)} bytes; 1+{len(coinb1)}+4+8 must be 52")
        self.cached = (prevhash, coinb1, height)
        self.cached_at = now
        return self.cached


# ------------------------------------------------------------------ server

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, *, difficulty, source, accept_target,
                 verbose=True, chain="knots"):
        super().__init__(addr, handler)
        self.difficulty = difficulty
        # Which chain's compare rule to grade with. The transport is identical;
        # only the rule differs, and grading Siacoin work with the Knots rule
        # would reject every correct share while looking like bad luck.
        self.chain = chain
        self.source = source
        self.accept_target = accept_target
        self.verbose = verbose
        self.accepted = 0
        self.rejected = 0
        self.submits = 0
        self.done = threading.Event()
        self.lock = threading.Lock()

    def say(self, msg):
        if self.verbose:
            print(msg, flush=True)

    def record(self, accepted):
        with self.lock:
            self.submits += 1
            if accepted:
                self.accepted += 1
                if self.accept_target and self.accepted >= self.accept_target:
                    self.done.set()
            else:
                self.rejected += 1


class Handler(socketserver.StreamRequestHandler):

    def setup(self):
        super().setup()
        self.jobs = {}
        self.job_counter = 0
        self.extranonce1 = bytes(random.getrandbits(8) for _ in range(4))
        self.authorized = False

    # -- wire helpers ----------------------------------------------------

    def send(self, obj):
        self.wfile.write((json.dumps(obj) + "\n").encode())
        self.wfile.flush()

    def push_job(self, clean=True):
        prevhash, coinb1, height = self.server.source.get()
        self.job_counter += 1
        job_id = f"fixture{self.job_counter:08x}"
        self.jobs[job_id] = {
            "prevhash": prevhash,
            "coinb1": coinb1,
            "coinb2": b"",
            "branches": [],
            "ntime": bytes.fromhex(POOL_NTIME),
            "height": height,
        }
        self.send({"id": None, "method": "mining.notify", "params": [
            job_id, prevhash.hex(), coinb1.hex(), "", [], "",
            POOL_NBITS, POOL_NTIME, clean,
        ]})
        self.server.say(f"  -> notify {job_id} (height {height})")

    # -- grading ---------------------------------------------------------

    def grade(self, job, extranonce2, ntime, nonce):
        """Return (accepted, share_difficulty). The oracle is sia_reference."""
        arbtx = arbitrary_tx(job["coinb1"], self.extranonce1, extranonce2,
                             job["coinb2"])
        root = merkle_root_from_branches(arbtx_leaf(arbtx), job["branches"])
        header = build_header(job["prevhash"], nonce, ntime, root)
        value = (sia_compare_value(header) if self.server.chain == "sia"
                 else pow_compare_value(header))
        target = difficulty_to_target(self.server.difficulty)
        # value == 0 would divide by zero and is not reachable in practice, but
        # a fixture that crashes on a lucky nonce is a fixture nobody trusts.
        share_diff = (difficulty_to_target(1.0) / value) if value else float("inf")
        return value <= target, share_diff

    # -- request loop ----------------------------------------------------

    def handle(self):
        peer = self.client_address
        self.server.say(f"client connected {peer}")
        try:
            for raw in self.rfile:
                line = raw.decode(errors="replace").strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    self.server.say(f"  <- unparseable: {line[:120]}")
                    continue
                self.dispatch(msg)
        except (ConnectionError, OSError):
            pass
        self.server.say(f"client gone {peer}")

    def dispatch(self, msg):
        method = msg.get("method")
        mid = msg.get("id")

        if method == "mining.subscribe":
            self.send({"id": mid, "result": [
                [["mining.notify", "fixture"]],
                self.extranonce1.hex(),
                EXTRANONCE2_SIZE,
            ], "error": None})
            self.server.say(f"  <- subscribe (extranonce1={self.extranonce1.hex()})")
            return

        if method == "mining.authorize":
            self.authorized = True
            self.send({"id": mid, "result": True, "error": None})
            self.server.say(f"  <- authorize {msg.get('params', [''])[0]}")
            self.send({"id": None, "method": "mining.set_difficulty",
                       "params": [self.server.difficulty]})
            self.push_job()
            return

        if method == "mining.suggest_difficulty":
            # Answered, unlike the real pool, but deliberately NOT honoured --
            # a fixture that silently changed difficulty under the client would
            # hide exactly the class of bug it is here to expose.
            self.send({"id": mid, "result": False, "error": None})
            return

        if method == "mining.submit":
            self.on_submit(mid, msg.get("params") or [])
            return

        if method is not None:
            self.send({"id": mid, "result": None,
                       "error": [20, f"Unknown method {method}", None]})

    def on_submit(self, mid, params):
        if len(params) < 5:
            self.send({"id": mid, "result": False,
                       "error": [20, "Malformed submit", None]})
            return
        _worker, job_id, en2_hex, ntime_hex, nonce_hex = params[:5]

        job = self.jobs.get(job_id)
        if job is None:
            self.server.record(False)
            self.send({"id": mid, "result": False,
                       "error": [21, "Job not found", None]})
            self.server.say(f"  <- submit for unknown job {job_id}")
            return

        # Width checks first, and loudly. In this dialect ntime and nonce are
        # 64-bit; a client that sent Bitcoin's 32-bit fields would otherwise be
        # graded as merely unlucky, and "all my shares are low difficulty" is
        # the single most misleading symptom a miner can produce.
        if len(ntime_hex) != 16 or len(nonce_hex) != 16:
            self.server.record(False)
            self.send({"id": mid, "result": False,
                       "error": [20, "ntime and nonce must be 16 hex chars "
                                     "(64-bit) in the Sia dialect", None]})
            self.server.say(f"  <- submit REJECTED: ntime={len(ntime_hex)} "
                            f"nonce={len(nonce_hex)} hex chars, expected 16/16")
            return
        if len(en2_hex) != EXTRANONCE2_SIZE * 2:
            self.server.record(False)
            self.send({"id": mid, "result": False,
                       "error": [20, "Bad extranonce2 size", None]})
            return

        try:
            en2 = bytes.fromhex(en2_hex)
            ntime = bytes.fromhex(ntime_hex)
            nonce = bytes.fromhex(nonce_hex)
        except ValueError:
            self.server.record(False)
            self.send({"id": mid, "result": False,
                       "error": [20, "Non-hex submit field", None]})
            return

        accepted, share_diff = self.grade(job, en2, ntime, nonce)
        self.server.record(accepted)
        if accepted:
            self.send({"id": mid, "result": True, "error": None})
            self.server.say(f"  <- submit ACCEPTED job={job_id} "
                            f"diff={share_diff:.6g} (need {self.server.difficulty:g}) "
                            f"nonce={nonce_hex}")
        else:
            self.send({"id": mid, "result": False,
                       "error": [23, "LowDifficultyShare", None]})
            self.server.say(f"  <- submit rejected job={job_id} "
                            f"diff={share_diff:.6g} (need {self.server.difficulty:g})")


# ----------------------------------------------------------------- client
# A minimal client, used only by --selftest. It is intentionally independent of
# miner/ so a green selftest says the FIXTURE works, not that the fixture and
# the miner share a bug.

def _selftest_client(port, difficulty, max_hashes=80_000_000):
    s = socket.create_connection(("127.0.0.1", port), timeout=30)
    s.settimeout(30)
    f = s.makefile("rwb")

    def send(obj):
        f.write((json.dumps(obj) + "\n").encode())
        f.flush()

    send({"id": 1, "method": "mining.subscribe", "params": ["selftest/1.0"]})
    send({"id": 2, "method": "mining.authorize", "params": ["tester", "x"]})

    en1 = None
    job = None
    diff = None
    deadline = time.time() + 30
    while time.time() < deadline and (en1 is None or job is None or diff is None):
        m = json.loads(f.readline())
        if m.get("id") == 1 and m.get("result"):
            en1 = bytes.fromhex(m["result"][1])
        elif m.get("method") == "mining.set_difficulty":
            diff = float(m["params"][0])
        elif m.get("method") == "mining.notify":
            job = m["params"]
    if en1 is None or job is None or diff is None:
        raise RuntimeError("handshake did not complete")

    job_id, prevhash_h, cb1_h, cb2_h, branches, _v, _nb, ntime_h, _c = job[:9]
    prevhash = bytes.fromhex(prevhash_h)
    ntime = bytes.fromhex(ntime_h)
    en2 = struct.pack(">Q", 1)
    arbtx = arbitrary_tx(bytes.fromhex(cb1_h), en1, en2, bytes.fromhex(cb2_h))
    root = merkle_root_from_branches(arbtx_leaf(arbtx), branches)
    target = difficulty_to_target(diff)

    found = None
    rule = sia_compare_value if CHAIN_UNDER_TEST == "sia" else pow_compare_value
    for n in range(max_hashes):
        nonce = struct.pack("<Q", n)
        if rule(build_header(prevhash, nonce, ntime, root)) <= target:
            found = nonce
            break
    if found is None:
        raise RuntimeError(f"no share found in {max_hashes} hashes at diff {diff}")

    results = {}

    def submit(tag, nonce_bytes, ident):
        send({"id": ident, "method": "mining.submit",
              "params": ["tester", job_id, en2.hex(), ntime.hex(), nonce_bytes.hex()]})
        end = time.time() + 30
        while time.time() < end:
            m = json.loads(f.readline())
            if m.get("id") == ident:
                results[tag] = m
                return
        raise RuntimeError(f"no verdict for {tag}")

    submit("good", found, 3)
    # A nonce that is almost certainly not a share. If this were accepted the
    # grader would be broken open, so the negative case matters as much as the
    # positive one.
    submit("bad", struct.pack("<Q", 0xDEADBEEFCAFEF00D), 4)
    # Bitcoin-width nonce: must be refused on width, not graded as unlucky.
    send({"id": 5, "method": "mining.submit",
          "params": ["tester", job_id, en2.hex(), ntime.hex(), "1234abcd"]})
    end = time.time() + 30
    while time.time() < end:
        m = json.loads(f.readline())
        if m.get("id") == 5:
            results["narrow"] = m
            break

    s.close()
    return found, results


CHAIN_UNDER_TEST = "knots"


def run_selftest():
    checks = []

    def check(name, fn):
        checks.append((name, fn))

    srv = Server(("127.0.0.1", 0), Handler, difficulty=0.001,
                 source=TemplateSource("synthetic"), accept_target=0,
                 verbose=False, chain=CHAIN_UNDER_TEST)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    try:
        t0 = time.time()
        found, res = _selftest_client(port, 0.001)
        elapsed = time.time() - t0

        check("a genuine share is ACCEPTED",
              lambda: _assert(res["good"].get("result") is True,
                              f"good share got {res['good']}"))
        check("a non-share is rejected as LowDifficultyShare",
              lambda: _assert(res["bad"].get("result") is False
                              and res["bad"].get("error", [None, None])[1]
                              == "LowDifficultyShare",
                              f"bad share got {res['bad']}"))
        check("a 32-bit nonce is refused on WIDTH, not graded as unlucky",
              lambda: _assert(res["narrow"].get("result") is False
                              and "16 hex" in (res["narrow"].get("error") or
                                               [None, ""])[1],
                              f"narrow nonce got {res['narrow']}"))
        check("the server counted exactly one accepted share",
              lambda: _assert(srv.accepted == 1 and srv.rejected == 2,
                              f"accepted={srv.accepted} rejected={srv.rejected}"))
        check("the fixture is fast enough to be usable in a test",
              lambda: _assert(elapsed < 60, f"took {elapsed:.1f}s"))

        passed = 0
        for name, fn in checks:
            try:
                fn()
            except Exception as exc:                 # noqa: BLE001
                print(f"  FAIL {name}\n       {exc}")
            else:
                passed += 1
                print(f"  OK   {name}")
        total = len(checks)
        if total == 0:
            print("RESULT: 0/0 FAIL - no checks were run")
            return 1
        print(f"\n  share found after grinding, nonce={found.hex()} in {elapsed:.1f}s")
        print(f"RESULT: {passed}/{total} {'PASS' if passed == total else 'FAIL'}")
        return 0 if passed == total else 1
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)


def _assert(cond, msg):
    if not cond:
        raise AssertionError(msg)


# -------------------------------------------------------------------- main

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=43101)
    ap.add_argument("--difficulty", type=float, default=0.001)
    ap.add_argument("--template-source", choices=["gbt", "synthetic"], default="gbt")
    ap.add_argument("--accept-target", type=int, default=0,
                    help="exit 0 once this many shares have been accepted")
    ap.add_argument("--timeout", type=float, default=0,
                    help="exit 1 after this many seconds without hitting the target")
    ap.add_argument("--chain", choices=["knots", "sia"], default="knots",
                    help="which compare rule to grade with (default knots)")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)

    if a.selftest:
        return run_selftest()

    srv = Server((a.host, a.port), Handler, difficulty=a.difficulty,
                 source=TemplateSource(a.template_source),
                 accept_target=a.accept_target, chain=a.chain)
    print(f"stratum fixture on {a.host}:{a.port} difficulty={a.difficulty} "
          f"templates={a.template_source} chain={a.chain}", flush=True)

    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        if a.accept_target:
            hit = srv.done.wait(timeout=a.timeout if a.timeout else None)
            print(f"accepted={srv.accepted} rejected={srv.rejected} "
                  f"submits={srv.submits}", flush=True)
            return 0 if hit else 1
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
