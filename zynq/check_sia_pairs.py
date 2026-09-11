#!/usr/bin/env python3
"""Grade the (nonce, hash) pairs tb_sia_core dumps, against Siacoin's rule.

The Sia core and the Knots core differ in exactly one place -- which BLAKE2b
digest word the prefilter taps and whether it is byte-reversed -- and getting it
wrong is invisible from every other angle. The message length, the framing, the
nonce iterator, the round schedule and the reported rate are all identical; only
the value is uncorrelated with the target. A miner in that state reports
candidates at the expected rate, fails every one in software, and looks like
flaky hardware.

    Siacoin : compares the digest as emitted, digest[0] most significant,
              so the top 64 bits are digest[0:8] big-endian = byteswap(H[0]).
    Knots   : compares the digest REVERSED, so its top 64 bits are
              digest[31:24] big-endian -- which is digest[24:32] read
              little-endian, i.e. H[3] itself.

So this checker verifies byteswap(H[0]) AND separately reports how many pairs
would have matched the Knots rule. A copy-paste of OspreyBlake2bStage4Core into
the Sia core would light that second counter up and fail here, by name, instead
of shipping.

Usage:  py -3 zynq/check_sia_pairs.py sia_pairs.txt
"""

from __future__ import annotations

import hashlib
import struct
import sys

MASK64 = 0xFFFFFFFFFFFFFFFF
NONCE_SLOT = 4

# Must match the BlockHeader assignments in tb/tb_sia_core.vhd exactly. Slot 4 is
# the grind slot and is overwritten by the core's iterator; it is listed so both
# sides describe the same 80-byte message.
HEADER_SLOTS = (
    0x1111111111111111,
    0x2222222222222222,
    0x3333333333333333,
    0x4444444444444444,
    0x5555555555555555,   # overwritten by the nonce
    0x6666666666666666,
    0x7777777777777777,
    0x8888888888888888,
    0x9999999999999999,
    0xAAAAAAAAAAAAAAAA,
)


def _digest(nonce: int) -> bytes:
    slots = list(HEADER_SLOTS)
    slots[NONCE_SLOT] = nonce & MASK64
    msg = b"".join(struct.pack("<Q", s) for s in slots)
    assert len(msg) == 80, len(msg)
    return hashlib.blake2b(msg, digest_size=32).digest()


def sia_top64(nonce: int) -> int:
    """What OspreySiaCore must report: byteswap(H[0])."""
    return int.from_bytes(_digest(nonce)[0:8], "big")


def knots_top64(nonce: int) -> int:
    """The OTHER chain's rule, kept as a named regression detector.

    If the Sia core is ever built by copying the Knots core, every pair will
    match this instead -- and the failure message will say so rather than
    leaving someone to rediscover the H[0]/H[3] distinction from first
    principles a second time.
    """
    return int.from_bytes(_digest(nonce)[24:32], "big")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    path = argv[0] if argv else "sia_pairs.txt"

    checked = 0
    matched = 0
    knots_matched = 0
    metavalues = 0
    malformed = 0
    failures: list[str] = []

    try:
        fh = open(path, "r", encoding="utf-8")
    except OSError as exc:
        print(f"CANNOT READ {path}: {exc}")
        return 1

    with fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            # GHDL prints metavalue warnings into the same stream when a signal
            # is still 'U'. Count them rather than dropping them silently: a run
            # that is mostly metavalues is not a run that passed.
            if "metavalue" in line or "U" in line.upper().replace("0X", ""):
                if not all(c in "0123456789abcdefABCDEF " for c in line):
                    metavalues += 1
                    continue
            parts = line.split()
            if len(parts) != 2:
                malformed += 1
                continue
            try:
                nonce = int(parts[0], 16)
                got = int(parts[1], 16)
            except ValueError:
                malformed += 1
                continue

            checked += 1
            want = sia_top64(nonce)
            if got == want:
                matched += 1
            else:
                if got == knots_top64(nonce):
                    knots_matched += 1
                if len(failures) < 5:
                    failures.append(
                        f"  line {lineno}: nonce={nonce:016x} got={got:016x} "
                        f"want={want:016x}")

    print(f"pairs checked={checked} matched={matched} "
          f"metavalue_lines={metavalues} malformed={malformed}")

    # A checker that graded nothing must never be mistaken for a pass. This is
    # the single most valuable line in the file.
    if checked == 0:
        print("SIA_PREFILTER: FAIL - zero pairs checked, nothing was graded")
        return 1

    if knots_matched:
        print(f"SIA_PREFILTER: FAIL - {knots_matched}/{checked} pairs match the "
              f"KNOTS rule byteswap(H[3]) instead of Siacoin's byteswap(H[0]). "
              f"The core is tapping the wrong digest word; see the header "
              f"comment in src/sia/OspreySiaCore.vhd.")
        for f in failures:
            print(f)
        return 1

    if matched != checked:
        print(f"SIA_PREFILTER: FAIL - {checked - matched}/{checked} mismatched, "
              f"and none of them match the Knots rule either")
        for f in failures:
            print(f)
        return 1

    print(f"SIA_PREFILTER: PASS - all {checked} pairs match byteswap(H[0])")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
