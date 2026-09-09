#!/usr/bin/env python3
"""Grade the (nonce, hash) pairs dumped by tb/tb_stage4_prefilter.vhd.

The bench runs OspreyBlake2bStage4Core with TargetTop64 = MAX so that every
pipeline slot reports a candidate, and writes one "<nonce_hex> <hash_hex>" line
per Success. This script is the oracle: for each pair it rebuilds the 80-byte
message with slot 4 set to the reported nonce, hashes it with the standard
library, and requires the reported HashTop64 to match.

Which word is "top" is the whole point. Bitcoin compares the PoW hash as a
big-endian 256-bit number after the reference reverses the digest
(final[31-i] = hash_b[i]), so the most significant 8 bytes of the compare value
are digest[31..24] -- BLAKE2b's H[3], read big-endian. Sia compares the digest
in emission order, so its leading zeros are in H[0]; inheriting that tap is the
bug this file exists to catch. Tapping H[0] is not "wrong by a constant": it is
uncorrelated with the target, so the miner reports candidates at the normal rate
and every single one fails host verification.

Matching a pair also proves the nonce pipeline offset (NonceOut = Nonce(0) - 97)
is right, since a wrong offset pairs each hash with someone else's nonce.

Usage:
    py -3 zynq/check_stage4_pairs.py stage4_pairs.txt
"""

from __future__ import annotations

import hashlib
import struct
import sys

# Must match the BlockHeader assignments in tb/tb_stage4_prefilter.vhd exactly.
# Slot 4 is a placeholder; the core overwrites it with the grinding nonce.
HEADER_SLOTS: tuple[int, ...] = (
    0x1111111111111111,
    0x2222222222222222,
    0x3333333333333333,
    0x4444444444444444,
    0x0000000000000000,
    0x5555555555555555,
    0x6666666666666666,
    0x7777777777777777,
    0x8888888888888888,
    0x9999999999999999,
)

MASK64 = 0xFFFFFFFFFFFFFFFF


def expected_top64(nonce: int) -> int:
    """Top 64 bits of the Bitcoin-order PoW compare value for this nonce."""
    slots = list(HEADER_SLOTS)
    slots[4] = nonce & MASK64
    msg = b"".join(struct.pack("<Q", s) for s in slots)
    digest = hashlib.blake2b(msg, digest_size=32).digest()
    # digest[24:32] is H[3] little-endian; reading it big-endian is byteswap(H[3]).
    return int.from_bytes(digest[24:32], "big")


def wrong_top64_h0(nonce: int) -> int:
    """What the pre-fix RTL produced, so a regression names itself."""
    slots = list(HEADER_SLOTS)
    slots[4] = nonce & MASK64
    msg = b"".join(struct.pack("<Q", s) for s in slots)
    digest = hashlib.blake2b(msg, digest_size=32).digest()
    return int.from_bytes(digest[0:8], "big")


def main(argv: list[str]) -> int:
    path = argv[1] if len(argv) > 1 else "stage4_pairs.txt"
    with open(path, "r", encoding="ascii") as fh:
        lines = [ln.strip() for ln in fh if ln.strip()]

    if not lines:
        print(f"STAGE4_PREFILTER: FAIL - no pairs in {path}")
        return 1

    checked = 0
    bad = 0
    looks_like_h0 = 0
    skipped_meta = 0
    for ln in lines:
        parts = ln.split()
        if len(parts) != 2:
            print(f"STAGE4_PREFILTER: FAIL - malformed line: {ln!r}")
            return 1
        # Before the 97-deep pipeline fills, the core drives X/U on these ports.
        # Those slots are not gradeable, but they are counted so that a run which
        # is ONLY metavalues cannot masquerade as a pass.
        if any(c not in "0123456789abcdefABCDEF" for c in parts[0] + parts[1]):
            skipped_meta += 1
            continue
        nonce = int(parts[0], 16)
        got = int(parts[1], 16)

        # The pipeline emits a few slots before the first real nonce has
        # propagated; those show up as an all-zero hash and are not gradeable.
        if got == 0:
            continue

        want = expected_top64(nonce)
        checked += 1
        if got != want:
            bad += 1
            if got == wrong_top64_h0(nonce):
                looks_like_h0 += 1
            if bad <= 5:
                print(
                    f"  MISMATCH nonce={nonce:016x} got={got:016x} want={want:016x}"
                    + ("  <- this is H[0], the Sia tap" if got == wrong_top64_h0(nonce) else "")
                )

    print(
        f"STAGE4_PREFILTER: checked={checked} bad={bad} "
        f"skipped_metavalue={skipped_meta} total_lines={len(lines)}"
    )
    if checked == 0:
        # An empty check set is a FAILURE, not a vacuous pass.
        print("STAGE4_PREFILTER: FAIL - no gradeable pairs (every hash was zero)")
        return 1
    if bad:
        if looks_like_h0:
            print(
                f"STAGE4_PREFILTER: FAIL - {looks_like_h0}/{bad} mismatches are exactly "
                "H[0]; the prefilter is tapping the Sia word, not Bitcoin's H[3]"
            )
        else:
            print(f"STAGE4_PREFILTER: FAIL - {bad}/{checked} pairs mismatched")
        return 1

    print(f"STAGE4_PREFILTER: PASS - all {checked} pairs match byteswap(H[3])")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
