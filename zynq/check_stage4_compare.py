#!/usr/bin/env python3
"""Grade WHICH WORD OspreyBlake2bStage4Core compares against the target.

zynq/check_stage4_pairs.py grades the word the core REPORTS. That is a different
question, and answering it is not enough: tb_stage4_prefilter drives
TargetTop64 = MAX, under which `Hash0 < MAX` and `Hash0_be < MAX` are both always
true, so the comparison operand is invisible to it. A core that compared the
byte-reversed word against an unreversed target passed that bench and reached
silicon, where it filtered on digest[24..25] while a real solution needs
digest[31..30] -- independent bits, so it surfaced essentially nothing.

The rule this file enforces:

    Bitcoin's compare value is the digest REVERSED (final[31-i] = hash_b[i]), so
    its top 64 bits are hash_b[31..24] read most-significant-first. BLAKE2b
    serialises h[3] LITTLE-endian into hash_b[24..31], so that value is

        int.from_bytes(digest[24:32], "little")   ==  h[3]  ==  VHDL Hash0

    and TargetTop64 is the top 64 bits of the big-endian 256-bit target, i.e.
    the same units. Therefore every nonce the core reports must satisfy
    Hash0 < TargetTop64.

Siacoin is the opposite and its core is correct as written: it compares the
digest AS EMITTED, so its top 64 bits are byteswap(h[0]) and OspreySiaCore keeps
its byte-reverse. Do not unify them; see zynq/check_sia_pairs.py.

Usage:  py -3 zynq/check_stage4_compare.py stage4_compare_pairs.txt
"""

from __future__ import annotations

import hashlib
import struct
import sys

MASK64 = 0xFFFFFFFFFFFFFFFF
NONCE_SLOT = 4

# Must match the BlockHeader assignments in tb/tb_stage4_compare.vhd exactly,
# which are in turn identical to tb/tb_stage4_prefilter.vhd's. Slot 4 is the
# grind slot and is overwritten by the core's iterator.
HEADER_SLOTS = (
    0x1111111111111111,
    0x2222222222222222,
    0x3333333333333333,
    0x4444444444444444,
    0x0000000000000000,   # overwritten by the nonce
    0x5555555555555555,
    0x6666666666666666,
    0x7777777777777777,
    0x8888888888888888,
    0x9999999999999999,
)


def _digest(nonce: int) -> bytes:
    slots = list(HEADER_SLOTS)
    slots[NONCE_SLOT] = nonce & MASK64
    msg = b"".join(struct.pack("<Q", s) for s in slots)
    assert len(msg) == 80, len(msg)
    return hashlib.blake2b(msg, digest_size=32).digest()


def compare_value_top64(nonce: int) -> int:
    """What the core MUST compare: h[3] as-is == VHDL Hash0."""
    return int.from_bytes(_digest(nonce)[24:32], "little")


def byteswapped_top64(nonce: int) -> int:
    """The OTHER operand -- VHDL Hash0_be -- kept as a named regression detector.

    This is also the word the core legitimately REPORTS, so it is not wrong in
    itself; it is only wrong as the thing compared against the target. If the
    emitted set satisfies this rule rather than the one above, the Verify process
    has been reverted to `if Hash0_be < TargetTop64`.
    """
    return int.from_bytes(_digest(nonce)[24:32], "big")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    path = argv[0] if argv else "stage4_compare_pairs.txt"

    target = None
    cycles = None
    checked = 0
    ok = 0
    swapped_rule = 0
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
            # The bench writes the target and cycle count as a header line so the
            # two cannot drift apart.
            if line.startswith("#"):
                parts = line.split()
                try:
                    target = int(parts[parts.index("target") + 1], 16)
                    cycles = int(parts[parts.index("cycles") + 1])
                except (ValueError, IndexError):
                    print(f"STAGE4_COMPARE: FAIL - unparseable header: {line!r}")
                    return 1
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

            if target is None:
                print("STAGE4_COMPARE: FAIL - pairs before the target header line")
                return 1

            checked += 1

            # The reported word must still be the byte-reversed one. If this
            # breaks, the dump is not what this checker thinks it is and every
            # verdict below would be meaningless.
            if got != byteswapped_top64(nonce):
                if len(failures) < 5:
                    failures.append(
                        f"  line {lineno}: reported {got:016x} is not "
                        f"byteswap(H[3]) {byteswapped_top64(nonce):016x}")
                continue

            if compare_value_top64(nonce) < target:
                ok += 1
            else:
                if byteswapped_top64(nonce) < target:
                    swapped_rule += 1
                if len(failures) < 5:
                    failures.append(
                        f"  line {lineno}: nonce={nonce:016x} "
                        f"Hash0={compare_value_top64(nonce):016x} "
                        f"Hash0_be={byteswapped_top64(nonce):016x} "
                        f"target={target:016x}")

    print(f"target={target if target is None else format(target, '016x')} "
          f"cycles={cycles} emitted={checked} satisfy_Hash0={ok} "
          f"satisfy_Hash0_be_only={swapped_rule} malformed={malformed}")

    # A checker that graded nothing must never be mistaken for a pass.
    if checked == 0:
        print("STAGE4_COMPARE: FAIL - zero pairs checked, nothing was graded")
        return 1

    if swapped_rule > ok:
        print(f"STAGE4_COMPARE: FAIL - {swapped_rule}/{checked} emitted pairs satisfy "
              f"the BYTE-REVERSED rule (Hash0_be < target) instead of Hash0 < target. "
              f"The Verify process is comparing the reported word rather than the "
              f"compare value; see the Verify block in "
              f"src/OspreyBlake2bStage4Core.vhd.")
        for f in failures:
            print(f)
        return 1

    if ok != checked:
        print(f"STAGE4_COMPARE: FAIL - {checked - ok}/{checked} emitted pairs do not "
              f"satisfy Hash0 < target, and they do not match the byte-reversed "
              f"rule either")
        for f in failures:
            print(f)
        return 1

    # Guard against the degenerate pass: if the core emitted on essentially every
    # cycle then the target was effectively MAX and this proved nothing, which is
    # exactly the hole tb_stage4_prefilter leaves.
    if cycles:
        rate = checked / cycles
        expected = target / 2 ** 64
        print(f"        hit rate {rate:.6f} against P(target)={expected:.6f}")
        if rate > 0.5:
            print("STAGE4_COMPARE: FAIL - the core emitted on most cycles, so the "
                  "target was not discriminating and the comparison is untested")
            return 1

    print(f"STAGE4_COMPARE: PASS - all {checked} emitted pairs satisfy Hash0 < target")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
