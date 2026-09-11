#!/usr/bin/env python3
"""Golden-reference decoder for Sia-style Stratum v1, mapped onto the FPGA's
stage-3 / stage-4 messages.

The pool at us-central01.miningrigrentals.com:50806 serves Bitcoin Knots
BLAKE2b (BTCB2) work over the Sia stratum dialect, not the Bitcoin one. That is
lucky rather than coincidental: the Sia dialect hands the miner exactly the two
BLAKE2b messages the Osprey pipeline already implements, so no re-derivation of
stages 1, 2 or 5 is needed on the miner side. This file is the boundary between
"what the pool said" and "what goes in the 168-byte work item", and it exists so
that a mis-decode is caught here instead of showing up as a silently zero share
rate.

The mapping, which is exact:

    arbtx        = coinb1 || extranonce1 || extranonce2 || coinb2
    ss3          = 0x00 || arbtx                                   (52 bytes)
                 = u32(0) || h2_hash(32) || m_extranonce(16)
    merkleroot   = fold(blake2b(0x00 || arbtx), merkle_branch)
                 = hash_a = blake2b(ss3)    when the branch list is empty
    ss4          = prevhash(32) || nonce(8) || ntime(8) || merkleroot(32)
                 = prev_hidden(32) || nNonce(4) || m_nonce2(4)
                   || m_time_offset(4) || m_nonce3(4) || hash_a(32)

so the pool's 64-bit nonce field lands on ss4[32:40], which is precisely slot 4
of the 10x64-bit array OspreyBlake2bStage4Core grinds. The Sia 64-bit nonce and
the Knots (nNonce, m_nonce2) pair are the same eight bytes seen through two
different struct definitions.

Three traps this file is built to guard against:

  1. The compare rule. Sia compares the BLAKE2b digest in emission order, so its
     leading zeros live in H[0]. Bitcoin reverses the digest before comparing
     (final[31-i] = hash_b[i]), so its most significant eight bytes are
     digest[31..24] -- H[3] read big-endian. We speak Sia's *transport* while
     obeying Bitcoin's *compare*. Tapping H[0] here is not wrong by a constant;
     it is uncorrelated with the target, so a miner would report candidates at
     the normal rate and have every single one rejected. Both rules are exported
     (pow_compare_value / sia_compare_value) and neither is the default by
     accident -- see the docstrings.

  2. The field widths. Sia stratum's ntime and nonce are 64-bit, so
     mining.submit carries 16 hex characters per field, not Bitcoin's 8. A
     decoder that assumes 8 silently truncates the nonce and submits garbage.

  3. coinb2. The Sia spec appends coinb2 to the arbitrary transaction. The live
     BTCB2 pool sends coinb2 = "", which is the only reason ss3 comes out at
     exactly 52 bytes. A non-empty coinb2 would break the FPGA mapping outright,
     so it is asserted rather than silently truncated.

Usage:
    py -3 zynq/sia_reference.py --selftest
    py -3 zynq/sia_reference.py --emit-stratum-vectors 8 [--seed 0x5A1A]
"""

from __future__ import annotations

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from blake2b_reference import (  # noqa: E402
    blake2b_nokey,
    compact_to_target,
    sha256,
    tagged_hash,
)

# ---------------- constants ----------------

STAGE3_LEN = 52
STAGE4_LEN = 80
SLOTS = 10

# Offsets inside the 80-byte Sia header, which is also ss4.
PREVHASH_OFF = 0
NONCE_OFF = 32
NTIME_OFF = 40
MERKLE_OFF = 48
NONCE_LEN = 8
NTIME_LEN = 8

MASK64 = 0xFFFFFFFFFFFFFFFF

# Stratum difficulty-1 target, per the SiaMining stratum spec. Identical to
# Bitcoin's pdiff-1 constant; the pool scales it by 1/difficulty.
DIFF1_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000

# Sia merkle domain separators. The leaf tag also supplies ss3's leading u32(0)
# together with the three zero bytes at the head of coinb1.
LEAF_TAG = b"\x00"
NODE_TAG = b"\x01"


def _as_bytes(v, what: str) -> bytes:
    """Accept either raw bytes or a hex string, because stratum mixes both."""
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    if isinstance(v, str):
        try:
            return bytes.fromhex(v)
        except ValueError as exc:
            raise ValueError(f"{what} is not valid hex: {v!r}") from exc
    raise TypeError(f"{what} must be bytes or a hex str, got {type(v).__name__}")


# ---------------- arbitrary transaction and merkle fold ----------------

def arbitrary_tx(coinb1, extranonce1, extranonce2, coinb2=b"") -> bytes:
    """Assemble the Sia "arbitrary transaction" the pool splices the miner into.

    Concatenation order is fixed by the stratum spec: coinb1, then the pool's
    extranonce1, then the miner's extranonce2, then coinb2. The live BTCB2 pool
    sends coinb2 = "" so the tail is a no-op there, but it is honoured rather
    than dropped -- a decoder that ignores coinb2 would produce a subtly wrong
    merkle root against any pool that uses it, and the resulting shares would
    look like plain bad luck.
    """
    return (_as_bytes(coinb1, "coinb1")
            + _as_bytes(extranonce1, "extranonce1")
            + _as_bytes(extranonce2, "extranonce2")
            + _as_bytes(coinb2, "coinb2"))


def arbtx_leaf(arbtx: bytes) -> bytes:
    """Leaf hash of the arbitrary transaction: blake2b(0x00 || arbtx).

    This 0x00 || arbtx byte string *is* ss3. The FPGA's stage-3 core hashes it
    verbatim, so its length is the FPGA mapping's load-bearing invariant and is
    checked by the caller (stratum_job_to_stages), not swallowed here.
    """
    return blake2b_nokey(LEAF_TAG + _as_bytes(arbtx, "arbtx"), outlen=32)


def merkle_root_from_branches(leaf: bytes, branches) -> bytes:
    """Fold the miner's leaf up through the pool's merkle branch.

    The arbitrary transaction is the RIGHTMOST leaf of the tree, so at every
    step the pool's branch element is the left child and the accumulator is the
    right one: acc = blake2b(0x01 || branch || acc). Swapping the operands still
    produces a well-formed 32-byte value, which is exactly why it has to be
    pinned by a test rather than eyeballed.
    """
    acc = _as_bytes(leaf, "leaf")
    if len(acc) != 32:
        raise ValueError(f"leaf must be 32B, got {len(acc)}")
    for i, br in enumerate(branches):
        b = _as_bytes(br, f"merkle_branch[{i}]")
        if len(b) != 32:
            raise ValueError(f"merkle_branch[{i}] must be 32B, got {len(b)}")
        acc = blake2b_nokey(NODE_TAG + b + acc, outlen=32)
    return acc


# ---------------- header ----------------

def build_header(prevhash, nonce, ntime, merkleroot) -> bytes:
    """Assemble the 80-byte Sia header, which is byte-identical to ss4.

    Every field is passed through in the byte order it travels on the wire; the
    pool's prevhash is already the Knots prev_hidden value, so nothing is
    reversed here. Reversing it "to be safe" is a popular way to produce a
    plausible-looking header that hashes to noise.
    """
    hdr = (_as_bytes(prevhash, "prevhash")
           + _as_bytes(nonce, "nonce")
           + _as_bytes(ntime, "ntime")
           + _as_bytes(merkleroot, "merkleroot"))
    assert len(hdr) == STAGE4_LEN, (
        f"header must be {STAGE4_LEN}B, got {len(hdr)} "
        f"(prevhash/merkleroot must be 32B and nonce/ntime 8B each -- "
        f"an 8-hex-char nonce is the Bitcoin width, not Sia's)")
    return hdr


# ---------------- compare rules ----------------

def pow_compare_value(header: bytes) -> int:
    """Knots rule: hash the header, BYTE-REVERSE the digest, read big-endian.

    This is the value that must be <= target for a BTCB2 share, and it is the
    rule the Osprey RTL implements. Its most significant eight bytes are
    digest[24:32] read big-endian (BLAKE2b's H[3] byteswapped), which is what
    the stage-4 prefilter reports as HashTop64.

    USE THIS ONE for anything that touches the BTCB2 pool or the FPGA.
    """
    digest = blake2b_nokey(_as_bytes(header, "header"), outlen=32)
    return int.from_bytes(digest, "little")   # == int.from_bytes(digest[::-1], 'big')


def pow_compare_top64(header: bytes) -> int:
    """The ORDERABLE top 64 bits of the Knots compare value: compare >> 192.

    Equal to BLAKE2b's H[3] read as a native little-endian word, i.e.
    struct.unpack('<Q', digest[24:32])[0]. This is the only 64-bit word that can
    legitimately be compared against build_work_item.target_top64(), because
    both are the most significant 64 bits of the same big-endian 256-bit number.

    It is deliberately NOT the same as expected_hash_top64(); see that
    function's docstring for the byteswap the hardware applies.
    """
    return (pow_compare_value(header) >> 192) & MASK64


def sia_compare_value(header: bytes) -> int:
    """Siacoin rule: hash the header and read the digest big-endian, as emitted.

    Provided for the Phase B Sia core, which mines real Siacoin and therefore
    puts its leading zeros in H[0] rather than H[3]. It is deliberately NOT the
    default: using it against BTCB2 yields a value uncorrelated with the target,
    so the miner reports candidates at the usual rate and every one is rejected.
    See zynq/check_stage4_pairs.py, which exists to name that exact regression.
    """
    digest = blake2b_nokey(_as_bytes(header, "header"), outlen=32)
    return int.from_bytes(digest, "big")


# ---------------- targets ----------------

def difficulty_to_target(difficulty: float) -> int:
    """Stratum difficulty -> 256-bit target (DIFF1_TARGET / difficulty).

    Pool difficulties below 1 are normal on a test rig and give a target LARGER
    than diff-1, so the result is clamped to 256 bits rather than allowed to
    overflow into a target no hash can exceed.
    """
    if difficulty <= 0:
        raise ValueError(f"difficulty must be positive, got {difficulty}")
    target = int(DIFF1_TARGET / difficulty)
    return min(target, (1 << 256) - 1)


def target_to_top64(target: int) -> int:
    """Top 64 bits of a 256-bit target -- the TargetTop64 the FPGA prefilters on."""
    return (target >> 192) & MASK64


def nbits_to_target(nbits) -> int:
    """Decode a stratum nbits field (little-endian on the wire) to a target.

    Sia stratum ships nBits byte-reversed relative to the RPC form: the pool's
    "d4c20319" is the node's 0x1903c2d4. Feeding the wire bytes straight into
    compact_to_target decodes exponent 0xd4, which is nonsense, so the reversal
    is done here once instead of at every call site.
    """
    b = _as_bytes(nbits, "nbits")
    if len(b) != 4:
        raise ValueError(f"nbits must be 4B, got {len(b)}")
    return compact_to_target(struct.unpack("<I", b)[0])


def prevhash_from_block_hash(block_hash) -> bytes:
    """Derive the pool's prevhash field from a getblocktemplate previousblockhash.

    prev_hidden = TaggedHash("Bitcoin prevblock header, hashed", prev_sane) with
    bytes 0..5 forced to zero. previousblockhash arrives in display order, which
    is already the "sane" order the tagged hash wants -- it is NOT reversed
    again. This was proven against the live pool: the value computed here from
    our own node's template equals the pool's mining.notify prevhash byte for
    byte.
    """
    prev_sane = _as_bytes(block_hash, "block_hash")
    if len(prev_sane) != 32:
        raise ValueError(f"block hash must be 32B, got {len(prev_sane)}")
    hidden = bytearray(tagged_hash("Bitcoin prevblock header, hashed", prev_sane))
    for i in range(6):
        hidden[i] = 0
    return bytes(hidden)


# ---------------- the whole decode ----------------

def stratum_job_to_stages(job, extranonce1, extranonce2):
    """Decode one mining.notify into (ss3, ss4, merkleroot).

    `job` is the 9-element params list exactly as the pool sends it:
        [job_id, prevhash, coinb1, coinb2, merkle_branch,
         version, nbits, ntime, clean_jobs]

    ss4 comes back with its nonce slot ZEROED. The nonce is what the FPGA
    grinds, so baking one in here would mean every work item carried a stale
    starting point; callers set it via expected_hash_top64 or by splicing eight
    bytes at NONCE_OFF.
    """
    if len(job) != 9:
        raise ValueError(
            f"mining.notify params must have 9 elements, got {len(job)}: {job!r}")
    _job_id, prevhash, coinb1, coinb2, branches, _version, _nbits, ntime, _clean = job

    arbtx = arbitrary_tx(coinb1, extranonce1, extranonce2, coinb2)
    ss3 = LEAF_TAG + arbtx
    # The FPGA's stage-3 core hashes a fixed 52-byte message. A pool that
    # widened coinb1, extranonce2 or coinb2 would still produce a valid Sia
    # share and a completely invalid work item, so this is a hard stop with the
    # arithmetic spelled out rather than a truncation.
    if len(ss3) != STAGE3_LEN:
        raise ValueError(
            f"ss3 must be {STAGE3_LEN}B, got {len(ss3)}: "
            f"1 + coinb1 {len(_as_bytes(coinb1, 'coinb1'))} "
            f"+ extranonce1 {len(_as_bytes(extranonce1, 'extranonce1'))} "
            f"+ extranonce2 {len(_as_bytes(extranonce2, 'extranonce2'))} "
            f"+ coinb2 {len(_as_bytes(coinb2, 'coinb2'))}; "
            f"the FPGA stage-3 core cannot hash this job")

    merkleroot = merkle_root_from_branches(arbtx_leaf(arbtx), branches or [])
    ss4 = build_header(prevhash, b"\x00" * NONCE_LEN, ntime, merkleroot)
    return ss3, ss4, merkleroot


def expected_hash_top64(ss4: bytes, nonce: int) -> int:
    """HashTop64 the stage-4 prefilter reports for this (ss4, nonce).

    The nonce is written little-endian into ss4[32:40] -- slot 4 of the core's
    10x64-bit array -- and the answer is digest[24:32] read BIG-endian. That
    matches src/OspreyBlake2bStage4Core.vhd (Hash0_be, lines 194-198) and
    miner/miner.c::expected_hash_top64, so this function predicts what the
    hardware actually puts on the wire.

    CAUTION -- this is byteswap(H[3]), not the top 64 bits of the compare value.
    The Knots compare value is int.from_bytes(hash_b, 'little'), whose top 64
    bits are H[3] read LITTLE-endian (see pow_compare_top64). The RTL byteswaps
    that word before both reporting it and comparing it against TargetTop64,
    while build_work_item.target_top64() supplies an un-swapped target. Byteswap
    does not preserve ordering, so the two are not comparable. That mismatch is
    a pre-existing hardware/host issue outside this file's scope; this function
    tracks the hardware on purpose, because its job is to predict the report and
    let miner.c's frame check succeed. The relationship is pinned by the
    selftest, so whichever side is changed first, that check names it.
    """
    buf = bytearray(_as_bytes(ss4, "ss4"))
    if len(buf) != STAGE4_LEN:
        raise ValueError(f"ss4 must be {STAGE4_LEN}B, got {len(buf)}")
    struct.pack_into("<Q", buf, NONCE_OFF, nonce & MASK64)
    digest = blake2b_nokey(bytes(buf), outlen=32)
    return int.from_bytes(digest[24:32], "big")


def pack_slots(msg: bytes) -> bytes:
    """Zero-pad a stage message out to the 10x64-bit slot array the core reads."""
    if len(msg) > SLOTS * 8:
        raise ValueError(f"message {len(msg)}B exceeds {SLOTS * 8}B slot array")
    return msg + b"\x00" * (SLOTS * 8 - len(msg))


# ---------------- captured fixture ----------------

# A real mining.notify from us-central01.miningrigrentals.com:50806, captured
# live, kept verbatim so the selftest grades against the wire and not against
# our own idea of the wire. ntime is eight zero bytes on this pool, and the
# merkle branch is empty, which is what makes merkleroot == blake2b(ss3).
CAPTURED_JOB = [
    "a647000013c7",                                                       # job_id
    "00000000000075a242522fd4708844dfbb8d6d5c302dc356935e08513503dbdd",   # prevhash
    "00000031bd27d82a5b25e42446814eab790095046062020d73a167e069766bdbbf98a800000000",  # coinb1
    "",                                                                   # coinb2
    [],                                                                   # merkle_branch
    "",                                                                   # version
    "d4c20319",                                                           # nbits (LE)
    "0000000000000000",                                                   # ntime
    True,                                                                 # clean_jobs
]
CAPTURED_EXTRANONCE1 = "2fed4795"
CAPTURED_EXTRANONCE2_SIZE = 8


# ---------------- selftest ----------------

def _selftest() -> int:
    """Grade every documented invariant. Zero checks run is a FAILURE."""
    checks = []

    def check(name, fn):
        checks.append((name, fn))

    # (a) The 52-byte invariant, from the real field widths.
    def _c_ss3_len():
        coinb1 = bytes(39)
        arbtx = arbitrary_tx(coinb1, bytes(4), bytes(8))
        assert len(arbtx) == 51, f"arbtx {len(arbtx)}"
        assert len(LEAF_TAG + arbtx) == STAGE3_LEN, f"ss3 {len(LEAF_TAG + arbtx)}"
    check("ss3 = 0x00 || 39B coinb1 || 4B en1 || 8B en2 is 52 bytes", _c_ss3_len)

    # (b) An empty branch list must be the identity, or a solo-mining-shaped job
    # would get an extra fold and hash to noise.
    def _c_empty_branch():
        leaf = blake2b_nokey(b"leaf probe", outlen=32)
        assert merkle_root_from_branches(leaf, []) == leaf
    check("empty merkle branch folds to the leaf itself", _c_empty_branch)

    # (c) Three-branch fold against a hand-rolled loop, including operand order.
    def _c_three_branch():
        leaf = blake2b_nokey(b"leaf probe", outlen=32)
        brs = [blake2b_nokey(bytes([i]), outlen=32).hex() for i in range(3)]
        got = merkle_root_from_branches(leaf, brs)
        acc = leaf
        for br in brs:
            acc = blake2b_nokey(b"\x01" + bytes.fromhex(br) + acc, outlen=32)
        assert got == acc, f"got={got.hex()} want={acc.hex()}"
        # Operand order must actually matter, otherwise this check is vacuous.
        swapped = leaf
        for br in brs:
            swapped = blake2b_nokey(b"\x01" + swapped + bytes.fromhex(br), outlen=32)
        assert got != swapped, "left/right fold order is not observable -- check is vacuous"
    check("3-branch fold matches a hand-rolled loop (and order is observable)",
          _c_three_branch)

    # (d) The diff-1 constant, both directions.
    def _c_diff1():
        assert difficulty_to_target(1) == DIFF1_TARGET, (
            f"0x{difficulty_to_target(1):064x} != 0x{DIFF1_TARGET:064x}")
        assert target_to_top64(DIFF1_TARGET) == 0x00000000FFFF0000
        # Below 1 must get EASIER (bigger target), not harder.
        assert difficulty_to_target(0.001) > DIFF1_TARGET
        assert difficulty_to_target(4096) < DIFF1_TARGET
    check("difficulty_to_target(1) is the documented diff-1 constant", _c_diff1)

    # (e) The real captured job decodes to the FPGA's two messages.
    def _c_real_job():
        en2 = bytes(CAPTURED_EXTRANONCE2_SIZE)
        ss3, ss4, root = stratum_job_to_stages(CAPTURED_JOB, CAPTURED_EXTRANONCE1, en2)
        assert len(ss3) == STAGE3_LEN, f"ss3 {len(ss3)}"
        assert len(ss4) == STAGE4_LEN, f"ss4 {len(ss4)}"
        assert blake2b_nokey(ss3, outlen=32) == root, (
            f"hash_a != merkleroot\n  hash_a={blake2b_nokey(ss3, outlen=32).hex()}"
            f"\n  root  ={root.hex()}")
        assert ss4[MERKLE_OFF:] == root, "merkleroot is not at ss4[48:80]"
        assert ss4[NONCE_OFF:NONCE_OFF + NONCE_LEN] == bytes(8), "nonce slot not zeroed"
        assert ss4[:32] == bytes.fromhex(CAPTURED_JOB[1]), "prevhash was mangled"
        # ss3's leading u32 must be zero -- that is what makes it a valid
        # stage-3 message and not just a 52-byte blob.
        assert ss3[:4] == bytes(4), f"ss3 must start with u32(0), got {ss3[:4].hex()}"
    check("captured live job -> 52B ss3, 80B ss4, blake2b(ss3) == merkleroot",
          _c_real_job)

    # (f) expected_hash_top64 against a fully independent recomputation.
    def _c_top64():
        en2 = bytes(CAPTURED_EXTRANONCE2_SIZE)
        ss3, ss4, root = stratum_job_to_stages(CAPTURED_JOB, CAPTURED_EXTRANONCE1, en2)
        n = 0
        for nonce in (0, 1, 0x0123456789ABCDEF, MASK64):
            got = expected_hash_top64(ss4, nonce)
            # Rebuild the header from the job's own fields rather than by
            # mutating ss4, and slice the digest with a different call.
            hdr = build_header(CAPTURED_JOB[1], struct.pack("<Q", nonce),
                               CAPTURED_JOB[7], root)
            digest = blake2b_nokey(hdr, outlen=32)
            want = struct.unpack(">Q", digest[24:32])[0]
            assert got == want, f"nonce={nonce:016x} got={got:016x} want={want:016x}"
            # It must come from H[3], not H[0]: tapping H[0] is the Sia word and
            # is uncorrelated with the Bitcoin target.
            wrong_h0 = struct.unpack(">Q", digest[0:8])[0]
            assert got != wrong_h0 or digest[0:8] == digest[24:32], (
                f"nonce={nonce:016x} H[3] tap collided with the H[0] tap")
            if got != wrong_h0:
                n += 1
        assert n > 0, "H[3] and H[0] agreed on every nonce -- check is vacuous"
    check("expected_hash_top64 == byteswap(H[3]) on 4 nonces, and != H[0]", _c_top64)

    # Pin the byteswap between what the hardware reports and what is orderable
    # against a target. These are NOT the same word; see expected_hash_top64.
    # If either side is ever changed, this is the check that names it.
    def _c_top64_vs_orderable():
        ss3, ss4, root = stratum_job_to_stages(
            CAPTURED_JOB, CAPTURED_EXTRANONCE1, bytes(8))
        differ = 0
        for nonce in (0, 7, 0xFEDCBA9876543210):
            hdr = build_header(CAPTURED_JOB[1], struct.pack("<Q", nonce),
                               CAPTURED_JOB[7], root)
            reported = expected_hash_top64(ss4, nonce)
            orderable = pow_compare_top64(hdr)
            assert reported == struct.unpack(
                ">Q", struct.pack("<Q", orderable))[0], (
                f"nonce={nonce:016x}: reported {reported:016x} is not "
                f"byteswap(orderable {orderable:016x})")
            assert orderable == struct.unpack("<Q", blake2b_nokey(
                hdr, outlen=32)[24:32])[0], "orderable top64 must be H[3] as-is"
            if reported != orderable:
                differ += 1
        assert differ > 0, (
            "reported and orderable agreed on every nonce -- check is vacuous")
    check("hardware HashTop64 is byteswap(orderable top64), pinned both ways",
          _c_top64_vs_orderable)

    # The two compare rules must be genuinely different, or exporting both is a lie.
    def _c_rules_differ():
        hdr = build_header(bytes(32), bytes(8), bytes(8), bytes(32))
        assert pow_compare_value(hdr) != sia_compare_value(hdr)
        digest = blake2b_nokey(hdr, outlen=32)
        assert pow_compare_value(hdr) == int.from_bytes(digest[::-1], "big")
        assert sia_compare_value(hdr) == int.from_bytes(digest, "big")
    check("pow_compare_value and sia_compare_value are distinct rules",
          _c_rules_differ)

    # nbits on the wire is byte-reversed relative to the node's RPC form.
    def _c_nbits():
        assert nbits_to_target(CAPTURED_JOB[6]) == compact_to_target(0x1903C2D4), (
            "pool nbits d4c20319 must decode as node bits 1903c2d4")
        assert nbits_to_target(CAPTURED_JOB[6]) != compact_to_target(0xD4C20319)
    check("pool nbits d4c20319 decodes as node bits 1903c2d4", _c_nbits)

    # prevhash derivation, including the six zeroed bytes.
    def _c_prevhash():
        probe = sha256(b"prevhash probe")
        hidden = prevhash_from_block_hash(probe)
        assert len(hidden) == 32
        assert hidden[:6] == bytes(6), f"bytes 0..5 not cleared: {hidden[:6].hex()}"
        raw = tagged_hash("Bitcoin prevblock header, hashed", probe)
        assert hidden[6:] == raw[6:], "tail must be the untouched tagged hash"
        # The captured prevhash has the same six-zero signature, which is the
        # cheap check that the pool really is sending prev_hidden and not a
        # plain block hash.
        assert bytes.fromhex(CAPTURED_JOB[1])[:6] == bytes(6)
    check("prevhash_from_block_hash zeroes bytes 0..5 and keeps the tail",
          _c_prevhash)

    # A wider coinb2 must be refused loudly, not truncated into a bad work item.
    def _c_coinb2_guard():
        bad = list(CAPTURED_JOB)
        bad[3] = "deadbeef"
        try:
            stratum_job_to_stages(bad, CAPTURED_EXTRANONCE1, bytes(8))
        except ValueError as exc:
            assert "52" in str(exc), f"error should name the 52-byte rule: {exc}"
            return
        raise AssertionError("non-empty coinb2 must be rejected, not truncated")
    check("non-empty coinb2 is refused with the 52-byte arithmetic", _c_coinb2_guard)

    # A Bitcoin-width (4-byte) nonce must not assemble into a header.
    def _c_width_guard():
        try:
            build_header(bytes(32), bytes(4), bytes(8), bytes(32))
        except AssertionError:
            return
        raise AssertionError("a 4-byte nonce must not produce an 80-byte header")
    check("a Bitcoin-width 4-byte nonce is rejected by build_header",
          _c_width_guard)

    # The slot packing the emitter uses must round-trip.
    def _c_slots():
        ss3, ss4, _ = stratum_job_to_stages(
            CAPTURED_JOB, CAPTURED_EXTRANONCE1, bytes(8))
        s3 = struct.unpack("<10Q", pack_slots(ss3))
        s4 = struct.unpack("<10Q", pack_slots(ss4))
        assert b"".join(struct.pack("<Q", s) for s in s3)[:STAGE3_LEN] == ss3
        assert b"".join(struct.pack("<Q", s) for s in s4) == ss4
        assert s3[7:] == (0, 0, 0), "ss3 tail slots must be zero padding"
    check("10x u64 slot packing round-trips both stage messages", _c_slots)

    # The emitter's whole contract is which FPGA topology a vector is valid for.
    # Pin BOTH directions: a branch-free vector must satisfy root == blake2b(ss3)
    # (the chained Knots core), and a branch-carrying one must NOT (the Sia core
    # that takes the root directly). Asserting only the first would let the
    # emitter silently start folding branches again and still pass -- which is
    # exactly the defect this check was added to catch.
    def _c_topology():
        job_no = [f"{1:012x}", prevhash_from_block_hash(bytes(32)).hex(),
                  (bytes(3) + sha256(b"h2") + bytes(4)).hex(), "",
                  [], "", "d4c20319", "0000000000000000", True]
        ss3, ss4, root = stratum_job_to_stages(job_no, bytes(4), bytes(8))
        assert blake2b_nokey(ss3, outlen=32) == root == ss4[48:80], \
            "branch-free job must put blake2b(ss3) in the merkle slots"

        job_br = list(job_no)
        job_br[4] = [blake2b_nokey(b"\x01", outlen=32).hex()]
        ss3b, ss4b, rootb = stratum_job_to_stages(job_br, bytes(4), bytes(8))
        assert ss3b == ss3, "a merkle branch must not disturb stage 3"
        assert rootb == ss4b[48:80]
        assert rootb != blake2b_nokey(ss3b, outlen=32), \
            "a folded root must differ from the stage-3 hash, or the fold is a no-op"
    check("branch-free root == blake2b(ss3); folded root differs", _c_topology)

    passed = 0
    for name, fn in checks:
        try:
            fn()
        except Exception as exc:                      # noqa: BLE001 - report, don't mask
            print(f"  FAIL {name}\n       {type(exc).__name__}: {exc}")
        else:
            passed += 1
            print(f"  OK   {name}")

    total = len(checks)
    if total == 0:
        # A selftest that graded nothing is a failure, not a silent pass.
        print("RESULT: 0/0 FAIL - no checks were run")
        return 1
    print(f"\nRESULT: {passed}/{total} {'PASS' if passed == total else 'FAIL'}")
    return 0 if passed == total else 1


# ---------------- deterministic vector emitter ----------------

def _emit_stratum_vectors(n: int, seed: int = 0x5A1A, max_branches: int = 0) -> None:
    """Emit N deterministic stratum-derived vectors to stdout.

    Each line is 22 space-separated 16-hex-digit fields:
        10 ss3 slots | 10 ss4 slots | TargetTop64 | expected HashTop64

    Slot packing is the same little-endian struct.unpack('<10Q', padded)
    convention blake2b_reference._emit_stage3_vectors uses, so these vectors
    drop into the existing testbench readers unchanged.

    The vectors are built by running a synthetic-but-well-formed stratum job
    through stratum_job_to_stages rather than by filling both messages with
    random bytes, so they exercise the real decode rather than two unrelated
    hashes.

    max_branches selects which FPGA topology the vector is valid for, and the
    distinction is not cosmetic:

      max_branches == 0 (default)
        No merkle branch, so the root IS blake2b(ss3). These vectors suit the
        CHAINED topology the shipped Knots bitstream implements, where
        OspreyBlake2bTop wires Stage4Msg(6..9) from Stage3's output and the
        work item's own merkle slots are ignored (OspreyBlake2bTop.vhd:95-98).

      max_branches > 0
        A fold is applied, so the root is NOT blake2b(ss3). Such a vector can
        only be mined by a core that takes the root DIRECTLY from the work
        item -- i.e. the Sia topology, which drops stage 3 entirely.

    Feeding branch-carrying vectors to a bench for the chained core would look
    like a hashing bug when it is really a topology mismatch, which is why this
    defaults to 0 rather than to "some variety". The C client refuses such jobs
    for the same reason (see worksrc_stratum.c).

    TargetTop64 is set to expected+1, i.e. every emitted vector is a case the
    prefilter MUST report as a hit. This mirrors _emit_stage4_vectors' choice; a
    vector whose target is unreachable proves nothing about the compare path.
    """
    import random
    rng = random.Random(seed)
    for _ in range(n):
        # A well-formed job: 3 zero bytes + a 32-byte pseudo-h2_hash + 4 bytes
        # of extranonce head, which is exactly the shape the live pool sends.
        pseudo_h2 = sha256(bytes(rng.getrandbits(8) for _ in range(16)))
        coinb1 = bytes(3) + pseudo_h2 + bytes(rng.getrandbits(8) for _ in range(4))
        en1 = bytes(rng.getrandbits(8) for _ in range(4))
        en2 = bytes(rng.getrandbits(8) for _ in range(8))
        prevhash = prevhash_from_block_hash(
            bytes(rng.getrandbits(8) for _ in range(32)))
        branches = [blake2b_nokey(bytes([rng.getrandbits(8)]), outlen=32).hex()
                    for _ in range(rng.randint(0, max_branches) if max_branches else 0)]
        job = [f"{rng.getrandbits(48):012x}", prevhash.hex(), coinb1.hex(), "",
               branches, "", "d4c20319", "0000000000000000", True]

        ss3, ss4, _ = stratum_job_to_stages(job, en1, en2)
        nonce = rng.getrandbits(64)
        expected = expected_hash_top64(ss4, nonce)

        # Bake the nonce into the emitted ss4 so the vector is self-contained;
        # the bench reads slot 4 as the nonce under test.
        ss4_at_nonce = bytearray(ss4)
        struct.pack_into("<Q", ss4_at_nonce, NONCE_OFF, nonce)

        s3 = struct.unpack("<10Q", pack_slots(ss3))
        s4 = struct.unpack("<10Q", pack_slots(bytes(ss4_at_nonce)))
        target_top64 = (expected + 1) & MASK64
        fields = list(s3) + list(s4) + [target_top64, expected]
        print(" ".join(f"{f:016x}" for f in fields))


def sia_top64(header: bytes, nonce: int) -> int:
    """Top 64 bits of SIACOIN's compare value for this nonce.

    Siacoin compares the digest in the order blake2b emits it, so digest[0] is
    the most significant byte and the leading zeros live at the FRONT. Since
    digest[0:8] is h[0] serialised little-endian, this value is byteswap(h[0]) --
    which is exactly what OspreySiaCore's Hash0_be carries.

    This is NOT expected_hash_top64() above. That one reads digest[24:32], the
    Knots rule, because Bitcoin reverses the whole digest first. The two are the
    single difference between the two cores, and a core built for one chain will
    pass every length, framing and nonce test while mining the other chain into
    the void -- so the two functions are kept separate and named for their chain.
    """
    h = bytearray(header)
    struct.pack_into("<Q", h, NONCE_OFF, nonce & MASK64)
    digest = blake2b_nokey(bytes(h), outlen=32)
    return int.from_bytes(digest[0:8], "big")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--selftest", action="store_true",
                    help="grade every documented invariant and print RESULT: n/n")
    ap.add_argument("--emit-stratum-vectors", type=int, metavar="N",
                    help="emit N deterministic vectors, one per line")
    ap.add_argument("--seed", type=lambda s: int(s, 0), default=0x5A1A,
                    help="RNG seed for --emit-stratum-vectors (default 0x5A1A)")
    ap.add_argument("--branches", type=int, default=0, metavar="K",
                    help="emit vectors carrying up to K merkle branches. 0 (the "
                         "default) keeps root == blake2b(ss3), which is what the "
                         "chained Knots core needs; >0 produces direct-root "
                         "vectors, which only a Sia-topology core can mine")
    a = ap.parse_args(argv)

    if a.emit_stratum_vectors is not None:
        if a.emit_stratum_vectors <= 0:
            print("--emit-stratum-vectors needs a positive count", file=sys.stderr)
            return 2
        if a.branches < 0:
            print("--branches cannot be negative", file=sys.stderr)
            return 2
        _emit_stratum_vectors(a.emit_stratum_vectors, a.seed, a.branches)
        return 0
    return _selftest()


if __name__ == "__main__":
    raise SystemExit(main())
