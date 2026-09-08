#!/usr/bin/env python3
"""
Build the 168-byte UART work item that OspreyBlake2bUartTop expects, from a
Bitcoin Knots block template, and prove it is correct against the golden
reference in blake2b_reference.py.

The FPGA implements only stages 3 and 4 of CBlockHeader::GetHash. Stages 1 and 2
(the SHA256d tagged hashes) and stage 5 (the XOR + byte reverse) stay on the zynq.
This module is the boundary: it turns a header into exactly the bytes that go down
the wire, and it re-derives the same values through the golden reference so a
mismatch is caught here rather than on hardware.

Wire format (see OspreyBlake2bUartTop.vhd):
    zynq -> FPGA, 168 bytes
        bytes   0.. 79  Stage3In slots 0..9   (8 bytes each, slot 0 first)
        bytes  80..159  Stage4In slots 0..9
        bytes 160..167  TargetTop64
    FPGA -> zynq, 17 bytes
        byte    0       0x01 success flag
        bytes   1.. 8   Nonce
        bytes   9..16   HashTop64

Usage:
    py -3 build_work_item.py --selftest
    py -3 build_work_item.py --from-node          # needs BTC_RPC_* env vars
"""
import argparse
import json
import os
import struct
import sys
import urllib.request
import base64

from blake2b_reference import (
    KnotsBlockHeaderV2,
    tagged_hash,
    blake2b_nokey,
    compact_to_target,
    apply_blake2b_target_shift,
    get_pow_hash,
)

STAGE3_LEN = 52
STAGE4_LEN = 80
SLOTS = 10
WORK_ITEM_LEN = 168
RESULT_LEN = 17


def stage_inputs(hdr: KnotsBlockHeaderV2):
    """Re-derive the stage-3 and stage-4 messages exactly as get_pow_hash does.

    Returns (ss3, ss4, hash_a). Kept deliberately parallel to the body of
    get_pow_hash so the two cannot drift silently; test_matches_reference()
    asserts they agree.
    """
    prevblock_ordered_sane = hdr.hashPrevBlock[::-1]
    xor_key_inner = tagged_hash("Bitcoin block hash PoW XOR key", hdr.m_xor_key)

    h1_payload = bytearray()
    h1_payload += struct.pack('<I', hdr.get_complete_version())
    h1_payload += prevblock_ordered_sane
    h1_payload += struct.pack('<i', hdr.m_height)
    h1_payload += hdr.hashMerkleRoot
    h1_payload += struct.pack('<I', hdr.get_time_on_wire())
    h1_payload += b'\x00'
    h1_payload += struct.pack('<I', hdr.nBits)
    h1_payload += struct.pack('<I', hdr.m_txcount)
    h1_payload += struct.pack('<B', hdr.m_flags)
    h1_payload += struct.pack('<B', hdr.m_xor_key_mask_clear_bits)
    h1_payload += xor_key_inner
    assert len(h1_payload) == 119, f"h1 payload must be 119B, got {len(h1_payload)}"
    h1_hash = tagged_hash("Bitcoin block header 1", bytes(h1_payload))

    h2_payload = h1_hash + b'\x00' * 32 + hdr.m_mm_rhs
    h2_hash = tagged_hash("Merge-mining hook", bytes(h2_payload))

    ss3 = struct.pack('<I', 0) + h2_hash + hdr.m_extranonce
    assert len(ss3) == STAGE3_LEN, f"stage3 msg must be {STAGE3_LEN}B, got {len(ss3)}"
    hash_a = blake2b_nokey(ss3, outlen=32)

    mode = hdr.m_flags & 3
    if mode != 0:
        raise NotImplementedError(
            f"the FPGA pipeline implements stage-4 mode 0 only; header requests mode {mode}")

    prevblock_hidden = bytearray(
        tagged_hash("Bitcoin prevblock header, hashed", prevblock_ordered_sane))
    for i in range(6):
        prevblock_hidden[i] = 0
    ss4 = (bytes(prevblock_hidden)
           + struct.pack('<I', hdr.nNonce)
           + struct.pack('<I', hdr.m_nonce2)
           + struct.pack('<I', hdr.m_time_offset)
           + struct.pack('<I', hdr.m_nonce3)
           + hash_a)
    assert len(ss4) == STAGE4_LEN, f"stage4 msg must be {STAGE4_LEN}B, got {len(ss4)}"
    return ss3, ss4, hash_a


def pack_slots(msg: bytes) -> bytes:
    """Zero-pad a stage message out to the 10x64-bit slot array the core reads."""
    if len(msg) > SLOTS * 8:
        raise ValueError(f"message {len(msg)}B exceeds {SLOTS*8}B slot array")
    return msg + b'\x00' * (SLOTS * 8 - len(msg))


def target_top64(nBits: int, shift: int = 22) -> int:
    """Top 64 bits of the shifted target, which is what the core prefilters on."""
    target = apply_blake2b_target_shift(nBits, shift)
    return (target >> 192) & 0xFFFFFFFFFFFFFFFF


def build_work_item(hdr: KnotsBlockHeaderV2, shift: int = 22) -> bytes:
    """Produce the exact 168 bytes to write to the FPGA UART."""
    ss3, ss4, _ = stage_inputs(hdr)
    stage3 = pack_slots(ss3)
    stage4 = pack_slots(ss4)
    tgt = struct.pack('<Q', target_top64(hdr.nBits, shift))
    item = stage3 + stage4 + tgt
    assert len(item) == WORK_ITEM_LEN, f"work item must be {WORK_ITEM_LEN}B, got {len(item)}"
    return item


def parse_result(buf: bytes):
    """Decode the 17-byte reply the FPGA sends on Success."""
    if len(buf) != RESULT_LEN:
        raise ValueError(f"result must be {RESULT_LEN}B, got {len(buf)}")
    flag = buf[0]
    nonce = struct.unpack('<Q', buf[1:9])[0]
    hash_top64 = struct.unpack('<Q', buf[9:17])[0]
    return {"success": flag == 0x01, "nonce": nonce, "hash_top64": hash_top64}


# ---------------- verification ----------------

def test_matches_reference(hdr: KnotsBlockHeaderV2) -> None:
    """The stage split must reproduce the golden reference's own hash."""
    ss3, ss4, hash_a = stage_inputs(hdr)

    # hash_a must be what stage 3 of the reference produces.
    assert hash_a == blake2b_nokey(ss3, outlen=32)

    # Recompose stage 5 from our stage-4 output and compare to get_pow_hash.
    hash_b = blake2b_nokey(ss4, outlen=32)
    if hdr.m_xor_key == b'\x00' * 16:
        xor_key_mask = b'\x00' * 32
    else:
        xor_key_mask = bytearray(tagged_hash("Bitcoin block hash PoW XOR mask", hdr.m_xor_key))
        clear_bytes = hdr.m_xor_key_mask_clear_bits // 8
        for i in range(clear_bytes):
            xor_key_mask[i] = 0
        rem = hdr.m_xor_key_mask_clear_bits % 8
        if rem:
            xor_key_mask[clear_bytes] &= (0xff >> rem)
    final = bytearray(32)
    for i in range(32):
        final[31 - i] = hash_b[i] ^ xor_key_mask[i]

    expected = get_pow_hash(hdr)
    assert bytes(final) == expected, (
        f"stage split does not reproduce the reference hash\n"
        f"  ours={bytes(final).hex()}\n  ref ={expected.hex()}")


def _selftest() -> int:
    import random
    rng = random.Random(0xC0FFEE)
    print("=== build_work_item selftest ===")

    checked = 0
    for i in range(100):
        hdr = KnotsBlockHeaderV2(
            nVersion=0x20000000,
            hashPrevBlock=bytes(rng.getrandbits(8) for _ in range(32)),
            hashMerkleRoot=bytes(rng.getrandbits(8) for _ in range(32)),
            nTime=rng.getrandbits(32),
            nBits=0x1903c2d4,
            nNonce=rng.getrandbits(32),
            m_nonce2=rng.getrandbits(32),
            m_nonce3=rng.getrandbits(32),
            m_extranonce=bytes(rng.getrandbits(8) for _ in range(16)),
            m_time_offset=rng.getrandbits(32),
            m_txcount=rng.getrandbits(16),
            m_flags=0,
            m_xor_key_mask_clear_bits=0,
            m_xor_key=b'\x00' * 16,
            m_height=969859,
            m_mm_rhs=bytes(rng.getrandbits(8) for _ in range(32)),
        )
        test_matches_reference(hdr)
        item = build_work_item(hdr)
        assert len(item) == WORK_ITEM_LEN
        checked += 1

    print(f"OK stage split reproduces get_pow_hash on {checked}/100 random headers")

    # Round-trip the result decoder.
    probe = struct.pack('<B', 1) + struct.pack('<Q', 0xDEADBEEFCAFEF00D) + struct.pack('<Q', 0x0000FFFFAABBCCDD)
    r = parse_result(probe)
    assert r["success"] and r["nonce"] == 0xDEADBEEFCAFEF00D and r["hash_top64"] == 0x0000FFFFAABBCCDD
    print("OK 17-byte result decoder round-trips")

    # Show one worked example so the wire bytes are inspectable.
    hdr = KnotsBlockHeaderV2(nBits=0x1903c2d4, m_height=969859)
    item = build_work_item(hdr)
    print(f"\nexample work item ({len(item)} bytes):")
    print(f"  Stage3In    [0:80]   {item[0:16].hex()}...{item[64:80].hex()}")
    print(f"  Stage4In   [80:160]  {item[80:96].hex()}...{item[144:160].hex()}")
    print(f"  TargetTop64[160:168] {item[160:168].hex()}")
    print(f"  target_top64 = 0x{target_top64(0x1903c2d4):016x}")
    print("\nRESULT: 100/100 PASS")
    return 0


def _rpc(method, params=None):
    url = os.environ["BTC_RPC_URL"]
    user = os.environ["BTC_RPC_USER"]
    pw = os.environ["BTC_RPC_PASS"]
    body = json.dumps({"jsonrpc": "1.0", "id": "cc", "method": method,
                       "params": params or []}).encode()
    req = urllib.request.Request(url, data=body)
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    req.add_header("Authorization", f"Basic {tok}")
    req.add_header("Content-Type", "text/plain")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)["result"]
    except urllib.error.HTTPError as e:
        # bitcoind returns the real JSON-RPC error in the body of a 500
        body = e.read().decode(errors="replace")
        try:
            err = json.loads(body).get("error")
            raise RuntimeError(f"RPC {method} failed: {err}") from None
        except json.JSONDecodeError:
            raise RuntimeError(f"RPC {method} HTTP {e.code}: {body[:300]}") from None


def _from_node() -> int:
    print("=== getblocktemplate from the local Knots node ===")
    # The node rejects a template request unless the client declares support for
    # the active blake2b rule:
    #   error -8 "Support for 'blake2b' rule requires explicit client support"
    tmpl = _rpc("getblocktemplate", [{"rules": ["segwit", "blake2b"]}])
    print(f"  height:        {tmpl['height']}")
    print(f"  bits:          {tmpl['bits']}")
    print(f"  previousblock: {tmpl['previousblockhash']}")
    print(f"  curtime:       {tmpl['curtime']}")
    print(f"  transactions:  {len(tmpl.get('transactions', []))}")

    nbits = int(tmpl["bits"], 16)
    hdr = KnotsBlockHeaderV2(
        nVersion=tmpl["version"],
        hashPrevBlock=bytes.fromhex(tmpl["previousblockhash"])[::-1],
        hashMerkleRoot=b'\x00' * 32,   # placeholder: real merkle needs the coinbase
        nTime=tmpl["curtime"],
        nBits=nbits,
        m_height=tmpl["height"],
    )
    test_matches_reference(hdr)
    print("  stage split verified against the golden reference for this template")

    item = build_work_item(hdr)
    print(f"\nwork item ({len(item)} bytes) for height {tmpl['height']}:")
    print(f"  Stage3In    {item[0:24].hex()}...")
    print(f"  Stage4In    {item[80:104].hex()}...")
    print(f"  TargetTop64 {item[160:168].hex()}  (0x{target_top64(nbits):016x})")
    print(f"\n  full target = 0x{apply_blake2b_target_shift(nbits):064x}")
    print("\nOK live template converted to a valid FPGA work item")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--from-node", action="store_true")
    a = ap.parse_args()
    if a.from_node:
        sys.exit(_from_node())
    sys.exit(_selftest())
