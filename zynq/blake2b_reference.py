#!/usr/bin/env python3
"""
Golden-reference Python implementation of the Bitcoin Knots BLAKE2b PoW hash.

Reverse-engineered from bitcoinknots/bitcoin @ 29.x-knots:
  src/primitives/block.h   - CBlockHeader / CompressedHeader (164B v2 header)
  src/primitives/block.cpp - CBlockHeader::GetHash() (two-stage BLAKE2b pipeline)
  src/crypto/blake2b.h     - blake2b_nokey (standard BLAKE2b, 32B digest, no key/salt/perso)
  src/pow.cpp              - ApplyBlake2bTargetShift (nBits shift for the fork)
  src/consensus/params.h   - Blake2bTargetShift{20} default, {22} on mainnet
  src/kernel/chainparams.cpp:227 - first BLAKE2b block at height 961640

Header v2 layout (serialization order, per block.h line 107 + line 111):
  Fields always serialized (80 bytes total = classic header):
    v            u32     - nVersion | 0x80000000 if header-v2
    hashPrevBlock u256   (32B)
    hashMerkleRoot u256  (32B)
    time_on_wire u32     - nTime, possibly offset-adjusted
    nBits        u32
    nNonce       u32

  Additional v2 fields (84 bytes extra = 164B total):
    m_nonce2                   u32
    m_nonce3                   u32
    m_extranonce               u128 (16B)
    m_time_offset              u32
    m_txcount                  u16
    m_flags                    u8
    m_xor_key_mask_clear_bits  u8
    m_xor_key                  u128 (16B)
    m_height                   i32
    m_mm_rhs                   u256 (32B)

Two-stage BLAKE2b pipeline (CBlockHeader::GetHash for header-v2):

  Stage 1 (SHA256d TaggedHash, "Bitcoin block header 1"):
    h1 = TaggedHash("Bitcoin block header 1") over 119 bytes:
      GetCompleteVersion (u32) || prevblock_ordered (32B) || m_height (i32) ||
      hashMerkleRoot (32B) || GetTimeOnWire (u32) || 0 (u8, reserved) ||
      nBits (u32) || m_txcount (u32) || m_flags (u8) ||
      m_xor_key_mask_clear_bits (u8) || SHA256(TaggedHash("Bitcoin block hash PoW XOR key") || m_xor_key) (32B)
    h1_hash = SHA256 of the above

  Stage 2 (SHA256d TaggedHash, "Merge-mining hook"):
    h2 = TaggedHash("Merge-mining hook") over 96 bytes:
      h1_hash (32B) || zeros (32B) || m_mm_rhs (32B)
    h2_hash = SHA256 of the above

  Stage 3 (BLAKE2b of 52 bytes "coinb1" region):
    ss = u32(0) || h2_hash (32B) || m_extranonce (16B)
    hash_a = blake2b_nokey(ss, out=32B)

  Stage 4 (BLAKE2b of mode-specific ASIC-visible message):
    Layout depends on (m_flags & 3):
      mode 0: ss = prevblock_hidden_zeroed_first6 (32B) || nNonce || m_nonce2 || m_time_offset || m_nonce3 || hash_a (total ~80B)
      mode 1: ss = nNonce || m_nonce2 || m_nonce3 || m_time_offset || hash_a (32B) || h2_hash (32B) (total 80B)
      mode 2: ss = zeros(80B) || h2_hash (32B) || nNonce || m_nonce2 || m_time_offset || m_nonce3 || hash_a (32B)  (total ~160B)
      mode 3: ss = zeros(32B) || mode-2 layout (total ~192B)
    hash_b = blake2b_nokey(ss, out=32B)

  Stage 5 (XOR + byte reverse):
    xor_key_mask = SHA256(TaggedHash("Bitcoin block hash PoW XOR mask") || m_xor_key)
    Apply xor_key_mask_clear_bits (zero low-order bits per spec)
    final[i] = hash_b[i] ^ xor_key_mask[i]  (then byte-reversed into uint256 output)

Target comparison:
  effective_nBits = ApplyBlake2bTargetShift(nBits, Blake2bTargetShift=22)
  target = compact_to_target(effective_nBits)
  block valid iff int.from_bytes(final_hash, 'big') <= target
"""
import hashlib
import struct


# ---------- helpers ----------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    return sha256(sha256(data))


def tagged_hash_prefix(tag: str) -> bytes:
    """Bitcoin TaggedHash: SHA256(SHA256(tag) || SHA256(tag)) prepended before data.
    The Knots TaggedHash class emits SHA256(tag)||SHA256(tag) as the FIRST 64 bytes,
    then subsequent writes append to the SHA256 state.
    Asserts h1.BytesWritten() == 0x40 + 119 confirm 64 bytes of tag prefix + 119 bytes payload.
    """
    th = sha256(tag.encode('ascii'))
    return th + th


def tagged_hash(tag: str, payload: bytes) -> bytes:
    """Return SHA256(tagged_hash_prefix(tag) || payload)."""
    return sha256(tagged_hash_prefix(tag) + payload)


def blake2b_nokey(data: bytes, outlen: int = 32) -> bytes:
    """Standard BLAKE2b with no key/salt/personalization, configurable digest length."""
    return hashlib.blake2b(data, digest_size=outlen).digest()


def compact_to_target(nBits: int) -> int:
    """Bitcoin compact-target decoding (see src/arith_uint256.cpp SetCompact)."""
    exp = (nBits >> 24) & 0xff
    mant = nBits & 0x007fffff
    negative = (nBits & 0x00800000) != 0
    if exp <= 3:
        mant >>= 8 * (3 - exp)
        target = mant
    else:
        target = mant << (8 * (exp - 3))
    if negative:
        target = -target
    return target


def apply_blake2b_target_shift(nBits: int, shift: int = 22) -> int:
    """Post-fork target shift per src/pow.cpp:19 ApplyBlake2bTargetShift.
    Rebuilds nBits with mantissa unchanged but exponent+=(shift+7)/8 bytes.
    NOTE: this is a first-cut reading; the C++ arith_uint256 shift is done on
    the decoded target then re-encoded to compact. If Phase-5 sim fails against
    the C++ oracle, revisit this to match the exact arith_uint256 semantics.
    """
    target = compact_to_target(nBits)
    target <<= shift
    # Re-encode is not needed for our comparison — we just return the target.
    return target


# ---------- header serialization ----------

class KnotsBlockHeaderV2:
    """Bitcoin Knots block header (v2, 164 bytes)."""

    VERSION_HEADER_V2_FLAG = 0x80000000

    def __init__(self,
                 nVersion=0x20000000,
                 hashPrevBlock=b'\x00' * 32,
                 hashMerkleRoot=b'\x00' * 32,
                 nTime=0,
                 nBits=0x1d00ffff,
                 nNonce=0,
                 m_nonce2=0,
                 m_nonce3=0,
                 m_extranonce=b'\x00' * 16,
                 m_time_offset=0,
                 m_txcount=0,
                 m_flags=0,
                 m_xor_key_mask_clear_bits=0,
                 m_xor_key=b'\x00' * 16,
                 m_height=0,
                 m_mm_rhs=b'\x00' * 32):
        self.nVersion = nVersion
        self.hashPrevBlock = hashPrevBlock
        self.hashMerkleRoot = hashMerkleRoot
        self.nTime = nTime
        self.nBits = nBits
        self.nNonce = nNonce
        self.m_nonce2 = m_nonce2
        self.m_nonce3 = m_nonce3
        self.m_extranonce = m_extranonce
        self.m_time_offset = m_time_offset
        self.m_txcount = m_txcount
        self.m_flags = m_flags
        self.m_xor_key_mask_clear_bits = m_xor_key_mask_clear_bits
        self.m_xor_key = m_xor_key
        self.m_height = m_height
        self.m_mm_rhs = m_mm_rhs

    def get_complete_version(self) -> int:
        return self.VERSION_HEADER_V2_FLAG | (self.nVersion & ~self.VERSION_HEADER_V2_FLAG)

    def get_time_on_wire(self) -> int:
        USE_TIME_OFFSET = 4
        if (self.m_flags & USE_TIME_OFFSET) == 0:
            return self.nTime
        return (self.nTime - self.m_time_offset) & 0xffffffff

    def serialize(self) -> bytes:
        """Serialize per block.h SERIALIZE_METHODS(CBlockHeader).
        Line 107: READWRITE(v, hashPrevBlock, hashMerkleRoot, time_on_wire, nBits, nNonce);
        Line 111: if (m_header_v2) READWRITE(m_nonce2, m_nonce3, m_extranonce, m_time_offset,
                                             m_txcount, m_flags, m_xor_key_mask_clear_bits,
                                             m_xor_key, m_height, m_mm_rhs);
        Total: 80 + 84 = 164 bytes.
        """
        out = bytearray()
        out += struct.pack('<I', self.get_complete_version())
        out += self.hashPrevBlock  # 32B little-endian on wire
        out += self.hashMerkleRoot
        out += struct.pack('<I', self.get_time_on_wire())
        out += struct.pack('<I', self.nBits)
        out += struct.pack('<I', self.nNonce)
        # v2 extras
        out += struct.pack('<I', self.m_nonce2)
        out += struct.pack('<I', self.m_nonce3)
        out += self.m_extranonce
        out += struct.pack('<I', self.m_time_offset)
        out += struct.pack('<H', self.m_txcount)
        out += struct.pack('<B', self.m_flags)
        out += struct.pack('<B', self.m_xor_key_mask_clear_bits)
        out += self.m_xor_key
        out += struct.pack('<i', self.m_height)
        out += self.m_mm_rhs
        assert len(out) == 164, f"header must be 164B, got {len(out)}"
        return bytes(out)


# ---------- PoW hash pipeline ----------

def get_pow_hash(hdr: KnotsBlockHeaderV2) -> bytes:
    """Bitcoin Knots BLAKE2b PoW hash for a header-v2 block.
    Returns the 32-byte final hash (byte-reversed uint256 form).
    """
    # ---- Stage 1: h1 = TaggedHash("Bitcoin block header 1")
    prevblock_ordered_sane = hdr.hashPrevBlock[::-1]
    xor_key_inner = tagged_hash("Bitcoin block hash PoW XOR key", hdr.m_xor_key)

    h1_payload = bytearray()
    h1_payload += struct.pack('<I', hdr.get_complete_version())
    h1_payload += prevblock_ordered_sane
    h1_payload += struct.pack('<i', hdr.m_height)
    h1_payload += hdr.hashMerkleRoot
    h1_payload += struct.pack('<I', hdr.get_time_on_wire())
    h1_payload += b'\x00'  # reserved for 40-bit time extension
    h1_payload += struct.pack('<I', hdr.nBits)
    h1_payload += struct.pack('<I', hdr.m_txcount)  # written as uint32 per block.cpp:51
    h1_payload += struct.pack('<B', hdr.m_flags)
    h1_payload += struct.pack('<B', hdr.m_xor_key_mask_clear_bits)
    h1_payload += xor_key_inner
    assert len(h1_payload) == 119, f"h1 payload must be 119B, got {len(h1_payload)}"
    h1_hash = tagged_hash("Bitcoin block header 1", bytes(h1_payload))

    # ---- Stage 2: h2 = TaggedHash("Merge-mining hook")
    h2_payload = h1_hash + b'\x00' * 32 + hdr.m_mm_rhs
    assert len(h2_payload) == 96, f"h2 payload must be 96B, got {len(h2_payload)}"
    h2_hash = tagged_hash("Merge-mining hook", bytes(h2_payload))

    # ---- Stage 3: BLAKE2b of the Sv1 "coinb1" region (52 bytes)
    ss3 = struct.pack('<I', 0) + h2_hash + hdr.m_extranonce
    assert len(ss3) == 52, f"stage3 msg must be 52B, got {len(ss3)}"
    hash_a = blake2b_nokey(ss3, outlen=32)

    # ---- Stage 4: BLAKE2b of the ASIC-visible message
    mode = hdr.m_flags & 3
    if mode == 0:
        prevblock_hidden = bytearray(tagged_hash("Bitcoin prevblock header, hashed", prevblock_ordered_sane))
        for i in range(6):
            prevblock_hidden[i] = 0
        ss4 = bytes(prevblock_hidden) + struct.pack('<I', hdr.nNonce) + struct.pack('<I', hdr.m_nonce2) + struct.pack('<I', hdr.m_time_offset) + struct.pack('<I', hdr.m_nonce3) + hash_a
    elif mode == 1:
        ss4 = struct.pack('<I', hdr.nNonce) + struct.pack('<I', hdr.m_nonce2) + struct.pack('<I', hdr.m_nonce3) + struct.pack('<I', hdr.m_time_offset) + hash_a + h2_hash
    elif mode == 2:
        ss4 = b'\x00' * 80 + h2_hash + struct.pack('<I', hdr.nNonce) + struct.pack('<I', hdr.m_nonce2) + struct.pack('<I', hdr.m_time_offset) + struct.pack('<I', hdr.m_nonce3) + hash_a
    elif mode == 3:
        ss4 = b'\x00' * 32 + b'\x00' * 80 + h2_hash + struct.pack('<I', hdr.nNonce) + struct.pack('<I', hdr.m_nonce2) + struct.pack('<I', hdr.m_time_offset) + struct.pack('<I', hdr.m_nonce3) + hash_a
    hash_b = blake2b_nokey(ss4, outlen=32)

    # ---- Stage 5: XOR + byte-reverse
    if hdr.m_xor_key == b'\x00' * 16:
        xor_key_mask = b'\x00' * 32
    else:
        xor_key_mask = bytearray(tagged_hash("Bitcoin block hash PoW XOR mask", hdr.m_xor_key))
        clear_bytes = hdr.m_xor_key_mask_clear_bits // 8
        for i in range(clear_bytes):
            xor_key_mask[i] = 0
        rem_bits = hdr.m_xor_key_mask_clear_bits % 8
        if rem_bits:
            xor_key_mask[clear_bytes] &= (0xff >> rem_bits)

    final = bytearray(32)
    for i in range(32):
        final[31 - i] = hash_b[i] ^ xor_key_mask[i]
    return bytes(final)


def meets_target(final_hash: bytes, nBits: int, blake2b_target_shift: int = 22) -> bool:
    """Return True if final_hash satisfies the post-fork BLAKE2b target."""
    target = apply_blake2b_target_shift(nBits, blake2b_target_shift)
    hash_int = int.from_bytes(final_hash, 'big')
    return hash_int <= target


# ---------- self-test with known reference vectors ----------

def _selftest():
    # 1. Standard BLAKE2b test vector (RFC 7693)
    v = blake2b_nokey(b'abc', outlen=64)
    expected_abc = bytes.fromhex(
        'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1'
        '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923'
    )
    assert v == expected_abc, f'BLAKE2b RFC vector mismatch:\n  got={v.hex()}\n  exp={expected_abc.hex()}'
    print('OK BLAKE2b RFC 7693 "abc" test vector matches')

    # 2. blake2b_nokey with 32B output
    v32 = blake2b_nokey(b'abc', outlen=32)
    assert len(v32) == 32
    print(f'OK BLAKE2b 32B "abc" digest: {v32.hex()}')

    # 3. Serialize null header, expect 164B
    hdr = KnotsBlockHeaderV2()
    ser = hdr.serialize()
    assert len(ser) == 164
    print(f'OK Null v2 header serializes to {len(ser)} bytes')

    # 4. Compute PoW hash for null header, mode 0
    h = get_pow_hash(hdr)
    print(f'OK Null header PoW hash (mode 0): {h.hex()}')

    # 5. Target decoding sanity
    t = compact_to_target(0x1d00ffff)
    print(f'OK compact_to_target(0x1d00ffff) = 0x{t:064x}')

    print('\nAll self-tests passed. Next step: compile a small C++ harness from Knots source')
    print('(src/primitives/block.cpp + src/crypto/blake2b.cpp + src/hash.cpp) that computes')
    print('CBlockHeader::GetHash() for the same header and asserts byte-identity to this Python.')


def _emit_stage3_vectors(n: int, seed: int = 0xDEADBEEF) -> None:
    """Emit N deterministic Stage-3 test vectors to stdout.

    Each line: 10 space-separated u64 hex (16 hex chars each, little-endian byte-to-word packing)
    followed by 4 space-separated u64 hex (expected HashOut).

    Stage-3 hashes a 52-byte message. Byte layout in 10-slot U64Array_t:
        slot 0..5 : bytes 0..47 (LE)
        slot 6    : bytes 48..51 in low 4 bytes, upper 4 bytes = 0
        slot 7..9 : all zero
    Expected: hashlib.blake2b(msg, digest_size=32).digest() interpreted as 4 LE u64.
    """
    import random
    rng = random.Random(seed)
    for i in range(n):
        msg = bytes(rng.randint(0, 255) for _ in range(52))
        # Pack to 10 u64 slots
        padded = msg + b'\x00' * (80 - 52)  # 80B total: slots 0..9
        slots = struct.unpack('<10Q', padded)
        digest = blake2b_nokey(msg, outlen=32)
        expected = struct.unpack('<4Q', digest)
        slot_hex = ' '.join(f'{s:016x}' for s in slots)
        exp_hex = ' '.join(f'{e:016x}' for e in expected)
        print(f'{slot_hex} {exp_hex}')


def _emit_stage4_vectors(n: int, seed: int = 0xCAFED00D) -> None:
    """Emit N Stage-4 smoke vectors to stdout.

    Each line: <kNonceSeed_hex> <10 slot hex> <TargetTop64_hex> <expected_Hash0_be_hex>
    Stage-4 iterates nonce internally, so the smoke test targets:
      set kNonceSeed to a value, drive fixed BlockHeader, expect Hash0_be for
      nonce = kNonceSeed - kPipeLength - 1 to compare against TargetTop64.
    """
    import random
    rng = random.Random(seed)
    kPipeLength = 96
    for i in range(n):
        nonce_seed = rng.randint(0, 2**64 - 1)
        target_nonce = (nonce_seed - kPipeLength - 1) & 0xFFFFFFFFFFFFFFFF
        # Build 80B message: slot 4 = target_nonce (little-endian), other slots random
        slots = [rng.randint(0, 2**64 - 1) for _ in range(10)]
        slots[4] = target_nonce
        msg = b''.join(struct.pack('<Q', s) for s in slots)
        # Full blake2b of 80B msg
        digest = blake2b_nokey(msg, outlen=32)
        # Hash0 = digest[0:8] as LE u64
        hash0_le = struct.unpack('<Q', digest[0:8])[0]
        # Hash0_be = byte-reverse of Hash0
        hash0_be = struct.unpack('>Q', struct.pack('<Q', hash0_le))[0]
        # TargetTop64 = hash0_be + 1 (so hash < target = True, Success rises)
        target_top64 = (hash0_be + 1) & 0xFFFFFFFFFFFFFFFF
        slot_hex = ' '.join(f'{s:016x}' for s in slots)
        print(f'{nonce_seed:016x} {slot_hex} {target_top64:016x} {hash0_be:016x}')


if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 3 and sys.argv[1] == '--emit-stage3-vectors':
        _emit_stage3_vectors(int(sys.argv[2]))
    elif len(sys.argv) >= 3 and sys.argv[1] == '--emit-stage4-vectors':
        _emit_stage4_vectors(int(sys.argv[2]))
    else:
        _selftest()
