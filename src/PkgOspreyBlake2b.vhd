-- Copyright (c) 2026, Fry Networks. Adapted from pedrorivera/SiaFpgaMiner (MIT, 2018).
--
-- === PkgOspreyBlake2b.vhd ===
--
-- Constants for the Bitcoin Knots BLAKE2b PoW hash pipeline (Osprey E100 VU35P).
-- Extends the base Sia PkgBlake2b with Knots-specific stage-3 and stage-4 sizings.
--
-- Reference: bitcoinknots/bitcoin @ 29.x-knots src/primitives/block.cpp CBlockHeader::GetHash.
-- Cross-checked against ./zynq/blake2b_reference.py (Phase 4 golden ref).
--
-- BLAKE2b init parameters are identical between Sia and Knots blake2b_nokey(out=32):
--   digest_length = 0x20, key_length = 0, fanout = 1, depth = 1
--   -> H[0] = IV[0] XOR 0x0000000001010020  (already present as kHin in PkgBlake2b)
--
-- The pipeline stages we need:
--   stage3: single-block BLAKE2b of 52 bytes (u32(0) || h2_hash || m_extranonce)
--           runs ONCE per new pool notify (extranonce change)
--   stage4: single-block BLAKE2b of 80 bytes (mode-0 layout)
--           runs PER NONCE — the hot path

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

library work;
  use work.PkgBlake2b.all;

package PkgOspreyBlake2b is

  ---------------------------------------------------------------------------
  -- Stage 3: BLAKE2b of 52-byte "coinb1" message
  ---------------------------------------------------------------------------
  -- Message layout (little-endian):
  --   bytes 0..3   : u32(0)        (reserved / final 3 bytes of "coinb1")
  --   bytes 4..35  : h2_hash       (SHA256, from zynq side)
  --   bytes 36..51 : m_extranonce  (u128 = 16 bytes, from pool subscribe)
  -- Total = 52 bytes; fits in 1 BLAKE2b block (128B) with final-block flag.
  constant kStage3MsgLen : unsigned(7 downto 0) := x"34"; -- 52 bytes

  ---------------------------------------------------------------------------
  -- Stage 4: BLAKE2b of 80-byte "ASIC-visible" message (mode 0)
  ---------------------------------------------------------------------------
  -- Byte layout (little-endian, per src/primitives/block.cpp case-0 branch):
  --   bytes 0..31  : prevblock_hidden (with bytes 0..5 forced to 0)
  --   bytes 32..35 : nNonce         (u32 LE)  <-- primary grind
  --   bytes 36..39 : m_nonce2       (u32 LE)  <-- secondary grind
  --   bytes 40..43 : m_time_offset  (u32 LE)  <-- work-item constant
  --   bytes 44..47 : m_nonce3       (u32 LE)  <-- work-item constant
  --   bytes 48..79 : hash_a         (u256 = 32B, from stage-3 output)
  --
  -- As 10 x u64 (little-endian words within the 80-byte payload):
  --   Msg(0) : bytes 0..7   = prevblock_hidden[0..8], low 48b forced to 0
  --   Msg(1) : bytes 8..15  = prevblock_hidden[8..16]
  --   Msg(2) : bytes 16..23 = prevblock_hidden[16..24]
  --   Msg(3) : bytes 24..31 = prevblock_hidden[24..32]
  --   Msg(4) : bytes 32..39 = nNonce (low 32b) || m_nonce2 (high 32b) <-- 64-bit ASIC-grind slot
  --   Msg(5) : bytes 40..47 = m_time_offset || m_nonce3               <-- fixed per work item
  --   Msg(6) : bytes 48..55 = hash_a[0..8]
  --   Msg(7) : bytes 56..63 = hash_a[8..16]
  --   Msg(8) : bytes 64..71 = hash_a[16..24]
  --   Msg(9) : bytes 72..79 = hash_a[24..32]
  --
  -- SCOPE REDUCTION (first-cut, session-3): iterate the 64-bit Msg(4) slot only,
  -- keep Msg(5) as an input constant. Full 64-bit nonce space per work item =
  -- 1.8e19 hashes. m_nonce3 rollover handled zynq-side by requesting new work.
  constant kStage4MsgLen : unsigned(7 downto 0) := x"50"; -- 80 bytes (same as Sia)

  ---------------------------------------------------------------------------
  -- Blake2bTargetShift (mainnet = 22, testnet = 20)
  ---------------------------------------------------------------------------
  constant kMainnetBlake2bTargetShift : integer := 22;
  constant kTestnetBlake2bTargetShift : integer := 20;

  ---------------------------------------------------------------------------
  -- Sigma index for the "grinding" slot in Sia's pipeline: 4.
  -- Knots stage-4 mode-0 also grinds Msg word index 4 (see byte layout above),
  -- so the sigma-index-4 replacement pattern from Sia works unchanged.
  ---------------------------------------------------------------------------
  constant kNonceSigmaIdx : integer := 4;

  ---------------------------------------------------------------------------
  -- Multi-core nonce partitioning
  ---------------------------------------------------------------------------
  -- A core seeded with S tests exactly the contiguous run S, S+1, S+2, ... one
  -- per clock. (The twelve Nonce registers inside the stage-4 core are twelve
  -- TIME-SKEWED views of one counter -- the offsets match how many cycles round
  -- i lags round 0 -- not twelve independent nonces. All twelve advance by 1
  -- every clock.)
  --
  -- So give core k the top of its own 1/2^m slice:
  --
  --     S_k = (k << (64 - m)) - 1,     m = ClogB2(N)
  --
  -- Non-overlap is structural, not probabilistic. For core j to reach core k's
  -- slice it must grind (k-j) * 2^(64-m) nonces; at N=8 that is >= 2^61. A work
  -- item lives ~30 s, which at 250 MHz is 7.5e9 clocks -- about 3e-9 of one
  -- slice. Exhausting a slice would take ~292,000 years.
  --
  -- The -1 matters: for k=0 this is all-ones, bit-identical to the single-core
  -- default, so N=1 reduces exactly to today's build and miner.c's
  -- `from_seed = 0 - r.nonce /* kNonceSeed is all ones */` stays true.
  -- numeric_std defines shift_left with a count >= the vector length as zeros,
  -- so the k=0 case is well-defined rather than relying on wrap.
  --
  -- Do NOT use a stride/interleave instead: keeping the twelve registers aligned
  -- under a +N increment would also require rescaling the skew table and the
  -- `NonceOut <= Nonce(0) - (kPipeLength+1)` correction, i.e. edits INSIDE
  -- OspreyBlake2bStage4Core -- which would invalidate tb_stage4_smoke,
  -- tb_stage4_prefilter and tb_stage4_compare, the three benches that exist
  -- precisely because prefilter bugs reached silicon before.
  --
  -- Do NOT use kNonceSeed + k either: adjacent seeds mean core k+1 tests at
  -- cycle t what core k tested at cycle t+1 -- near-total duplicate work that
  -- looks like a healthy N-core miner in every metric except hash rate.
  --
  -- Free consequence: the top m bits of any verified nonce ARE the core index,
  -- so per-core liveness is observable host-side at zero protocol cost.
  function ClogB2(n : positive) return natural;
  function CoreNonceSeed(idx : natural; n : positive) return unsigned;

end PkgOspreyBlake2b;

package body PkgOspreyBlake2b is

  function ClogB2(n : positive) return natural is
    variable r : natural  := 0;
    variable v : positive := 1;
  begin
    while v < n loop
      v := v * 2;
      r := r + 1;
    end loop;
    return r;
  end function;

  function CoreNonceSeed(idx : natural; n : positive) return unsigned is
    constant m : natural := ClogB2(n);
  begin
    return shift_left(to_unsigned(idx, 64), 64 - m) - 1;
  end function;

end PkgOspreyBlake2b;
