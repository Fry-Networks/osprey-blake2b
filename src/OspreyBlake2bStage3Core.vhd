-- Copyright (c) 2026, Fry Networks. Adapted from pedrorivera/SiaFpgaMiner (MIT, 2018).
--
-- === OspreyBlake2bStage3Core.vhd ===
--
-- Stage-3 BLAKE2b of the 52-byte "coinb1" region for Bitcoin Knots BLAKE2b PoW.
--
-- Runs ONCE per pool notify (extranonce change), not per nonce. The output feeds
-- into stage-4 as hash_a. Because it runs infrequently, an unrolled 96-clock
-- pipeline is overkill; a serial 12-round implementation would suffice. For
-- consistency with stage-4 and to reuse the same MixG/QuadG entities, we use
-- the same unrolled structure.
--
-- Deltas vs stage-4:
--   1. No nonce iteration — the whole 52-byte msg is fixed for the work item.
--   2. Message length constant is 52 (kStage3MsgLen) not 80 (V12 XOR term).
--   3. Output is the FULL 256-bit hash (4 x u64), not just the top 64 bits.
--
-- Message layout (52 bytes, from PkgOspreyBlake2b):
--   bytes 0..3   : u32(0) reserved
--   bytes 4..35  : h2_hash (SHA256 from zynq)
--   bytes 36..51 : m_extranonce (u128 from pool)
--
-- As BlockHeader input (6.5 u64 words — the 7th slot has 4 valid bytes then 4 zero):
--   BlockHeader(0) : bytes 0..7   = u32(0) || low 4 bytes of h2_hash
--   BlockHeader(1) : bytes 8..15  = h2_hash bytes 4..12
--   BlockHeader(2) : bytes 16..23 = h2_hash bytes 12..20
--   BlockHeader(3) : bytes 24..31 = h2_hash bytes 20..28
--   BlockHeader(4) : bytes 32..39 = h2_hash bytes 28..32 || extranonce bytes 0..4
--   BlockHeader(5) : bytes 40..47 = extranonce bytes 4..12
--   BlockHeader(6) : bytes 48..55 = extranonce bytes 12..16 || zero pad
--   (BlockHeader(7..9) are unused; caller MUST zero them)
--
-- The BLAKE2b padding rule handles the trailing zeros automatically (t counter =
-- 52 not 128; final block flag set).

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

library work;
  use work.PkgBlake2b.all;
  use work.PkgOspreyBlake2b.all;

entity OspreyBlake2bStage3Core is
  port(
    Clk : in std_logic;
    -- '1' = fresh input arrived; hold '1' for at least 96 cycles for the result
    -- to propagate through the pipeline. Toggle back to '0' when idle.
    Enable : in std_logic;
    -- 10-word input (only slots 0..6 carry data; 7..9 must be zeroed by caller).
    BlockHeader : in U64Array_t(9 downto 0);
    -- Full 256-bit hash output (little-endian words matching BLAKE2b spec).
    -- Valid ~96 clocks after BlockHeader stabilizes with Enable = '1'.
    HashOut : out U64Array_t(3 downto 0)
  );
end OspreyBlake2bStage3Core;

architecture rtl of OspreyBlake2bStage3Core is

  constant kGPerMixer : integer := 4;
  constant kMixRounds : integer := 12;

  type U64Array2D_t is array (integer range <>) of U64Array_t(kGPerMixer-1 downto 0);

  signal Msg : U64Array_t(15 downto 0) := (others => kU64Zeros);
  signal A1_in, B1_in, C1_in, D1_in, X1, Y1 : U64Array2D_t(kMixRounds-1 downto 0) := (others => (others => kU64Zeros));
  signal A2_in, B2_in, C2_in, D2_in, X2, Y2 : U64Array2D_t(kMixRounds-1 downto 0) := (others => (others => kU64Zeros));
  signal A1_out, B1_out, C1_out, D1_out     : U64Array2D_t(kMixRounds-1 downto 0) := (others => (others => kU64Zeros));
  signal A2_out, B2_out, C2_out, D2_out     : U64Array2D_t(kMixRounds-1 downto 0) := (others => (others => kU64Zeros));

  -- TODO(session-4 or later): the exact mapping from A2_out(last) / B2_out(last)
  -- / C2_out(last) / D2_out(last) to V0..V15 depends on the ror/rol pattern used
  -- inside QuadG + between mixers. Sia's Blake2bMinerCore.vhd:228 accessed
  -- A2_out(11)(0) [as V0] and C2_out(11)(2) [claimed as V8] to compute
  -- H_new[0] = H[0] XOR V0 XOR V8. For a FULL 256-bit output we need the same
  -- extraction for H[1], H[2], H[3]. This SHOULD follow the same column pattern
  -- but MUST be validated against the Python golden reference (Phase 5 testbench,
  -- HARD GATE 100/100). Below I mirror Sia's Hash[0] extraction and derive the
  -- other 3 by column analogy — flag for simulator verification.

  signal A2_out_dly : U64Array_t(kGPerMixer-1 downto 0) := (others => kU64Zeros);

begin

  -- Msg population.  Higher indices must be zero (BLAKE2b block-padding handles
  -- the missing 128-52=76 bytes automatically via the t-counter = 52).
  Msg(9 downto 0)   <= BlockHeader;
  Msg(15 downto 10) <= (others => (others => '0'));

  -- V-vector init: kHin from PkgBlake2b applies unchanged. V12 XOR gets the
  -- Knots stage-3 msg length (52 bytes) instead of Sia's 80.
  A1_in(0)(0) <= kHin(0);
  A1_in(0)(1) <= kHin(1);
  A1_in(0)(2) <= kHin(2);
  A1_in(0)(3) <= kHin(3);
  B1_in(0)(0) <= kHin(4);
  B1_in(0)(1) <= kHin(5);
  B1_in(0)(2) <= kHin(6);
  B1_in(0)(3) <= kHin(7);
  C1_in(0)(0) <= kIV(0);
  C1_in(0)(1) <= kIV(1);
  C1_in(0)(2) <= kIV(2);
  C1_in(0)(3) <= kIV(3);
  -- V12 XOR (msg_len_in_bytes) — differs from Sia (80) to Knots stage-3 (52).
  D1_in(0)(0) <= kIV(4) xor (x"00000000000000" & kStage3MsgLen);
  D1_in(0)(1) <= kIV(5);
  D1_in(0)(2) <= not kIV(6);
  D1_in(0)(3) <= kIV(7);

  RoundGen: for i in 0 to kMixRounds-1 generate
    -- No nonce substitution — feed the message straight through.
    MsgFeedGen: for j in 0 to 3 generate
      X1(i)(j) <= Msg(kSigma(i mod 10, 2*j));
      Y1(i)(j) <= Msg(kSigma(i mod 10, 2*j+1));
      X2(i)(j) <= Msg(kSigma(i mod 10, 2*j+8));
      Y2(i)(j) <= Msg(kSigma(i mod 10, 2*j+9));
    end generate;

    Mixer1: entity work.QuadG
    port map(
      Clk => Clk, A_in => A1_in(i), B_in => B1_in(i), C_in => C1_in(i), D_in => D1_in(i),
      X => X1(i), Y => Y1(i),
      A_out => A1_out(i), B_out => B1_out(i), C_out => C1_out(i), D_out => D1_out(i)
    );

    A2_in(i) <= A1_out(i);
    B2_in(i) <= B1_out(i)(0) & B1_out(i)(3 downto 1);
    C2_in(i) <= C1_out(i)(1 downto 0) & C1_out(i)(3 downto 2);
    D2_in(i) <= D1_out(i)(2 downto 0) & D1_out(i)(3);

    Mixer2: entity work.QuadG
    port map(
      Clk => Clk, A_in => A2_in(i), B_in => B2_in(i), C_in => C2_in(i), D_in => D2_in(i),
      X => X2(i), Y => Y2(i),
      A_out => A2_out(i), B_out => B2_out(i), C_out => C2_out(i), D_out => D2_out(i)
    );

    AllButLastRound: if i /= kMixRounds-1 generate
      A1_in(i+1) <= A2_out(i);
      B1_in(i+1) <= B2_out(i)(2 downto 0) & B2_out(i)(3);
      C1_in(i+1) <= C2_out(i)(1 downto 0) & C2_out(i)(3 downto 2);
      D1_in(i+1) <= D2_out(i)(0) & D2_out(i)(3 downto 1);
    end generate;
  end generate RoundGen;

  -- 4-way A2_out delay to align with C2_out (same 1-cycle delay as Sia).
  DelayV: process(Clk)
  begin
    if rising_edge(Clk) then
      A2_out_dly <= A2_out(kMixRounds-1);
    end if;
  end process;

  -- 256-bit hash extraction.  Sia's Blake2bMinerCore:228 established that the
  -- top word Hash[0] = kHin(0) XOR A2_out(11)(0) XOR C2_out(11)(2). By column
  -- analogy we derive Hash[1..3] using the same pattern. THIS DERIVATION MUST
  -- BE VALIDATED against the Python golden reference (Phase 5 testbench, HARD
  -- GATE). If the C2_out index mapping is not simply (2, 3, 0, 1) but some
  -- other permutation, this is a first place to debug when the testbench fails.
  HashOut(0) <= kHin(0) xor A2_out_dly(0) xor C2_out(kMixRounds-1)(2);
  HashOut(1) <= kHin(1) xor A2_out_dly(1) xor C2_out(kMixRounds-1)(3);
  HashOut(2) <= kHin(2) xor A2_out_dly(2) xor C2_out(kMixRounds-1)(0);
  HashOut(3) <= kHin(3) xor A2_out_dly(3) xor C2_out(kMixRounds-1)(1);

end rtl;
