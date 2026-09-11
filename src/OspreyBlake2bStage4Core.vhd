-- Copyright (c) 2026, Fry Networks. Adapted from pedrorivera/SiaFpgaMiner (MIT, 2018).
--
-- === OspreyBlake2bStage4Core.vhd ===
--
-- Modified Sia Blake2bMinerCore for Bitcoin Knots BLAKE2b PoW hard fork (Osprey VU35P).
-- Handles ONLY stage-4, mode-0 message layout — 80 bytes, matches Sia's msg length.
-- The 12-round × 2-mixer × 4-step G unrolled pipeline is REUSED unchanged from Sia.
--
-- Deltas vs Sia:
--   1. Nonce widened 48 -> 64 bits (Msg(4) = full nNonce||m_nonce2 slot).
--   2. Target NOT read from BlockHeader(4); comes on a separate 64-bit input
--      (top word of the shifted target; full 256-bit compare happens in the
--      zynq-side share verifier using the Python golden reference).
--   3. hash_a comes from stage-3 output; caller wires it into Msg(6..9).
--   4. m_time_offset || m_nonce3 comes from BlockHeader; caller keeps it constant
--      across a work item.
--
-- BLAKE2b init parameters (kHin, IV XOR 0x0000000001010020) are byte-identical
-- to Knots blake2b_nokey(out=32), so PkgBlake2b constants apply unchanged.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

library work;
  use work.PkgBlake2b.all;
  use work.PkgOspreyBlake2b.all;

entity OspreyBlake2bStage4Core is
  generic(
    -- Initial nonce value. Different cores get different seeds to grind
    -- distinct portions of the 64-bit nNonce||m_nonce2 space in parallel.
    kNonceSeed : unsigned(63 downto 0) := (others => '1') -- first cycle wraps to 0
  );
  port(
    Clk    : in std_logic;
    -- When '0', reset nonce iterator to kNonceSeed. When '1', grind.
    Enable : in std_logic;
    -- 80-byte message. Slot 4 will be OVERWRITTEN by the grinding nonce.
    -- Fill from PkgOspreyBlake2b comment:
    --   BlockHeader(0..3) = prevblock_hidden (32B, with first 6 bytes zeroed)
    --   BlockHeader(4)    = <ignored — overwritten by nonce iterator>
    --   BlockHeader(5)    = m_time_offset || m_nonce3
    --   BlockHeader(6..9) = hash_a (32B from stage-3)
    BlockHeader : in U64Array_t(9 downto 0);
    -- Top 64 bits of the shifted target. If HashTop64 < TargetTop64, a candidate
    -- is signaled; full 256-bit comparison happens in the zynq share verifier.
    TargetTop64 : in unsigned(63 downto 0);
    -- Candidate nonce (nNonce in low 32b, m_nonce2 in high 32b). Only valid when
    -- Success = '1'.
    NonceOut : out unsigned(63 downto 0);
    -- Top 64 bits of the observed hash — for the zynq to log / verify.
    HashTop64Out : out unsigned(63 downto 0);
    -- Rising edge indicates the pipeline reported a top-64-bit-prefilter pass.
    Success : out std_logic := '0'
  );
end OspreyBlake2bStage4Core;

architecture rtl of OspreyBlake2bStage4Core is

  constant kGPerMixer : integer := 4;
  constant kMixRounds : integer := 12;
  constant kPipeLength: integer := 4*2*12; -- 4 clks * 2 mixers * 12 rounds

  type U64Array2D_t is array (integer range <>) of U64Array_t(kGPerMixer-1 downto 0);
  -- 64-bit nonce array (vs Sia's 48-bit)
  type U64NonceArray_t is array (integer range <>) of unsigned(63 downto 0);

  signal Msg : U64Array_t(15 downto 0) := (others => kU64Zeros);
  signal Hash0, Hash0_be, A2_out_dly : unsigned(63 downto 0) := kU64Zeros;
  signal A1_in, B1_in, C1_in, D1_in, X1, Y1 : U64Array2D_t(kMixRounds-1 downto 0) := (others => (others => kU64Zeros));
  signal A2_in, B2_in, C2_in, D2_in, X2, Y2 : U64Array2D_t(kMixRounds-1 downto 0) := (others => (others => kU64Zeros));
  signal A1_out, B1_out, C1_out, D1_out     : U64Array2D_t(kMixRounds-1 downto 0) := (others => (others => kU64Zeros));
  signal A2_out, B2_out, C2_out, D2_out     : U64Array2D_t(kMixRounds-1 downto 0) := (others => (others => kU64Zeros));
  signal Nonce : U64NonceArray_t(kMixRounds-1 downto 0);

begin

  -- Message population: same as Sia, msg word 4 will be sigma-index-4 replaced
  -- with the grinding nonce inside the mixer wiring below.
  Msg(9 downto 0)   <= BlockHeader;
  Msg(15 downto 10) <= (others => (others => '0'));

  -- 64-bit nonce iterator (Sia had 48-bit)
  RNG: process(Clk)
  begin
    if rising_edge(Clk) then
      if Enable = '0' then
        Nonce(0)  <= kNonceSeed;
        Nonce(1)  <= kNonceSeed - 8;
        Nonce(2)  <= kNonceSeed - 20 - 2; -- Y (see original Sia comment table)
        Nonce(3)  <= kNonceSeed - 28;
        Nonce(4)  <= kNonceSeed - 32 - 2; -- Y
        Nonce(5)  <= kNonceSeed - 44;
        Nonce(6)  <= kNonceSeed - 48;
        Nonce(7)  <= kNonceSeed - 60 - 2; -- Y
        Nonce(8)  <= kNonceSeed - 68 - 2; -- Y
        Nonce(9)  <= kNonceSeed - 72 - 2; -- Y
        Nonce(10) <= kNonceSeed - 80;
        Nonce(11) <= kNonceSeed - 88;
      else
        for i in 0 to 11 loop
          Nonce(i) <= Nonce(i) + 1;
        end loop;
      end if;
    end if;
  end process;

  -- V-vector init: kHin comes from PkgBlake2b (IV XOR 0x0000000001010020),
  -- identical for Knots blake2b_nokey(out=32).
  A1_in(0)(0) <= kHin(0);                                  -- V0
  A1_in(0)(1) <= kHin(1);                                  -- V1
  A1_in(0)(2) <= kHin(2);                                  -- V2
  A1_in(0)(3) <= kHin(3);                                  -- V3
  B1_in(0)(0) <= kHin(4);                                  -- V4
  B1_in(0)(1) <= kHin(5);                                  -- V5
  B1_in(0)(2) <= kHin(6);                                  -- V6
  B1_in(0)(3) <= kHin(7);                                  -- V7
  C1_in(0)(0) <= kIV(0);                                   -- V8
  C1_in(0)(1) <= kIV(1);                                   -- V9
  C1_in(0)(2) <= kIV(2);                                   -- V10
  C1_in(0)(3) <= kIV(3);                                   -- V11
  -- V12 = IV[4] XOR msg-length-in-bytes. Knots stage-4 mode-0 = 80 bytes = same
  -- as Sia, so the XOR constant is unchanged.
  D1_in(0)(0) <= kIV(4) xor (x"00000000000000" & kStage4MsgLen); -- V12
  D1_in(0)(1) <= kIV(5);                                   -- V13
  D1_in(0)(2) <= not kIV(6);                               -- V14 (last block => invert)
  D1_in(0)(3) <= kIV(7);                                   -- V15

  RoundGen: for i in 0 to kMixRounds-1 generate

    -- Sigma-index-4 message-feed: Msg(4) is replaced with the 64-bit nonce
    -- (Sia used 48-bit; we use the full 64-bit slot for nNonce||m_nonce2).
    MsgFeedGen: for j in 0 to 3 generate
      X1(i)(j) <= Msg(kSigma(i mod 10, 2*j))     when kSigma(i mod 10, 2*j)     /= kNonceSigmaIdx else Nonce(i);
      Y1(i)(j) <= Msg(kSigma(i mod 10, 2*j+1))   when kSigma(i mod 10, 2*j+1)   /= kNonceSigmaIdx else Nonce(i);
      X2(i)(j) <= Msg(kSigma(i mod 10, 2*j+8))   when kSigma(i mod 10, 2*j+8)   /= kNonceSigmaIdx else Nonce(i);
      Y2(i)(j) <= Msg(kSigma(i mod 10, 2*j+9))   when kSigma(i mod 10, 2*j+9)   /= kNonceSigmaIdx else Nonce(i);
    end generate;

    Mixer1: entity work.QuadG
    port map(
      Clk => Clk, A_in => A1_in(i), B_in => B1_in(i), C_in => C1_in(i), D_in => D1_in(i),
      X => X1(i), Y => Y1(i),
      A_out => A1_out(i), B_out => B1_out(i), C_out => C1_out(i), D_out => D1_out(i)
    );

    A2_in(i) <= A1_out(i);
    B2_in(i) <= B1_out(i)(0) & B1_out(i)(3 downto 1);          -- ror 1
    C2_in(i) <= C1_out(i)(1 downto 0) & C1_out(i)(3 downto 2); -- ror 2
    D2_in(i) <= D1_out(i)(2 downto 0) & D1_out(i)(3);          -- ror 3

    Mixer2: entity work.QuadG
    port map(
      Clk => Clk, A_in => A2_in(i), B_in => B2_in(i), C_in => C2_in(i), D_in => D2_in(i),
      X => X2(i), Y => Y2(i),
      A_out => A2_out(i), B_out => B2_out(i), C_out => C2_out(i), D_out => D2_out(i)
    );

    AllButLastRound: if i /= kMixRounds-1 generate
      A1_in(i+1) <= A2_out(i);
      B1_in(i+1) <= B2_out(i)(2 downto 0) & B2_out(i)(3);          -- rol 1
      C1_in(i+1) <= C2_out(i)(1 downto 0) & C2_out(i)(3 downto 2); -- rol 2
      D1_in(i+1) <= D2_out(i)(0) & D2_out(i)(3 downto 1);          -- rol 3
    end generate;

  end generate RoundGen;

  -- Top-64-bit prefilter: Hash0 = H[3] = h3 XOR V3 XOR V11 after the 12th round.
  --
  -- Sia takes H[0] here, and this design did too until it was caught on
  -- hardware. Sia compares its digest in the order blake2b emits it, so its
  -- leading zeros live in H[0]. Bitcoin does not: the reference builds
  -- final[31-i] = hash_b[i], so the compare value is the digest BYTE-REVERSED
  -- and its most significant 8 bytes are digest[31..24] -- that is H[3], not
  -- H[0]. Prefiltering on H[0] is uncorrelated with the real target, so
  -- candidates arrive at the expected rate and every one fails verification:
  -- the miner looks perfectly healthy and finds nothing.
  --
  -- Lane mapping. The rounds leave the v-vector in the diagonal-step frame and
  -- the NEXT round's input un-rotates it, so the un-rotation wiring is what
  -- defines which raw lane holds which v. For C that wiring is
  -- C1_in(k) <= C2_out((k+2) mod 4), i.e. un-rotated C(k) = V(8+k). Hence
  -- V8 = C2_out(2) -- which is what the old H[0] code used, confirming the
  -- direction -- and therefore V11 = C(3) = C2_out((3+2) mod 4) = C2_out(1).
  -- A is passed through unrotated (A1_in(i+1) <= A2_out(i)), so V3 = A2_out(3).
  DelayV3: process(Clk)
  begin
    if rising_edge(Clk) then
      A2_out_dly <= A2_out(kMixRounds-1)(3);
    end if;
  end process;

  Hash0 <= kHin(3) xor A2_out_dly xor C2_out(kMixRounds-1)(1);

  -- Hash0_be is the byte-reverse of Hash0. It is REPORTED, never compared --
  -- see the two separate roles below.
  Hash0_be <= Hash0( 7 downto  0) & Hash0(15 downto  8) & Hash0(23 downto 16) & Hash0(31 downto 24) &
              Hash0(39 downto 32) & Hash0(47 downto 40) & Hash0(55 downto 48) & Hash0(63 downto 56);

  -- COMPARE Hash0. REPORT Hash0_be. They are deliberately different values, and
  -- this block exists so nobody "fixes" that back.
  --
  -- The comparison used to be against Hash0_be, and that was wrong. BLAKE2b
  -- serialises h[3] LITTLE-endian into digest[24..31], and Bitcoin's compare
  -- value is the whole digest reversed (final[31-i] = hash_b[i]) -- so its top
  -- eight bytes are hash_b[31..24], and reading those most-significant-first is
  -- h[3] itself. Hash0 IS the compare value's top 64 bits, already, in the same
  -- units as TargetTop64 (which the host builds as the top 64 bits of the
  -- big-endian 256-bit target). Byte-reversing it first compared a permuted
  -- value against an unpermuted target: the filter then passed on
  -- digest[24..25] while a real solution needs digest[31..30]. Those are
  -- independent, so at any real target it essentially never surfaced one --
  -- which is what blocks_submitted = 0 had been reporting for months.
  --
  -- Sia is the opposite case and its core is correct as written: Siacoin
  -- compares the digest AS EMITTED, so its top 64 bits are digest[0..7]
  -- big-endian = byteswap(h[0]), and OspreySiaCore must keep its byte-reverse.
  -- Same pipeline, opposite convention. Do not unify them.
  --
  -- HashTop64Out keeps carrying Hash0_be because that word has a different job:
  -- it is the host's frame-integrity check. miner.c's expected_hash_top64() and
  -- sia_stratum.c's sia_expected_top64() both recompute byteswap(h[3]) and
  -- require equality, which proves the part computed the digest correctly. It
  -- is never compared against a target on either side, so changing it would
  -- break three equality checks and zynq/check_stage4_pairs.py for no gain.
  --
  -- Still a PREFILTER: true validation needs all 256 bits plus the stage-5
  -- XOR-key-mask, and that happens zynq-side.
  Verify: process(Clk)
  begin
    if rising_edge(Clk) then
      if Hash0 < TargetTop64 then
        Success      <= '1';
        NonceOut     <= Nonce(0) - (kPipeLength + 1); -- account for pipeline latency
        HashTop64Out <= Hash0_be;
      else
        Success      <= '0';
        NonceOut     <= (others => '0');
        HashTop64Out <= (others => '0');
      end if;
    end if;
  end process;

end rtl;
