-- Copyright (c) 2026, Fry Networks. Adapted from pedrorivera/SiaFpgaMiner (MIT, 2018).
--
-- === OspreySiaCore.vhd ===
--
-- Siacoin BLAKE2b-256 mining core: one compression of an 80-byte header,
-- grinding Msg(4) as a 64-bit nonce. The 12-round x 2-mixer x 4-step G pipeline
-- is the vendor's, unchanged.
--
-- Deltas vs the vendor Blake2bMinerCore:
--   1. Nonce widened 48 -> 64 bits, matching Sia's 8-byte nonce field exactly.
--   2. The target arrives on its own port instead of riding in BlockHeader(4),
--      because slot 4 is the grind slot here and cannot also carry a target.
--
-- Delta vs this repo's OspreyBlake2bStage4Core: THE PREFILTER TAP. That is the
-- entire difference, and getting it wrong is silent -- the miner looks healthy
-- and finds nothing -- so it is worth stating exactly why the two chains differ.
--
--   BLAKE2b emits h[0] into digest[0..7] LITTLE-endian, h[3] into digest[24..31].
--
--   Siacoin compares the digest in the order blake2b emits it: digest[0] is the
--   most significant byte. So the compare value's top 64 bits are digest[0..7]
--   read big-endian, which is byteswap(h[0]). Tap H[0], then byte-reverse.
--
--   Bitcoin/Knots compares the digest REVERSED (final[31-i] = digest[i]), so its
--   top 64 bits are digest[31..24] read big-endian -- and digest[24..31] read
--   little-endian is h[3] itself. Tap H[3], and do NOT byte-reverse.
--
-- This core is the Sia case: H[0] with the byte-reverse, exactly as the vendor
-- had it. zynq/check_sia_pairs.py grades the emitted pairs against
-- byteswap(H[0]) and carries a named detector for the H[3] form, so a copy-paste
-- from the Knots core cannot pass quietly.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

library work;
  use work.PkgBlake2b.all;
  use work.PkgOspreySia.all;

entity OspreySiaCore is
  generic(
    -- Initial nonce value. Different cores get different seeds so several can
    -- grind disjoint portions of the 64-bit space.
    kNonceSeed : unsigned(63 downto 0) := (others => '1') -- first cycle wraps to 0
  );
  port(
    Clk    : in std_logic;
    -- When '0', reset the nonce iterator to kNonceSeed. When '1', grind.
    Enable : in std_logic;
    -- The 80-byte Sia header as 10 x u64. Slot 4 is OVERWRITTEN by the nonce
    -- iterator; slots 6..9 are the merkle root and are used as supplied -- there
    -- is no stage 3 to overwrite them, which is the point of this core.
    BlockHeader : in U64Array_t(9 downto 0);
    -- Top 64 bits of the 256-bit share/network target.
    TargetTop64 : in unsigned(63 downto 0);
    NonceOut     : out unsigned(63 downto 0);
    HashTop64Out : out unsigned(63 downto 0);
    Success      : out std_logic := '0'
  );
end OspreySiaCore;

architecture rtl of OspreySiaCore is

  constant kGPerMixer : integer := 4;
  constant kMixRounds : integer := 12;
  constant kPipeLength: integer := 4*2*12; -- 4 clks * 2 mixers * 12 rounds

  type U64Array2D_t is array (integer range <>) of U64Array_t(kGPerMixer-1 downto 0);
  type U64NonceArray_t is array (integer range <>) of unsigned(63 downto 0);

  signal Msg : U64Array_t(15 downto 0) := (others => kU64Zeros);
  signal Hash0, Hash0_be, A2_out_dly : unsigned(63 downto 0) := kU64Zeros;
  signal A1_in, B1_in, C1_in, D1_in, X1, Y1 : U64Array2D_t(kMixRounds-1 downto 0) := (others => (others => kU64Zeros));
  signal A2_in, B2_in, C2_in, D2_in, X2, Y2 : U64Array2D_t(kMixRounds-1 downto 0) := (others => (others => kU64Zeros));
  signal A1_out, B1_out, C1_out, D1_out     : U64Array2D_t(kMixRounds-1 downto 0) := (others => (others => kU64Zeros));
  signal A2_out, B2_out, C2_out, D2_out     : U64Array2D_t(kMixRounds-1 downto 0) := (others => (others => kU64Zeros));
  signal Nonce : U64NonceArray_t(kMixRounds-1 downto 0);

begin

  Msg(9 downto 0)   <= BlockHeader;
  Msg(15 downto 10) <= (others => (others => '0'));

  -- 64-bit nonce iterator. The per-lane offsets are the vendor's, derived from
  -- where each round's sigma schedule reads word 4; they are not arbitrary and
  -- must not be "tidied".
  RNG: process(Clk)
  begin
    if rising_edge(Clk) then
      if Enable = '0' then
        Nonce(0)  <= kNonceSeed;
        Nonce(1)  <= kNonceSeed - 8;
        Nonce(2)  <= kNonceSeed - 20 - 2; -- Y
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

  -- V-vector init. kHin = IV XOR 0x0000000001010020, which is identical for Sia
  -- and Knots because both are blake2b_nokey with a 32-byte digest.
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
  D1_in(0)(0) <= kIV(4) xor (x"00000000000000" & kSiaMsgLen); -- V12 = IV4 xor 80
  D1_in(0)(1) <= kIV(5);                                   -- V13
  D1_in(0)(2) <= not kIV(6);                               -- V14 (last block)
  D1_in(0)(3) <= kIV(7);                                   -- V15

  RoundGen: for i in 0 to kMixRounds-1 generate

    MsgFeedGen: for j in 0 to 3 generate
      X1(i)(j) <= Msg(kSigma(i mod 10, 2*j))     when kSigma(i mod 10, 2*j)     /= kSiaNonceSigmaIdx else Nonce(i);
      Y1(i)(j) <= Msg(kSigma(i mod 10, 2*j+1))   when kSigma(i mod 10, 2*j+1)   /= kSiaNonceSigmaIdx else Nonce(i);
      X2(i)(j) <= Msg(kSigma(i mod 10, 2*j+8))   when kSigma(i mod 10, 2*j+8)   /= kSiaNonceSigmaIdx else Nonce(i);
      Y2(i)(j) <= Msg(kSigma(i mod 10, 2*j+9))   when kSigma(i mod 10, 2*j+9)   /= kSiaNonceSigmaIdx else Nonce(i);
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

  -- Prefilter: Hash0 = H[0] = h0 XOR V0 XOR V8 after the 12th round.
  --
  -- Lane mapping, same derivation as the Knots core but landing on different
  -- lanes. A is passed through unrotated (A1_in(i+1) <= A2_out(i)), so
  -- V0 = A2_out(0). For C the un-rotation is C1_in(k) <= C2_out((k+2) mod 4),
  -- i.e. un-rotated C(k) = V(8+k), so V8 = C(0) = C2_out(2).
  DelayV0: process(Clk)
  begin
    if rising_edge(Clk) then
      A2_out_dly <= A2_out(kMixRounds-1)(0);
    end if;
  end process;

  Hash0 <= kHin(0) xor A2_out_dly xor C2_out(kMixRounds-1)(2);

  -- Byte-reverse. Sia's compare value is the digest as emitted with digest[0]
  -- most significant, and digest[0..7] is h[0] little-endian -- so the reversal
  -- is what makes the 64-bit compare below an ordering on the real value. The
  -- Knots core must NOT do this; see the header comment.
  Hash0_be <= Hash0( 7 downto  0) & Hash0(15 downto  8) & Hash0(23 downto 16) & Hash0(31 downto 24) &
              Hash0(39 downto 32) & Hash0(47 downto 40) & Hash0(55 downto 48) & Hash0(63 downto 56);

  -- A PREFILTER. The host still compares all 256 bits before submitting.
  Verify: process(Clk)
  begin
    if rising_edge(Clk) then
      if Hash0_be < TargetTop64 then
        Success      <= '1';
        NonceOut     <= Nonce(0) - (kPipeLength + 1); -- pipeline latency
        HashTop64Out <= Hash0_be;
      else
        Success      <= '0';
        NonceOut     <= (others => '0');
        HashTop64Out <= (others => '0');
      end if;
    end if;
  end process;

end rtl;
