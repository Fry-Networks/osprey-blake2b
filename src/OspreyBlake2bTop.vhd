-- Copyright (c) 2026, Fry Networks. Adapted from pedrorivera/SiaFpgaMiner (MIT, 2018).
--
-- === OspreyBlake2bTop.vhd ===
--
-- Top-level entity for the Bitcoin Knots BLAKE2b PoW mining pipeline on the
-- Osprey E100 VU35P.
--
-- Wires stage-3 (BLAKE2b of 52-byte "coinb1") into stage-4 (BLAKE2b of 80-byte
-- ASIC-visible msg with 3-way nonce). Presents flat external ports for the
-- zynq to drive; UART framing is added by a wrapper (OspreyBlake2bUartTop.vhd,
-- session 4 or later).
--
-- Data flow:
--   1. Zynq computes h1_hash + h2_hash + prevblock_hidden (all SHA256-derived).
--   2. Zynq delivers Stage3In (52 bytes = 6.5 u64 slots).
--   3. Stage-3 core BLAKE2b's it; ~96 cycles later HashA is stable.
--   4. Stage-4 core receives Stage4In (0..5 = prevblock_hidden + m_time_offset||m_nonce3),
--      overlays HashA into slots 6..9, and grinds 64-bit nNonce||m_nonce2 through
--      slot 4.
--   5. When a candidate is found (top-64-bit prefilter passes), Success asserts
--      and Nonce + HashTop64 are latched.
--   6. Zynq reads Success/Nonce/HashTop64, computes the full 256-bit hash +
--      XOR-key-mask stage-5 finalization + full 256-bit target compare using
--      the Python golden reference (blake2b_reference.py). Submit share to pool
--      if it validates.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

library work;
  use work.PkgBlake2b.all;
  use work.PkgOspreyBlake2b.all;

entity OspreyBlake2bTop is
  generic(
    -- Different top-level instances get different seeds so multiple cores on
    -- one VU35P grind non-overlapping portions of the 64-bit nonce space.
    kNonceSeed : unsigned(63 downto 0) := (others => '1')
  );
  port(
    Clk : in std_logic;
    -- '0' = idle (both stages hold state); '1' = active grind.
    Enable : in std_logic;
    -- Stage-3 message: 52 bytes packed into 7 u64 slots (slots 7..9 must be 0).
    Stage3In : in U64Array_t(9 downto 0);
    -- Stage-4 partial message: slots 0..5 are prevblock_hidden + m_time_offset||m_nonce3.
    -- Slot 4 is IGNORED (overwritten by internal nonce iterator).
    -- Slots 6..9 are IGNORED (overwritten by HashA from stage-3).
    Stage4In : in U64Array_t(9 downto 0);
    -- Top 64 bits of the shifted Bitcoin Knots target (Blake2bTargetShift=22
    -- applied on the zynq side before the value reaches this port).
    TargetTop64 : in unsigned(63 downto 0);
    -- Candidate output. Success rises for one cycle when a top-64-bit prefilter
    -- passes; Nonce is the winning nNonce||m_nonce2 pair; HashTop64 is the
    -- corresponding hash prefix (for zynq-side verification).
    Success      : out std_logic;
    Nonce        : out unsigned(63 downto 0);
    HashTop64    : out unsigned(63 downto 0)
  );
end OspreyBlake2bTop;

architecture rtl of OspreyBlake2bTop is

  signal HashA         : U64Array_t(3 downto 0);
  signal Stage4Msg     : U64Array_t(9 downto 0);

begin

  ---------------------------------------------------------------------------
  -- Stage 3: hash the 52-byte "coinb1" region once per work item.
  ---------------------------------------------------------------------------
  U_Stage3: entity work.OspreyBlake2bStage3Core
  port map(
    Clk         => Clk,
    Enable      => Enable,
    BlockHeader => Stage3In,
    HashOut     => HashA
  );

  ---------------------------------------------------------------------------
  -- Compose stage-4 msg:
  --   slots 0..3 from Stage4In (prevblock_hidden — first 6 bytes forced to
  --     zero by the zynq before it reaches us)
  --   slot 4 IGNORED (overwritten by nonce iterator inside stage-4 core)
  --   slot 5 from Stage4In (m_time_offset || m_nonce3)
  --   slots 6..9 from HashA (stage-3 output = 32 bytes)
  ---------------------------------------------------------------------------
  Stage4Msg(0) <= Stage4In(0);
  Stage4Msg(1) <= Stage4In(1);
  Stage4Msg(2) <= Stage4In(2);
  Stage4Msg(3) <= Stage4In(3);
  Stage4Msg(4) <= (others => '0'); -- overwritten by iterator inside stage-4
  Stage4Msg(5) <= Stage4In(5);
  Stage4Msg(6) <= HashA(0);
  Stage4Msg(7) <= HashA(1);
  Stage4Msg(8) <= HashA(2);
  Stage4Msg(9) <= HashA(3);

  ---------------------------------------------------------------------------
  -- Stage 4: hash the 80-byte ASIC-visible msg, grinding Msg(4) as the nonce.
  ---------------------------------------------------------------------------
  U_Stage4: entity work.OspreyBlake2bStage4Core
  generic map(
    kNonceSeed => kNonceSeed
  )
  port map(
    Clk          => Clk,
    Enable       => Enable,
    BlockHeader  => Stage4Msg,
    TargetTop64  => TargetTop64,
    NonceOut     => Nonce,
    HashTop64Out => HashTop64,
    Success      => Success
  );

end rtl;
