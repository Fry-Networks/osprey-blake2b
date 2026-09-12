-- NOTE ON WHY THIS FILE CARRIES TWO DESIGN UNITS.
--
-- OspreyBlake2bResultArb belongs in its own file and was written that way. It
-- lives here because build/synth.tcl names its ten sources explicitly and this
-- session cannot edit that script: ~/.claude/settings.json denies
-- Read(./build/**), which is aimed at build ARTIFACTS but also covers
-- build/synth.tcl, a source-controlled build script -- and the Edit tool
-- requires a prior Read. A new .vhd would therefore never be compiled.
--
-- VHDL allows several design units per file, and synth.tcl reads
-- OspreyBlake2bTop.vhd before OspreyBlake2bUartTop.vhd, so the arbiter is
-- analysed before the entity that instantiates it. If the deny is ever lifted,
-- split this back out and add it to the source list -- nothing else changes.

-- Copyright (c) 2026, Fry Networks. MIT.
--
-- OspreyBlake2bResultArb.vhd
--
-- Round-robin arbiter between N mining cores and the single UART transmitter.
--
-- WHY THIS EXISTS. The transmitter accepts a result only while it is idle
-- (OspreyBlake2bUartGetWork's `when Idle => if Success`), has no busy output,
-- and silently discards anything asserted while it is busy. With one core that
-- already costs real throughput: measured on hardware, 44.79 frames/s yielded
-- 199.8 MH/s against a 250 MH/s part (20% lost), while the same part at 13.39
-- frames/s yielded 238.9 MH/s (4% lost). Loss tracks roughly twice the TX-busy
-- fraction, because the level-sensitive FSM re-arms the instant it returns to
-- Idle. With N cores and no arbiter the loss is worse and, more importantly,
-- UNFAIR: a fixed priority starves cores 1..N-1, which looks exactly like "the
-- extra cores do not work".
--
-- WHAT IT DOES NOT PROMISE. A 17-byte frame at 115200 baud occupies 170 bit
-- times = 1.4756 ms, so the link tops out at 677 frames/s no matter how many
-- cores feed it. Above that, drops are arithmetic, not a bug. So the property
-- this block actually guarantees is:
--
--     frames_emitted + sum(Drop) == sum(Success)
--
-- Nothing is lost SILENTLY. Every dropped candidate is counted, per core, in a
-- saturating counter. That is a checkable conservation law; "never drops" is not
-- achievable and claiming it would be a lie.
--
-- FRAME FORMAT IS UNTOUCHED. The host's parse_result rejects anything whose
-- first byte is not 0x01, and three consecutive rejects force a re-sync, so any
-- new frame type would be a protocol break. Core identity is not transmitted --
-- it rides for free in the top bits of the nonce, because each core is seeded
-- with a distinct high-bit slice.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

entity OspreyBlake2bResultArb is
  generic(
    kNumCores : positive := 1;
    kIdxBits  : natural  := 0        -- ceil(log2(kNumCores)); 0 when kNumCores = 1
  );
  port(
    Clk    : in std_logic;
    aReset : in std_logic;

    -- From the cores. Flattened because VHDL-2008 unconstrained arrays of
    -- unsigned in a port would force the package type on every instantiator.
    CoreSuccess : in std_logic_vector(kNumCores-1 downto 0);
    CoreNonce   : in std_logic_vector(64*kNumCores-1 downto 0);
    CoreHash    : in std_logic_vector(64*kNumCores-1 downto 0);

    -- To the transmitter.
    ResultReady : in  boolean;                        -- TX is idle, will accept now
    ResultValid : out boolean;                        -- one-cycle grant pulse
    ResultNonce : out unsigned(63 downto 0);
    ResultHash  : out unsigned(63 downto 0);

    -- Saturating per-core drop counters, for simulation and for an ILA. These
    -- deliberately do NOT reach the wire protocol.
    DropCount   : out std_logic_vector(16*kNumCores-1 downto 0)
  );
end OspreyBlake2bResultArb;

architecture rtl of OspreyBlake2bResultArb is

  type Word64Array_t is array (natural range <>) of unsigned(63 downto 0);
  type Word16Array_t is array (natural range <>) of unsigned(15 downto 0);

  signal Nonce : Word64Array_t(kNumCores-1 downto 0);
  signal Hash  : Word64Array_t(kNumCores-1 downto 0);
  signal Vld   : std_logic_vector(kNumCores-1 downto 0) := (others => '0');
  signal Drop  : Word16Array_t(kNumCores-1 downto 0)    := (others => (others => '0'));
  signal Grant : std_logic_vector(kNumCores-1 downto 0);

  signal RrPtr : natural range 0 to kNumCores-1 := 0;

  signal GrantIdx   : natural range 0 to kNumCores-1 := 0;
  signal GrantValid : boolean := false;

begin

  ---------------------------------------------------------------------------
  -- Combinational round-robin select over the valid slots, starting at RrPtr.
  ---------------------------------------------------------------------------
  Select_p: process(Vld, RrPtr, ResultReady)
    variable idx   : natural;
    variable found : boolean;
  begin
    found := false;
    idx   := 0;
    if ResultReady then
      for n in 0 to kNumCores-1 loop
        -- Walk outward from RrPtr so no core can be starved by a busier
        -- lower-numbered neighbour.
        if not found then
          if Vld((RrPtr + n) mod kNumCores) = '1' then
            idx   := (RrPtr + n) mod kNumCores;
            found := true;
          end if;
        end if;
      end loop;
    end if;
    GrantIdx   <= idx;
    GrantValid <= found;
  end process;

  GrantGen: for k in 0 to kNumCores-1 generate
    Grant(k) <= '1' when (GrantValid and GrantIdx = k) else '0';
  end generate;

  ---------------------------------------------------------------------------
  -- Capture. One slot per core. A Success arriving on the same cycle as its own
  -- grant REFILLS the slot rather than counting a drop -- getting that ordering
  -- wrong would under-report throughput and over-report loss.
  ---------------------------------------------------------------------------
  Capture: process(aReset, Clk)
  begin
    if aReset = '1' then
      Vld  <= (others => '0');
      Drop <= (others => (others => '0'));
    elsif rising_edge(Clk) then
      for k in 0 to kNumCores-1 loop
        if CoreSuccess(k) = '1' and (Vld(k) = '0' or Grant(k) = '1') then
          Nonce(k) <= unsigned(CoreNonce(64*k + 63 downto 64*k));
          Hash(k)  <= unsigned(CoreHash (64*k + 63 downto 64*k));
          Vld(k)   <= '1';
        elsif CoreSuccess(k) = '1' then
          if Drop(k) /= x"FFFF" then          -- saturate, never wrap
            Drop(k) <= Drop(k) + 1;
          end if;
        elsif Grant(k) = '1' then
          Vld(k) <= '0';
        end if;
      end loop;
    end if;
  end process;

  ---------------------------------------------------------------------------
  -- Advance the pointer past whoever was just served.
  ---------------------------------------------------------------------------
  Rr_p: process(aReset, Clk)
  begin
    if aReset = '1' then
      RrPtr <= 0;
    elsif rising_edge(Clk) then
      if GrantValid then
        RrPtr <= (GrantIdx + 1) mod kNumCores;
      end if;
    end if;
  end process;

  ResultValid <= GrantValid;
  ResultNonce <= Nonce(GrantIdx);
  ResultHash  <= Hash(GrantIdx);

  DropGen: for k in 0 to kNumCores-1 generate
    DropCount(16*k + 15 downto 16*k) <= std_logic_vector(Drop(k));
  end generate;

end rtl;


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
    kNonceSeed : unsigned(63 downto 0) := (others => '1');
    -- Recompute HashA on-chip, or take it from the work item?
    --
    -- FALSE is correct and is the default. The host ALREADY puts the value on
    -- the wire, on both work sources:
    --   getblocktemplate: miner/work_item.c:87 computes hash_a = blake2b(ss3)
    --                     and line 99 writes it to ss4+48.
    --   stratum:          miner/sia_stratum.c:74 writes merkleroot to ss4+48,
    --                     and jobs carrying merkle branches are refused
    --                     (worksrc_stratum.c:132), so root == leaf ==
    --                     blake2b(0x00 || arbtx) == blake2b(ss3).
    -- ss4[48..79] arrives as Stage4In(6..9), so the on-chip stage 3 was
    -- recomputing a value it was already being handed.
    --
    -- It is not cheap: stage 3 is a fully unrolled 96-clock pipeline costing
    -- ~9,313 CLB / ~50k LUT / ~97k FF -- about half the used logic, and a whole
    -- extra mining core's worth -- to run ONCE per pool notify (~30 s) rather
    -- than per nonce. Its own header says as much. It also owned the design's
    -- worst setup path, whose destination was inside U_Stage3.
    --
    -- TRUE is kept because OspreyBlake2bStage3Core remains the only full 256-bit
    -- oracle for the shared QuadG/MixG math (tb_stage3_core's 100/100 vector
    -- gate), and because flipping one boolean is the cheapest possible revert.
    kOnChipStage3 : boolean := false
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
  S3On: if kOnChipStage3 generate
    U_Stage3: entity work.OspreyBlake2bStage3Core
    port map(
      Clk         => Clk,
      Enable      => Enable,
      BlockHeader => Stage3In,
      HashOut     => HashA
    );
  end generate;

  -- Stage 3 bypassed: the host already supplied HashA in ss4[48..79], which
  -- arrives as Stage4In(6..9). See the kOnChipStage3 comment on the entity.
  S3Off: if not kOnChipStage3 generate
    HashA(0) <= Stage4In(6);
    HashA(1) <= Stage4In(7);
    HashA(2) <= Stage4In(8);
    HashA(3) <= Stage4In(9);
  end generate;

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
