-- Copyright (c) 2026, Fry Networks. Adapted from pedrorivera/SiaFpgaMiner (MIT, 2018).
--
-- === OspreyBlake2bUartTop.vhd ===
--
-- Chip-level top for the Osprey (VU35P CIV). OspreyBlake2bTop exposes the raw
-- parallel core interface (Stage3In/Stage4In 10x64 each, plus TargetTop64/Nonce/
-- HashTop64) — about 1155 bonded IOB after synthesis, against 416 available on
-- the fsvh2104 package (277% over). That is a core boundary, not a chip boundary.
-- This wrapper serialises it onto the board's UART, taking chip IO to 5 pins.
--
-- BOARD INTERFACE matches PachiraMining/E300_development
-- hardware/constrain_e300_vu35p_civ.xdc, which targets this exact part
-- (xcvu35p_CIV-fsvh2104-2-e):
--     clk_p / clk_n   BB18 / BC18   LVDS, 100 MHz, DIFF_TERM_ADV TERM_100
--     rx              C12           LVCMOS12
--     tx              B9            LVCMOS12
--     resetn          BE17          LVCMOS18, active LOW, driven by the zynq
-- That reference design also declares its hash clock at period 4.000 ns, i.e.
-- 250 MHz — the same rate clock_mgmt.vhd generates here.
--
-- ---------------------------------------------------------------------------
-- Wire protocol (8N1, LSB-first, 115200 baud @ 250 MHz -> kBitTimeInClks 2170)
-- ---------------------------------------------------------------------------
-- zynq -> FPGA, 168 bytes, in transmission order:
--     bytes   0.. 79  Stage3In   slots 0..9, 8 bytes each, slot 0 first
--     bytes  80..159  Stage4In   slots 0..9, 8 bytes each, slot 0 first
--     bytes 160..167  TargetTop64
--
-- FPGA -> zynq, 17 bytes, sent when the pipeline reports Success:
--     byte    0       0x01 success flag
--     bytes   1.. 8   Nonce
--     bytes   9..16   HashTop64
--
-- The receiver shifts RIGHT -- each new bit enters at the top and pushes the
-- rest down -- so after all 1344 bits the FIRST byte received sits at the LOW
-- end of WorkData, at bits 7..0. Byte b is therefore at bits 8b+7 downto 8b,
-- and because BLAKE2b words are little-endian (first byte = least significant)
-- each 64-bit slot is simply the natural ascending slice.
--
-- This comment used to claim the opposite, and the code followed it.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

library unisim;
  use unisim.vcomponents.all;

library work;
  use work.PkgBlake2b.all;
  use work.PkgOspreyBlake2b.all;

entity OspreyBlake2bUartTop is
  generic(
    -- MiningClk / 115200 baud. MUST track clock_mgmt.vhd's CLKOUT0_DIVIDE_F.
    --   250.000 MHz (divide 4.000) -> 2170
    --   222.222 MHz (divide 4.500) -> 1929   <-- current
    -- Getting this wrong does not fail synthesis or timing; the board simply
    -- goes quiet, because every byte is clocked at the wrong rate.
    kBitTimeInClks : positive := 1929;
    kNonceSeed     : unsigned(63 downto 0) := (others => '1');
    -- Debug echo: emit one extra frame per work item, tagged 0x02, carrying the
    -- TargetTop64 and Stage3In(0) the core actually parsed. It is what proved the
    -- receive path once the unpack was mirrored, and it costs one frame per work
    -- item, so it stays in the source but is OFF for production. Synthesis
    -- constant-folds the whole path away when this is false.
    kDebugEcho     : boolean := false;
    -- Number of stage-4 mining cores. The ladder moves this ONE number.
    --
    -- Budget after stage 3 was removed: one core is 9,737 CLB = 8.94% of the
    -- device, so N=4 is ~35.8% of the device but ~71.5% of SLR0 -- the last rung
    -- that fits in a single SLR without floorplanning. N>=5 needs SLR1, which is
    -- currently 0.00% used.
    --
    -- Each core gets a distinct high-bit nonce slice via CoreNonceSeed, its own
    -- registered copy of the work item, and a slot in the round-robin arbiter.
    kNumCores      : positive := 8
  );
  port(
    -- This is the ENTIRE chip interface, and it matches the vendor's
    -- constrain_e300_vu35p_non_CIV.xdc exactly: rx, tx and the differential
    -- board clocks, nothing else. There is deliberately no reset pin -- see
    -- below.
    clk_p  : in  std_logic;  -- BB18 (the vendor's clk2_p), LVDS 100 MHz
    clk_n  : in  std_logic;  -- BC18 (clk2_n)
    rx     : in  std_logic;  -- C12, UART from the zynq, LVCMOS18
    tx     : out std_logic   -- B9,  UART to the zynq,   LVCMOS18
  );
end OspreyBlake2bUartTop;

architecture rtl of OspreyBlake2bUartTop is

  constant kRxBytes : positive := 168;
  constant kTxBytes : positive := 17;
  constant kRxBits  : positive := kRxBytes*8;   -- 1344
  constant kTxBits  : positive := kTxBytes*8;   -- 136

  signal ClkIn      : std_logic;   -- single-ended 100 MHz after IBUFDS
  signal MiningClk  : std_logic;
  signal LockedLcl  : std_logic;
  signal aResetInt  : std_logic;

  signal WorkData   : std_logic_vector(kRxBits-1 downto 0);
  signal NewWork    : boolean;

  -- A COMPLETE work item, latched on NewWork. The core must never see the
  -- receiver's live shift register; see the comment above UnpackGen.
  signal WorkDataHeld : std_logic_vector(kRxBits-1 downto 0) := (others => '0');

  -- Clock enable for WorkDataHeld, kept as its own signal purely so it can carry
  -- MAX_FANOUT. NewWork is one flop and WorkDataHeld is 1,344 of them, so the
  -- unreplicated enable became the design's worst setup path the moment stage 3
  -- was removed: post-R1 the critical path was NewWork_reg/C ->
  -- WorkDataHeld_reg[647]/CE, and WNS fell from +0.453 to +0.215 (fmax 282 ->
  -- 264 MHz) even though the design had halved in size. Letting the tool
  -- replicate the driver turns one 1344-load net into ~21 short ones. The fanout
  -- is fixed by the register width, so it does NOT grow with core count.
  signal NewWorkCe : std_logic;
  attribute max_fanout : integer;
  attribute max_fanout of NewWorkCe : signal is 64;
  signal ResultData : std_logic_vector(kTxBits-1 downto 0);

  signal Stage3In     : U64Array_t(9 downto 0);
  signal Stage4In     : U64Array_t(9 downto 0);
  signal TargetTop64  : unsigned(63 downto 0);
  signal Enable       : std_logic;
  signal Success      : std_logic;
  signal SuccessBool  : boolean;
  signal DbgPulse     : boolean := false;
  signal TxTrigger    : boolean;
  signal Nonce        : unsigned(63 downto 0);
  signal HashTop64    : unsigned(63 downto 0);

  -- Arbitrated result path. Even at one core the transmitter silently dropped
  -- any Success raised while a frame was in flight; measured on hardware that
  -- cost 20% at 45 frames/s and 4% at 13 frames/s. The arbiter gives every core
  -- a capture slot and a counted, saturating drop counter, so nothing is lost
  -- without being counted.
  -- Flattened per-core result bus into the arbiter.
  signal CoreSuccess : std_logic_vector(kNumCores-1 downto 0);
  signal CoreNonceV  : std_logic_vector(64*kNumCores-1 downto 0);
  signal CoreHashV   : std_logic_vector(64*kNumCores-1 downto 0);

  attribute dont_touch : string;

  signal TxReady    : boolean;
  signal ArbValid   : boolean;
  signal ArbNonce   : unsigned(63 downto 0);
  signal ArbHash    : unsigned(63 downto 0);
  signal ArbDrops   : std_logic_vector(16*kNumCores-1 downto 0);

begin

  ---------------------------------------------------------------------------
  -- Differential board clock -> single-ended
  ---------------------------------------------------------------------------
  U_ClkBuf: IBUFDS
  generic map(
    DQS_BIAS => "FALSE"
  )
  port map(
    I  => clk_p,
    IB => clk_n,
    O  => ClkIn
  );

  ---------------------------------------------------------------------------
  -- Clocking: 100 MHz board reference -> 250 MHz MiningClk
  ---------------------------------------------------------------------------
  -- The MMCM is never held in reset. There used to be a resetn port constrained
  -- to BE17, described as "active low, from the zynq", but the vendor's own
  -- constraint file for this board has no reset pin at all -- its only ports are
  -- rx, tx and the four differential clocks. So BE17 was a guess, and an
  -- unusually costly one: if that ball is not driven high the inverted input
  -- holds the MMCM and the whole pipeline in reset forever, and the board
  -- answers work items with perfect silence. Which is exactly what it did.
  --
  -- No external reset is needed. Xilinx configuration loads every flop with its
  -- declared initial value, so the design starts from a known state, and the
  -- MMCM's own Locked output supplies the only release that actually matters.
  U_Clk: entity work.clock_mgmt
  port map(
    ClkIn     => ClkIn,
    aReset    => '0',
    MiningClk => MiningClk,
    Locked    => LockedLcl
  );

  -- Hold the UART and pipeline in reset until the MMCM has locked.
  aResetInt <= not LockedLcl;

  ---------------------------------------------------------------------------
  -- UART work interface
  ---------------------------------------------------------------------------
  U_Uart: entity work.OspreyBlake2bUartGetWork
  generic map(
    kBitTimeInClks => kBitTimeInClks,
    kRxBytes       => kRxBytes,
    kTxBytes       => kTxBytes
  )
  port map(
    aReset     => aResetInt,
    Clk        => MiningClk,
    aRx        => rx,
    Tx         => tx,
    NewWork    => NewWork,
    WorkData   => WorkData,
    Success     => SuccessBool,
    ResultData  => ResultData,
    ResultReady => TxReady
  );

  ---------------------------------------------------------------------------
  -- Unpack the work item.
  --   Stage3In slot i  <- bytes (i*8) .. (i*8+7)
  --   Stage4In slot i  <- bytes (80 + i*8) .. (80 + i*8+7)
  --   TargetTop64      <- bytes 160..167
  ---------------------------------------------------------------------------
  -- The receiver shifts right, so byte b of the stream ends up at bits
  -- 8b+7 downto 8b, and a BLAKE2b word (little-endian, first byte least
  -- significant) is exactly the ascending 64-bit slice.
  --
  -- This was previously written through a ByteHigh() helper that placed the
  -- first received byte at the TOP of WorkData -- the mirror image of what the
  -- shift register actually does. The consequences were severe and misleading:
  -- every field was read from the wrong end of the buffer AND byte-swapped
  -- within itself, so Stage3In (and hence HashA and stage 4's slots 6..9),
  -- Stage4In and TargetTop64 were all wrong at once.
  --
  -- The decisive clue was that TargetTop64 landed on WorkData bits 63..0, which
  -- hold bytes 0..7 -- the beginning of Stage3In, not bytes 160..167. So the
  -- core prefiltered against a value lifted from prevblock_hidden and never
  -- looked at the target at all, which is exactly why making the requested
  -- target 1024x looser changed the observed candidate rate by nothing
  -- (rx_bytes 2688 -> 2703).
  --
  -- The result frame is unaffected: its low byte is transmitted first, and
  -- reading the nonce little-endian yields values that track kNonceSeed exactly,
  -- so that path was always correct.
  -- The core is fed from a HELD copy, never from WorkData directly.
  --
  -- WorkData is the receiver's live shift register, driven straight out of
  -- OspreyBlake2bUartGetWork. A 168-byte item takes 14.58 ms to clock in at
  -- 115200 baud, and during all of it the top 64 bits -- which is where
  -- TargetTop64 is sliced from -- hold the eight most recently arrived bytes.
  -- Those bytes are digest material, i.e. effectively uniform random. The
  -- pipeline free-runs, so `Hash0 < TargetTop64` was comparing one pseudo-random
  -- 64-bit value against another and came out true on roughly half of the
  -- ~3.65 million clocks in that window. The transmitter's `when Idle => if
  -- Success` is level-sensitive, so it re-armed immediately and streamed frames
  -- back to back for the whole transfer.
  --
  -- On the wire that showed up as exactly 16 bytes read per work push, every
  -- push, forever: the host sits in uart_write's TX_FULL spin for ~13.2 ms of
  -- the 14.58 ms and cannot drain, so it can only ever recover one RX FIFO's
  -- worth. 16 is the FIFO depth, not a frame length -- the giveaway that the
  -- burst was never a frame boundary at all.
  --
  -- Latching on NewWork fixes it at the source. NewWork is a one-cycle pulse
  -- raised after the final byte is shifted in, so workDataLcl is already
  -- complete when it fires. WorkDataHeld resets to all zeros, which makes
  -- TargetTop64 = 0 before the first item ever lands -- and nothing is ever
  -- below zero, so the core stays silent until it has real work. RunCtl drops
  -- Enable on the same NewWork pulse, so the message and the nonce reload land
  -- together and the core resumes on a consistent view.
  NewWorkCe <= '1' when NewWork else '0';

  HoldWork: process(aResetInt, MiningClk)
  begin
    if aResetInt = '1' then
      WorkDataHeld <= (others => '0');
    elsif rising_edge(MiningClk) then
      if NewWorkCe = '1' then
        WorkDataHeld <= WorkData;
      end if;
    end if;
  end process;

  UnpackGen: for i in 0 to 9 generate
    Stage3In(i) <= unsigned(WorkDataHeld(64*i        + 63 downto 64*i));
    Stage4In(i) <= unsigned(WorkDataHeld(64*(10 + i) + 63 downto 64*(10 + i)));
  end generate;
  TargetTop64 <= unsigned(WorkDataHeld(64*20 + 63 downto 64*20));

  ---------------------------------------------------------------------------
  -- Run control. NewWork drops Enable for a single cycle, which reloads the
  -- nonce iterator to kNonceSeed; otherwise the grind runs continuously.
  --
  -- Enable used to be dropped on Success as well, to "halt the grind until the
  -- zynq sends the next work item". In the core, Enable = '0' does not pause
  -- anything -- it RELOADS the nonce iterator to kNonceSeed. So every reported
  -- candidate restarted the search from the seed. At the bring-up target, where
  -- Success asserts on almost every cycle, the iterator was reset on almost
  -- every cycle and the nonce never left a ~20-wide band around the seed: the
  -- captured frames ran seed-98 to seed-78 and never advanced, against the
  -- ~369,000 per frame they should have. It is not only a bring-up artifact
  -- either -- at the real target Success still fires roughly once in 256 hashes,
  -- so the part would have re-ground the same couple of hundred nonces forever
  -- and searched nothing.
  --
  -- Success needs no run-control involvement at all: it only gates a result
  -- frame onto the UART. The nonce must keep advancing underneath it.
  ---------------------------------------------------------------------------
  RunCtl: process(aResetInt, MiningClk)
  begin
    if aResetInt = '1' then
      Enable <= '0';
    elsif rising_edge(MiningClk) then
      if NewWork then
        Enable <= '0';
      else
        Enable <= '1';
      end if;
    end if;
  end process;

  ---------------------------------------------------------------------------
  -- The BLAKE2b mining pipeline
  ---------------------------------------------------------------------------
  -- kNumCores cores, each on its OWN registered copy of the work item, the
  -- target and enable.
  --
  -- The registration is not cosmetic. MixG_FlopPipe_4 takes its operands
  -- combinationally, so every work-item bit reaches all 96 G units of a core;
  -- driving N cores from one net multiplies that fanout by N and the critical
  -- path degrades linearly in N. This design has already been bitten twice by
  -- exactly that: post-R1 the worst path was NewWork -> WorkDataHeld[*].CE
  -- (1,344 loads), and post-R2 it is Enable -> Stage4/Nonce_reg[*].S (768 loads
  -- at ONE core, so N*768 at N). A register per core makes each net drive one
  -- core's worth and nothing more.
  --
  -- DONT_TOUCH is mandatory: the N copies are bit-identical, and without it
  -- Vivado merges them straight back into one register and the fanout reduction
  -- -- the entire point -- silently disappears.
  CoreGen: for k in 0 to kNumCores-1 generate
    signal S4Reg  : U64Array_t(9 downto 0);
    signal TgtReg : unsigned(63 downto 0);
    signal EnReg  : std_logic;
    signal Succ_k : std_logic;
    signal Nonce_k, Hash_k : unsigned(63 downto 0);

    attribute dont_touch of S4Reg  : signal is "true";
    attribute dont_touch of TgtReg : signal is "true";
    attribute dont_touch of EnReg  : signal is "true";
  begin
    -- The work item is quasi-static (one change per ~30 s pool notify), so an
    -- extra cycle of latency costs nothing. Enable goes through the SAME depth
    -- so the message and the nonce reload still land together.
    PerCoreReg: process(MiningClk)
    begin
      if rising_edge(MiningClk) then
        S4Reg  <= Stage4In;
        TgtReg <= TargetTop64;
        EnReg  <= Enable;
      end if;
    end process;

    U_Core: entity work.OspreyBlake2bTop
    generic map(
      kNonceSeed    => CoreNonceSeed(k, kNumCores),
      kOnChipStage3 => false
    )
    port map(
      Clk         => MiningClk,
      Enable      => EnReg,
      Stage3In    => Stage3In,      -- unused when kOnChipStage3 is false
      Stage4In    => S4Reg,
      TargetTop64 => TgtReg,
      Success     => Succ_k,
      Nonce       => Nonce_k,
      HashTop64   => Hash_k
    );

    CoreSuccess(k) <= Succ_k;
    CoreNonceV(64*k + 63 downto 64*k) <= std_logic_vector(Nonce_k);
    CoreHashV (64*k + 63 downto 64*k) <= std_logic_vector(Hash_k);
  end generate CoreGen;

  ---------------------------------------------------------------------------
  -- Debug echo: report what the core actually PARSED out of the work item.
  --
  -- Every remaining question is about the core's internal view -- which bytes
  -- became TargetTop64, whether the receive phase is right -- and none of it is
  -- observable from the host, which has cost many build-deploy cycles of
  -- inference. So one frame is emitted per work item carrying the parsed
  -- TargetTop64 and the first stage-3 slot, tagged 0x02 so the host cannot
  -- confuse it with a candidate.
  --
  -- If the receive phase is correct these come back byte-for-byte equal to what
  -- was transmitted; any rotation shows up immediately and its size is directly
  -- readable from how the bytes have shifted.
  --
  -- NewWork is a one-cycle pulse, and WorkData is stable by the cycle after it,
  -- so the echo is registered one cycle late.
  ---------------------------------------------------------------------------
  -- OFF for production (kDebugEcho = false): the generate is elaborated away, so
  -- DbgPulse is a constant false and the reply path below reduces to the plain
  -- candidate frame. Nothing is left to optimise out at synthesis.
  DbgOn: if kDebugEcho generate
    DbgEcho: process(aResetInt, MiningClk)
    begin
      if aResetInt = '1' then
        DbgPulse <= false;
      elsif rising_edge(MiningClk) then
        DbgPulse <= NewWork;
      end if;
    end process;
  end generate;

  DbgOff: if not kDebugEcho generate
    DbgPulse <= false;
  end generate;

  -- The transmitter latches on a RISING edge, so the debug pulse and a candidate
  -- must not be asserted in the same cycle or one would be swallowed. NewWork
  -- has just reloaded the nonce iterator, so no candidate is pending here.
  ---------------------------------------------------------------------------
  -- Result arbitration. At kNumCores = 1 this is a one-slot buffer, which is
  -- still worth having: it converts "Success while TX busy is silently thrown
  -- away" into "Success is held until the transmitter can take it, and if it
  -- cannot, the loss is counted".
  ---------------------------------------------------------------------------
  U_Arb: entity work.OspreyBlake2bResultArb
  generic map(
    kNumCores => kNumCores,
    kIdxBits  => ClogB2(kNumCores)
  )
  port map(
    Clk         => MiningClk,
    aReset      => aResetInt,
    CoreSuccess => CoreSuccess,
    CoreNonce   => CoreNonceV,
    CoreHash    => CoreHashV,
    ResultReady => TxReady,
    ResultValid => ArbValid,
    ResultNonce => ArbNonce,
    ResultHash  => ArbHash,
    DropCount   => ArbDrops
  );

  TxTrigger <= DbgPulse or ArbValid;

  ---------------------------------------------------------------------------
  -- Pack the reply. The transmitter shifts the LOW byte out first, so the flag
  -- occupies the low byte and is received first by the zynq.
  ---------------------------------------------------------------------------
  ResultData <= (std_logic_vector(Stage3In(0)) & std_logic_vector(TargetTop64) & x"02")
                when DbgPulse else
                (std_logic_vector(ArbHash) & std_logic_vector(ArbNonce) & x"01");

  SuccessBool <= TxTrigger;

end rtl;
