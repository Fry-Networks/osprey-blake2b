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
    -- 250 MHz / 115200 baud. Keep in step with clock_mgmt.vhd's MMCM output.
    kBitTimeInClks : positive := 2170;
    kNonceSeed     : unsigned(63 downto 0) := (others => '1');
    -- Debug echo: emit one extra frame per work item, tagged 0x02, carrying the
    -- TargetTop64 and Stage3In(0) the core actually parsed. It is what proved the
    -- receive path once the unpack was mirrored, and it costs one frame per work
    -- item, so it stays in the source but is OFF for production. Synthesis
    -- constant-folds the whole path away when this is false.
    kDebugEcho     : boolean := false
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
    Success    => SuccessBool,
    ResultData => ResultData
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
  UnpackGen: for i in 0 to 9 generate
    Stage3In(i) <= unsigned(WorkData(64*i        + 63 downto 64*i));
    Stage4In(i) <= unsigned(WorkData(64*(10 + i) + 63 downto 64*(10 + i)));
  end generate;
  TargetTop64 <= unsigned(WorkData(64*20 + 63 downto 64*20));

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
  U_Core: entity work.OspreyBlake2bTop
  generic map(
    kNonceSeed => kNonceSeed
  )
  port map(
    Clk         => MiningClk,
    Enable      => Enable,
    Stage3In    => Stage3In,
    Stage4In    => Stage4In,
    TargetTop64 => TargetTop64,
    Success     => Success,
    Nonce       => Nonce,
    HashTop64   => HashTop64
  );

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
  TxTrigger <= DbgPulse or (Success = '1');

  ---------------------------------------------------------------------------
  -- Pack the reply. The transmitter shifts the LOW byte out first, so the flag
  -- occupies the low byte and is received first by the zynq.
  ---------------------------------------------------------------------------
  ResultData <= (std_logic_vector(Stage3In(0)) & std_logic_vector(TargetTop64) & x"02")
                when DbgPulse else
                (std_logic_vector(HashTop64) & std_logic_vector(Nonce) & x"01");

  SuccessBool <= TxTrigger;

end rtl;
