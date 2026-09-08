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
-- The receiver shifts right, so the FIRST byte received lands in the HIGH end of
-- WorkData. ByteHigh() below encodes that; do not "simplify" it to ascending
-- offsets without re-deriving the direction.

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
    kNonceSeed     : unsigned(63 downto 0) := (others => '1')
  );
  port(
    clk_p  : in  std_logic;  -- BB18, LVDS 100 MHz board reference
    clk_n  : in  std_logic;  -- BC18
    resetn : in  std_logic;  -- BE17, active LOW, from the zynq
    rx     : in  std_logic;  -- C12, UART from the zynq
    tx     : out std_logic   -- B9,  UART to the zynq
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
  signal aResetExt  : std_logic;
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
  signal Nonce        : unsigned(63 downto 0);
  signal HashTop64    : unsigned(63 downto 0);

  -- Byte b (0-based, transmission order) occupies bits ByteHigh(b) downto ByteHigh(b)-7.
  -- First byte received sits at the top, hence the descending mapping.
  function ByteHigh(b : natural) return natural is
  begin
    return kRxBits-1 - b*8;
  end function;

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

  -- Board reset is active low.
  aResetExt <= not resetn;

  ---------------------------------------------------------------------------
  -- Clocking: 100 MHz board reference -> 250 MHz MiningClk
  ---------------------------------------------------------------------------
  U_Clk: entity work.clock_mgmt
  port map(
    ClkIn     => ClkIn,
    aReset    => aResetExt,
    MiningClk => MiningClk,
    Locked    => LockedLcl
  );

  -- Hold the UART and pipeline in reset until the MMCM has locked.
  aResetInt <= aResetExt or (not LockedLcl);

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
  UnpackGen: for i in 0 to 9 generate
    Stage3In(i) <= unsigned(WorkData(ByteHigh(i*8)      downto ByteHigh(i*8+7)-7));
    Stage4In(i) <= unsigned(WorkData(ByteHigh(80 + i*8) downto ByteHigh(80 + i*8+7)-7));
  end generate;
  TargetTop64 <= unsigned(WorkData(ByteHigh(160) downto ByteHigh(167)-7));

  ---------------------------------------------------------------------------
  -- Run control. NewWork restarts the nonce iterator by dropping Enable for a
  -- cycle; Success halts the grind until the zynq sends the next work item.
  ---------------------------------------------------------------------------
  RunCtl: process(aResetInt, MiningClk)
  begin
    if aResetInt = '1' then
      Enable <= '0';
    elsif rising_edge(MiningClk) then
      if NewWork then
        Enable <= '0';
      elsif Success = '1' then
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

  SuccessBool <= (Success = '1');

  ---------------------------------------------------------------------------
  -- Pack the reply. The transmitter shifts the LOW byte out first, so the 0x01
  -- flag occupies the low byte and is received first by the zynq.
  ---------------------------------------------------------------------------
  ResultData <= std_logic_vector(HashTop64) &
                std_logic_vector(Nonce) &
                x"01";

end rtl;
