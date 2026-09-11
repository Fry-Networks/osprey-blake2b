-- Copyright (c) 2026, Fry Networks. Adapted from pedrorivera/SiaFpgaMiner (MIT, 2018).
--
-- === OspreySiaUartTop.vhd ===
--
-- Chip-level top for the Siacoin core on the Osprey E100 (VU35P). Same board
-- interface and the same four pins as the Knots wrapper -- clk_p, clk_n, rx, tx
-- -- because it is the same board; only the payload differs.
--
-- ---------------------------------------------------------------------------
-- Wire protocol (8N1, LSB-first, 115200 baud @ 250 MHz -> kBitTimeInClks 2170)
-- ---------------------------------------------------------------------------
-- zynq -> FPGA, 88 bytes, in transmission order:
--     bytes  0.. 7   parent block ID  slot 0     (Header slots 0..3)
--     bytes  8..31   parent block ID  slots 1..3
--     bytes 32..39   nonce slot       (IGNORED -- the iterator drives it)
--     bytes 40..47   timestamp
--     bytes 48..79   merkle root      (Header slots 6..9, used AS SUPPLIED)
--     bytes 80..87   TargetTop64
--
-- FPGA -> zynq, 17 bytes, sent when the pipeline reports Success:
--     byte    0      0x01 success flag
--     bytes   1.. 8  Nonce
--     bytes   9..16  HashTop64
--
-- 88 rather than the Knots wrapper's 168 because there is no second stage
-- message to carry: Sia's merkle root arrives folded and the header IS the
-- whole message. The reply frame is deliberately identical in shape so the
-- host's 17-byte parser, its frame-sync and its 0x01 flag handling are shared
-- between the two modules rather than forked.
--
-- OspreyBlake2bUartGetWork is instantiated UNMODIFIED. It was already generic
-- over kRxBytes/kTxBytes -- that is exactly the parameterisation the Sia
-- original lacked -- so a different frame size needs no new receiver and no
-- edit to a file the Knots bitstream also depends on.
--
-- The receiver shifts RIGHT, so the FIRST byte received sits at the LOW end of
-- WorkData: byte b is at bits 8b+7 downto 8b, and a BLAKE2b word (little-endian,
-- first byte least significant) is the natural ascending 64-bit slice. Getting
-- this mirrored once already cost this project a silent, fully-wrong bitstream,
-- so the mapping below is deliberately the same shape as the Knots one and is
-- covered by tb_sia_unpack.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

library unisim;
  use unisim.vcomponents.all;

library work;
  use work.PkgBlake2b.all;
  use work.PkgOspreySia.all;

entity OspreySiaUartTop is
  generic(
    -- 250 MHz / 115200 baud. Keep in step with clock_mgmt.vhd's MMCM output.
    kBitTimeInClks : positive := 2170;
    kNonceSeed     : unsigned(63 downto 0) := (others => '1')
  );
  port(
    clk_p  : in  std_logic;  -- BB18, LVDS 100 MHz
    clk_n  : in  std_logic;  -- BC18
    rx     : in  std_logic;  -- C12, UART from the zynq, LVCMOS18
    tx     : out std_logic   -- B9,  UART to the zynq,   LVCMOS18
  );
end OspreySiaUartTop;

architecture rtl of OspreySiaUartTop is

  constant kRxBytes : positive := kSiaWorkItemBytes;   -- 88
  constant kTxBytes : positive := kSiaResultBytes;     -- 17
  constant kRxBits  : positive := kRxBytes*8;          -- 704
  constant kTxBits  : positive := kTxBytes*8;          -- 136

  signal ClkIn      : std_logic;
  signal MiningClk  : std_logic;
  signal LockedLcl  : std_logic;
  signal aResetInt  : std_logic;

  signal WorkData   : std_logic_vector(kRxBits-1 downto 0);
  signal NewWork    : boolean;
  signal ResultData : std_logic_vector(kTxBits-1 downto 0);

  signal Header      : U64Array_t(9 downto 0);
  signal TargetTop64 : unsigned(63 downto 0);
  signal Enable      : std_logic;
  signal Success     : std_logic;
  signal SuccessBool : boolean;
  signal Nonce       : unsigned(63 downto 0);
  signal HashTop64   : unsigned(63 downto 0);

begin

  U_ClkBuf: IBUFDS
  generic map(
    DQS_BIAS => "FALSE"
  )
  port map(
    I  => clk_p,
    IB => clk_n,
    O  => ClkIn
  );

  -- The MMCM is never held in reset, and there is no reset pin: the vendor's
  -- board file has none, Xilinx configuration loads every flop with its declared
  -- initial value, and the MMCM's Locked output is the only release that
  -- matters. A guessed reset ball that is not actually driven high holds the
  -- whole pipeline in reset forever and the board answers with silence -- which
  -- is what happened to the Knots design before that port was removed.
  U_Clk: entity work.clock_mgmt
  port map(
    ClkIn     => ClkIn,
    aReset    => '0',
    MiningClk => MiningClk,
    Locked    => LockedLcl
  );

  aResetInt <= not LockedLcl;

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
  -- Unpack: Header slot i <- bytes (i*8)..(i*8+7); TargetTop64 <- bytes 80..87.
  ---------------------------------------------------------------------------
  UnpackGen: for i in 0 to 9 generate
    Header(i) <= unsigned(WorkData(64*i + 63 downto 64*i));
  end generate;
  TargetTop64 <= unsigned(WorkData(64*10 + 63 downto 64*10));

  ---------------------------------------------------------------------------
  -- Run control. NewWork drops Enable for one cycle, which RELOADS the nonce
  -- iterator to kNonceSeed. Success must NOT touch Enable: in the core,
  -- Enable = '0' does not pause anything, it reloads -- so gating on Success
  -- would restart the search from the seed on every reported candidate and pin
  -- the nonce to a narrow band forever. The Knots design shipped that bug once.
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

  U_Core: entity work.OspreySiaTop
  generic map(
    kNonceSeed => kNonceSeed
  )
  port map(
    Clk         => MiningClk,
    Enable      => Enable,
    Header      => Header,
    TargetTop64 => TargetTop64,
    Success     => Success,
    Nonce       => Nonce,
    HashTop64   => HashTop64
  );

  ---------------------------------------------------------------------------
  -- Pack the reply. The transmitter shifts the LOW byte out first, so the flag
  -- occupies the low byte and arrives at the zynq first.
  ---------------------------------------------------------------------------
  ResultData  <= std_logic_vector(HashTop64) & std_logic_vector(Nonce) & x"01";
  SuccessBool <= (Success = '1');

end rtl;
