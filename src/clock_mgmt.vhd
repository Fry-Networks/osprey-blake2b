-- Copyright (c) 2026, Fry Networks. Adapted from pedrorivera/SiaFpgaMiner (MIT, 2018).
-- Osprey VU35P clock management. Adapted from vendor Clocking_K7.vhd (Sia SiaFpgaMiner, MIT 2018),
-- retargeted to UltraScale+ MMCME4_ADV.
--
-- Purpose: convert board oscillator (assumed 100 MHz LVDS/LVCMOS input) into a stable 250 MHz
-- MiningClk feeding the Blake2b hashing pipeline. Locked should gate the Enable of downstream
-- cores until the MMCM has captured the input.
--
-- MMCM math (VCO must stay within 800 MHz .. 1600 MHz for MMCME4 in speed grade -2):
--   CLKIN1_PERIOD       = 10.000 ns  (100 MHz input)
--   DIVCLK_DIVIDE       = 1
--   CLKFBOUT_MULT_F     = 10.0       -> VCO = 100 * 10 / 1 = 1000 MHz
--   CLKOUT0_DIVIDE_F    = 4.0        -> MiningClk = 1000 / 4 = 250 MHz
--
-- 250 MHz was chosen as a conservative starting point vs Sia's 400 MHz K7. Blake2b pipeline
-- timing under UltraScale+ should reach 350-400 MHz with pipeline retiming; leave headroom
-- for the first synthesis run and raise via CLKOUT0_DIVIDE_F once timing closure is proven.
--
-- If GHDL analyze fails on this file it is expected: GHDL mcode backend does not ship the
-- xilinx UNISIM primitive library. This is a synthesis-only file (Vivado owns the primitive
-- expansion). See the primitive component declaration below for the reference contract.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

library unisim;
  use unisim.vcomponents.all;

entity clock_mgmt is
  port (
    ClkIn     : in  std_logic;
    aReset    : in  std_logic;
    MiningClk : out std_logic;
    Locked    : out std_logic
  );
end clock_mgmt;

architecture rtl of clock_mgmt is

  signal ClkOut0Raw : std_logic;
  signal FbIn       : std_logic;
  signal FbOut      : std_logic;

begin

  U_Mmcm : MMCME4_ADV
    generic map (
      BANDWIDTH             => "OPTIMIZED",
      COMPENSATION          => "AUTO",
      DIVCLK_DIVIDE         => 1,
      CLKFBOUT_MULT_F       => 10.000,
      CLKFBOUT_PHASE        => 0.000,
      CLKIN1_PERIOD         => 10.000,
      CLKIN2_PERIOD         => 0.000,
      -- VCO 1000 MHz / 4.500 = 222.222 MHz.
      --
      -- Backed off from 4.000 (250 MHz) DELIBERATELY, to buy cores. Hash rate is
      -- cores x clock, and the two are not worth the same: at N=4 one extra core
      -- is +25% while one divider step is ~3%. Four cores closed at WNS +0.075 ns
      -- -- under the +0.10 floor -- so 250 MHz cannot carry a fifth. Trading one
      -- step of clock for a doubling of cores is strongly positive:
      --
      --     N=8 @ 222.2 MHz = 1.78 GH/s   vs   N=4 @ 250 MHz = 1.03 GH/s
      --
      -- CLB is not the constraint here (N=4 sits at 34.76%); timing is.
      --
      -- MUST be kept in step with kBitTimeInClks in OspreyBlake2bUartTop.vhd,
      -- which is clock/115200. At 222.222 MHz that is 1929, not 2170. A stale
      -- value there silently kills the UART and the board goes quiet.
      CLKOUT0_DIVIDE_F      => 4.500,
      CLKOUT0_DUTY_CYCLE    => 0.500,
      CLKOUT0_PHASE         => 0.000,
      REF_JITTER1           => 0.010,
      REF_JITTER2           => 0.010,
      STARTUP_WAIT          => "FALSE"
    )
    port map (
      CLKIN1       => ClkIn,
      CLKIN2       => '0',
      CLKFBIN      => FbIn,
      CLKINSEL     => '1',
      RST          => aReset,
      PWRDWN       => '0',
      DADDR        => (others => '0'),
      DI           => (others => '0'),
      DWE          => '0',
      DEN          => '0',
      DCLK         => '0',
      DRDY         => open,
      DO           => open,
      CLKOUT0      => ClkOut0Raw,
      CLKOUT0B     => open,
      CLKOUT1      => open,
      CLKOUT1B     => open,
      CLKOUT2      => open,
      CLKOUT2B     => open,
      CLKOUT3      => open,
      CLKOUT3B     => open,
      CLKOUT4      => open,
      CLKOUT5      => open,
      CLKOUT6      => open,
      CLKFBOUT     => FbOut,
      CLKFBOUTB    => open,
      CDDCREQ      => '0',
      CDDCDONE     => open,
      PSCLK        => '0',
      PSEN         => '0',
      PSINCDEC     => '0',
      PSDONE       => open,
      CLKINSTOPPED => open,
      CLKFBSTOPPED => open,
      LOCKED       => Locked
    );

  -- Feedback path buffer.
  U_FbBufg : BUFG
    port map (
      I => FbOut,
      O => FbIn
    );

  -- Output clock buffer (UltraScale+ standard).
  U_ClkOutBufg : BUFGCE
    port map (
      I  => ClkOut0Raw,
      CE => '1',
      O  => MiningClk
    );

end rtl;
