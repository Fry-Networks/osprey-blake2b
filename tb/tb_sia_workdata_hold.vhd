-- Copyright (c) 2026, Fry Networks. MIT.
--
-- tb_sia_workdata_hold.vhd
--
-- Sia analogue of tb_workdata_hold.vhd. Proves the Sia core must be fed a HELD
-- work item, never the receiver's live shift register.
--
-- THE BUG. OspreySiaUartTop sliced Header/TargetTop64 straight out of WorkData,
-- the register OspreyBlake2bUartGetWork is still shifting into. Identical defect
-- to the one OspreyBlake2bUartTop shipped before HoldWork was added there -- see
-- tb_workdata_hold.vhd for the full hardware symptom (~half of all clocks during
-- an 88-byte transfer reporting Success on the live wiring, because the
-- free-running pipeline compares one glitching 64-bit value against another).
--
-- WHY NO EXISTING BENCH CAUGHT IT. OspreySiaUartTop, like OspreyBlake2bUartTop,
-- pulls in UNISIM (IBUFDS, MMCME4_ADV, BUFGCE via clock_mgmt) and cannot be
-- instantiated under GHDL mcode. tb_sia_core drives BlockHeader as a plain
-- signal and never exercises the receiver at all; tb_sia_unpack checks the byte
-- MAP, not the WHEN. Neither says anything about whether Header/TargetTop64 are
-- valid mid-transfer. This bench closes that gap the same way
-- tb_workdata_hold.vhd did: instantiate the REAL receiver
-- (OspreyBlake2bUartGetWork, shared between both chains) and the REAL core
-- (OspreySiaTop, itself a thin UNISIM-free wrapper over OspreySiaCore), and wire
-- them the two possible ways.
--
-- WHAT IS MIRRORED, STATED PLAINLY. UartTop cannot be instantiated here, so its
-- six-line HoldWork register is reproduced below rather than referenced. The
-- receiver and the core are the real entities; only the wiring between them is
-- the bench's.
--
-- POSITIVE CONTROL. Both wirings run side by side off the SAME rx stream. The
-- live one must fire during reception and the held one must not -- a bare
-- "held == 0" proves nothing without the live counter showing the bench can
-- actually see the fault.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;
library std;
  use std.textio.all;
library work;
  use work.PkgBlake2b.all;
  use work.PkgOspreySia.all;

entity tb_sia_workdata_hold is
end tb_sia_workdata_hold;

architecture bench of tb_sia_workdata_hold is

  constant kClkPeriod : time     := 4 ns;
  constant kBitClks   : positive := 4;     -- 2170 on hardware; 4 keeps the sim short
  constant kRxBytes   : positive := kSiaWorkItemBytes;   -- 88
  constant kTxBytes   : positive := kSiaResultBytes;     -- 17
  constant kRxBits    : positive := kRxBytes*8;          -- 704

  signal Clk    : std_logic := '0';
  signal aReset : std_logic := '1';
  signal rxLine : std_logic := '1';        -- idle high

  signal sim_done : boolean := false;

  -- Per-wiring signals: 0 = LIVE (the bug), 1 = HELD (the fix)
  type Slv704Array_t is array (0 to 1) of std_logic_vector(kRxBits-1 downto 0);
  signal WorkData : Slv704Array_t;
  signal Feed     : Slv704Array_t;
  signal NewWork  : boolean_vector(0 to 1);
  signal Enable   : std_logic_vector(0 to 1) := (others => '0');
  signal CoreSucc : std_logic_vector(0 to 1);

  signal WorkDataHeld : std_logic_vector(kRxBits-1 downto 0) := (others => '0');

  -- Counted only while the item is still being clocked in.
  signal InRx      : boolean := false;
  signal SuccLive  : natural := 0;
  signal SuccHeld  : natural := 0;
  signal SuccAfter : natural := 0;

begin

  ClkGen: process
  begin
    if sim_done then wait; end if;
    Clk <= '0'; wait for kClkPeriod/2;
    Clk <= '1'; wait for kClkPeriod/2;
  end process;

  ---------------------------------------------------------------------------
  -- Two receivers, same rx stream. Success is tied off: this bench grades the
  -- CORE's Success directly, so the UART transmitter cannot mask the effect.
  ---------------------------------------------------------------------------
  RxGen: for k in 0 to 1 generate
    U_Rx: entity work.OspreyBlake2bUartGetWork
      generic map (kBitTimeInClks => kBitClks, kRxBytes => kRxBytes, kTxBytes => kTxBytes)
      port map (
        aReset     => aReset,
        Clk        => Clk,
        aRx        => rxLine,
        Tx         => open,
        NewWork    => NewWork(k),
        WorkData   => WorkData(k),
        Success     => false,
        ResultData  => (others => '0'),
        ResultReady => open
      );
  end generate;

  -- Wiring 0: LIVE -- what OspreySiaUartTop did before the fix.
  Feed(0) <= WorkData(0);

  -- Wiring 1: HELD -- mirrors OspreySiaUartTop's HoldWork process (added by
  -- this same fix).
  HoldWork: process(aReset, Clk)
  begin
    if aReset = '1' then
      WorkDataHeld <= (others => '0');
    elsif rising_edge(Clk) then
      if NewWork(1) then
        WorkDataHeld <= WorkData(1);
      end if;
    end if;
  end process;
  Feed(1) <= WorkDataHeld;

  ---------------------------------------------------------------------------
  -- Two cores, fed the two ways. RunCtl mirrors OspreySiaUartTop: NewWork drops
  -- Enable for one cycle, reloading the nonce iterator. Success must NOT touch
  -- Enable -- see OspreySiaUartTop's own RunCtl comment.
  ---------------------------------------------------------------------------
  CoreGen: for k in 0 to 1 generate
    signal Hdr : U64Array_t(9 downto 0);
    signal Tgt : unsigned(63 downto 0);
  begin
    UnpackGen: for i in 0 to 9 generate
      Hdr(i) <= unsigned(Feed(k)(64*i + 63 downto 64*i));
    end generate;
    Tgt <= unsigned(Feed(k)(64*10 + 63 downto 64*10));

    RunCtl: process(aReset, Clk)
    begin
      if aReset = '1' then
        Enable(k) <= '0';
      elsif rising_edge(Clk) then
        if NewWork(k) then Enable(k) <= '0'; else Enable(k) <= '1'; end if;
      end if;
    end process;

    U_Core: entity work.OspreySiaTop
      port map (
        Clk => Clk, Enable => Enable(k),
        Header => Hdr, TargetTop64 => Tgt,
        Success => CoreSucc(k), Nonce => open, HashTop64 => open
      );
  end generate;

  ---------------------------------------------------------------------------
  -- Counters
  ---------------------------------------------------------------------------
  Count: process(Clk)
  begin
    if rising_edge(Clk) then
      if InRx then
        if CoreSucc(0) = '1' then SuccLive <= SuccLive + 1; end if;
        if CoreSucc(1) = '1' then SuccHeld <= SuccHeld + 1; end if;
      else
        if CoreSucc(1) = '1' then SuccAfter <= SuccAfter + 1; end if;
      end if;
    end if;
  end process;

  ---------------------------------------------------------------------------
  -- Stimulus: one full 88-byte work item, 8N1.
  --   bytes  0..79 : varied body (header/merkle-root-like), so the LIVE
  --                  Header/target swing wide during the transfer
  --   bytes 80..87 : TargetTop64, little-endian = 1 -> quiet once it lands
  ---------------------------------------------------------------------------
  Stim: process
    variable ln  : line;
    variable b   : std_logic_vector(7 downto 0);

    procedure SendByte(v : std_logic_vector(7 downto 0)) is
    begin
      rxLine <= '0';                                   -- start
      wait for kBitClks * kClkPeriod;
      for i in 0 to 7 loop                             -- LSB first
        rxLine <= v(i);
        wait for kBitClks * kClkPeriod;
      end loop;
      rxLine <= '1';                                   -- stop
      wait for kBitClks * kClkPeriod;
    end procedure;
  begin
    aReset <= '1';
    wait for 20 * kClkPeriod;
    aReset <= '0';
    wait for 20 * kClkPeriod;

    InRx <= true;
    for i in 0 to kRxBytes-1 loop
      if i < 80 then
        b := std_logic_vector(to_unsigned((i*37 + 11) mod 256, 8));
      elsif i = 80 then
        b := x"01";                                    -- LSB of TargetTop64
      else
        b := x"00";
      end if;
      SendByte(b);
    end loop;
    -- NewWork lands a cycle after the last stop bit; let it settle, then stop
    -- counting the reception window.
    wait for 10 * kClkPeriod;
    InRx <= false;

    -- Let the held core run on the real (tiny) target for a while.
    wait for 4000 * kClkPeriod;

    write(ln, string'("SIA_WORKDATA_HOLD: during-rx  live=")); write(ln, SuccLive);
    write(ln, string'("  held="));                             write(ln, SuccHeld);
    write(ln, string'("   after-rx held="));                   write(ln, SuccAfter);
    writeline(output, ln);

    -- Positive control: the bench must be able to SEE the fault.
    if SuccLive = 0 then
      write(ln, string'("SIA_WORKDATA_HOLD: FAIL - positive control did not fire. The live "
                      & "wiring produced no Success during reception, so this bench cannot "
                      & "detect the bug and a zero on the held path proves nothing."));
      writeline(output, ln);
      assert false severity failure;
    end if;

    if SuccHeld /= 0 then
      write(ln, string'("SIA_WORKDATA_HOLD: FAIL - the held wiring fired "));
      write(ln, SuccHeld);
      write(ln, string'(" time(s) during reception. The core is still seeing an "
                      & "incomplete work item."));
      writeline(output, ln);
      assert false severity failure;
    end if;

    write(ln, string'("SIA_WORKDATA_HOLD: PASS - live fired "));
    write(ln, SuccLive);
    write(ln, string'(" during reception, held fired 0."));
    writeline(output, ln);

    sim_done <= true;
    wait;
  end process;

end bench;
