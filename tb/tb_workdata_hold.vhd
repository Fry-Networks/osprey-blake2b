-- Copyright (c) 2026, Fry Networks. MIT.
--
-- tb_workdata_hold.vhd
--
-- Proves the core must be fed a HELD work item, never the receiver's live shift
-- register.
--
-- THE BUG. OspreyBlake2bUartGetWork drives WorkData straight out of workDataLcl,
-- the register it is still shifting into. OspreyBlake2bUartTop sliced
-- TargetTop64 out of the TOP 64 bits of that -- which, mid-transfer, are just
-- the eight most recently arrived bytes. Those are digest material, so for the
-- entire 14.58 ms a 168-byte item takes at 115200 baud, the free-running
-- pipeline was comparing one pseudo-random 64-bit value against another.
-- Success came out true on roughly half of ~3.65 million clocks per item.
--
-- On hardware that presented as exactly 16 bytes read per work push, forever:
-- the host is stuck in uart_write's TX_FULL spin for ~13.2 ms of the transfer
-- and can only ever drain one RX FIFO. 16 is the FIFO depth, not a frame length.
--
-- WHY NO EXISTING BENCH CAUGHT IT. Nothing in tb/ instantiates
-- OspreyBlake2bUartTop or OspreySiaUartTop -- and nothing can, because both pull
-- in UNISIM (IBUFDS, MMCME4_ADV, BUFGCE) and GHDL mcode has no UNISIM library.
-- tb_unpack drives WorkData as a plain signal and only checks the slice MAP, so
-- it validates where each field lives and says nothing about WHEN the field is
-- valid. This bench closes that gap by instantiating the REAL receiver and the
-- REAL core -- the two UNISIM-free pieces -- and wiring them the two possible
-- ways.
--
-- WHAT IS MIRRORED, STATED PLAINLY. UartTop cannot be instantiated here, so the
-- six-line HoldWork register is reproduced below rather than referenced. The
-- receiver and the core are the real entities; only the wiring between them is
-- the bench's. That is the most of the real design that can be put under a
-- simulator without building the UNISIM libraries.
--
-- POSITIVE CONTROL. Both wirings run side by side off the SAME rx stream. The
-- live one must fire during reception and the held one must not. A bench that
-- only asserted "held == 0" would pass just as happily if the stimulus were
-- broken and neither core ever saw anything -- a bare zero is not evidence. The
-- live counter is what makes the zero mean something.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;
library std;
  use std.textio.all;
library work;
  use work.PkgBlake2b.all;

entity tb_workdata_hold is
end tb_workdata_hold;

architecture bench of tb_workdata_hold is

  constant kClkPeriod : time     := 4 ns;
  constant kBitClks   : positive := 4;     -- 2170 on hardware; 4 keeps the sim short
  constant kRxBytes   : positive := 168;
  constant kTxBytes   : positive := 17;
  constant kRxBits    : positive := kRxBytes*8;

  signal Clk    : std_logic := '0';
  signal aReset : std_logic := '1';
  signal rxLine : std_logic := '1';        -- idle high

  signal sim_done : boolean := false;

  -- Per-wiring signals: 0 = LIVE (the bug), 1 = HELD (the fix)
  type Slv1344Array_t is array (0 to 1) of std_logic_vector(kRxBits-1 downto 0);
  signal WorkData : Slv1344Array_t;
  signal Feed     : Slv1344Array_t;
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

  -- Wiring 0: LIVE -- what the RTL did before the fix.
  Feed(0) <= WorkData(0);

  -- Wiring 1: HELD -- mirrors OspreyBlake2bUartTop's HoldWork process.
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
  -- Two cores, fed the two ways. RunCtl mirrors UartTop: NewWork drops Enable
  -- for one cycle, reloading the nonce iterator.
  ---------------------------------------------------------------------------
  CoreGen: for k in 0 to 1 generate
    signal S3, S4 : U64Array_t(9 downto 0);
    signal Tgt    : unsigned(63 downto 0);
  begin
    UnpackGen: for i in 0 to 9 generate
      S3(i) <= unsigned(Feed(k)(64*i        + 63 downto 64*i));
      S4(i) <= unsigned(Feed(k)(64*(10 + i) + 63 downto 64*(10 + i)));
    end generate;
    Tgt <= unsigned(Feed(k)(64*20 + 63 downto 64*20));

    RunCtl: process(aReset, Clk)
    begin
      if aReset = '1' then
        Enable(k) <= '0';
      elsif rising_edge(Clk) then
        if NewWork(k) then Enable(k) <= '0'; else Enable(k) <= '1'; end if;
      end if;
    end process;

    U_Core: entity work.OspreyBlake2bTop
      port map (
        Clk => Clk, Enable => Enable(k),
        Stage3In => S3, Stage4In => S4, TargetTop64 => Tgt,
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
  -- Stimulus: one full 168-byte work item, 8N1.
  --   bytes 0..159  : varied body (digest-like), so the LIVE target swings wide
  --   bytes 160..167: TargetTop64, little-endian = 1  -> quiet once it lands
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
      if i < 160 then
        b := std_logic_vector(to_unsigned((i*37 + 11) mod 256, 8));
      elsif i = 160 then
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

    write(ln, string'("WORKDATA_HOLD: during-rx  live=")); write(ln, SuccLive);
    write(ln, string'("  held="));                         write(ln, SuccHeld);
    write(ln, string'("   after-rx held="));               write(ln, SuccAfter);
    writeline(output, ln);

    -- Positive control: the bench must be able to SEE the fault.
    if SuccLive = 0 then
      write(ln, string'("WORKDATA_HOLD: FAIL - positive control did not fire. The live "
                      & "wiring produced no Success during reception, so this bench cannot "
                      & "detect the bug and a zero on the held path proves nothing."));
      writeline(output, ln);
      assert false severity failure;
    end if;

    if SuccHeld /= 0 then
      write(ln, string'("WORKDATA_HOLD: FAIL - the held wiring fired "));
      write(ln, SuccHeld);
      write(ln, string'(" time(s) during reception. The core is still seeing an "
                      & "incomplete work item."));
      writeline(output, ln);
      assert false severity failure;
    end if;

    write(ln, string'("WORKDATA_HOLD: PASS - live fired "));
    write(ln, SuccLive);
    write(ln, string'(" during reception, held fired 0."));
    writeline(output, ln);

    sim_done <= true;
    wait;
  end process;

end bench;
