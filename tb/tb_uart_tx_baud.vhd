-- Copyright (c) 2026, Fry Networks. MIT.
--
-- tb_uart_tx_baud.vhd
--
-- Proves the transmitter needs its own baud counter.
--
-- THE BUG. OspreyBlake2bUartGetWork drove both directions from one bitTime, and
-- restartBaud -- asserted by the RECEIVER on every start-bit edge -- preloads
-- clkCount to -(kBitTimeInClks/2) to centre RX sampling. That also re-phases any
-- TX byte in flight, moving its remaining bit cells by up to half a cell. A
-- 168-byte work item does it 168 times across 14.58 ms.
--
-- Why it stayed hidden: with one core and a production target, a candidate frame
-- and a work-item reception almost never overlap, and when they do the host's
-- "three unparseable frames -> resync" hides it. The corruption is silent -- a
-- shifted cell still yields a well-formed 17-byte frame, just with wrong bytes
-- in it. It becomes routine as soon as the result path is busy.
--
-- THE TEST. Start a result frame, then clock a work item in underneath it, and
-- decode tx the way the zynq actually does: sample at NOMINAL bit centres off a
-- fixed local reference, not off the DUT's own (possibly shifted) timing. If the
-- TX phase moves, the decoded bytes differ from what was handed to ResultData.
--
-- Expected: FAIL with the shared bitTime, PASS with the separate txBitTime.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;
library std;
  use std.textio.all;

entity tb_uart_tx_baud is
end tb_uart_tx_baud;

architecture bench of tb_uart_tx_baud is

  constant kClkPeriod : time     := 4 ns;
  constant kBitClks   : positive := 8;
  -- BaudGen counts 0..kBitTimeInClks INCLUSIVE before pulsing, so a cell is
  -- kBitTimeInClks+1 clocks, not kBitTimeInClks. On hardware that is 2171 vs
  -- 2170 (0.046%, irrelevant against 8N1's ~2% tolerance), but at these sim
  -- values it is 12.5% and the decoder walks off the cell within one frame.
  constant kBitTime   : time     := (kBitClks + 1) * kClkPeriod;
  constant kRxBytes   : positive := 168;
  constant kTxBytes   : positive := 17;

  signal Clk    : std_logic := '0';
  signal aReset : std_logic := '1';
  signal rxLine : std_logic := '1';
  signal txLine : std_logic;

  signal Succ       : boolean := false;
  signal ResultData : std_logic_vector(kTxBytes*8-1 downto 0) := (others => '0');

  signal sim_done  : boolean := false;
  signal rx_active : boolean := false;

  -- Decoder results
  signal got      : std_logic_vector(kTxBytes*8-1 downto 0) := (others => '0');
  signal got_n    : natural := 0;
  signal dec_done : boolean := false;

begin

  ClkGen: process
  begin
    if sim_done then wait; end if;
    Clk <= '0'; wait for kClkPeriod/2;
    Clk <= '1'; wait for kClkPeriod/2;
  end process;

  DUT: entity work.OspreyBlake2bUartGetWork
    generic map (kBitTimeInClks => kBitClks, kRxBytes => kRxBytes, kTxBytes => kTxBytes)
    port map (
      aReset     => aReset,
      Clk        => Clk,
      aRx        => rxLine,
      Tx         => txLine,
      NewWork    => open,
      WorkData   => open,
      Success     => Succ,
      ResultData  => ResultData,
      ResultReady => open
    );

  ---------------------------------------------------------------------------
  -- Decoder: exactly what a UART on the other end does. Detect the start bit,
  -- then sample 8 data bits at nominal 1-bit intervals starting 1.5 bit times
  -- after the falling edge. Timing comes from THIS process, never from the DUT.
  ---------------------------------------------------------------------------
  Decode: process
    variable b : std_logic_vector(7 downto 0);
  begin
    wait until aReset = '0';
    for n in 0 to kTxBytes-1 loop
      wait until falling_edge(txLine);      -- start bit
      wait for kBitTime + kBitTime/2;       -- centre of data bit 0
      for i in 0 to 7 loop
        b(i) := txLine;
        if i < 7 then wait for kBitTime; end if;
      end loop;
      got(8*n+7 downto 8*n) <= b;
      got_n <= n + 1;
      wait for kBitTime;                    -- ride out the stop bit
    end loop;
    dec_done <= true;
    wait;
  end process;

  ---------------------------------------------------------------------------
  -- Stimulus
  ---------------------------------------------------------------------------
  Stim: process
    variable ln : line;

    procedure SendRxByte(v : std_logic_vector(7 downto 0)) is
    begin
      rxLine <= '0';
      wait for kBitTime;
      for i in 0 to 7 loop
        rxLine <= v(i);
        wait for kBitTime;
      end loop;
      rxLine <= '1';
      wait for kBitTime;
    end procedure;
  begin
    -- A recognisable payload: flag 0x01 then a varied body, so a half-cell slip
    -- cannot coincidentally decode to the same bytes.
    ResultData(7 downto 0) <= x"01";
    for n in 1 to kTxBytes-1 loop
      ResultData(8*n+7 downto 8*n) <= std_logic_vector(to_unsigned((n*53 + 29) mod 256, 8));
    end loop;

    aReset <= '1';
    wait for 20 * kClkPeriod;
    aReset <= '0';
    wait for 20 * kClkPeriod;

    -- Kick off the result frame.
    Succ <= true;
    wait for 2 * kClkPeriod;
    Succ <= false;

    -- Now clock a work item in UNDERNEATH it. Every start bit here re-phases the
    -- shared baud counter, which is the whole point of the test.
    wait for 2 * kBitTime;
    rx_active <= true;
    for i in 0 to kRxBytes-1 loop
      SendRxByte(std_logic_vector(to_unsigned((i*37 + 11) mod 256, 8)));
      exit when dec_done;
    end loop;
    rx_active <= false;

    -- Give the frame room to finish if it has not already.
    for w in 0 to 400 loop
      exit when dec_done;
      wait for kBitTime;
    end loop;

    write(ln, string'("UART_TX_BAUD: decoded ")); write(ln, got_n);
    write(ln, string'(" of ")); write(ln, kTxBytes); write(ln, string'(" bytes"));
    writeline(output, ln);

    if got_n /= kTxBytes then
      write(ln, string'("UART_TX_BAUD: FAIL - only ")); write(ln, got_n);
      write(ln, string'(" bytes framed; the transmitter never completed a clean frame "
                      & "while the receiver was active."));
      writeline(output, ln);
      assert false severity failure;
    end if;

    if got /= ResultData then
      write(ln, string'("UART_TX_BAUD: FAIL - decoded frame does not match ResultData. "
                      & "TX bit cells were re-phased by RX start bits (shared baud "
                      & "generator)."));
      writeline(output, ln);
      for n in 0 to kTxBytes-1 loop
        if got(8*n+7 downto 8*n) /= ResultData(8*n+7 downto 8*n) then
          write(ln, string'("    byte ")); write(ln, n);
          write(ln, string'(" expected ")); hwrite(ln, ResultData(8*n+7 downto 8*n));
          write(ln, string'(" got "));      hwrite(ln, got(8*n+7 downto 8*n));
          writeline(output, ln);
        end if;
      end loop;
      assert false severity failure;
    end if;

    write(ln, string'("UART_TX_BAUD: PASS - all 17 bytes decoded bit-exact at nominal "
                    & "cell centres while a 168-byte work item was being received."));
    writeline(output, ln);

    sim_done <= true;
    wait;
  end process;

end bench;
