-- Copyright (c) 2026, Fry Networks. MIT.
--
-- tb_result_arbiter.vhd
--
-- Grades OspreyBlake2bResultArb against the REAL transmitter.
--
-- The property under test is NOT "never drops". A 17-byte frame at 115200 baud
-- occupies 170 bit times, so the link tops out at 677 frames/s no matter how
-- many cores feed it; above that, dropping is arithmetic. What must hold is that
-- nothing is lost SILENTLY:
--
--     grants + sum(DropCount) == sum(CoreSuccess)
--
-- Every candidate is either handed to the transmitter or counted as dropped.
--
-- Second property: FAIRNESS. A fixed-priority arbiter would serve core 0 and
-- starve the rest, which on hardware is indistinguishable from "the extra cores
-- do not work" -- the single most likely way a multi-core build can look fine in
-- utilisation and timing while delivering nothing. So under sustained overload
-- every core must receive grants, and roughly equally.
--
-- Run with kNumCores = 4 even though the current bitstream ships 1: the point is
-- to prove the plumbing BEFORE the rung that depends on it.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;
library std;
  use std.textio.all;

entity tb_result_arbiter is
end tb_result_arbiter;

architecture bench of tb_result_arbiter is

  constant kN        : positive := 4;
  constant kClkPeriod: time     := 4 ns;
  constant kBitClks  : positive := 4;
  constant kTxBytes  : positive := 17;
  constant kRxBytes  : positive := 168;

  signal Clk    : std_logic := '0';
  signal aReset : std_logic := '1';

  signal CoreSuccess : std_logic_vector(kN-1 downto 0) := (others => '0');
  signal CoreNonce   : std_logic_vector(64*kN-1 downto 0) := (others => '0');
  signal CoreHash    : std_logic_vector(64*kN-1 downto 0) := (others => '0');
  signal DropCount   : std_logic_vector(16*kN-1 downto 0);

  signal TxReady  : boolean;
  signal ArbValid : boolean;
  signal ArbNonce : unsigned(63 downto 0);
  signal ArbHash  : unsigned(63 downto 0);

  signal ResultData : std_logic_vector(kTxBytes*8-1 downto 0);

  signal nSuccess : natural := 0;
  signal nGrant   : natural := 0;
  type NatArray_t is array (natural range <>) of natural;
  signal perCore  : NatArray_t(kN-1 downto 0) := (others => 0);

  signal sim_done : boolean := false;

begin

  ClkGen: process
  begin
    if sim_done then wait; end if;
    Clk <= '0'; wait for kClkPeriod/2;
    Clk <= '1'; wait for kClkPeriod/2;
  end process;

  U_Arb: entity work.OspreyBlake2bResultArb
    generic map (kNumCores => kN, kIdxBits => 2)
    port map (Clk => Clk, aReset => aReset,
              CoreSuccess => CoreSuccess, CoreNonce => CoreNonce, CoreHash => CoreHash,
              ResultReady => TxReady, ResultValid => ArbValid,
              ResultNonce => ArbNonce, ResultHash => ArbHash,
              DropCount => DropCount);

  ResultData <= std_logic_vector(ArbHash) & std_logic_vector(ArbNonce) & x"01";

  -- The REAL transmitter, so grant pacing is the true 170-bit-time frame.
  U_Tx: entity work.OspreyBlake2bUartGetWork
    generic map (kBitTimeInClks => kBitClks, kRxBytes => kRxBytes, kTxBytes => kTxBytes)
    port map (aReset => aReset, Clk => Clk, aRx => '1', Tx => open,
              NewWork => open, WorkData => open,
              Success => ArbValid, ResultData => ResultData,
              ResultReady => TxReady);

  -- Each core's nonce carries its index in the top bits, exactly as the
  -- high-bit seed split will on hardware, so grants can be attributed.
  NonceGen: for k in 0 to kN-1 generate
    CoreNonce(64*k + 63 downto 64*k) <=
      std_logic_vector(shift_left(to_unsigned(k, 64), 62) or to_unsigned(k + 1, 64));
    CoreHash(64*k + 63 downto 64*k) <= std_logic_vector(to_unsigned(16#ABC# + k, 64));
  end generate;

  Tally: process(Clk)
    variable idx : natural;
    variable inc : natural;
  begin
    if rising_edge(Clk) then
      if aReset = '0' then
        -- Accumulate in a VARIABLE. `nSuccess <= nSuccess + 1` inside the loop
        -- is a signal assignment, so only the last iteration survives and the
        -- count comes out 1 per cycle instead of one per asserting core -- which
        -- looks exactly like the arbiter losing candidates.
        inc := 0;
        for k in 0 to kN-1 loop
          if CoreSuccess(k) = '1' then inc := inc + 1; end if;
        end loop;
        nSuccess <= nSuccess + inc;
        if ArbValid then
          nGrant <= nGrant + 1;
          idx := to_integer(shift_right(ArbNonce, 62));
          if idx < kN then perCore(idx) <= perCore(idx) + 1; end if;
        end if;
      end if;
    end if;
  end process;

  Stim: process
    variable ln    : line;
    variable drops : natural;
  begin
    aReset <= '1'; wait for 20*kClkPeriod;
    aReset <= '0'; wait for 20*kClkPeriod;

    -- (a) sparse: one per core, spaced well beyond a frame time
    for k in 0 to kN-1 loop
      CoreSuccess(k) <= '1'; wait for kClkPeriod; CoreSuccess(k) <= '0';
      wait for 200 * kBitClks * kClkPeriod;
    end loop;

    -- (b) simultaneous: every core on the same cycle
    CoreSuccess <= (others => '1'); wait for kClkPeriod;
    CoreSuccess <= (others => '0');
    wait for 900 * kBitClks * kClkPeriod;

    -- (c) sustained overload: every core, every cycle
    CoreSuccess <= (others => '1');
    wait for 30000 * kClkPeriod;
    CoreSuccess <= (others => '0');
    -- Drain. Each core can still be HOLDING a captured candidate that has been
    -- neither granted nor dropped, and those are in flight, not lost. A frame is
    -- 170 bit times = 680 clocks here, so kN held slots need >= kN frames to
    -- clear. Stopping early leaves conservation short by exactly the number of
    -- resident slots, which reads as a leak and is not one.
    wait for (kN + 8) * 170 * kBitClks * kClkPeriod;

    drops := 0;
    for k in 0 to kN-1 loop
      drops := drops + to_integer(unsigned(DropCount(16*k + 15 downto 16*k)));
    end loop;

    write(ln, string'("RESULT_ARB: success=")); write(ln, nSuccess);
    write(ln, string'(" grants="));             write(ln, nGrant);
    write(ln, string'(" drops="));              write(ln, drops);
    writeline(output, ln);
    write(ln, string'("RESULT_ARB: per-core grants ="));
    for k in 0 to kN-1 loop write(ln, string'(" ")); write(ln, perCore(k)); end loop;
    writeline(output, ln);

    if nGrant = 0 then
      write(ln, string'("RESULT_ARB: FAIL - no grants at all; nothing was exercised."));
      writeline(output, ln); assert false severity failure;
    end if;

    -- Drop counters saturate at 0xFFFF by design, so only check conservation
    -- exactly when none of them pegged.
    if drops < kN * 65535 then
      if nGrant + drops /= nSuccess then
        write(ln, string'("RESULT_ARB: FAIL - conservation broken: grants+drops="));
        write(ln, nGrant + drops);
        write(ln, string'(" but success=")); write(ln, nSuccess);
        write(ln, string'(". Candidates went missing without being counted."));
        writeline(output, ln); assert false severity failure;
      end if;
    else
      write(ln, string'("RESULT_ARB: note - a drop counter saturated; conservation "
                      & "not checkable this run, fairness still is."));
      writeline(output, ln);
    end if;

    for k in 0 to kN-1 loop
      if perCore(k) = 0 then
        write(ln, string'("RESULT_ARB: FAIL - core ")); write(ln, k);
        write(ln, string'(" was never granted. Round-robin is not working and the "
                        & "extra cores would contribute nothing."));
        writeline(output, ln); assert false severity failure;
      end if;
    end loop;

    for k in 0 to kN-1 loop
      if perCore(k) * 4 < perCore(0) or perCore(0) * 4 < perCore(k) then
        write(ln, string'("RESULT_ARB: FAIL - grant distribution is lopsided; core "));
        write(ln, k); write(ln, string'(" is starved relative to core 0."));
        writeline(output, ln); assert false severity failure;
      end if;
    end loop;

    write(ln, string'("RESULT_ARB: PASS - conservation holds and all "));
    write(ln, kN); write(ln, string'(" cores are served fairly."));
    writeline(output, ln);

    sim_done <= true;
    wait;
  end process;

end bench;
