-- Copyright (c) 2026, Fry Networks. MIT.
--
-- tb_stage3_bypass.vhd
--
-- Proves that bypassing on-chip stage 3 is behaviourally identical to computing
-- it, cycle for cycle.
--
-- WHY BYPASS. HashA is already on the wire. On getblocktemplate the host does
-- hash_a = blake2b(ss3) (miner/work_item.c:87) and writes it to ss4+48 (:99); on
-- stratum it writes merkleroot to ss4+48 (miner/sia_stratum.c:74) and refuses any
-- job with merkle branches (worksrc_stratum.c:132), so root == leaf ==
-- blake2b(0x00 || arbtx) == blake2b(ss3). ss4[48..79] arrives as Stage4In(6..9).
-- The on-chip stage was recomputing a value it was already handed -- for about
-- 9,313 CLB, roughly half the used logic and a whole extra mining core, to run
-- once per pool notify rather than per nonce.
--
-- THE TEST. One OspreyBlake2bStage3Core computes HashA from Stage3In. Two
-- OspreyBlake2bTop instances run side by side off the same clock:
--   A: kOnChipStage3 = TRUE  -- given Stage3In, computes HashA itself
--   B: kOnChipStage3 = FALSE -- given the reference HashA in Stage4In(6..9)
-- Every other input is identical. Their Success / Nonce / HashTop64 outputs must
-- agree on every single cycle.
--
-- The reference stage-3 core carries the same 96-clock latency as A's internal
-- one, so HashA lands at the same instant for both and the comparison is exact
-- rather than approximate.
--
-- TargetTop64 = MAX so Success asserts on essentially every cycle: that makes
-- this a dense comparison of the full output stream, not a sampling of rare
-- events. A mismatch counter of zero is only meaningful because the agreement
-- counter is large -- both are printed.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;
library std;
  use std.textio.all;
library work;
  use work.PkgBlake2b.all;

entity tb_stage3_bypass is
end tb_stage3_bypass;

architecture bench of tb_stage3_bypass is

  constant kClkPeriod : time    := 10 ns;
  constant kRunCycles : integer := 1200;
  constant kFill      : integer := 260;   -- > stage3 96 + stage4 96 + margin

  signal Clk    : std_logic := '0';
  signal Enable : std_logic := '0';

  signal Stage3In : U64Array_t(9 downto 0) := (others => (others => '0'));
  signal Stage4In : U64Array_t(9 downto 0) := (others => (others => '0'));
  signal S4B      : U64Array_t(9 downto 0);
  signal HashARef : U64Array_t(3 downto 0);
  signal Target   : unsigned(63 downto 0) := (others => '1');

  signal SuccA, SuccB : std_logic;
  signal NonceA, NonceB : unsigned(63 downto 0);
  signal HashA_o, HashB_o : unsigned(63 downto 0);

  signal cyc      : integer := 0;
  signal agree    : integer := 0;
  signal mismatch : integer := 0;
  signal sim_done : boolean := false;

begin

  ClkGen: process
  begin
    if sim_done then wait; end if;
    Clk <= '0'; wait for kClkPeriod/2;
    Clk <= '1'; wait for kClkPeriod/2;
  end process;

  -- A distinctive stage-3 message, and stage-4 slots that are deliberately NOT
  -- the right HashA, so instance A can only pass by computing it.
  Stage3In(0) <= x"0123456789abcdef";
  Stage3In(1) <= x"fedcba9876543210";
  Stage3In(2) <= x"1122334455667788";
  Stage3In(3) <= x"99aabbccddeeff00";
  Stage3In(4) <= x"0f1e2d3c4b5a6978";
  Stage3In(5) <= x"8796a5b4c3d2e1f0";
  Stage3In(6) <= (others => '0');
  Stage3In(7) <= (others => '0');
  Stage3In(8) <= (others => '0');
  Stage3In(9) <= (others => '0');

  Stage4In(0) <= x"00000000dead1111";
  Stage4In(1) <= x"2222222222222222";
  Stage4In(2) <= x"3333333333333333";
  Stage4In(3) <= x"4444444444444444";
  Stage4In(4) <= (others => '0');
  Stage4In(5) <= x"5555555555555555";
  Stage4In(6) <= x"deadbeefdeadbeef";   -- junk for A; B gets the real thing below
  Stage4In(7) <= x"deadbeefdeadbeef";
  Stage4In(8) <= x"deadbeefdeadbeef";
  Stage4In(9) <= x"deadbeefdeadbeef";

  -- Reference stage 3, same entity and therefore same latency as A's internal one.
  U_Ref: entity work.OspreyBlake2bStage3Core
    port map (Clk => Clk, Enable => Enable, BlockHeader => Stage3In, HashOut => HashARef);

  S4B(5 downto 0) <= Stage4In(5 downto 0);
  S4B(6) <= HashARef(0);
  S4B(7) <= HashARef(1);
  S4B(8) <= HashARef(2);
  S4B(9) <= HashARef(3);

  A_OnChip: entity work.OspreyBlake2bTop
    generic map (kOnChipStage3 => true)
    port map (Clk => Clk, Enable => Enable,
              Stage3In => Stage3In, Stage4In => Stage4In, TargetTop64 => Target,
              Success => SuccA, Nonce => NonceA, HashTop64 => HashA_o);

  B_Bypass: entity work.OspreyBlake2bTop
    generic map (kOnChipStage3 => false)
    port map (Clk => Clk, Enable => Enable,
              Stage3In => Stage3In, Stage4In => S4B, TargetTop64 => Target,
              Success => SuccB, Nonce => NonceB, HashTop64 => HashB_o);

  Compare: process(Clk)
  begin
    if rising_edge(Clk) then
      if Enable = '1' then
        cyc <= cyc + 1;
        if cyc > kFill then
          if SuccA = SuccB and NonceA = NonceB and HashA_o = HashB_o then
            agree <= agree + 1;
          else
            mismatch <= mismatch + 1;
          end if;
        end if;
      end if;
    end if;
  end process;

  Stim: process
    variable ln : line;
  begin
    Enable <= '0';
    wait for 10 * kClkPeriod;
    Enable <= '1';
    wait for kRunCycles * kClkPeriod;
    Enable <= '0';
    wait for 5 * kClkPeriod;

    write(ln, string'("STAGE3_BYPASS: compared ")); write(ln, agree + mismatch);
    write(ln, string'(" cycles  agree=")); write(ln, agree);
    write(ln, string'("  mismatch=")); write(ln, mismatch);
    writeline(output, ln);

    if agree = 0 then
      write(ln, string'("STAGE3_BYPASS: FAIL - nothing was compared. A zero mismatch "
                      & "count here would be vacuous."));
      writeline(output, ln);
      assert false severity failure;
    end if;

    if mismatch /= 0 then
      write(ln, string'("STAGE3_BYPASS: FAIL - the bypassed instance does not match the "
                      & "on-chip one. Taking HashA from Stage4In(6..9) is NOT equivalent."));
      writeline(output, ln);
      assert false severity failure;
    end if;

    write(ln, string'("STAGE3_BYPASS: PASS - on-chip and bypassed cores agree on "));
    write(ln, agree);
    write(ln, string'(" consecutive cycles of Success/Nonce/HashTop64."));
    writeline(output, ln);

    sim_done <= true;
    wait;
  end process;

end bench;
