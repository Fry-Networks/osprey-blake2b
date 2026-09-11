-- Copyright (c) 2026, Fry Networks. MIT.
--
-- tb_stage4_compare.vhd
--
-- Checks the thing tb_stage4_prefilter.vhd could not: WHICH WORD the Verify
-- process compares against TargetTop64.
--
-- tb_stage4_prefilter grades the word the core REPORTS, and it drives
-- TargetTop64 = MAX so that every pipeline slot emits a pair. That is the right
-- choice for its job, but it means `Hash0 < MAX` and `Hash0_be < MAX` are both
-- true for every value the core will ever produce -- so the comparison operand
-- is completely unobserved. A core comparing the byte-reversed word against an
-- unreversed target passes that bench, and passed it, all the way into a
-- synthesised bitstream that mined nothing for months.
--
-- So this bench drives a REAL target and grades the comparison instead:
-- zynq/check_stage4_compare.py requires every emitted pair to satisfy
--
--     int.from_bytes(digest[24:32], "little") < TargetTop64      (= Hash0)
--
-- and separately counts how many instead satisfy the byte-reversed rule, so a
-- regression names itself rather than just failing.
--
-- SIZING, which is the whole reason this is a separate bench. The discriminator
-- is that EVERY emitted pair must satisfy the unswapped rule. With the wrong
-- operand the emitted set satisfies the SWAPPED rule instead, and agrees with
-- the unswapped one only by chance -- at rate P = TargetTop64 / 2**64. So P must
-- be small enough that chance agreement is rare, and the run long enough that
-- the sample is not. At P = 1/256 and 100,000 cycles that is ~390 emitted pairs,
-- of which a broken core would pass ~1.5. At MAX, P = 1 and nothing whatsoever
-- is distinguishable.
--
-- The target is written into the dump as a header line rather than duplicated in
-- the checker, so the two cannot drift apart.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;
library std;
  use std.textio.all;
library work;
  use work.PkgBlake2b.all;

entity tb_stage4_compare is
end tb_stage4_compare;

architecture bench of tb_stage4_compare is

  constant kClkPeriod   : time    := 10 ns;
  constant kRunCycles   : integer := 4000;
  constant kNonceSeedTb : unsigned(63 downto 0) := x"0000000000000064"; -- 100

  -- P = 1/16. Sized against GHDL mcode's actual speed on this core, not against
  -- an ideal: 100k cycles at P = 1/256 would have been a sharper discriminator
  -- but takes well over ten minutes to simulate. At P = 1/16 over 4000 cycles
  -- the expectation is ~250 emitted pairs, of which a wrong-operand core would
  -- pass ~16 by chance -- so the two verdicts are still ~250/250 against
  -- ~16/250, which the checker separates by comparing the two populations
  -- rather than by a threshold.
  constant kTargetTb    : unsigned(63 downto 0) := x"0FFFFFFFFFFFFFFF";

  signal Clk          : std_logic := '0';
  signal Enable       : std_logic := '0';
  signal BlockHeader  : U64Array_t(9 downto 0) := (others => (others => '0'));
  signal TargetTop64  : unsigned(63 downto 0) := kTargetTb;
  signal NonceOut     : unsigned(63 downto 0);
  signal HashTop64Out : unsigned(63 downto 0);
  signal Success      : std_logic;

  signal sim_done      : boolean := false;
  signal success_count : integer := 0;

  -- Same steady-state gate as tb_stage4_prefilter: the core is a 96-stage
  -- pipeline and NonceOut is Nonce(0) - 97, so anything reported before the pipe
  -- has filled pairs a nonce with a hash that does not belong to it. The checker
  -- treats an empty result set as a failure, so this gate cannot quietly swallow
  -- the run.
  constant kFillCycles : integer := 100;  -- > kPipeLength + 1 = 97
  signal   fill_count  : integer := 0;

begin

  ClkGen: process
  begin
    if sim_done then
      wait;
    end if;
    Clk <= '0';
    wait for kClkPeriod/2;
    Clk <= '1';
    wait for kClkPeriod/2;
  end process;

  dut: entity work.OspreyBlake2bStage4Core
    generic map (
      kNonceSeed => kNonceSeedTb
    )
    port map (
      Clk          => Clk,
      Enable       => Enable,
      BlockHeader  => BlockHeader,
      TargetTop64  => TargetTop64,
      NonceOut     => NonceOut,
      HashTop64Out => HashTop64Out,
      Success      => Success
    );

  -- Must match HEADER_SLOTS in zynq/check_stage4_compare.py exactly. Identical
  -- to tb_stage4_prefilter's so the two benches describe the same message.
  -- Slot 4 is overwritten by the internal nonce iterator.
  BlockHeader(0) <= x"1111111111111111";
  BlockHeader(1) <= x"2222222222222222";
  BlockHeader(2) <= x"3333333333333333";
  BlockHeader(3) <= x"4444444444444444";
  BlockHeader(4) <= (others => '0');
  BlockHeader(5) <= x"5555555555555555";
  BlockHeader(6) <= x"6666666666666666";
  BlockHeader(7) <= x"7777777777777777";
  BlockHeader(8) <= x"8888888888888888";
  BlockHeader(9) <= x"9999999999999999";

  dump: process(Clk)
    file     fh    : text open write_mode is "stage4_compare_pairs.txt";
    variable ln    : line;
    variable slv   : std_logic_vector(63 downto 0);
    variable hdr   : boolean := false;
  begin
    if rising_edge(Clk) then
      if not hdr then
        -- Header line: the checker reads the target and the cycle count from
        -- here instead of duplicating them, so the bench and the oracle cannot
        -- disagree about what was run.
        write(ln, string'("# target "));
        slv := std_logic_vector(kTargetTb);
        hwrite(ln, slv);
        write(ln, string'(" cycles "));
        write(ln, kRunCycles);
        writeline(fh, ln);
        hdr := true;
      end if;

      if Enable = '0' then
        fill_count <= 0;
      elsif fill_count <= kFillCycles then
        fill_count <= fill_count + 1;
      end if;

      if Success = '1' and Enable = '1' and fill_count > kFillCycles then
        success_count <= success_count + 1;
        slv := std_logic_vector(NonceOut);
        hwrite(ln, slv);
        write(ln, string'(" "));
        slv := std_logic_vector(HashTop64Out);
        hwrite(ln, slv);
        writeline(fh, ln);
      end if;
    end if;
  end process;

  stimulus: process
    variable ln : line;
  begin
    Enable <= '0';
    wait for 5 * kClkPeriod;
    Enable <= '1';
    wait for kRunCycles * kClkPeriod;
    Enable <= '0';
    wait for 5 * kClkPeriod;

    write(ln, string'("STAGE4_COMPARE pairs_written="));
    write(ln, success_count);
    write(ln, string'(" of "));
    write(ln, kRunCycles);
    write(ln, string'(" cycles"));
    writeline(output, ln);

    -- Grading is zynq/check_stage4_compare.py's job. This bench only guarantees
    -- the sample is big enough to be worth grading: at P = 1/256 over 100k
    -- cycles the expectation is ~390, so 100 is a generous floor that still
    -- catches a core that has stopped emitting.
    if success_count >= 100 then
      write(ln, string'("STAGE4_COMPARE: EMITTED - grade with zynq/check_stage4_compare.py stage4_compare_pairs.txt"));
    else
      write(ln, string'("STAGE4_COMPARE: FAIL too few pairs"));
    end if;
    writeline(output, ln);

    sim_done <= true;
    wait;
  end process;

end bench;
