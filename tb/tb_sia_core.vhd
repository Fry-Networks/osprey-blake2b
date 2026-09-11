-- Copyright (c) 2026, Fry Networks. MIT.
--
-- tb_sia_core.vhd
--
-- HARD GATE for OspreySiaCore. Runs the core free with a maximum target so every
-- pipeline slot reports, and dumps one "<nonce> <hash>" line per Success to
-- sia_pairs.txt. zynq/check_sia_pairs.py grades those pairs against
-- byteswap(H[0]) -- Siacoin's compare rule -- and carries a named detector for
-- the Knots H[3] rule so a copy-paste from OspreyBlake2bStage4Core cannot pass.
--
-- Why the pairs are dumped instead of driving vectors and comparing one hash:
-- the core substitutes its own nonce into Msg(4), and each of the 12 round
-- lanes holds a DIFFERENT nonce so that a staggered pipeline stays coherent.
-- There is therefore no way to pin the nonce from outside and no vector that
-- names the message the core actually hashed. Grading what it really ground is
-- both easier and stronger. This mirrors tb_stage4_prefilter, which exists
-- because a MAX-target smoke test never compares HashTop64Out to anything --
-- and that is exactly how a core tapping the wrong digest word survived a
-- 100/100 gate and reached silicon once already.
--
-- The bench itself asserts only that it produced enough to grade; correctness is
-- the Python oracle's verdict, because an oracle written in the same language
-- and by the same hand as the DUT is not an oracle.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;
library std;
  use std.textio.all;
library work;
  use work.PkgBlake2b.all;
  use work.PkgOspreySia.all;

entity tb_sia_core is
end tb_sia_core;

architecture bench of tb_sia_core is

  constant kClkPeriod   : time    := 10 ns;
  constant kNonceSeedTb : unsigned(63 downto 0) := x"0000000000000064";
  constant kRunCycles   : integer := 400;
  -- The first kPipeLength+1 = 97 reports come from a pipeline that is still
  -- filling with initial-value garbage. Discarding a round 100 keeps those out
  -- of the graded set without hiding a real failure -- the count that is graded
  -- is printed, and the checker fails outright if it is zero.
  constant kFillCycles  : integer := 100;

  signal Clk         : std_logic := '0';
  signal Enable      : std_logic := '0';
  signal BlockHeader : U64Array_t(9 downto 0) := (others => (others => '0'));
  signal TargetTop64 : unsigned(63 downto 0) := (others => '1');
  signal NonceOut    : unsigned(63 downto 0);
  signal HashTop64   : unsigned(63 downto 0);
  signal Success     : std_logic;

  signal sim_done : boolean := false;

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

  dut: entity work.OspreySiaCore
    generic map (
      kNonceSeed => kNonceSeedTb
    )
    port map (
      Clk          => Clk,
      Enable       => Enable,
      BlockHeader  => BlockHeader,
      TargetTop64  => TargetTop64,
      NonceOut     => NonceOut,
      HashTop64Out => HashTop64,
      Success      => Success
    );

  -- Must match HEADER_SLOTS in zynq/check_sia_pairs.py exactly. Slot 4 is the
  -- grind slot and its value here is irrelevant -- the iterator overwrites it --
  -- but it is still declared so the two sides describe the same message.
  BlockHeader(0) <= x"1111111111111111";
  BlockHeader(1) <= x"2222222222222222";
  BlockHeader(2) <= x"3333333333333333";
  BlockHeader(3) <= x"4444444444444444";
  BlockHeader(4) <= x"5555555555555555";
  BlockHeader(5) <= x"6666666666666666";
  BlockHeader(6) <= x"7777777777777777";
  BlockHeader(7) <= x"8888888888888888";
  BlockHeader(8) <= x"9999999999999999";
  BlockHeader(9) <= x"aaaaaaaaaaaaaaaa";

  stimulus: process
    file fh             : text open write_mode is "sia_pairs.txt";
    variable ln         : line;
    variable slv        : std_logic_vector(63 downto 0);
    variable emitted    : integer := 0;
    variable fill_count : integer := 0;
  begin
    Enable <= '0';
    wait for 5 * kClkPeriod;
    Enable <= '1';

    for i in 0 to kRunCycles-1 loop
      wait until rising_edge(Clk);
      fill_count := fill_count + 1;
      if Success = '1' and fill_count > kFillCycles then
        slv := std_logic_vector(NonceOut);
        hwrite(ln, slv);
        write(ln, string'(" "));
        slv := std_logic_vector(HashTop64);
        hwrite(ln, slv);
        writeline(fh, ln);
        emitted := emitted + 1;
      end if;
    end loop;

    file_close(fh);

    write(ln, string'("SIA_CORE cycles="));
    write(ln, kRunCycles);
    write(ln, string'(" emitted="));
    write(ln, emitted);
    writeline(output, ln);

    -- 100 graded pairs is the bar the Knots stage-3 gate set. Falling short
    -- means the run was too short or the core stopped reporting, and either way
    -- the checker must not be handed a thin sample and called green.
    if emitted >= 100 then
      write(ln, string'("SIA_CORE: EMITTED - grade with zynq/check_sia_pairs.py sia_pairs.txt"));
    else
      write(ln, string'("SIA_CORE: FAIL too few pairs"));
    end if;
    writeline(output, ln);

    sim_done <= true;
    wait;
  end process;

end bench;
