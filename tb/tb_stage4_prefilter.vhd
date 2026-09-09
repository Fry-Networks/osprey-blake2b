-- Copyright (c) 2026, Fry Networks. MIT.
--
-- tb_stage4_prefilter.vhd
--
-- Checks the thing tb_stage4_smoke.vhd could not: that the word the prefilter
-- compares against the target is the RIGHT word of the digest.
--
-- The smoke test drives TargetTop64 = MAX, so Success asserts on every cycle no
-- matter what HashTop64Out contains, and it never compares HashTop64Out to
-- anything. That is exactly how a prefilter tapping H[0] instead of H[3]
-- survived a 100/100 gate and got synthesised into a bitstream: with the wrong
-- word the miner still reports candidates at the expected rate, and every one
-- fails verification on the host.
--
-- This bench keeps TargetTop64 = MAX on purpose -- that makes every pipeline
-- slot report a (nonce, hash) pair -- and dumps each pair to a file. The
-- checker in zynq/check_stage4_pairs.py rebuilds the 80-byte message with
-- slot 4 = the reported nonce, runs it through hashlib's BLAKE2b, and requires
-- HashTop64Out to equal digest[24:32] read big-endian, i.e. byteswap(H[3]).
--
-- That also validates the nonce pipeline offset (NonceOut = Nonce(0) - 97),
-- which was hand-derived: if the offset is wrong the reported nonce does not
-- correspond to the reported hash and every pair fails.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;
library std;
  use std.textio.all;
library work;
  use work.PkgBlake2b.all;

entity tb_stage4_prefilter is
end tb_stage4_prefilter;

architecture bench of tb_stage4_prefilter is

  constant kClkPeriod   : time    := 10 ns;
  constant kRunCycles   : integer := 400;
  constant kNonceSeedTb : unsigned(63 downto 0) := x"0000000000000064"; -- 100

  signal Clk          : std_logic := '0';
  signal Enable       : std_logic := '0';
  signal BlockHeader  : U64Array_t(9 downto 0) := (others => (others => '0'));
  signal TargetTop64  : unsigned(63 downto 0) := (others => '1');
  signal NonceOut     : unsigned(63 downto 0);
  signal HashTop64Out : unsigned(63 downto 0);
  signal Success      : std_logic;

  signal sim_done      : boolean := false;
  signal success_count : integer := 0;

  -- The core is a 96-stage pipeline and NonceOut is Nonce(0) - (96+1), so nothing
  -- it reports is meaningful until the pipeline has been fed for that many cycles,
  -- and it keeps draining stale slots after Enable drops. Both windows report a
  -- nonce that does not belong to the hash beside it. Grading them would be
  -- grading uninitialised state, so the dump is gated to the steady-state window
  -- instead -- and the checker treats an empty result set as a failure, so this
  -- gate cannot quietly swallow the whole run.
  constant kFillCycles : integer := 100;  -- > kPipeLength + 1 = 97
  signal fill_count    : integer := 0;

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

  -- Must match HEADER_SLOTS in zynq/check_stage4_pairs.py exactly.
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
    file     fh  : text open write_mode is "stage4_pairs.txt";
    variable ln  : line;
    variable slv : std_logic_vector(63 downto 0);
  begin
    if rising_edge(Clk) then
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

    write(ln, string'("STAGE4_PREFILTER pairs_written="));
    write(ln, success_count);
    writeline(output, ln);

    -- The pairs themselves are graded by zynq/check_stage4_pairs.py; this bench
    -- only guarantees it produced enough of them to be worth grading.
    if success_count >= 50 then
      write(ln, string'("STAGE4_PREFILTER: EMITTED"));
    else
      write(ln, string'("STAGE4_PREFILTER: FAIL too few pairs"));
    end if;
    writeline(output, ln);

    sim_done <= true;
    wait;
  end process;

end bench;
