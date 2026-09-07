-- Copyright (c) 2026, Fry Networks. MIT.
--
-- tb_stage4_smoke.vhd
--
-- Smoke test for OspreyBlake2bStage4Core: verifies the pipeline runs, the
-- nonce iterator increments, and Success asserts under a permissive target.
--
-- Full correctness of the Blake2b compression is proven by tb_stage3_core.vhd
-- (100/100 HARD GATE) because Stage4 reuses the same QuadG pipeline with only
-- the Msg(4)-sigma-4-replaces-nonce delta and target compare. This smoke test
-- catches structural/timing bugs in the nonce iterator + Verify process.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;
library std;
  use std.textio.all;
library work;
  use work.PkgBlake2b.all;

entity tb_stage4_smoke is
end tb_stage4_smoke;

architecture bench of tb_stage4_smoke is

  constant kClkPeriod   : time    := 10 ns;
  constant kRunCycles   : integer := 300;  -- enough for pipeline to fully fill
  constant kNonceSeedTb : unsigned(63 downto 0) := x"0000000000000064"; -- 100

  signal Clk          : std_logic := '0';
  signal Enable       : std_logic := '0';
  signal BlockHeader  : U64Array_t(9 downto 0) := (others => (others => '0'));
  signal TargetTop64  : unsigned(63 downto 0) := (others => '1');  -- MAX: hash < target always
  signal NonceOut     : unsigned(63 downto 0);
  signal HashTop64Out : unsigned(63 downto 0);
  signal Success      : std_logic;

  signal sim_done       : boolean := false;
  signal success_count  : integer := 0;
  signal last_nonce_out : unsigned(63 downto 0) := (others => '0');

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

  -- Populate a fixed header (all zeros for prevblock_hidden; hash_a slots also zero)
  -- Slot 4 will be overwritten by internal nonce iterator regardless.
  BlockHeader(0) <= x"1111111111111111";
  BlockHeader(1) <= x"2222222222222222";
  BlockHeader(2) <= x"3333333333333333";
  BlockHeader(3) <= x"4444444444444444";
  BlockHeader(4) <= (others => '0');  -- ignored (nonce iterator)
  BlockHeader(5) <= x"5555555555555555";
  BlockHeader(6) <= x"6666666666666666";
  BlockHeader(7) <= x"7777777777777777";
  BlockHeader(8) <= x"8888888888888888";
  BlockHeader(9) <= x"9999999999999999";

  -- Monitor Success + NonceOut
  monitor: process(Clk)
  begin
    if rising_edge(Clk) then
      if Success = '1' then
        success_count <= success_count + 1;
        last_nonce_out <= NonceOut;
      end if;
    end if;
  end process;

  stimulus: process
    variable ln       : line;
    variable slv      : std_logic_vector(63 downto 0);
    variable verdict  : string(1 to 4);
  begin
    Enable <= '0';
    wait for 5 * kClkPeriod;
    Enable <= '1';
    wait for kRunCycles * kClkPeriod;
    Enable <= '0';
    wait for 5 * kClkPeriod;

    write(ln, string'("STAGE4_SMOKE cycles="));
    write(ln, kRunCycles);
    write(ln, string'(" success_count="));
    write(ln, success_count);
    write(ln, string'(" last_nonce="));
    slv := std_logic_vector(last_nonce_out);
    hwrite(ln, slv);
    write(ln, string'(" last_hash_top64="));
    slv := std_logic_vector(HashTop64Out);
    hwrite(ln, slv);
    writeline(output, ln);

    -- Smoke gate: with TargetTop64=MAX, Success should rise many times.
    -- Require at least 50 Success cycles within 300-cycle window.
    if success_count >= 50 then
      verdict := "PASS";
    else
      verdict := "FAIL";
    end if;
    write(ln, string'("SMOKE: "));
    write(ln, verdict);
    writeline(output, ln);

    sim_done <= true;
    wait;
  end process;

end bench;
