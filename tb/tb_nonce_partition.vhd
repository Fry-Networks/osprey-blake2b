-- Copyright (c) 2026, Fry Networks. MIT.
--
-- tb_nonce_partition.vhd
--
-- Proves the multi-core nonce split tests every nonce once and no nonce twice.
--
-- The two ways a multi-core miner can look perfect and deliver nothing:
--   * every core grinds the SAME nonces (e.g. seeds kNonceSeed + k), so N cores
--     do one core's work while utilisation, timing and frame rate all look right;
--   * the seeds are fine but the twelve time-skewed nonce registers inside the
--     core fall out of alignment, so each round consumes a different nonce and
--     the digest corresponds to none of them.
-- Both present as "candidates report at the normal rate and never verify", which
-- this repo has already paid for once.
--
-- The scheme: core k starts at S_k = (k << (64-m)) - 1, m = ClogB2(N), and steps
-- by exactly 1 per clock. Disjointness cannot be proved by sampling 2^64 values,
-- so it is proved STRUCTURALLY: the top m bits of every nonce a core reports are
-- its own index. That is exactly what the scheme promises, and it is also what
-- gives per-core liveness on hardware for free.
--
-- TargetTop64 = MAX so every pipeline slot reports, making NonceOut observable
-- (it is the only window onto the internal counter).

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;
library std;
  use std.textio.all;
library work;
  use work.PkgBlake2b.all;
  use work.PkgOspreyBlake2b.all;

entity tb_nonce_partition is
end tb_nonce_partition;

architecture bench of tb_nonce_partition is

  constant kN         : positive := 4;
  constant kM         : natural  := ClogB2(kN);
  constant kClkPeriod : time     := 10 ns;
  constant kRun       : integer  := 900;
  constant kFill      : integer  := 120;   -- > kPipeLength + 1 = 97

  signal Clk    : std_logic := '0';
  signal Enable : std_logic := '0';
  signal Hdr    : U64Array_t(9 downto 0) := (others => (others => '0'));
  signal Target : unsigned(63 downto 0) := (others => '1');

  type U64Arr is array (natural range <>) of unsigned(63 downto 0);
  signal NonceO : U64Arr(kN-1 downto 0);
  signal Succ   : std_logic_vector(kN-1 downto 0);

  signal cyc      : integer := 0;
  signal badIdx   : integer := 0;    -- nonce whose top bits are not its core
  signal badStep  : integer := 0;    -- nonce that did not advance by exactly 1
  signal checked  : integer := 0;
  signal sim_done : boolean := false;

begin

  ClkGen: process
  begin
    if sim_done then wait; end if;
    Clk <= '0'; wait for kClkPeriod/2;
    Clk <= '1'; wait for kClkPeriod/2;
  end process;

  Hdr(0) <= x"1111111111111111";
  Hdr(1) <= x"2222222222222222";
  Hdr(2) <= x"3333333333333333";
  Hdr(3) <= x"4444444444444444";
  Hdr(5) <= x"5555555555555555";
  Hdr(6) <= x"6666666666666666";
  Hdr(7) <= x"7777777777777777";
  Hdr(8) <= x"8888888888888888";
  Hdr(9) <= x"9999999999999999";

  CoreGen: for k in 0 to kN-1 generate
    U_Core: entity work.OspreyBlake2bStage4Core
      generic map (kNonceSeed => CoreNonceSeed(k, kN))
      port map (Clk => Clk, Enable => Enable, BlockHeader => Hdr,
                TargetTop64 => Target, NonceOut => NonceO(k),
                HashTop64Out => open, Success => Succ(k));
  end generate;

  Check: process(Clk)
    variable prev : U64Arr(kN-1 downto 0) := (others => (others => '0'));
    variable seen : std_logic_vector(kN-1 downto 0) := (others => '0');
    variable bi, bs, ck : integer;
  begin
    if rising_edge(Clk) then
      if Enable = '1' then
        cyc <= cyc + 1;
        if cyc > kFill then
          bi := badIdx; bs := badStep; ck := checked;
          for k in 0 to kN-1 loop
            if Succ(k) = '1' then
              ck := ck + 1;
              -- structural disjointness: top m bits ARE the core index
              if to_integer(shift_right(NonceO(k), 64 - kM)) /= k then
                bi := bi + 1;
              end if;
              -- no skip: strictly +1 per cycle
              if seen(k) = '1' and NonceO(k) /= prev(k) + 1 then
                bs := bs + 1;
              end if;
              prev(k) := NonceO(k);
              seen(k) := '1';
            end if;
          end loop;
          badIdx <= bi; badStep <= bs; checked <= ck;
        end if;
      end if;
    end if;
  end process;

  Stim: process
    variable ln : line;
  begin
    -- N=1 must reduce EXACTLY to the shipped single-core seed, or the one-core
    -- build silently changes and miner.c's NONCE_GUARD arithmetic breaks.
    assert CoreNonceSeed(0, 1) = unsigned'(x"FFFFFFFFFFFFFFFF")
      report "NONCE_PARTITION: FAIL - CoreNonceSeed(0,1) is not all-ones; the "
           & "single-core build would change behaviour." severity failure;

    Enable <= '0'; wait for 10*kClkPeriod;
    Enable <= '1'; wait for kRun*kClkPeriod;
    Enable <= '0'; wait for 5*kClkPeriod;

    write(ln, string'("NONCE_PARTITION: cores=")); write(ln, kN);
    write(ln, string'(" m=")); write(ln, kM);
    write(ln, string'(" checked=")); write(ln, checked);
    write(ln, string'(" wrong_slice=")); write(ln, badIdx);
    write(ln, string'(" non_unit_step=")); write(ln, badStep);
    writeline(output, ln);

    if checked = 0 then
      write(ln, string'("NONCE_PARTITION: FAIL - nothing was checked; zeros above "
                      & "would be vacuous."));
      writeline(output, ln); assert false severity failure;
    end if;
    if badIdx /= 0 then
      write(ln, string'("NONCE_PARTITION: FAIL - a core reported a nonce outside its "
                      & "own slice; the cores overlap and are duplicating work."));
      writeline(output, ln); assert false severity failure;
    end if;
    if badStep /= 0 then
      write(ln, string'("NONCE_PARTITION: FAIL - a core's nonce did not advance by "
                      & "exactly 1; nonces are being skipped."));
      writeline(output, ln); assert false severity failure;
    end if;

    write(ln, string'("NONCE_PARTITION: PASS - "));
    write(ln, checked);
    write(ln, string'(" reports, every one inside its own slice, every step +1, and "
                    & "N=1 reduces to the shipped seed."));
    writeline(output, ln);
    sim_done <= true;
    wait;
  end process;

end bench;
