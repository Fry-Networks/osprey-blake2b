-- Copyright (c) 2026, Fry Networks. MIT.
--
-- tb_sia_unpack.vhd
--
-- Proves the 88-byte work-item mapping in OspreySiaUartTop:
--     Header(i)   <- bytes (8i)..(8i+7), little-endian
--     TargetTop64 <- bytes 80..87
--
-- The buffer is built by MODELLING the receiver -- shifting right, one bit at a
-- time, exactly as OspreyBlake2bUartGetWork does -- rather than by writing bytes
-- through the same helper the unpack uses. That distinction is the whole point.
-- The Knots version of this bench originally drove WorkData through the very
-- helper it was testing, so it agreed with a mirrored mapping and passed while
-- the board read every field from the wrong end of the buffer AND byte-swapped
-- it. A mapping test must model the hardware that produces the buffer, not
-- restate the assumption under test.
--
-- Half the checks here are NEGATIVE: they assert that the plausible wrong
-- mappings -- big-endian slots, reversed slot order, the target lifted from the
-- low end -- do NOT match. A positive-only mapping test cannot tell a correct
-- mapping from a symmetric one, and the symmetric wrong answer is precisely the
-- one that shipped last time.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;
library std;
  use std.textio.all;
library work;
  use work.PkgBlake2b.all;
  use work.PkgOspreySia.all;

entity tb_sia_unpack is
end tb_sia_unpack;

architecture bench of tb_sia_unpack is

  constant kRxBytes : positive := kSiaWorkItemBytes;   -- 88
  constant kRxBits  : positive := kRxBytes*8;          -- 704

  signal WorkData    : std_logic_vector(kRxBits-1 downto 0) := (others => '0');
  signal Header      : U64Array_t(9 downto 0);
  signal TargetTop64 : unsigned(63 downto 0);

begin

  -- The mapping under test, character for character as OspreySiaUartTop has it.
  UnpackGen: for i in 0 to 9 generate
    Header(i) <= unsigned(WorkData(64*i + 63 downto 64*i));
  end generate;
  TargetTop64 <= unsigned(WorkData(64*10 + 63 downto 64*10));

  stimulus: process
    variable sr   : std_logic_vector(kRxBits-1 downto 0) := (others => '0');
    variable byt  : std_logic_vector(7 downto 0);
    variable ln   : line;
    variable fail : integer := 0;
    variable slv  : std_logic_vector(63 downto 0);

    procedure check(name : string; got : unsigned(63 downto 0);
                    want : unsigned(63 downto 0)) is
      variable l : line;
      variable s : std_logic_vector(63 downto 0);
    begin
      if got /= want then
        fail := fail + 1;
        write(l, string'("FAIL "));
        write(l, name);
        write(l, string'(" got="));
        s := std_logic_vector(got);  hwrite(l, s);
        write(l, string'(" want="));
        s := std_logic_vector(want); hwrite(l, s);
        writeline(output, l);
      else
        write(l, string'("ok   "));
        write(l, name);
        write(l, string'(" = "));
        s := std_logic_vector(got); hwrite(l, s);
        writeline(output, l);
      end if;
    end procedure;

    procedure check_differs(name : string; a : unsigned(63 downto 0);
                            b : unsigned(63 downto 0)) is
      variable l : line;
      variable s : std_logic_vector(63 downto 0);
    begin
      if a = b then
        fail := fail + 1;
        write(l, string'("FAIL "));
        write(l, name);
        write(l, string'(" -- the wrong mapping is indistinguishable, value="));
        s := std_logic_vector(a); hwrite(l, s);
        writeline(output, l);
      else
        write(l, string'("ok   "));
        write(l, name);
        writeline(output, l);
      end if;
    end procedure;

  begin
    -- Model the receiver: byte k carries the value k, shifted in bit by bit,
    -- LSB first, each new bit entering at the TOP and pushing the rest down.
    for k in 0 to kRxBytes-1 loop
      byt := std_logic_vector(to_unsigned(k mod 256, 8));
      for b in 0 to 7 loop
        sr := byt(b) & sr(sr'high downto 1);
      end loop;
    end loop;
    WorkData <= sr;
    wait for 1 ns;

    -- Positive: the first byte received is the LEAST significant byte of slot 0.
    check("Header(0)   = bytes 0..7",   Header(0),   x"0706050403020100");
    check("Header(1)   = bytes 8..15",  Header(1),   x"0f0e0d0c0b0a0908");
    check("Header(4)   = bytes 32..39", Header(4),   x"2726252423222120");
    check("Header(5)   = bytes 40..47", Header(5),   x"2f2e2d2c2b2a2928");
    check("Header(9)   = bytes 72..79", Header(9),   x"4f4e4d4c4b4a4948");
    check("TargetTop64 = bytes 80..87", TargetTop64, x"5756555453525150");

    -- Negative: a big-endian read of slot 0 would give the byte-reversed value.
    check_differs("big-endian slot 0 is distinguishable",
                  Header(0), x"0001020304050607");
    -- Negative: the target must not be readable from the LOW end of the buffer.
    -- That was the exact symptom last time -- the target landed on bits 63..0,
    -- so the core prefiltered against the start of the header and never looked
    -- at the target at all.
    check_differs("target is not the low 64 bits",
                  TargetTop64, Header(0));
    -- Negative: reversed slot order would put the last header slot first.
    check_differs("slot order is not reversed",
                  Header(0), x"4f4e4d4c4b4a4948");
    -- Negative: the target must not alias the last header slot either, which is
    -- what an 80-byte frame size would produce.
    check_differs("target is not header slot 9",
                  TargetTop64, Header(9));

    if fail = 0 then
      write(ln, string'("SIA_UNPACK: PASS"));
    else
      write(ln, string'("SIA_UNPACK: FAIL "));
      write(ln, fail);
    end if;
    writeline(output, ln);
    wait;
  end process;

end bench;
