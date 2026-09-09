-- Copyright (c) 2026, Fry Networks. MIT.
--
-- tb_unpack.vhd
--
-- Unit test for the work-item byte -> slot mapping in OspreyBlake2bUartTop.
--
-- IMPORTANT: this bench drives the ACTUAL receive shift register, bit by bit,
-- LSB-first per byte, exactly as OspreyBlake2bUartGetWork does:
--
--     workDataLcl <= rx & workDataLcl(workDataLcl'high downto 1);
--
-- An earlier version of this file instead wrote bytes into WorkData through the
-- same ByteHigh() helper the unpack used to read them. That is a test which can
-- only ever agree with itself: it reported PASS while the mapping was mirrored
-- end-for-end, and the real defect went to hardware. A mapping test must model
-- the hardware that produces the buffer, not restate the assumption under test.
--
-- What the shift register actually does: each new bit enters at the top and
-- pushes the rest down, so after all 1344 bits the FIRST bit received has been
-- shifted down 1343 times and sits at position 0. Byte b therefore occupies bits
-- 8b+7 downto 8b, and since BLAKE2b words are little-endian (first byte least
-- significant) each 64-bit slot is the plain ascending slice.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;
library std;
  use std.textio.all;
library work;
  use work.PkgBlake2b.all;

entity tb_unpack is
end tb_unpack;

architecture bench of tb_unpack is

  constant kRxBytes : positive := 168;
  constant kRxBits  : positive := kRxBytes*8;

  signal WorkData    : std_logic_vector(kRxBits-1 downto 0) := (others => '0');
  signal Stage3In    : U64Array_t(9 downto 0);
  signal Stage4In    : U64Array_t(9 downto 0);
  signal TargetTop64 : unsigned(63 downto 0);

begin

  -- Mirror of the unpack in OspreyBlake2bUartTop. Keep the two in step.
  UnpackGen: for i in 0 to 9 generate
    Stage3In(i) <= unsigned(WorkData(64*i        + 63 downto 64*i));
    Stage4In(i) <= unsigned(WorkData(64*(10 + i) + 63 downto 64*(10 + i)));
  end generate;
  TargetTop64 <= unsigned(WorkData(64*20 + 63 downto 64*20));

  stimulus: process
    variable ln   : line;
    variable fail : integer := 0;
    variable sr   : std_logic_vector(kRxBits-1 downto 0) := (others => '0');
    variable byt  : std_logic_vector(7 downto 0);

    procedure check(name : string; got : unsigned(63 downto 0); want : unsigned(63 downto 0)) is
      variable l : line;
    begin
      if got /= want then
        fail := fail + 1;
        write(l, string'("FAIL " & name & " got="));
        hwrite(l, std_logic_vector(got));
        write(l, string'(" want="));
        hwrite(l, std_logic_vector(want));
        writeline(output, l);
      else
        write(l, string'("ok   " & name & " = "));
        hwrite(l, std_logic_vector(got));
        writeline(output, l);
      end if;
    end procedure;

  begin
    -- Shift in byte k = k, LSB first, exactly as the receiver does.
    for k in 0 to kRxBytes-1 loop
      byt := std_logic_vector(to_unsigned(k mod 256, 8));
      for b in 0 to 7 loop
        sr := byt(b) & sr(sr'high downto 1);
      end loop;
    end loop;
    WorkData <= sr;
    wait for 1 ns;

    -- Byte 0 is the least significant byte of slot 0, so slot 0 reads back as
    -- 0x0706050403020100.
    check("Stage3In(0)", Stage3In(0), x"0706050403020100");
    check("Stage3In(1)", Stage3In(1), x"0f0e0d0c0b0a0908");
    check("Stage3In(9)", Stage3In(9), x"4f4e4d4c4b4a4948");
    -- Stage4In starts at byte 80 = 0x50.
    check("Stage4In(0)", Stage4In(0), x"5756555453525150");
    check("Stage4In(9)", Stage4In(9), x"9f9e9d9c9b9a9998");
    -- TargetTop64 is bytes 160..167 = 0xa0..0xa7. Getting this from the wrong
    -- end of the buffer is what made the core prefilter against bytes 0..7.
    check("TargetTop64", TargetTop64, x"a7a6a5a4a3a2a1a0");

    if fail = 0 then
      write(ln, string'("UNPACK: PASS"));
    else
      write(ln, string'("UNPACK: FAIL "));
      write(ln, fail);
    end if;
    writeline(output, ln);
    wait;
  end process;

end bench;
