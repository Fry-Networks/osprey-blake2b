-- Copyright (c) 2026, Fry Networks. Adapted from pedrorivera/SiaFpgaMiner (MIT, 2018).
--
-- === OspreySiaTop.vhd ===
--
-- Top level of the Siacoin mining pipeline: one OspreySiaCore, and nothing else.
--
-- The Knots top (OspreyBlake2bTop) wires a stage-3 core into a stage-4 core and
-- OVERWRITES the stage-4 message's last four slots with stage 3's output:
--
--     Stage4Msg(6..9) <= HashA;       -- OspreyBlake2bTop.vhd:95-98
--
-- That is correct for Knots -- those 32 bytes are hash_a, which only the FPGA
-- can compute -- but it also means that design structurally cannot mine a job
-- whose merkle root came from a pool with a non-empty branch, because the root
-- it needs is not the hash of anything it holds.
--
-- Sia has no such stage. The last 32 bytes of the header are the merkle root,
-- already folded by whoever built the job, so they pass through untouched. That
-- single difference is what lets this core mine branch-carrying pool work, and
-- it is also why there is so little here: dropping stage 3 removes about half
-- the logic of the Knots design.
--
-- Data flow:
--   1. The host supplies the 80-byte header (parent ID, nonce slot, timestamp,
--      merkle root) and the top 64 bits of the target.
--   2. The core grinds slot 4 and prefilters on byteswap(H[0]).
--   3. On a hit, Success pulses and Nonce/HashTop64 latch.
--   4. The host recomputes the full 256-bit hash and compares the whole target
--      before submitting -- the on-chip compare is 64 bits and is only a filter.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

library work;
  use work.PkgBlake2b.all;
  use work.PkgOspreySia.all;

entity OspreySiaTop is
  generic(
    kNonceSeed : unsigned(63 downto 0) := (others => '1')
  );
  port(
    Clk    : in std_logic;
    Enable : in std_logic;
    -- The whole 80-byte header. Slot 4 is ignored (the iterator drives it);
    -- slots 6..9 are the merkle root and ARE used, unlike the Knots top.
    Header      : in U64Array_t(9 downto 0);
    TargetTop64 : in unsigned(63 downto 0);
    Success      : out std_logic;
    Nonce        : out unsigned(63 downto 0);
    HashTop64    : out unsigned(63 downto 0)
  );
end OspreySiaTop;

architecture rtl of OspreySiaTop is
begin

  U_Core: entity work.OspreySiaCore
  generic map(
    kNonceSeed => kNonceSeed
  )
  port map(
    Clk          => Clk,
    Enable       => Enable,
    BlockHeader  => Header,
    TargetTop64  => TargetTop64,
    NonceOut     => Nonce,
    HashTop64Out => HashTop64,
    Success      => Success
  );

end rtl;
