-- Copyright (c) 2026, Fry Networks. Adapted from pedrorivera/SiaFpgaMiner (MIT, 2018).
--
-- === PkgOspreySia.vhd ===
--
-- Constants for the Siacoin BLAKE2b PoW core on the Osprey E100 VU35P.
--
-- Siacoin's work header is 80 bytes and its PoW is a single BLAKE2b-256 of that
-- header, so this design is SHORTER than the Knots one next door, not longer:
-- there is no stage 3. Knots needs one because its 80-byte ASIC-visible message
-- ends in hash_a, the hash of a separate 52-byte region, which the FPGA must
-- compute itself. Sia's last 32 bytes are the merkle root, which arrives from
-- the pool already folded. Dropping stage 3 removes roughly half the logic.
--
-- Header layout (80 bytes), and how it maps onto the 10 x u64 message slots:
--   bytes  0..31 : parent block ID   -> Msg(0..3)
--   bytes 32..39 : nonce             -> Msg(4)   <-- the grind slot, sigma index 4
--   bytes 40..47 : timestamp         -> Msg(5)
--   bytes 48..79 : merkle root       -> Msg(6..9)
--
-- That is the same slot arithmetic the Knots stage-4 message uses, which is the
-- whole reason a pool can serve Knots work to Sia firmware over Sia stratum.
--
-- THE ONE THING THAT DIFFERS, and it is not cosmetic: which digest word the
-- prefilter taps, and whether it is byte-reversed. See OspreySiaCore.vhd.

library ieee;
  use ieee.std_logic_1164.all;
  use ieee.numeric_std.all;

library work;
  use work.PkgBlake2b.all;

package PkgOspreySia is

  -- 80 bytes, the same length as Knots stage 4; PkgBlake2b.kMsgLen is already
  -- x"50" because that is Sia's native size.
  constant kSiaMsgLen : unsigned(7 downto 0) := x"50";

  -- Wire framing. 80 header bytes plus the 64-bit target, then a 17-byte reply
  -- identical in shape to the Knots one (flag, nonce, hash prefix) so the host
  -- parser is shared.
  constant kSiaHeaderBytes   : integer := 80;
  constant kSiaTargetBytes   : integer := 8;
  constant kSiaWorkItemBytes : integer := kSiaHeaderBytes + kSiaTargetBytes;  -- 88
  constant kSiaResultBytes   : integer := 17;

  -- Message word replaced by the nonce iterator. Sia grinds Msg(4); so does
  -- Knots stage 4, so the sigma-index-4 substitution pattern is inherited
  -- unchanged from the vendor core.
  constant kSiaNonceSigmaIdx : integer := 4;

end PkgOspreySia;
