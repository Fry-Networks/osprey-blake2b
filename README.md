# Osprey E100 (VU35P) BLAKE2b Mining Bitstream — Bitcoin Knots

Open-source VHDL for a two-stage BLAKE2b Proof-of-Work mining pipeline
targeting the Osprey E100 miner (Xilinx Virtex UltraScale+ VU35P,
`xcvu35p-fsvh2104-2-e`) for the Bitcoin Knots BLAKE2b hard fork
(`DEPLOYMENT_BLAKE2B`, mainnet activation height 961640,
`Blake2bTargetShift = 22`).

## Status

| Component                              | Status |
|----------------------------------------|--------|
| HDL design (mining core)               | Complete, GHDL-analyze-clean under VHDL-2008 |
| Python golden reference                | Complete, RFC 7693 verified |
| Behavioral simulation — Stage 3        | **100/100 HARD GATE PASS** under GHDL |
| Behavioral simulation — Stage 4 smoke  | PASS (nonce iterator + pipeline alignment) |
| VU35P clock management (`MMCME4_ADV`)  | Authored (`src/clock_mgmt.vhd`), 250 MHz |
| Xilinx constraints (`.xdc`)            | **Real board pins** from the vendor E300 constraint file |
| Chip-level UART wrapper                | Complete (`src/OspreyBlake2bUartTop.vhd`) — 5 board pins |
| Vivado synthesis + P&R                 | **Complete** — timing met, 0 routing errors, DRC 0 errors |
| `.bit` artifact                        | Built (21.3 MB). Not committed — see Releases |
| Osprey deployment glue (CGI upload)    | **NOT PROVIDED** — deployment path documented, not tested |
| Zynq-side miner binary                 | **NOT PROVIDED** — see "What remains" |

Evidence file: [`reports/hardgate-stage3-100.txt`](reports/hardgate-stage3-100.txt)
(100 vectors × 4 × u64 hash, SHA-256 of vector file + all tested RTL sources).

## Overview

Bitcoin Knots' BLAKE2b PoW splits into five stages
(see `src/primitives/block.cpp` `CBlockHeader::GetHash` in bitcoinknots/bitcoin):

1. `SHA256d` TaggedHash "Bitcoin block header 1" (host-side).
2. `SHA256d` TaggedHash "Merge-mining hook" (host-side).
3. **`BLAKE2b(52 bytes)`** — hashes `u32(0) || h2_hash || m_extranonce`; runs once per pool `notify` (FPGA-side, `src/OspreyBlake2bStage3Core.vhd`).
4. **`BLAKE2b(80 bytes)`** — hashes the ASIC-visible header with the 64-bit
   grinding slot at `Msg(4)`; runs per nonce, is the hot path (FPGA-side,
   `src/OspreyBlake2bStage4Core.vhd`).
5. XOR with `m_xor_key` mask + byte-reverse (host-side).

Only stages 3 and 4 are on the FPGA. The Zynq host handles the SHA-256d
prefix, the XOR finalization, and full 256-bit target compare. The FPGA
core emits a 64-bit prefilter `Success` when the top 64 bits of the stage-4
hash pass a shifted target.

## Provenance

Adapted from [pedrorivera/SiaFpgaMiner](https://github.com/pedrorivera/SiaFpgaMiner)
(MIT 2018). Retargeted from the Kintex-7 to the Xilinx Virtex UltraScale+
VU35P. Delta from Sia:

- Header format: Sia's 80-byte mining header → Knots' 164-byte v2 header
  (with 52-byte coinb1 region + 80-byte ASIC-visible message).
- Two chained cores (`Stage3Core` + `Stage4Core`) replace Sia's single core.
- Nonce iterator widened from 48-bit to 64-bit (Msg(4) slot = `nNonce || m_nonce2`).
- Target compare on the top 64 bits (host-side does full 256-bit + XOR finalization).
- Sigma-index-4 nonce replacement pattern is inherited unchanged from Sia
  (both target `Msg(4)` for the grind slot).
- Clocking primitive migrated from K7 `PLLE2_ADV` to UltraScale+ `MMCME4_ADV`.

Vendor source (with the original 2018 MIT license header) lives under
`vendor/sia-fpga/` for direct comparison against modifications.

## Repository layout

```
src/                        Osprey-specific VHDL (top, stage cores, package, clocking)
  OspreyBlake2bTop.vhd      Top-level; wires Stage3 → Stage4
  OspreyBlake2bStage3Core.vhd
  OspreyBlake2bStage4Core.vhd
  PkgOspreyBlake2b.vhd
  clock_mgmt.vhd            VU35P MMCME4_ADV 100 MHz → 250 MHz mining clock
constraints/
  osprey_vu35p.xdc          Placeholder pin LOCs (ASSUMED_PIN, see caveats)
tb/                         VHDL-2008 testbenches (textio, plain GHDL)
  tb_stage3_core.vhd
  tb_stage4_smoke.vhd
  vectors/stage3_vectors_100.txt
zynq/                       Host-side Python
  blake2b_reference.py      RFC 7693-verified BLAKE2b + Knots PoW pipeline
                            (also emits GHDL test vectors)
reports/                    HARD GATE evidence + audit outputs
vendor/sia-fpga/            Original SiaFpgaMiner sources (MIT 2018, verbatim)
```

## Build / verify

### Python golden reference (self-test + emit test vectors)

```bash
py -3 zynq/blake2b_reference.py                              # RFC 7693 self-test
py -3 zynq/blake2b_reference.py --emit-stage3-vectors 100 > tb/vectors/stage3_vectors_100.txt
```

The self-test asserts BLAKE2b of "abc" matches the RFC 7693 published digest.

### GHDL behavioral simulation (verifies the 100/100 HARD GATE)

GHDL 6.0.0 mcode backend (Windows `winget install ghdl.ghdl`) or newer:

```bash
cd osprey-blake2b

# Analyze in dependency order
ghdl -a --std=08 --work=work --workdir=src/ghdl-work \
     vendor/sia-fpga/PkgBlake2b.vhd \
     src/PkgOspreyBlake2b.vhd \
     vendor/sia-fpga/MixG_FlopPipe_4.vhd \
     vendor/sia-fpga/QuadG.vhd \
     src/OspreyBlake2bStage3Core.vhd \
     src/OspreyBlake2bStage4Core.vhd \
     src/OspreyBlake2bTop.vhd \
     tb/tb_stage3_core.vhd \
     tb/tb_stage4_smoke.vhd

# Elaborate + run Stage3 hard gate
ghdl -e --std=08 --work=work --workdir=src/ghdl-work tb_stage3_core
ghdl -r --std=08 --work=work --workdir=src/ghdl-work tb_stage3_core --stop-time=200ms

# Expect final line:  RESULT: 100/100 PASS

# Stage4 smoke test
ghdl -e --std=08 --work=work --workdir=src/ghdl-work tb_stage4_smoke
ghdl -r --std=08 --work=work --workdir=src/ghdl-work tb_stage4_smoke --stop-time=10ms
```

Note: `src/clock_mgmt.vhd` references the Xilinx `UNISIM` library and will
NOT analyze under GHDL mcode (mcode has no `UNISIM` primitive support).
It is a synthesis-only file — Vivado expands `MMCME4_ADV`.

### Vivado synthesis + implementation

Requires Vivado ML Enterprise (the VU35P HBM part is not covered by the free tier).

```
# Out-of-context synthesis of the mining core (no IO buffers, fast, no pin LOCs needed)
vivado -mode batch -source build/synth.tcl -tclargs ooc

# Full flow on the chip-level UART wrapper, through to a bitstream
vivado -mode batch -source build/synth.tcl -tclargs full
```

`-tclargs` must come last; Vivado hands everything after it to the script.

Results on `xcvu35p_CIV-fsvh2104-2-e` with Vivado 2026.1:

| Metric | Core only (OOC) | Chip-level (full) |
|--------|-----------------|-------------------|
| WNS @ 250 MHz | +2.349 ns | +0.365 ns |
| WHS | +0.058 ns | +0.010 ns |
| Failing endpoints | 0 / 190,970 | 0 / 195,409 |
| CLB LUTs | 97,895 (11.2%) | 98,015 (11.2%) |
| CLB Registers | 191,161 (11.0%) | 192,728 (11.1%) |
| Bonded IOB | n/a (OOC) | 5 / 416 (1.2%) |
| Routing | n/a | 260,283 / 260,283 nets, 0 errors |
| DRC | n/a | 0 errors |

Utilization is ~11%, so roughly eight parallel cores would fit on the device.

## Caveats — what remains before real hardware bring-up

- **Pin LOCs — RESOLVED.** `constraints/osprey_vu35p.xdc` (the original
  OOC/core-boundary placeholder file, still flagged `# ASSUMED_PIN` /
  `# TODO_PIN`) is superseded for real bring-up by
  `constraints/osprey_vu35p_uart.xdc`, which already carries the real
  vendor pins for the chip-level UART wrapper (`clk_p`/`clk_n`=BB18/BC18
  LVDS, `rx`=C12, `tx`=B9, all LVCMOS18, no reset pin) sourced from
  `PachiraMining/E300_development hardware/constrain_e300_vu35p_non_CIV.xdc`.
  This has been independently cross-checked against another team's E300
  pin-forensics effort (bitstream IOB-frame decoding + `devmem2` register
  validation on real VU33P/VU35P/VU9P/VU7P hardware) and the pins agree
  exactly — clock, UART pins, IOSTANDARD, and the absence of a real reset
  pin (the vendor's own board files never expose one; treat any `resetn`
  LOC as an unverified guess, as this repo's own `OspreyBlake2bUartTop.vhd`
  header now correctly notes).
- **Zynq–PL interconnect — RESOLVED.** The top-level exposes ~1408 wires
  (Stage3In + Stage4In + TargetTop64 + Nonce + HashTop64). A real Osprey
  build needs a UART / I²C / AXI-Lite wrapper to serialize these across
  the physical Zynq–PL bus. `OspreyBlake2bUartTop.vhd` now implements
  exactly this, bringing chip IO down to 5 pins — see `build/synth.tcl`'s
  `full` mode.
- **Deployment.** The Osprey firmware exposes a CGI endpoint
  (`Page=setDracaenaAlgoStatus`) that accepts custom git-managed algo
  modules with matching `/opt/<algo>/bits/` layout. This has not been
  round-tripped end-to-end. Do not deploy against a producing miner
  without a full config + bitstream backup first.
  **Bitstream programming hazard:** on E300-family boards (Zynq PS
  managing external UltraScale+ PL chips over JTAG), do **not** attempt
  to program via `/dev/fpga0` or the Zynq `DEVCFG` PROG_B path — that
  path is for the Zynq's *own* PL fabric, not an externally-attached
  chip, and driving it against an external FPGA has been observed to
  crash the Zynq PS outright on this board family. The chips are reached
  over JTAG through memory-mapped AXI-JTAG bridge cores (one per chip),
  which is the path any deployment tooling must use, with correct
  handling of multi-SLR devices (VU9P/VU35P are 3-SLR; VU33P is 1-SLR)
  during the JTAG programming sequence.
- **Pool.** Bitcoin Knots BLAKE2b pool support is nascent. The Msg(4)
  grind expectation matches Sia, but the surrounding stratum contract
  (share submission format, target format) must be aligned with whatever
  pool is used.

## Contributing

Open a GitHub issue on this repo for design questions, pin-LOC updates,
Vivado synthesis reports, or Osprey CGI deployment traces. Pull requests
welcome, especially: `build/synth.tcl`, real pin LOCs for the E100,
Zynq-side UART/I²C bridge, and stratum client.

## License

MIT (see [LICENSE](LICENSE)), with attribution to SiaFpgaMiner (MIT 2018,
Pedro Rivera).
