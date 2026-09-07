# =============================================================================
# osprey_vu35p.xdc  --  Constraints for the Osprey E100 (VU35P) Blake2b bitstream
# =============================================================================
# Target part      : xcvu35p-fsvh2104-2-e  (Virtex UltraScale+ / FSVH2104 / -2)
# Board            : Osprey E100 (chip vu35p_civ per prior recon)
# Top entity       : OspreyBlake2bTop
# MiningClk target : 250 MHz (via clock_mgmt / MMCME4_ADV; see src/clock_mgmt.vhd)
#
# =============================================================================
# HAZARD: every LOC below is marked ASSUMED_PIN or TODO_PIN.
# =============================================================================
# We do NOT have the Osprey E100 schematic in this session, so pin assignments
# are placeholders. THIS FILE WILL NOT PRODUCE A WORKING BITSTREAM AS-IS.
# Before real synthesis + bring-up, an operator with the E100 schematic must:
#   1. Replace every ASSUMED_PIN / TODO_PIN LOC with the physical package pin.
#   2. Verify IOSTANDARD matches the bank IO voltage on the physical board.
#   3. Verify the MiningClk input pin is on a global-clock-capable I/O.
#   4. Uncomment / add any board-level bank voltage or DRIVE strength constraints.
# See the "OUT-OF-SCOPE-DISCOVERED — PIN TODO CHECKLIST" section at the bottom.
# =============================================================================

# -----------------------------------------------------------------------------
# Primary clock input (100 MHz assumed).
# -----------------------------------------------------------------------------
set_property PACKAGE_PIN AA1 [get_ports Clk]                      ;# ASSUMED_PIN - replace with Osprey E100 main clock pin
set_property IOSTANDARD LVDS [get_ports Clk]                      ;# ASSUMED_IOSTD - LVDS if differential, LVCMOS18 if single-ended
create_clock -name sys_clk -period 10.000 [get_ports Clk]         ;# 100 MHz board oscillator feeds MMCME4_ADV
# Note: 250 MHz MiningClk is derived by clock_mgmt.vhd and auto-inferred from CLKOUT0_DIVIDE_F.

# -----------------------------------------------------------------------------
# Control ports
# -----------------------------------------------------------------------------
set_property PACKAGE_PIN AA2 [get_ports Enable]                   ;# TODO_PIN
set_property IOSTANDARD LVCMOS18 [get_ports Enable]

set_property PACKAGE_PIN AA3 [get_ports Success]                  ;# TODO_PIN
set_property IOSTANDARD LVCMOS18 [get_ports Success]

# -----------------------------------------------------------------------------
# Stage3In[0..9] : 10 x 64-bit slots (640 wires) - from zynq
# -----------------------------------------------------------------------------
# Full pin list omitted for readability; enumerate all 640 as TODO_PIN below.
# The pattern is the same as Stage4In. IOSTANDARD LVCMOS18 default.
# TODO_PIN: place_property PACKAGE_PIN <pin> [get_ports {Stage3In[i][j]}] for i in 0..9, j in 0..63
set_property IOSTANDARD LVCMOS18 [get_ports {Stage3In[*][*]}]     ;# TODO_PIN - individual LOCs required
set_property IOSTANDARD LVCMOS18 [get_ports {Stage4In[*][*]}]     ;# TODO_PIN - individual LOCs required

# -----------------------------------------------------------------------------
# TargetTop64 : 64-bit shifted-target input from zynq
# -----------------------------------------------------------------------------
set_property IOSTANDARD LVCMOS18 [get_ports {TargetTop64[*]}]     ;# TODO_PIN

# -----------------------------------------------------------------------------
# Result outputs to zynq
# -----------------------------------------------------------------------------
set_property IOSTANDARD LVCMOS18 [get_ports {Nonce[*]}]           ;# TODO_PIN
set_property IOSTANDARD LVCMOS18 [get_ports {HashTop64[*]}]       ;# TODO_PIN

# -----------------------------------------------------------------------------
# Timing exceptions
# -----------------------------------------------------------------------------
# Success is a strobe consumed by an asynchronous zynq handshake process; skip
# static timing checks on the launch flop -> zynq path.
set_false_path -to [get_ports Success]
# Same for the Nonce + HashTop64 latched-on-Success outputs (zynq only samples
# them after Success asserts and has its own synchronizer).
set_false_path -to [get_ports {Nonce[*]}]
set_false_path -to [get_ports {HashTop64[*]}]
# Enable is a slow-changing async input.
set_false_path -from [get_ports Enable]

# -----------------------------------------------------------------------------
# Configuration bank / bitstream options (conservative defaults - verify per board)
# -----------------------------------------------------------------------------
set_property BITSTREAM.CONFIG.SPI_BUSWIDTH  4 [current_design]    ;# ASSUMED - E100 boot flash width
set_property CONFIG_MODE SPIx4 [current_design]                   ;# ASSUMED
set_property BITSTREAM.CONFIG.CONFIGRATE 33  [current_design]     ;# 33 MHz conservative

# =============================================================================
# OUT-OF-SCOPE-DISCOVERED - PIN TODO CHECKLIST
# =============================================================================
# The following items MUST be resolved before real hardware bring-up.
# Each is BLOCKER for synthesis-that-programs-real-silicon, but is OUT-OF-SCOPE
# for this OSS release (we lack the Osprey E100 schematic).
#
#   [ ] Clk (100 MHz clock input) - physical package pin + IOSTANDARD (LVDS vs LVCMOS)
#   [ ] Enable                    - control input pin, sync group
#   [ ] Success                   - status output pin, drive strength
#   [ ] Stage3In[0..9][0..63]     - 640 data pins (may map to a parallel bus or serialized via UART)
#   [ ] Stage4In[0..9][0..63]     - 640 data pins (may map to same bus as Stage3In)
#   [ ] TargetTop64[0..63]        - 64 data pins
#   [ ] Nonce[0..63]              - 64 result pins
#   [ ] HashTop64[0..63]          - 64 result pins
#   [ ] Bank voltage assignments  - each IO bank on VU35P has its own VCCO
#   [ ] SPI boot flash pins       - if custom, override BITSTREAM.CONFIG defaults
#   [ ] JTAG chain constraints    - if multi-device chain
#
# The 1408 total I/Os likely EXCEED the physical pin count of any real Osprey
# E100 IO interface, which strongly implies the zynq<->FPGA bus is SERIALIZED
# (e.g. via UART, SPI, or a parallel bus < 64 bits wide). This suggests a
# wrapper entity (OspreyBlake2bUartTop.vhd, referenced in OspreyBlake2bTop.vhd
# header) will serialize/deserialize before the physical IO layer. That
# wrapper - and the corresponding constraints - are OUT-OF-SCOPE for the current
# session (see fixlog).
# =============================================================================
