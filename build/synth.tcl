#-----------------------------------------------------------------------------
# Osprey E100 (VU35P) BLAKE2b mining pipeline — Vivado batch synthesis
#
# Target: xcvu35p_CIV-fsvh2104-2-e
#   The Osprey firmware reports chipType "vu35p_civ" via the getAllInfo CGI
#   endpoint. The vendor's own board file
#   (PachiraMining/E300_development hardware/constrain_e300_vu35p_civ.xdc)
#   names this exact part in its header, which confirms the package and speed
#   grade. Override with -tclargs to try an alternate.
#
# Two modes:
#   ooc   (default) out-of-context synthesis. No IO buffers, no pin constraints.
#                   Produces real utilization + timing for the mining core.
#   full            full flow through write_bitstream, on the chip-level wrapper.
#
# IO NOTE: OspreyBlake2bTop exposes Stage3In/Stage4In as 10x64-bit arrays plus
# TargetTop64/Nonce/HashTop64, which synthesises to 1155 bonded IOB against the
# 416 the fsvh2104 package provides (277% over). That is a core boundary, not a
# chip boundary. OspreyBlake2bUartTop serialises it onto the board UART and is
# what the full flow implements; chip IO is then 5 pins.
#
# Usage:
#   vivado -mode batch -source build/synth.tcl
#   vivado -mode batch -source build/synth.tcl -tclargs full
#   vivado -mode batch -source build/synth.tcl -tclargs ooc xcvu35p_CIV-fsvh2892-2-e
#-----------------------------------------------------------------------------

set mode "ooc"
set part "xcvu35p_CIV-fsvh2104-2-e"
if { $argc >= 1 } { set mode [lindex $argv 0] }
if { $argc >= 2 } { set part [lindex $argv 1] }

# ooc  -> synthesise the mining core (OspreyBlake2bTop) out of context
# full -> synthesise + implement the chip-level UART wrapper (OspreyBlake2bUartTop),
#         which serialises the core's 1155-IOB parallel interface down to 6 pins.
if { $mode eq "full" } {
  set topmod "OspreyBlake2bUartTop"
} else {
  set topmod "OspreyBlake2bTop"
}

set root [file normalize [file dirname [info script]]/..]
puts "INFO: root = $root"
puts "INFO: mode = $mode"
puts "INFO: part = $part"
puts "INFO: top  = $topmod"

file mkdir $root/reports
file mkdir $root/bitstream
file mkdir $root/build

# --- sources, in dependency order -------------------------------------------
set srcs [list \
  $root/vendor/sia-fpga/PkgBlake2b.vhd \
  $root/src/PkgOspreyBlake2b.vhd \
  $root/vendor/sia-fpga/MixG_FlopPipe_4.vhd \
  $root/vendor/sia-fpga/QuadG.vhd \
  $root/src/OspreyBlake2bStage3Core.vhd \
  $root/src/OspreyBlake2bStage4Core.vhd \
  $root/src/OspreyBlake2bTop.vhd \
]

foreach f $srcs {
  if { ![file exists $f] } { puts "ERROR: missing source $f"; exit 1 }
  read_vhdl -vhdl2008 $f
  puts "INFO: read $f"
}

# clock_mgmt.vhd instantiates MMCME4_ADV from UNISIM. It is only needed for the
# full flow (OOC synthesis of the core does not use it).
if { $mode eq "full" } {
  foreach extra [list     $root/src/clock_mgmt.vhd     $root/src/OspreyBlake2bUartGetWork.vhd     $root/src/OspreyBlake2bUartTop.vhd   ] {
    if { ![file exists $extra] } { puts "ERROR: missing source $extra"; exit 1 }
    read_vhdl -vhdl2008 $extra
    puts "INFO: read $extra"
  }
}

# --- constraints -------------------------------------------------------------
# The full flow reads the board constraint file (real pin LOCs from the vendor
# E300 file). Pin LOCs are meaningless out of context, so OOC instead gets a
# generated timing-only constraint.
if { $mode eq "full" } {
  set xdc $root/constraints/osprey_vu35p_uart.xdc
  if { [file exists $xdc] } { read_xdc $xdc; puts "INFO: read $xdc" }   else { puts "ERROR: missing $xdc"; exit 1 }
} else {
  set oocxdc $root/build/ooc_timing.xdc
  set fh [open $oocxdc w]
  puts $fh "# OOC timing-only constraint: 250 MHz on Clk (matches clock_mgmt.vhd MMCM output)"
  puts $fh "create_clock -period 4.000 -name Clk \[get_ports Clk\]"
  close $fh
  read_xdc $oocxdc
  puts "INFO: wrote + read $oocxdc"
}

# --- synthesis ---------------------------------------------------------------
if { $mode eq "full" } {
  synth_design -top $topmod -part $part
} else {
  synth_design -top $topmod -part $part -mode out_of_context
}

report_utilization -file $root/reports/utilization_synth.txt
report_timing_summary -file $root/reports/timing_synth.txt
write_checkpoint -force $root/build/post_synth.dcp
puts "INFO: post-synth checkpoint written"

# Surface headline synth numbers in the log
puts "INFO: post-synth utilization: [report_utilization -return_string -quiet]"
puts "INFO: synthesis complete"

if { $mode ne "full" } {
  puts "INFO: OOC mode — stopping before implementation (no IO buffers, no bitstream)."
  puts "INFO: reports/utilization_synth.txt and reports/timing_synth.txt are the deliverables."
  exit 0
}

# --- implementation ----------------------------------------------------------
opt_design
place_design
phys_opt_design
route_design

report_utilization        -file $root/reports/utilization.txt
report_timing_summary     -file $root/reports/timing_summary.txt
report_route_status       -file $root/reports/route_status.txt
write_checkpoint -force   $root/build/post_route.dcp

# Fail loudly on negative slack rather than shipping a broken bitstream
set wns [get_property SLACK [get_timing_paths -max_paths 1 -nworst 1 -setup]]
set whs [get_property SLACK [get_timing_paths -max_paths 1 -nworst 1 -hold]]
puts "INFO: WNS = $wns ns"
puts "INFO: WHS = $whs ns"
if { $wns < 0 || $whs < 0 } {
  puts "ERROR: timing not met (WNS=$wns WHS=$whs). Not writing bitstream."
  exit 2
}

write_bitstream -force $root/bitstream/osprey_blake2b.bit
puts "INFO: bitstream written to $root/bitstream/osprey_blake2b.bit"
exit 0
