# Vivado build for the Siacoin bitstream (Osprey E100, VU35P).
#
#   vivado -mode batch -source src/sia/synth_sia.tcl -tclargs xcvu35p-fsvh2104-2-e
#
# THE PART ARGUMENT IS NOT OPTIONAL IN PRACTICE. The default below is the plain
# VU35P because that is what this board actually is: its JTAG IDCODE reads
# 0x14b71093, which masks to 4b71093 = VU35P. The CGI's getAllInfo reports
# chipType "vu35p_civ" and believing it once cost a full synthesis run targeting
# the wrong silicon. The IDCODE is authoritative; pass the part explicitly
# anyway so the intent is on the command line.
#
# This is a separate script from build/synth.tcl rather than a mode added to it:
# the two designs share only the vendor primitives and the UART receiver, and a
# single script with two source lists and two top modules is how the wrong list
# gets synthesised under the right name.

set part "xcvu35p-fsvh2104-2-e"
if { $argc >= 1 } { set part [lindex $argv 0] }

set root [file normalize [file dirname [info script]]/../..]
set topmod "OspreySiaUartTop"

puts "INFO: root   = $root"
puts "INFO: part   = $part"
puts "INFO: top    = $topmod"

# Dependency order. Note OspreyBlake2bUartGetWork is REUSED unmodified -- it is
# generic over kRxBytes/kTxBytes, so the 88/17 framing needs no new receiver --
# and clock_mgmt is shared as-is. Nothing from the Knots hash pipeline is here:
# the Sia design has no stage 3.
set srcs [list \
  $root/vendor/sia-fpga/PkgBlake2b.vhd \
  $root/src/sia/PkgOspreySia.vhd \
  $root/vendor/sia-fpga/MixG_FlopPipe_4.vhd \
  $root/vendor/sia-fpga/QuadG.vhd \
  $root/src/sia/OspreySiaCore.vhd \
  $root/src/sia/OspreySiaTop.vhd \
  $root/src/clock_mgmt.vhd \
  $root/src/OspreyBlake2bUartGetWork.vhd \
  $root/src/sia/OspreySiaUartTop.vhd \
]

foreach f $srcs {
  if { ![file exists $f] } { puts "ERROR: missing source $f"; exit 1 }
  read_vhdl -vhdl2008 $f
  puts "INFO: read $f"
}

# Same board, same four pins, same 100 MHz LVDS reference -- so the same
# constraint file. The port names match (clk_p, clk_n, rx, tx) by design.
set xdc $root/constraints/osprey_vu35p_uart.xdc
if { [file exists $xdc] } {
  read_xdc $xdc
  puts "INFO: read $xdc"
} else {
  puts "ERROR: missing $xdc"
  exit 1
}

synth_design -top $topmod -part $part

file mkdir $root/reports
report_utilization    -file $root/reports/sia_utilization_synth.txt
report_timing_summary -file $root/reports/sia_timing_synth.txt
write_checkpoint -force $root/build/sia_post_synth.dcp

opt_design
place_design
phys_opt_design
route_design

report_utilization    -file $root/reports/sia_utilization.txt
report_timing_summary -file $root/reports/sia_timing_summary.txt
report_route_status   -file $root/reports/sia_route_status.txt
write_checkpoint -force $root/build/sia_post_route.dcp

# Fail loudly on negative slack rather than shipping a bitstream that cannot
# meet its own clock. A board that is programmed and silent is far more
# expensive to diagnose than a build that refused to finish.
set wns [get_property SLACK [get_timing_paths -max_paths 1 -nworst 1 -setup]]
set whs [get_property SLACK [get_timing_paths -max_paths 1 -nworst 1 -hold]]
puts "INFO: WNS = $wns ns"
puts "INFO: WHS = $whs ns"
if { $wns < 0 || $whs < 0 } {
  puts "ERROR: timing not met (WNS=$wns WHS=$whs). Not writing bitstream."
  exit 2
}

file mkdir $root/bitstream
write_bitstream -force $root/bitstream/osprey_sia.bit
puts "INFO: bitstream written to $root/bitstream/osprey_sia.bit"
exit 0
