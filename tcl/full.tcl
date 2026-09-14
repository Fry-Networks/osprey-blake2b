# R1 -- full flow with the broadcast trunk, implementation directives and a
# post-route phys_opt_design pass. Exploration rung: NO bitstream.
#
# build/synth.tcl is left byte-identical so the shipped flow stays reproducible;
# this is a sibling that adds what R0 showed was missing. build/synth.tcl calls
# opt_design / place_design / phys_opt_design / route_design bare -- no
# -directive anywhere in the repo -- and has no post-route phys_opt at all.
#
#   vivado -mode batch -source tcl/full.tcl -tclargs full xcvu35p-fsvh2104-2-e
#
# NOTE the part: build/synth.tcl defaults to the _CIV variant, which this board
# is not (JTAG IDCODE reads 0x14b71093 = plain VU35P). Always pass it.

set mode "full"
set part "xcvu35p-fsvh2104-2-e"
if { $argc >= 1 } { set mode [lindex $argv 0] }
if { $argc >= 2 } { set part [lindex $argv 1] }

set root [file normalize [file dirname [info script]]/..]
set_param general.maxThreads 8
puts "INFO: maxThreads = [get_param general.maxThreads]"
puts "INFO: root=$root mode=$mode part=$part"

file mkdir $root/reports
file mkdir $root/build

foreach f [list \
  $root/vendor/sia-fpga/PkgBlake2b.vhd \
  $root/src/PkgOspreyBlake2b.vhd \
  $root/vendor/sia-fpga/MixG_FlopPipe_4.vhd \
  $root/vendor/sia-fpga/QuadG.vhd \
  $root/src/OspreyBlake2bStage3Core.vhd \
  $root/src/OspreyBlake2bStage4Core.vhd \
  $root/src/OspreyBlake2bTop.vhd \
  $root/src/clock_mgmt.vhd \
  $root/src/OspreyBlake2bUartGetWork.vhd \
  $root/src/OspreyBlake2bUartTop.vhd ] {
  if { ![file exists $f] } { puts "ERROR: missing source $f"; exit 1 }
  read_vhdl -vhdl2008 $f
}
read_xdc $root/constraints/osprey_vu35p_uart.xdc

synth_design -top OspreyBlake2bUartTop -part $part
report_utilization    -file $root/reports/r1_utilization_synth.txt
report_timing_summary -max_paths 10 -file $root/reports/r1_timing_synth.txt
write_checkpoint -force $root/build/r1_post_synth.dcp
puts "INFO: synthesis done"

# --- implementation, with directives R0 showed the flow has never used --------
# The critical population is 98% routing with zero logic levels, so the levers
# that matter are placement spread and router effort. SSI_SpreadSLLs allocates
# extra area for regions of high connectivity, which is exactly the broadcast
# trunk. Deliberately NOT HigherDelayCost or NoTimingRelaxation: at ~75% CLB
# both bias the router away from congestion relief and away from leaving room
# for the hold detours this design needs (344,064 zero-logic FF->FF copies).
opt_design      -directive Explore
place_design    -directive SSI_SpreadSLLs
phys_opt_design -directive AggressiveExplore
route_design    -directive AggressiveExplore

proc wns_whs {} {
  list [get_property SLACK [get_timing_paths -max_paths 1 -nworst 1 -setup]] \
       [get_property SLACK [get_timing_paths -max_paths 1 -nworst 1 -hold]]
}
lassign [wns_whs] w0 h0
puts "INFO: post-route baseline WNS=$w0 WHS=$h0"

# Post-route phys_opt, which the shipped flow does not run at all. Checkpointed
# and rolled back per pass: it is hold-aware but not hold-infallible, and WHS is
# only +0.009 ns, so a shortened net on a zero-logic copy goes negative at once.
for {set i 1} {$i <= 3} {incr i} {
  write_checkpoint -force $root/build/r1_pre_pro_$i.dcp
  phys_opt_design -directive Explore
  lassign [wns_whs] w h
  puts "INFO: post-route phys_opt pass $i: WNS=$w WHS=$h"
  if { $h < 0.005 } {
    puts "WARN: pass $i regressed WHS to $h (floor 0.005). Reverting, stopping."
    close_design
    open_checkpoint $root/build/r1_pre_pro_$i.dcp
    break
  }
  if { $w - $w0 < 0.010 } { puts "INFO: pass $i gained <10 ps. Stopping."; break }
  set w0 $w
}

report_utilization     -slr  -file $root/reports/r1_utilization.txt
report_timing_summary  -max_paths 20 -file $root/reports/r1_timing_summary.txt
report_route_status          -file $root/reports/r1_route_status.txt
report_design_analysis -congestion -file $root/reports/r1_congestion.txt
report_timing -setup -max_paths 500 -nworst 500 -path_type summary \
              -file $root/reports/r1_setup_top500.txt
write_checkpoint -force $root/build/r1_post_route.dcp

lassign [wns_whs] wns whs
puts "INFO: R1 FINAL WNS = $wns ns"
puts "INFO: R1 FINAL WHS = $whs ns"
puts "INFO: R1 exploration rung complete -- no bitstream written by design"
exit 0
