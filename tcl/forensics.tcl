# R0 -- read the routed checkpoint we already have, and answer one question:
# is the +0.123 ns worst path an OUTLIER, or is the near-critical population a
# wall? Every timing decision so far rests on a single data point, because
# build/synth.tcl calls bare report_timing_summary, which prints one path per
# group. This costs no build time and changes nothing on disk in the design.
#
#   vivado -mode batch -source tcl/forensics.tcl
#
# Writes reports/fx_*.txt. Does not modify the checkpoint.

set root [file normalize [file dirname [info script]]/..]
set_param general.maxThreads 8
puts "INFO: maxThreads now [get_param general.maxThreads]"

open_checkpoint $root/build/post_route.dcp

file mkdir $root/reports

# The decision input: the slack distribution of the worst 500 setup paths.
report_timing -setup -max_paths 500 -nworst 500 -path_type summary \
              -file $root/reports/fx_setup_top500.txt

# Full detail on the worst few, so the limiting structure is nameable.
report_timing -setup -max_paths 10 -nworst 1 -input_pins \
              -file $root/reports/fx_setup_top10_full.txt

# Hold, same treatment -- WHS is +0.009 and every setup fix risks it.
report_timing -hold -max_paths 200 -nworst 200 -path_type summary \
              -file $root/reports/fx_hold_top200.txt

# How much of the near-critical population crosses an SLR?
set np [get_timing_paths -setup -max_paths 2000 -nworst 2000 -slack_lesser_than 0.60]
puts "INFO: paths with slack < 0.60 ns : [llength $np]"
set np30 [get_timing_paths -setup -max_paths 2000 -nworst 2000 -slack_lesser_than 0.30]
puts "INFO: paths with slack < 0.30 ns : [llength $np30]"
set np20 [get_timing_paths -setup -max_paths 2000 -nworst 2000 -slack_lesser_than 0.20]
puts "INFO: paths with slack < 0.20 ns : [llength $np20]"

# Laguna usage. utilization.txt section 12 reported 1,996 SLR crossings with
# "Using Both TX_REG and RX_REG: 0" -- every crossing an unregistered wire.
report_utilization -slr -file $root/reports/fx_util_slr.txt

exit 0
