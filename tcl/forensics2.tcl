# R0b -- the number that decides the clock ceiling.
#
# R0 showed all 244 near-critical paths are one of three structures, and all
# three are the per-core DISTRIBUTION network (work broadcast, enable fanout,
# target fanout), not the BLAKE2b math. Post-synthesis WNS is +2.055 ns, so the
# logic itself is good for ~409 MHz.
#
# So the real ceiling is set by the worst path that is NOT distribution: once
# the trunk retires A/B/C, that is what is left. Pull a deep sample and classify.

set root [file normalize [file dirname [info script]]/..]
set_param general.maxThreads 8
open_checkpoint $root/build/post_route.dcp

report_timing -setup -max_paths 6000 -nworst 6000 -path_type summary \
              -file $root/reports/fx_setup_top6000.txt

# Ask the tool directly for the worst path that starts inside a mixer, i.e. the
# BLAKE2b pipeline's own limit rather than the distribution network's.
set mix [get_pins -quiet -hier -filter {NAME =~ *U_Stage4/RoundGen*Mixer*/C}]
puts "INFO: mixer launch pins found: [llength $mix]"
if {[llength $mix] > 0} {
    report_timing -setup -from $mix -max_paths 20 -nworst 20 -path_type summary \
                  -file $root/reports/fx_mixer_worst.txt
    set mp [get_timing_paths -setup -from $mix -max_paths 1 -nworst 1]
    if {[llength $mp] > 0} {
        puts "INFO: WORST MIXER-LAUNCHED SETUP SLACK = [get_property SLACK $mp] ns"
    }
}

# And the worst path that does NOT start at any of the three distribution regs.
set dist [get_pins -quiet -hier -filter {NAME =~ *WorkDataHeld_reg*/C || NAME =~ *EnReg_reg/C || NAME =~ *TgtReg_reg*/C}]
puts "INFO: distribution launch pins: [llength $dist]"

exit 0
