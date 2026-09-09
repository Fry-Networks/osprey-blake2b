# OOC timing-only constraint: 250 MHz on Clk (matches clock_mgmt.vhd MMCM output)
create_clock -period 4.000 -name Clk [get_ports Clk]
