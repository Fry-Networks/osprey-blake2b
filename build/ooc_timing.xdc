# OOC timing-only constraint: 222.222 MHz on Clk (matches clock_mgmt.vhd's shipped
# CLKOUT0_DIVIDE_F => 4.500, VCO 1000 MHz / 4.5)
create_clock -period 4.500 -name Clk [get_ports Clk]
