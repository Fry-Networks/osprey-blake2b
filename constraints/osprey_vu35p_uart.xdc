#-----------------------------------------------------------------------------
# Osprey (VU35P CIV) — constraints for OspreyBlake2bUartTop
#
# Part: xcvu35p_CIV-fsvh2104-2-e
#
# Pin assignments are taken from the vendor's own board constraint file:
#   PachiraMining/E300_development  hardware/constrain_e300_vu35p_civ.xdc
# which targets this exact part number. The Osprey firmware reports
# chipType "vu35p_civ" via its getAllInfo CGI endpoint, matching that file.
#
# Signals used here (subset of the vendor pinout):
#   clk_p / clk_n   BB18 / BC18   LVDS 100 MHz reference, DIFF_TERM_ADV TERM_100
#   rx              C12           LVCMOS12
#   tx              B9            LVCMOS12
#   resetn          BE17          LVCMOS18, active low, driven by the zynq
#
# The vendor design declares its hash clock at period 4.000 ns (250 MHz); this
# design generates the same rate from the 100 MHz reference via MMCME4_ADV in
# clock_mgmt.vhd.
#
# Unused vendor pins, kept here as a record for later work:
#   i2c_sda AY27, i2c_scl AY26 (LVCMOS18)   — board management
#   refclk_1_p/n BD23/BD24, refclk_3_p/n F13/F12, refclk_4_p/n BC32/BC33
#-----------------------------------------------------------------------------

set_property CONFIG_VOLTAGE 1.8 [current_design]

# --- 100 MHz differential reference clock ------------------------------------
set_property PACKAGE_PIN BB18 [get_ports clk_p]
set_property PACKAGE_PIN BC18 [get_ports clk_n]
set_property IOSTANDARD LVDS [get_ports clk_p]
set_property IOSTANDARD LVDS [get_ports clk_n]
set_property DIFF_TERM_ADV TERM_100 [get_ports clk_p]
set_property DIFF_TERM_ADV TERM_100 [get_ports clk_n]

create_clock -period 10.000 -name clk_p [get_ports clk_p]

# --- UART to/from the zynq ----------------------------------------------------
set_property PACKAGE_PIN C12 [get_ports rx]
set_property IOSTANDARD LVCMOS12 [get_ports rx]
set_property PACKAGE_PIN B9 [get_ports tx]
set_property IOSTANDARD LVCMOS12 [get_ports tx]

# --- Reset (active low, external) --------------------------------------------
set_property PACKAGE_PIN BE17 [get_ports resetn]
set_property IOSTANDARD LVCMOS18 [get_ports resetn]

# --- Asynchronous / slow paths ------------------------------------------------
# resetn is async; double-flopped inside clock_mgmt and the UART.
set_false_path -from [get_ports resetn]

# rx is asynchronous serial, double-flopped in OspreyBlake2bUartGetWork.
set_false_path -from [get_ports rx]

# tx changes at baud rate, far slower than MiningClk.
set_false_path -to [get_ports tx]

# --- Bitstream configuration ---------------------------------------------------
# CONFIGRATE must be one of Vivado's legal enum values (2.7 .. 127.5).
set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 4 [current_design]
set_property BITSTREAM.CONFIG.CONFIGRATE 51.0 [current_design]
set_property CONFIG_MODE SPIx4 [current_design]

# Vendor file notes this shrinks the bitstream; harmless and speeds config.
set_property BITSTREAM.GENERAL.COMPRESS True [current_design]
