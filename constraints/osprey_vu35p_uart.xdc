#-----------------------------------------------------------------------------
# Osprey (plain VU35P) — constraints for OspreyBlake2bUartTop
#
# Part: xcvu35p-fsvh2104-2-e
#
# Pin assignments now come from the vendor's NON-CIV board file:
#   PachiraMining/E300_development  hardware/constrain_e300_vu35p_non_CIV.xdc
# This file previously followed ..._vu35p_civ.xdc because the firmware reports
# chipType "vu35p_civ" -- but that is settable metadata, not a probe, and the
# board's JTAG IDCODE (0x14b71093 -> part field 4b71093) is plain VU35P per the
# vendor loader's own table.
#
# Signals used here (the vendor's whole external interface is rx, tx and four
# differential clocks -- there is no reset pin):
#   clk_p / clk_n   BB18 / BC18   LVDS 100 MHz (the vendor's clk2), DIFF_TERM
#   rx              C12           LVCMOS18
#   tx              B9            LVCMOS18
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
set_property DIFF_TERM TRUE [get_ports clk_p]
set_property DIFF_TERM TRUE [get_ports clk_n]

create_clock -period 10.000 -name clk_p [get_ports clk_p]

# --- UART to/from the zynq ----------------------------------------------------
# LVCMOS18, not LVCMOS12. The vendor file is explicit about this and these pins
# sit in a 1.8V bank; driving tx as a 1.2V output leaves it below what the zynq
# receiver reliably reads as a high, which is one of the two reasons this board
# accepted work and answered with silence.
set_property PACKAGE_PIN C12 [get_ports rx]
set_property IOSTANDARD LVCMOS18 [get_ports rx]
set_property PACKAGE_PIN B9 [get_ports tx]
set_property IOSTANDARD LVCMOS18 [get_ports tx]

# --- No reset pin -------------------------------------------------------------
# There was a resetn here on BE17, "active low, driven by the zynq". The vendor's
# board file has no reset port at all, so BE17 was a guess; if that ball is not
# actually driven high, the inverted input holds the MMCM and the entire pipeline
# in reset forever. The design now releases on the MMCM's own Locked output --
# see OspreyBlake2bUartTop.vhd.

# --- Asynchronous / slow paths ------------------------------------------------
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
