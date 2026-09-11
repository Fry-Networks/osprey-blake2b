# Osprey BLAKE2b miner.
#
# The Zynq is 32-bit ARM armhf (loader ELF: EI_CLASS=1, e_machine=0x28,
# interpreter /lib/ld-linux-armhf.so.3), so the cross target is
# arm-linux-gnueabihf and the binary is linked -static — the device's Ubuntu
# 16.04 userspace is old and we do not want to depend on its libc.
#
#   make            -> blake2b       (ARM, static, for the Osprey)
#   make host       -> blake2b_host  (native, for offline validation)
#   make golden     -> emit the 168-byte work item for cross-checking vs Python

CROSS   ?= arm-linux-gnueabihf-
CC      := $(CROSS)gcc
HOSTCC  ?= gcc
CFLAGS  := -O2 -Wall -Wextra -std=c11 -pthread
LDFLAGS := -static -pthread

SRC := miner.c work_item.c sha256.c blake2b.c uio_uart.c \
       bech32.c coinbase.c merkle.c block.c devfee.c selftest_block.c \
       dns.c stratum.c sia_stratum.c worksrc.c worksrc_stratum.c \
       selftest_stratum.c
HDR := work_item.h sha256.h blake2b.h uio_uart.h \
       bech32.h coinbase.h merkle.h block.h devfee.h \
       dns.h stratum.h sia_stratum.h worksrc.h worksrc_stratum.h

all: blake2b siacoin

blake2b: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)
	@file $@

# Same sources, same mining loop, different default chain. The two chains share
# the Sia stratum transport and differ only in the work-item layout (168 vs 88
# bytes) and the compare rule (H[3] vs H[0]) -- so one code path with a compiled
# default is far safer than a forked miner, where a fix to one would quietly
# not reach the other. --algo overrides at runtime either way.
siacoin: $(SRC) $(HDR)
	$(CC) $(CFLAGS) -DOSPREY_DEFAULT_ALGO_SIA -o $@ $(SRC) $(LDFLAGS)
	@file $@

siacoin_host: $(SRC) $(HDR)
	$(HOSTCC) $(CFLAGS) -DOSPREY_DEFAULT_ALGO_SIA -o $@ $(SRC) -pthread

host: blake2b_host

blake2b_host: $(SRC) $(HDR)
	$(HOSTCC) $(CFLAGS) -o $@ $(SRC) -pthread

# Offline cross-check: this must byte-match
#   py -3 ../zynq/build_work_item.py --selftest
golden: blake2b_host
	./blake2b_host --selftest vectors

clean:
	rm -f blake2b blake2b_host siacoin siacoin_host

.PHONY: all host golden clean
