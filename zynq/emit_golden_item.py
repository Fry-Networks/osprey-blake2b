#!/usr/bin/env python3
"""Emit the canonical 168-byte work item as hex, for diffing against
`miner/blake2b_host --dump-item`.

Same fixture the C side hardcodes: default header fields, nBits=0x1903c2d4,
m_height=969859. The two implementations must agree byte for byte -- the C
miner's framing is a port of build_work_item.py, and a silent divergence would
desync every work item the FPGA is ever handed.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from blake2b_reference import KnotsBlockHeaderV2  # noqa: E402
from build_work_item import build_work_item  # noqa: E402


def main() -> int:
    h = KnotsBlockHeaderV2()
    h.nBits = 0x1903C2D4
    h.m_height = 969859
    # build_work_item(hdr, shift=22): the second argument is the TARGET SHIFT,
    # not a target value. Passing a computed 256-bit target here shifts the
    # target to zero and silently produces an item whose TargetTop64 is all
    # zeroes -- a work item the FPGA can never satisfy.
    item = build_work_item(h)
    if len(item) != 168:
        print(f"ERROR: expected 168 bytes, got {len(item)}", file=sys.stderr)
        return 1
    print(item.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
