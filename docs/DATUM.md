# DATUM — why this miner does not implement it, and where a pool backend would go

**Status: BLOCKER — not implementable as specified.** This is not a deferral for
convenience. Four independent reasons make it structurally impossible here, and
each one alone would be sufficient.

## Why it cannot be built

**1. There is no published protocol specification.** DATUM's own README
describes the gateway↔DATUM-Prime protocol as custom, still evolving, subject to
change without notice, and to be documented elsewhere at some future point. An
implementation would have to be reverse-engineered from a moving target, and any
result would be correct only by accident and only until the next change.

**2. It is the wrong layer.** DATUM is a *miner→pool* protocol. The gateway sits
between hardware and pool, and obtains its block templates from a local Bitcoin
node over **getblocktemplate** — exactly the path this miner already implements.
For solo mining against our own node, DATUM would add a hop that does nothing:
GBT in, GBT out. What solo mining needs is `getblocktemplate` plus `submitblock`,
and both are implemented and proven against the live node.

**3. It is the wrong chain.** DATUM is deployed by OCEAN Pool for mainnet
Bitcoin. This is a BLAKE2b fork with a 164-byte v2 header carrying `m_nonce2`,
`m_nonce3`, a 16-byte extranonce, a time offset, an XOR key and a merge-mining
RHS. OCEAN would not issue work for this chain, and its share validation would
reject our headers as malformed rather than merely losing.

**4. Even where DATUM exists, hardware does not speak it.** Miners attach to a
DATUM gateway over **Stratum v1**. So the integration a miner would actually
need is a Stratum v1 client, not a DATUM client. DATUM is what the *gateway*
speaks upstream, and we are not a gateway.

## Where a Stratum v1 backend would attach

Point (4) is the useful part, so the seam is recorded rather than lost.

`miner.c` already treats work acquisition as a swappable source: `--synthetic-work`
builds work locally with no network at all, and the default path calls
`get_template()` to fetch it over GBT. Both converge on the same contract —
populate a `knots_header_t`, then hand it to `build_work_item()`.

A Stratum backend slots in as a third source at that same seam:

- **Work in.** `mining.notify` carries prevhash, the coinbase split into
  `coinb1`/`coinb2`, the merkle branch, version, nbits and ntime. That maps onto
  `knots_header_t` directly, except that the pool supplies a *merkle branch*
  rather than a root: fold the coinbase txid through the branch instead of
  calling `merkle_root()` over a full transaction list. `coinbase.c` still builds
  the coinbase — the pool dictates its shape, but the assembly is the same.
- **Extranonce.** `mining.subscribe` returns `extranonce1` and an `extranonce2`
  size; `extranonce2` becomes the per-work rolling field. This chain also has a
  16-byte header `m_extranonce`, and the two are **not** interchangeable — a
  pool-supplied extranonce belongs in the coinbase scriptSig, where the pool
  expects to find it.
- **Result out.** `submit_block()` is replaced by `mining.submit`; the pool
  assembles and broadcasts the block, so no full serialization is sent.
- **Difficulty.** `mining.set_difficulty` replaces `--target-shift`. The existing
  `target_top64_from_bits()` already converts a compact target for the FPGA, so
  it needs a share-difficulty entry point rather than a rewrite.

The parts that would be reused unchanged: `work_item.c`, `sha256.c`, `blake2b.c`,
`uio_uart.c`, `bech32.c` and most of `coinbase.c`. The parts that are
GBT-specific and would not carry over: `get_template()`, `merkle_root()` over a
full transaction set, and `block_serialize()`.

## Bearing on pool visibility

This is also the answer to "why does the Osprey not appear on any pool
dashboard". It holds no Stratum connection — its configured pool field points at
our own GBT proxy, not a pool — so there is nothing for a pool to display. That
is solo mining working as designed, not a fault. Appearing on a pool is a
different feature, and it is the feature described above.

## Sources

- OCEAN-xyz/datum_gateway — <https://github.com/OCEAN-xyz/datum_gateway>
- DATUM protocol overview — <https://d-central.tech/datum-protocol/>
