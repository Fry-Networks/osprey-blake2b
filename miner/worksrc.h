/* Pluggable work source.
 *
 * docs/DATUM.md describes this seam and why it is the right one: the miner
 * already had two ways to obtain work -- --synthetic-work builds it locally
 * with no network at all, and the default path fetches it over
 * getblocktemplate -- and both converged on the same contract before handing
 * off to build_work_item(). Stratum slots in as a third source at that same
 * point. What follows is that contract made explicit.
 *
 * The unit of exchange is deliberately the two stage messages and the target,
 * not a knots_header_t. A GBT template really is a Knots header, but a stratum
 * job is not: the pool supplies a merkle branch and an arbitrary transaction,
 * and several header fields (m_flags, m_xor_key, m_mm_rhs, m_height) simply do
 * not appear on the wire. Forcing a job through knots_header_t would mean
 * inventing values for them, and an invented field that later stops being zero
 * is a silent wrong-hash bug. The stage messages are what the FPGA actually
 * consumes, so they are what a source produces.
 *
 * Verification stays with the source for the same reason. GBT owns the
 * network-target rule and the full block it must serialise; stratum owns the
 * share-difficulty rule and mining.submit. Neither belongs in the mining loop.
 */
#ifndef WORKSRC_H
#define WORKSRC_H

#include <stdint.h>

#include "work_item.h"

typedef struct {
    uint8_t  ss3[STAGE3_LEN];   /* 52 B: u32(0) || h2_hash || m_extranonce   */
    uint8_t  ss4[STAGE4_LEN];   /* 80 B: prev_hidden || nonce || ntime || hash_a */
    uint64_t target_top64;      /* what the FPGA prefilters against          */
    int      valid;
} work_ctx_t;

/* on_candidate() return values. */
#define WORKSRC_CAND_BAD      0   /* the reported prefilter word does not reproduce */
#define WORKSRC_CAND_OK       1   /* reproduces, but does not meet the target       */
#define WORKSRC_CAND_SOLUTION 2   /* meets the target; the source has handled it    */

typedef struct worksrc {
    const char *name;

    /* Produce the next work item. Returns 0 on success. A source with nothing
     * to offer yet (a pool that has not sent a job) returns non-zero and is
     * asked again on the next tick -- it must not block. */
    int (*get_work)(work_ctx_t *ctx);

    /* Non-blocking housekeeping, called every pass of the mining loop. NULL if
     * the source has none. `now` is wall-clock seconds. */
    void (*poll)(uint64_t now);

    /* Verify a candidate the FPGA reported and, if it is a solution, act on it.
     * `nonce` is the full 64-bit value already corrected for pipeline latency. */
    int (*on_candidate)(const work_ctx_t *ctx, uint64_t nonce, uint64_t hash_top64);

    /* How often to push fresh work, in seconds. GBT uses 30; a pool source
     * pushes on its own schedule and sets this low so a new job is picked up
     * promptly. */
    unsigned refresh_s;

    /* Wire size of one work item, in bytes. The Knots bitstream takes 168
     * (two stage messages plus the target); the Siacoin bitstream takes 88
     * (the 80-byte header plus the target) because it has no stage 3. The
     * receiver on the FPGA is a free-running mod-N byte counter with no
     * framing, so sending the wrong length does not error -- it permanently
     * rotates every subsequent item. Hence this travels with the source rather
     * than being a constant in the loop. */
    size_t item_len;
} worksrc_t;

/* Pack a context into the wire item the FPGA expects, in the layout that goes
 * with `item_len`:
 *
 *   168 (Knots)  [0..51] ss3 zero-padded to the 80-byte slot boundary,
 *                [80..159] ss4, [160..167] target_top64 little-endian.
 *                Identical to build_work_item().
 *
 *    88 (Siacoin) [0..79] the header (ss4), [80..87] target_top64.
 *                No stage-3 region: that core takes the merkle root straight
 *                from the item instead of hashing it on-chip.
 *
 * Kept here rather than duplicated per source so the two layouts cannot drift.
 * Returns the number of bytes written, or 0 if item_len is not one this
 * function knows -- silently sending a short item would desynchronise the
 * FPGA's byte counter for good. */
size_t worksrc_pack_item(const work_ctx_t *ctx, size_t item_len,
                         uint8_t out[WORK_ITEM_LEN]);

/* Register a source. Sources register themselves during start-up; the registry
 * is static and tiny because there will only ever be a handful. */
void worksrc_register(const worksrc_t *src);

/* Look a source up by name ("gbt", "synthetic", "stratum"). NULL if absent. */
const worksrc_t *worksrc_find(const char *name);

/* Comma-free list of the registered names, for usage text and logs. */
const char *worksrc_list(void);

#endif /* WORKSRC_H */
