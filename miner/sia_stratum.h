/* Sia-dialect stratum job -> Osprey stage messages.
 *
 * Pure functions, no sockets and no globals, so selftest_stratum.c can drive
 * them with captured pool data and compare against zynq/sia_reference.py.
 *
 * The mapping this file implements is the whole reason a Knots pool can talk
 * Sia stratum, and it is exact rather than approximate:
 *
 *     0x00 || arbtx                          ==  ss3  (52 bytes)
 *     prevhash || nonce || ntime || root     ==  ss4  (80 bytes)
 *
 * where arbtx = coinb1 || extranonce1 || extranonce2 || coinb2. Line them up
 * against stage_inputs() in work_item.c and every field coincides:
 *
 *     ss3[0..3]   u32(0)            <- 0x00 prefix + coinb1[0..2]
 *     ss3[4..35]  h2_hash           <- coinb1[3..34]
 *     ss3[36..51] m_extranonce      <- coinb1[35..] || extranonce1 || extranonce2
 *     ss4[0..31]  prev_hidden       <- prevhash (first 6 bytes zero, as the
 *                                     tagged hash is masked before it ships)
 *     ss4[32..39] nNonce||m_nonce2  <- the 64-bit nonce slot
 *     ss4[40..47] m_time_offset||m_nonce3 <- ntime (both zero on this chain)
 *     ss4[48..79] hash_a            <- the merkle root
 *
 * The 52-byte total is not a coincidence to be checked loosely: the FPGA's
 * stage-3 length is baked into the bitstream as kStage3MsgLen, so an arbtx of
 * any other size cannot be mined by this hardware at all. build_stages()
 * therefore rejects rather than truncates.
 */
#ifndef SIA_STRATUM_H
#define SIA_STRATUM_H

#include <stddef.h>
#include <stdint.h>

#include "stratum.h"
#include "work_item.h"

/* arbtx = coinb1 || extranonce1 || extranonce2 || coinb2. Returns 0 on success. */
int sia_arbtx(const stratum_job_t *j,
              const uint8_t *en1, size_t en1_len,
              const uint8_t *en2, size_t en2_len,
              uint8_t *out, size_t maxlen, size_t *outlen);

/* leaf = blake2b(0x00 || arbtx). The null-byte prefix is the Sia leaf tag. */
void sia_arbtx_leaf(const uint8_t *arbtx, size_t len, uint8_t leaf[32]);

/* Fold the branch: acc = blake2b(0x01 || branch || acc), starting from the
 * arbitrary transaction's hash. Note the arbitrary tx is the RIGHTMOST leaf,
 * which is why the accumulator goes on the right of each concatenation. */
void sia_merkle_root(const stratum_job_t *j, const uint8_t leaf[32], uint8_t root[32]);

/* Whole decode. Fills ss3, ss4 (nonce slot zeroed) and the merkle root.
 * Returns 0 on success, -1 if the arbitrary transaction is not exactly 51
 * bytes (so that 0x00||arbtx is the 52 the FPGA's stage 3 requires). */
int sia_build_stages(const stratum_job_t *j,
                     const uint8_t *en1, size_t en1_len,
                     const uint8_t *en2, size_t en2_len,
                     uint8_t ss3[STAGE3_LEN], uint8_t ss4[STAGE4_LEN],
                     uint8_t merkleroot[32]);

/* The word the FPGA prefilter reports: byte-reversed digest word H[3], i.e.
 * digest[24..31] read big-endian. Not H[0] -- see the comment block at the top
 * of miner.c, and zynq/check_stage4_pairs.py, which exists to catch exactly
 * that confusion. */
uint64_t sia_expected_top64(const uint8_t ss4[STAGE4_LEN], uint64_t nonce);

/* The full 256-bit compare value for a nonce: blake2b(ss4) byte-reversed, so
 * out[0] is the most significant byte and hash_meets_target() applies. */
void sia_pow_compare(const uint8_t ss4[STAGE4_LEN], uint64_t nonce, uint8_t out[32]);

/* ------------------------------------------------------- Siacoin proper ----
 *
 * Everything above speaks the Sia stratum TRANSPORT while obeying Bitcoin's
 * COMPARE, because the pool the device is configured for serves Knots work over
 * the Sia dialect. The three functions below are for the other case -- mining
 * actual Siacoin -- and they differ in exactly two ways:
 *
 *   1. The compare rule. Siacoin compares the digest as emitted, so its leading
 *      zeros are in digest[0..7] and the prefilter word is byteswap(H[0]).
 *      Knots reverses the digest first, making the word H[3]. Same pipeline,
 *      same framing, uncorrelated values -- see src/sia/OspreySiaCore.vhd.
 *
 *   2. No 52-byte constraint. The Siacoin bitstream has no stage 3: its merkle
 *      root arrives from the pool already folded and is used as supplied. So the
 *      arbitrary transaction may be any length, and a merkle branch is fine --
 *      both of which the Knots path must refuse.
 */

/* Build only the 80-byte header (nonce slot zeroed). No length constraint,
 * branches folded normally. Returns 0 on success. */
int sia_build_header(const stratum_job_t *j,
                     const uint8_t *en1, size_t en1_len,
                     const uint8_t *en2, size_t en2_len,
                     uint8_t header[STAGE4_LEN], uint8_t merkleroot[32]);

/* Siacoin's prefilter word: byteswap(H[0]), i.e. digest[0..7] big-endian. */
uint64_t sia_chain_expected_top64(const uint8_t header[STAGE4_LEN], uint64_t nonce);

/* Siacoin's full compare value: the digest as emitted, out[0] most significant,
 * so hash_meets_target() applies directly. */
void sia_chain_pow_compare(const uint8_t header[STAGE4_LEN], uint64_t nonce,
                           uint8_t out[32]);

#endif /* SIA_STRATUM_H */
