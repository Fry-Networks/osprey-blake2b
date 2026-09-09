/* Full block serialisation for submitblock.
 *
 * This chain is NOT legacy Bitcoin. Its v2 header is 164 bytes, carrying
 * m_nonce2/m_nonce3, a 16-byte extranonce, a time offset, the tx count, flags,
 * a 16-byte XOR key and the merge-mining RHS. The field order below is taken
 * from vendor/knots/src/primitives/block.h SERIALIZE_METHODS (lines 103-125);
 * a block serialised in legacy 80-byte form would be rejected outright.
 */
#ifndef OSPREY_BLOCK_H
#define OSPREY_BLOCK_H

#include <stddef.h>
#include <stdint.h>

#include "work_item.h"

#define BLOCK_HEADER_V2_LEN 164

/* Serialise just the header. out must hold BLOCK_HEADER_V2_LEN bytes.
 * Returns the length written, or negative on failure. */
int block_serialize_header(const knots_header_t *h, uint8_t *out, size_t outsz);

/* Serialise header ++ CompactSize(ntx) ++ raw transactions.
 *
 * coinbase_raw is the witness-serialised coinbase. tx_data is the concatenation
 * of the template's transactions exactly as their `data` fields gave them, so
 * they are never re-encoded, and tx_count counts them (excluding the coinbase).
 *
 * Returns the length written, or negative on failure.
 */
int block_serialize(const knots_header_t *h,
                    const uint8_t *coinbase_raw, size_t coinbase_len,
                    const uint8_t *tx_data, size_t tx_data_len, size_t tx_count,
                    uint8_t *out, size_t outsz);

#endif /* OSPREY_BLOCK_H */
