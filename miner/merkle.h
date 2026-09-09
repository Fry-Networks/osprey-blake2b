/* Bitcoin merkle root over a list of txids. */
#ifndef OSPREY_MERKLE_H
#define OSPREY_MERKLE_H

#include <stddef.h>
#include <stdint.h>

/* Compute the merkle root of `count` 32-byte txids, in INTERNAL byte order
 * (the order sha256d produces, not the reversed display order).
 *
 * ids may be modified. Returns 0 on success. count must be >= 1; the coinbase
 * txid is ids[0].
 */
int merkle_root(uint8_t *ids, size_t count, uint8_t out[32]);

#endif /* OSPREY_MERKLE_H */
