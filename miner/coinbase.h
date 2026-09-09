/* Coinbase transaction construction.
 *
 * This is the piece that turns "we can hash a header" into "we can win a
 * block". Until now get_template() left hashMerkleRoot zero, so no solved
 * header corresponded to a real block.
 */
#ifndef OSPREY_COINBASE_H
#define OSPREY_COINBASE_H

#include <stddef.h>
#include <stdint.h>

#define COINBASE_MAX 1024

typedef struct {
    uint8_t  raw[COINBASE_MAX];   /* serialised WITH witness (for the block) */
    size_t   raw_len;
    uint8_t  stripped[COINBASE_MAX]; /* serialised WITHOUT witness (for txid) */
    size_t   stripped_len;
    uint8_t  txid[32];            /* sha256d(stripped), internal byte order */
} coinbase_t;

/* Build the coinbase paying `value` to `address`.
 *
 * height             BIP34 requires it as the first scriptSig push.
 * extranonce         8 bytes of grinding room in the scriptSig. The FPGA varies
 *                    the header nonce, not this, but rolling it between
 *                    templates keeps distinct work distinct.
 * witness_commitment hex from the template's default_witness_commitment, or NULL
 *                    if the template has none. When present it MUST be added as
 *                    an output verbatim, or the block is invalid under BIP141.
 *
 * Returns 0 on success.
 */
int coinbase_build(coinbase_t *cb,
                   const char *address,
                   uint64_t value,
                   int32_t height,
                   uint64_t extranonce,
                   const char *witness_commitment_hex);

#endif /* OSPREY_COINBASE_H */
