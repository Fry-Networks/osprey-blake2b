/* SHA-256 + Bitcoin tagged hash.
 *
 * Core transform is the public-domain implementation style of Brad Conte
 * (github.com/B-Con/crypto-algorithms), rewritten here so the miner has no
 * external dependencies and links -static for the Zynq.
 */
#ifndef OSPREY_SHA256_H
#define OSPREY_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_DIGEST_LEN 32

typedef struct {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[SHA256_DIGEST_LEN]);

/* One-shot convenience. */
void sha256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_LEN]);

/* Bitcoin TaggedHash: SHA256( SHA256(tag) || SHA256(tag) || payload ).
 * Matches blake2b_reference.py:tagged_hash(). */
void tagged_hash(const char *tag, const uint8_t *payload, size_t len,
                 uint8_t out[SHA256_DIGEST_LEN]);

#endif /* OSPREY_SHA256_H */
