/* BLAKE2b per RFC 7693. Reference-style implementation, correctness over speed —
 * this only runs once per reported candidate, not in any hot loop. */
#include "blake2b.h"
#include <string.h>

static const uint64_t IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t SIGMA[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0},
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3}
};

static uint64_t rotr64(uint64_t x, unsigned n) { return (x >> n) | (x << (64 - n)); }

static uint64_t load64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];   /* little-endian */
    return v;
}

static void store64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (i * 8));
}

#define G(r, i, a, b, c, d)                        \
    do {                                           \
        a = a + b + m[SIGMA[r][2 * (i)]];          \
        d = rotr64(d ^ a, 32);                     \
        c = c + d;                                 \
        b = rotr64(b ^ c, 24);                     \
        a = a + b + m[SIGMA[r][2 * (i) + 1]];      \
        d = rotr64(d ^ a, 16);                     \
        c = c + d;                                 \
        b = rotr64(b ^ c, 63);                     \
    } while (0)

static void compress(uint64_t h[8], const uint8_t block[128],
                     uint64_t t, int last)
{
    uint64_t v[16], m[16];

    for (int i = 0; i < 16; ++i) m[i] = load64(block + i * 8);
    for (int i = 0; i < 8; ++i)  v[i] = h[i];
    for (int i = 0; i < 8; ++i)  v[8 + i] = IV[i];

    v[12] ^= t;                 /* low word of the counter; 128-bit high word is 0 here */
    if (last) v[14] = ~v[14];

    for (int r = 0; r < 12; ++r) {
        G(r, 0, v[0], v[4], v[8],  v[12]);
        G(r, 1, v[1], v[5], v[9],  v[13]);
        G(r, 2, v[2], v[6], v[10], v[14]);
        G(r, 3, v[3], v[7], v[11], v[15]);
        G(r, 4, v[0], v[5], v[10], v[15]);
        G(r, 5, v[1], v[6], v[11], v[12]);
        G(r, 6, v[2], v[7], v[8],  v[13]);
        G(r, 7, v[3], v[4], v[9],  v[14]);
    }

    for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
}

void blake2b_nokey(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    uint64_t h[8];
    uint8_t block[128];
    size_t off = 0;
    uint64_t counter = 0;

    for (int i = 0; i < 8; ++i) h[i] = IV[i];
    /* param block: digest_length | key_length<<8 | fanout<<16 | depth<<24 */
    h[0] ^= 0x01010000ULL ^ (uint64_t)outlen;

    /* All complete-but-not-final blocks. */
    while (inlen - off > 128) {
        counter += 128;
        compress(h, in + off, counter, 0);
        off += 128;
    }

    /* Final block, zero-padded. An empty message still gets one final block. */
    size_t rem = inlen - off;
    memset(block, 0, sizeof block);
    memcpy(block, in + off, rem);
    counter += rem;
    compress(h, block, counter, 1);

    for (size_t i = 0; i < outlen; ++i)
        out[i] = (uint8_t)(h[i / 8] >> (8 * (i % 8)));
    (void)store64;
}
