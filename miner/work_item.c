#include "work_item.h"
#include "sha256.h"
#include "blake2b.h"
#include <string.h>

#define HEADER_V2_FLAG 0x80000000u
#define USE_TIME_OFFSET 4

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void put_le64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (i * 8));
}

static uint64_t get_le64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

void knots_header_init(knots_header_t *h)
{
    memset(h, 0, sizeof *h);
    h->nVersion = 0x20000000u;
    h->nBits    = 0x1d00ffffu;
}

static uint32_t complete_version(const knots_header_t *h)
{
    return HEADER_V2_FLAG | (h->nVersion & ~HEADER_V2_FLAG);
}

static uint32_t time_on_wire(const knots_header_t *h)
{
    if ((h->m_flags & USE_TIME_OFFSET) == 0) return h->nTime;
    return (uint32_t)(h->nTime - h->m_time_offset);
}

int stage_inputs(const knots_header_t *h,
                 uint8_t ss3[STAGE3_LEN], uint8_t ss4[STAGE4_LEN],
                 uint8_t hash_a[32])
{
    uint8_t prev_sane[32], xor_key_inner[32];
    uint8_t h1_payload[119], h1_hash[32];
    uint8_t h2_payload[96],  h2_hash[32];
    uint8_t prev_hidden[32];
    size_t  o = 0;

    if ((h->m_flags & 3) != 0) return -1;      /* FPGA implements mode 0 only */

    /* prevblock_ordered_sane = hashPrevBlock reversed */
    for (int i = 0; i < 32; ++i) prev_sane[i] = h->hashPrevBlock[31 - i];

    tagged_hash("Bitcoin block hash PoW XOR key", h->m_xor_key, 16, xor_key_inner);

    /* ---- stage 1: 119-byte payload ---- */
    put_le32(h1_payload + o, complete_version(h));            o += 4;
    memcpy  (h1_payload + o, prev_sane, 32);                  o += 32;
    put_le32(h1_payload + o, (uint32_t)h->m_height);          o += 4;   /* i32 LE */
    memcpy  (h1_payload + o, h->hashMerkleRoot, 32);          o += 32;
    put_le32(h1_payload + o, time_on_wire(h));                o += 4;
    h1_payload[o++] = 0x00;                                             /* reserved */
    put_le32(h1_payload + o, h->nBits);                       o += 4;
    put_le32(h1_payload + o, (uint32_t)h->m_txcount);         o += 4;   /* u16 written as u32 */
    h1_payload[o++] = h->m_flags;
    h1_payload[o++] = h->m_xor_key_mask_clear_bits;
    memcpy  (h1_payload + o, xor_key_inner, 32);              o += 32;
    if (o != sizeof h1_payload) return -2;
    tagged_hash("Bitcoin block header 1", h1_payload, sizeof h1_payload, h1_hash);

    /* ---- stage 2 ---- */
    memcpy(h2_payload,      h1_hash, 32);
    memset(h2_payload + 32, 0,       32);
    memcpy(h2_payload + 64, h->m_mm_rhs, 32);
    tagged_hash("Merge-mining hook", h2_payload, sizeof h2_payload, h2_hash);

    /* ---- stage 3 message: u32(0) || h2_hash || m_extranonce ---- */
    put_le32(ss3, 0);
    memcpy(ss3 + 4,  h2_hash, 32);
    memcpy(ss3 + 36, h->m_extranonce, 16);
    blake2b_nokey(ss3, STAGE3_LEN, hash_a, 32);

    /* ---- stage 4 message, mode 0 ---- */
    tagged_hash("Bitcoin prevblock header, hashed", prev_sane, 32, prev_hidden);
    for (int i = 0; i < 6; ++i) prev_hidden[i] = 0;

    o = 0;
    memcpy  (ss4 + o, prev_hidden, 32);        o += 32;
    put_le32(ss4 + o, h->nNonce);              o += 4;
    put_le32(ss4 + o, h->m_nonce2);            o += 4;
    put_le32(ss4 + o, h->m_time_offset);       o += 4;
    put_le32(ss4 + o, h->m_nonce3);            o += 4;
    memcpy  (ss4 + o, hash_a, 32);             o += 32;
    if (o != STAGE4_LEN) return -3;

    return 0;
}

int build_work_item(const knots_header_t *h, uint64_t target_top64,
                    uint8_t out[WORK_ITEM_LEN])
{
    uint8_t ss3[STAGE3_LEN], ss4[STAGE4_LEN], hash_a[32];
    int rc = stage_inputs(h, ss3, ss4, hash_a);
    if (rc != 0) return rc;

    memset(out, 0, WORK_ITEM_LEN);
    memcpy(out,                 ss3, STAGE3_LEN);   /* zero-padded to 80 */
    memcpy(out + SLOTS * 8,     ss4, STAGE4_LEN);
    put_le64(out + 2 * SLOTS * 8, target_top64);
    return 0;
}

int get_pow_hash(const knots_header_t *h, uint8_t out[32])
{
    uint8_t ss3[STAGE3_LEN], ss4[STAGE4_LEN], hash_a[32], hash_b[32];
    uint8_t mask[32];
    int rc = stage_inputs(h, ss3, ss4, hash_a);
    if (rc != 0) return rc;

    blake2b_nokey(ss4, STAGE4_LEN, hash_b, 32);

    /* ---- stage 5: XOR mask, then byte-reverse into uint256 order ---- */
    int key_zero = 1;
    for (int i = 0; i < 16; ++i) if (h->m_xor_key[i]) { key_zero = 0; break; }

    if (key_zero) {
        memset(mask, 0, 32);
    } else {
        tagged_hash("Bitcoin block hash PoW XOR mask", h->m_xor_key, 16, mask);
        unsigned clear_bytes = h->m_xor_key_mask_clear_bits / 8;
        for (unsigned i = 0; i < clear_bytes && i < 32; ++i) mask[i] = 0;
        unsigned rem = h->m_xor_key_mask_clear_bits % 8;
        if (rem && clear_bytes < 32) mask[clear_bytes] &= (uint8_t)(0xff >> rem);
    }

    for (int i = 0; i < 32; ++i) out[31 - i] = (uint8_t)(hash_b[i] ^ mask[i]);
    return 0;
}

/* 256-bit big-endian target = compact_to_target(nBits) << shift. */
void compact_to_target_shifted(uint32_t nBits, unsigned shift, uint8_t out[32])
{
    uint32_t exp  = (nBits >> 24) & 0xff;
    uint32_t mant = nBits & 0x007fffff;

    memset(out, 0, 32);
    if (nBits & 0x00800000) return;            /* negative: reference returns -target;
                                                  a negative target is never satisfiable */

    /* Place the mantissa, then apply the fork's left shift, all in one bit offset.
     * value = mant * 2^(8*(exp-3) + shift), or mant >> (8*(3-exp)) when exp <= 3. */
    long bitpos;
    if (exp <= 3) {
        mant >>= 8 * (3 - exp);
        bitpos = (long)shift;
    } else {
        bitpos = 8L * ((long)exp - 3) + (long)shift;
    }

    for (int b = 0; b < 24; ++b) {             /* mantissa is 23 bits + guard */
        if (!((mant >> b) & 1)) continue;
        long pos = bitpos + b;                 /* bit index from the LSB of a 256-bit int */
        if (pos < 0 || pos >= 256) continue;   /* shifted out entirely */
        int byte_from_lsb = (int)(pos / 8);
        out[31 - byte_from_lsb] |= (uint8_t)(1u << (pos % 8));
    }
}

uint64_t target_top64_from_bits(uint32_t nBits, unsigned shift)
{
    uint8_t t[32];
    uint64_t v = 0;
    compact_to_target_shifted(nBits, shift, t);
    for (int i = 0; i < 8; ++i) v = (v << 8) | t[i];   /* top 64 bits, big-endian */
    return v;
}

int hash_meets_target(const uint8_t hash_be[32], const uint8_t target_be[32])
{
    return memcmp(hash_be, target_be, 32) <= 0;
}

int parse_result(const uint8_t buf[RESULT_LEN], fpga_result_t *r)
{
    r->success    = (buf[0] == 0x01);
    r->nonce      = get_le64(buf + 1);
    r->hash_top64 = get_le64(buf + 9);
    return r->success ? 0 : -1;
}
