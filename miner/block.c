#include "block.h"

#include <string.h>

static void put_u16le(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static size_t put_compact(uint8_t *p, uint64_t v)
{
    if (v < 0xfd)        { p[0] = (uint8_t)v; return 1; }
    if (v <= 0xffff)     { p[0] = 0xfd; put_u16le(p + 1, (uint16_t)v); return 3; }
    if (v <= 0xffffffff) { p[0] = 0xfe; put_u32le(p + 1, (uint32_t)v); return 5; }
    p[0] = 0xff;
    for (int i = 0; i < 8; ++i) p[1 + i] = (uint8_t)(v >> (8 * i));
    return 9;
}

int block_serialize_header(const knots_header_t *h, uint8_t *out, size_t outsz)
{
    if (!h || !out || outsz < BLOCK_HEADER_V2_LEN) return -1;
    uint8_t *p = out;

    /* Legacy-shaped prefix, but with the v2 flag folded into the version. */
    put_u32le(p, knots_complete_version(h));      p += 4;
    memcpy(p, h->hashPrevBlock, 32);              p += 32;
    memcpy(p, h->hashMerkleRoot, 32);             p += 32;
    put_u32le(p, knots_time_on_wire(h));          p += 4;
    put_u32le(p, h->nBits);                       p += 4;
    put_u32le(p, h->nNonce);                      p += 4;

    /* v2 tail, in the order block.h:111 writes it. */
    put_u32le(p, h->m_nonce2);                    p += 4;
    put_u32le(p, h->m_nonce3);                    p += 4;
    memcpy(p, h->m_extranonce, 16);               p += 16;
    put_u32le(p, h->m_time_offset);               p += 4;
    put_u16le(p, h->m_txcount);                   p += 2;
    *p++ = h->m_flags;
    *p++ = h->m_xor_key_mask_clear_bits;
    memcpy(p, h->m_xor_key, 16);                  p += 16;
    put_u32le(p, (uint32_t)h->m_height);          p += 4;
    memcpy(p, h->m_mm_rhs, 32);                   p += 32;

    return (int)(p - out);                        /* 164 */
}

int block_serialize(const knots_header_t *h,
                    const uint8_t *coinbase_raw, size_t coinbase_len,
                    const uint8_t *tx_data, size_t tx_data_len, size_t tx_count,
                    uint8_t *out, size_t outsz)
{
    if (!h || !coinbase_raw || !out) return -1;
    if (outsz < BLOCK_HEADER_V2_LEN + 9 + coinbase_len + tx_data_len) return -1;

    int hlen = block_serialize_header(h, out, outsz);
    if (hlen < 0) return -1;

    uint8_t *p = out + hlen;
    p += put_compact(p, (uint64_t)(tx_count + 1));   /* +1 for the coinbase */
    memcpy(p, coinbase_raw, coinbase_len); p += coinbase_len;
    if (tx_data_len) { memcpy(p, tx_data, tx_data_len); p += tx_data_len; }

    return (int)(p - out);
}
