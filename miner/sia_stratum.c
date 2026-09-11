#include "sia_stratum.h"
#include "blake2b.h"

#include <string.h>

int sia_arbtx(const stratum_job_t *j,
              const uint8_t *en1, size_t en1_len,
              const uint8_t *en2, size_t en2_len,
              uint8_t *out, size_t maxlen, size_t *outlen)
{
    size_t need = j->coinb1_len + en1_len + en2_len + j->coinb2_len;
    if (need > maxlen) return -1;

    size_t o = 0;
    memcpy(out + o, j->coinb1, j->coinb1_len); o += j->coinb1_len;
    memcpy(out + o, en1,       en1_len);       o += en1_len;
    memcpy(out + o, en2,       en2_len);       o += en2_len;
    memcpy(out + o, j->coinb2, j->coinb2_len); o += j->coinb2_len;

    *outlen = o;
    return 0;
}

void sia_arbtx_leaf(const uint8_t *arbtx, size_t len, uint8_t leaf[32])
{
    uint8_t buf[1 + 4 * STRATUM_MAX_CB];
    buf[0] = 0x00;
    if (len > sizeof buf - 1) len = sizeof buf - 1;   /* caller has already bounded this */
    memcpy(buf + 1, arbtx, len);
    blake2b_nokey(buf, len + 1, leaf, 32);
}

void sia_merkle_root(const stratum_job_t *j, const uint8_t leaf[32], uint8_t root[32])
{
    uint8_t acc[32], step[1 + 64];
    memcpy(acc, leaf, 32);
    for (int i = 0; i < j->nbranches; ++i) {
        step[0] = 0x01;
        memcpy(step + 1,      j->branches[i], 32);
        memcpy(step + 1 + 32, acc,            32);
        blake2b_nokey(step, sizeof step, acc, 32);
    }
    memcpy(root, acc, 32);
}

int sia_build_stages(const stratum_job_t *j,
                     const uint8_t *en1, size_t en1_len,
                     const uint8_t *en2, size_t en2_len,
                     uint8_t ss3[STAGE3_LEN], uint8_t ss4[STAGE4_LEN],
                     uint8_t merkleroot[32])
{
    uint8_t arbtx[4 * STRATUM_MAX_CB];
    size_t  arblen = 0;

    if (sia_arbtx(j, en1, en1_len, en2, en2_len, arbtx, sizeof arbtx, &arblen) != 0)
        return -1;

    /* 1 + 51 == 52 == STAGE3_LEN. Anything else cannot be hashed by this
     * bitstream, so say so instead of producing a work item that will grind
     * forever and never match. */
    if (arblen + 1 != STAGE3_LEN) return -1;

    ss3[0] = 0x00;
    memcpy(ss3 + 1, arbtx, arblen);

    uint8_t leaf[32];
    sia_arbtx_leaf(arbtx, arblen, leaf);
    sia_merkle_root(j, leaf, merkleroot);

    memset(ss4, 0, STAGE4_LEN);
    memcpy(ss4 +  0, j->prevhash, 32);
    /* ss4[32..39] is the nonce slot; the FPGA iterates it, so it stays zero. */
    memcpy(ss4 + 40, j->ntime,     8);
    memcpy(ss4 + 48, merkleroot,  32);

    return 0;
}

/* The nonce occupies ss4[32..39] as a little-endian 64-bit word: the low half
 * is nNonce and the high half m_nonce2, which is precisely the 8-byte Sia
 * nonce field at header offset 32. */
static void put_nonce(uint8_t ss4[STAGE4_LEN], uint64_t nonce)
{
    for (int i = 0; i < 8; ++i) ss4[32 + i] = (uint8_t)((nonce >> (8 * i)) & 0xff);
}

uint64_t sia_expected_top64(const uint8_t ss4_in[STAGE4_LEN], uint64_t nonce)
{
    uint8_t ss4[STAGE4_LEN], hb[32];
    memcpy(ss4, ss4_in, STAGE4_LEN);
    put_nonce(ss4, nonce);
    blake2b_nokey(ss4, STAGE4_LEN, hb, 32);

    uint64_t v = 0;
    for (int i = 24; i < 32; ++i) v = (v << 8) | hb[i];
    return v;
}

void sia_pow_compare(const uint8_t ss4_in[STAGE4_LEN], uint64_t nonce, uint8_t out[32])
{
    uint8_t ss4[STAGE4_LEN], hb[32];
    memcpy(ss4, ss4_in, STAGE4_LEN);
    put_nonce(ss4, nonce);
    blake2b_nokey(ss4, STAGE4_LEN, hb, 32);

    /* Bitcoin's convention: the compare value is the digest reversed, so
     * out[0] carries digest[31] and a plain memcmp against a big-endian target
     * is the right test. */
    for (int i = 0; i < 32; ++i) out[i] = hb[31 - i];
}

/* ------------------------------------------------------- Siacoin proper --- */

int sia_build_header(const stratum_job_t *j,
                     const uint8_t *en1, size_t en1_len,
                     const uint8_t *en2, size_t en2_len,
                     uint8_t header[STAGE4_LEN], uint8_t merkleroot[32])
{
    uint8_t arbtx[4 * STRATUM_MAX_CB];
    size_t  arblen = 0;

    if (sia_arbtx(j, en1, en1_len, en2, en2_len, arbtx, sizeof arbtx, &arblen) != 0)
        return -1;

    /* No 52-byte check here, deliberately. That constraint belongs to the Knots
     * bitstream, whose stage 3 hashes this blob on-chip at a length baked into
     * the silicon. The Siacoin core never sees the arbitrary transaction -- only
     * the folded root -- so any length the pool sends is fine. */
    uint8_t leaf[32];
    sia_arbtx_leaf(arbtx, arblen, leaf);
    sia_merkle_root(j, leaf, merkleroot);

    memset(header, 0, STAGE4_LEN);
    memcpy(header +  0, j->prevhash, 32);   /* parent block ID */
    /* header[32..39] is the nonce slot; the FPGA iterates it. */
    memcpy(header + 40, j->ntime,     8);   /* timestamp */
    memcpy(header + 48, merkleroot,  32);
    return 0;
}

uint64_t sia_chain_expected_top64(const uint8_t header_in[STAGE4_LEN], uint64_t nonce)
{
    uint8_t h[STAGE4_LEN], hb[32];
    memcpy(h, header_in, STAGE4_LEN);
    put_nonce(h, nonce);
    blake2b_nokey(h, STAGE4_LEN, hb, 32);

    /* digest[0..7] big-endian == byteswap(H[0]). NOT digest[24..31]: that is
     * the Knots word, and mining Siacoin against it reports candidates at the
     * normal rate that every one of which fails verification. */
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | hb[i];
    return v;
}

void sia_chain_pow_compare(const uint8_t header_in[STAGE4_LEN], uint64_t nonce,
                           uint8_t out[32])
{
    uint8_t h[STAGE4_LEN];
    memcpy(h, header_in, STAGE4_LEN);
    put_nonce(h, nonce);
    /* Siacoin compares the digest exactly as blake2b emits it. */
    blake2b_nokey(h, STAGE4_LEN, out, 32);
}
