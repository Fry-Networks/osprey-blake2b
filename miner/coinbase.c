#include "coinbase.h"
#include "bech32.h"
#include "sha256.h"

#include <string.h>

/* --- little serialisation helpers ------------------------------------- */

static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void put_u64le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i));
}

/* Bitcoin CompactSize. Coinbase scripts and output counts are always small
 * here, but the full form is cheap and avoids a latent limit. */
static size_t put_compact(uint8_t *p, uint64_t v)
{
    if (v < 0xfd)        { p[0] = (uint8_t)v; return 1; }
    if (v <= 0xffff)     { p[0] = 0xfd; p[1] = (uint8_t)v; p[2] = (uint8_t)(v >> 8); return 3; }
    if (v <= 0xffffffff) { p[0] = 0xfe; put_u32le(p + 1, (uint32_t)v); return 5; }
    p[0] = 0xff; put_u64le(p + 1, v); return 9;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex2bin(const char *hex, uint8_t *out, size_t outsz, size_t *outlen)
{
    size_t n = strlen(hex);
    if (n % 2) return -1;
    if (n / 2 > outsz) return -1;
    for (size_t i = 0; i < n / 2; ++i) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *outlen = n / 2;
    return 0;
}

/* BIP34: the block height is the first push of the coinbase scriptSig, as a
 * minimally-encoded signed little-endian integer. Getting the minimal encoding
 * wrong makes the block invalid, so the high-bit case gets its own zero byte. */
static size_t push_height(uint8_t *p, int32_t height)
{
    uint8_t tmp[5];
    size_t n = 0;
    uint32_t h = (uint32_t)height;
    while (h) { tmp[n++] = (uint8_t)(h & 0xff); h >>= 8; }
    if (n == 0) tmp[n++] = 0;
    else if (tmp[n - 1] & 0x80) tmp[n++] = 0;
    p[0] = (uint8_t)n;
    memcpy(p + 1, tmp, n);
    return n + 1;
}

int coinbase_build(coinbase_t *cb,
                   const char *address,
                   uint64_t value,
                   int32_t height,
                   uint64_t extranonce,
                   const char *witness_commitment_hex)
{
    if (!cb || !address) return -1;
    memset(cb, 0, sizeof *cb);

    bech32_addr_t a;
    if (bech32_decode_addr(address, &a) != 0) return -2;   /* never guess an address */
    uint8_t spk[64];
    int spk_len = bech32_scriptpubkey(&a, spk, sizeof spk);
    if (spk_len < 0) return -3;

    uint8_t wc[64];
    size_t wc_len = 0;
    if (witness_commitment_hex && *witness_commitment_hex) {
        if (hex2bin(witness_commitment_hex, wc, sizeof wc, &wc_len) != 0) return -4;
    }

    /* scriptSig: <height> <extranonce>. */
    uint8_t script[64];
    size_t slen = push_height(script, height);
    script[slen++] = 8;
    put_u64le(script + slen, extranonce);
    slen += 8;

    /* Build the no-witness form first: it defines the txid, and the witness
     * form is the same bytes plus the marker/flag and the witness stack. */
    uint8_t *p = cb->stripped;
    put_u32le(p, 2); p += 4;                       /* version */
    p += put_compact(p, 1);                        /* 1 input */
    memset(p, 0, 32); p += 32;                     /* null prevout hash */
    put_u32le(p, 0xffffffffU); p += 4;             /* prevout index */
    p += put_compact(p, slen);
    memcpy(p, script, slen); p += slen;
    put_u32le(p, 0xffffffffU); p += 4;             /* sequence */

    uint64_t nout = wc_len ? 2 : 1;
    p += put_compact(p, nout);
    put_u64le(p, value); p += 8;
    p += put_compact(p, (uint64_t)spk_len);
    memcpy(p, spk, (size_t)spk_len); p += spk_len;
    if (wc_len) {
        /* The commitment from the template is already a complete scriptPubKey
         * (it begins 6a24aa21a9ed...), so it is emitted verbatim with a zero
         * value rather than re-wrapped. */
        put_u64le(p, 0); p += 8;
        p += put_compact(p, wc_len);
        memcpy(p, wc, wc_len); p += wc_len;
    }
    put_u32le(p, 0); p += 4;                       /* locktime */
    cb->stripped_len = (size_t)(p - cb->stripped);

    sha256d(cb->stripped, cb->stripped_len, cb->txid);

    /* Witness form: version, 0x00 marker, 0x01 flag, inputs.., outputs..,
     * one witness stack of a single 32-byte zero (the BIP141 coinbase witness
     * reserved value), locktime. */
    uint8_t *w = cb->raw;
    put_u32le(w, 2); w += 4;
    *w++ = 0x00;
    *w++ = 0x01;
    size_t mid = cb->stripped_len - 4 - 4;         /* body between version and locktime */
    memcpy(w, cb->stripped + 4, mid); w += mid;
    w += put_compact(w, 1);                        /* 1 witness item */
    w += put_compact(w, 32);
    memset(w, 0, 32); w += 32;
    put_u32le(w, 0); w += 4;
    cb->raw_len = (size_t)(w - cb->raw);

    return 0;
}
