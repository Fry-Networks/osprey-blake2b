/* bech32 / bech32m decoding. See bech32.h for why the checksum is mandatory. */

#include "bech32.h"

#include <string.h>

static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

#define BECH32_CONST  1U
#define BECH32M_CONST 0x2bc830a3U

static uint32_t polymod(const uint8_t *values, size_t len)
{
    static const uint32_t GEN[5] = {
        0x3b6a57b2U, 0x26508e6dU, 0x1ea119faU, 0x3d4233ddU, 0x2a1462b3U
    };
    uint32_t chk = 1;
    for (size_t i = 0; i < len; ++i) {
        uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffffU) << 5) ^ values[i];
        for (int j = 0; j < 5; ++j)
            if ((top >> j) & 1) chk ^= GEN[j];
    }
    return chk;
}

static int charset_index(char c)
{
    for (int i = 0; i < 32; ++i)
        if (CHARSET[i] == c) return i;
    return -1;
}

/* 5-bit groups -> 8-bit bytes. Rejects the malleable encodings BIP173 forbids:
 * leftover bits must be fewer than 5 and must be zero. */
static int convert5to8(const uint8_t *in, size_t inlen, uint8_t *out, size_t outsz, size_t *outlen)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;
    for (size_t i = 0; i < inlen; ++i) {
        acc = (acc << 5) | in[i];
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            if (n >= outsz) return -1;
            out[n++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    if (bits >= 5) return -1;                      /* too much padding */
    if ((acc << (8 - bits)) & 0xff) return -1;     /* non-zero padding */
    *outlen = n;
    return 0;
}

int bech32_decode_addr(const char *addr, bech32_addr_t *out)
{
    if (!addr || !out) return -1;
    size_t len = strlen(addr);
    if (len < 8 || len > 90) return -1;

    /* Mixed case is explicitly invalid; normalise to lower. */
    int has_lower = 0, has_upper = 0;
    for (size_t i = 0; i < len; ++i) {
        char c = addr[i];
        if (c < 33 || c > 126) return -1;
        if (c >= 'a' && c <= 'z') has_lower = 1;
        if (c >= 'A' && c <= 'Z') has_upper = 1;
    }
    if (has_lower && has_upper) return -1;

    char buf[91];
    for (size_t i = 0; i < len; ++i) {
        char c = addr[i];
        buf[i] = (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
    }
    buf[len] = 0;

    const char *sep = strrchr(buf, '1');
    if (!sep) return -1;
    size_t hrplen = (size_t)(sep - buf);
    size_t datalen = len - hrplen - 1;
    if (hrplen < 1 || hrplen >= sizeof out->hrp) return -1;
    if (datalen < 6) return -1;                    /* checksum alone is 6 */

    uint8_t values[128];
    size_t vlen = 0;
    for (size_t i = 0; i < hrplen; ++i) values[vlen++] = (uint8_t)(buf[i] >> 5);
    values[vlen++] = 0;
    for (size_t i = 0; i < hrplen; ++i) values[vlen++] = (uint8_t)(buf[i] & 31);

    uint8_t data[128];
    for (size_t i = 0; i < datalen; ++i) {
        int v = charset_index(buf[hrplen + 1 + i]);
        if (v < 0) return -1;
        data[i] = (uint8_t)v;
        if (vlen >= sizeof values) return -1;
        values[vlen++] = (uint8_t)v;
    }

    uint32_t chk = polymod(values, vlen);
    int witver = data[0];
    /* BIP350: witness v0 uses bech32, v1+ uses bech32m. Accepting the wrong
     * constant here is exactly how funds get sent to an address the network
     * will not honour. */
    if (witver == 0) {
        if (chk != BECH32_CONST) return -1;
    } else {
        if (chk != BECH32M_CONST) return -1;
    }
    if (witver > 16) return -1;

    size_t proglen = 0;
    if (convert5to8(data + 1, datalen - 1 - 6, out->program, sizeof out->program, &proglen) != 0)
        return -1;
    if (proglen < 2 || proglen > 40) return -1;
    if (witver == 0 && proglen != 20 && proglen != 32) return -1;

    memcpy(out->hrp, buf, hrplen);
    out->hrp[hrplen] = 0;
    out->witver = witver;
    out->program_len = proglen;
    return 0;
}

int bech32_scriptpubkey(const bech32_addr_t *a, uint8_t *out, size_t outsz)
{
    if (!a || !out) return -1;
    if (outsz < a->program_len + 2) return -1;
    /* OP_0 is 0x00; OP_1..OP_16 are 0x51..0x60. */
    out[0] = (a->witver == 0) ? 0x00 : (uint8_t)(0x50 + a->witver);
    out[1] = (uint8_t)a->program_len;
    memcpy(out + 2, a->program, a->program_len);
    return (int)(a->program_len + 2);
}
