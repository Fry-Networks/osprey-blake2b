/* bech32 / bech32m address decoding, enough to turn a payout address into a
 * scriptPubKey.
 *
 * This exists because getting it wrong is not a recoverable error: a coinbase
 * paying to a malformed witness program burns the entire block reward. The
 * checksum is therefore verified, not assumed, and decode_addr() refuses
 * anything it does not fully understand rather than guessing.
 */
#ifndef OSPREY_BECH32_H
#define OSPREY_BECH32_H

#include <stddef.h>
#include <stdint.h>

#define BECH32_MAX_PROGRAM 40

typedef struct {
    char    hrp[8];                        /* "bc" for mainnet */
    int     witver;                        /* 0 for P2WPKH/P2WSH, 1 for taproot */
    uint8_t program[BECH32_MAX_PROGRAM];
    size_t  program_len;                   /* 20 = P2WPKH, 32 = P2WSH/taproot */
} bech32_addr_t;

/* Decode and CHECKSUM-VERIFY a bech32/bech32m address.
 * Returns 0 on success, negative on any failure. */
int bech32_decode_addr(const char *addr, bech32_addr_t *out);

/* Build the scriptPubKey for a decoded address: OP_<witver> PUSH(len) program.
 * Returns the script length, or negative on failure. */
int bech32_scriptpubkey(const bech32_addr_t *a, uint8_t *out, size_t outsz);

#endif /* OSPREY_BECH32_H */
