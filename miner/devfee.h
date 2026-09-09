/* Time-based developer fee.
 *
 * Every DEVFEE_INTERVAL-th template is mined to the developer address instead of
 * the operator's. Templates are pushed on a fixed cadence, so a share of
 * templates is a share of hashing time, which is what makes this a *time*-based
 * fee rather than a share-based one.
 */
#ifndef OSPREY_DEVFEE_H
#define OSPREY_DEVFEE_H

#include <stdint.h>

#define DEVFEE_PERCENT  5
#define DEVFEE_INTERVAL 20                 /* 1 in 20 == 5% */

/* Fry Networks, BTCB2 (BLAKE2b Knots fork). Verified bech32: hrp bc, witness
 * v0, program 12e023d773abcec4dbe4ebe90424ecac94e5a470. */
#define DEVFEE_ADDRESS  "bc1qztsz84mn408vfklya05sgf8v4j2wtfrscszene"

/* Siacoin payout for a future Sia bitstream. Metadata only -- nothing in this
 * miner spends it, and it is NOT a bech32 address, so it must never be fed to
 * the coinbase builder. */
#define DEVFEE_SIA_ADDRESS \
    "6fcc0d5243aab6255a92c6e9cc992c63e1b1e2f11af77c3945ab2fd96ebb41467af0db44ae62"

/* Advance the template counter and return the address to pay. Call exactly once
 * per template. */
const char *devfee_next_payout(const char *user_address);

/* Whether the CURRENT template (the one the last call selected) is a dev-fee
 * template. */
int devfee_current_is_dev(void);

uint64_t devfee_templates_total(void);
uint64_t devfee_templates_dev(void);

/* Test seam: reset the counter so selftests are order-independent. */
void devfee_reset(void);

#endif /* OSPREY_DEVFEE_H */
