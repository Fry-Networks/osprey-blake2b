/* Stratum work source: the worksrc.h backend that drives stratum.c. */
#ifndef WORKSRC_STRATUM_H
#define WORKSRC_STRATUM_H

#include <stdint.h>

#include "worksrc.h"

/* Which chain's rules apply on top of the shared Sia stratum transport.
 *
 * The transport is identical -- same subscribe, same 64-bit ntime and nonce,
 * same arbitrary transaction, same merkle fold. What differs is downstream of
 * it, and the two differences are not interchangeable:
 *
 *   KNOTS  168-byte work item (ss3 + ss4 + target). The bitstream hashes the
 *          arbitrary transaction on-chip, so 0x00||arbtx must be exactly 52
 *          bytes and a merkle branch cannot be folded. Compare on H[3].
 *
 *   SIA     88-byte work item (header + target). The merkle root arrives
 *          folded and is used as supplied, so any arbtx length and any branch
 *          are fine. Compare on H[0].
 *
 * Running one chain's compare rule against the other's silicon produces a miner
 * that reports candidates at the normal rate and fails every one. */
typedef enum {
    WORKSRC_CHAIN_KNOTS = 0,
    WORKSRC_CHAIN_SIA   = 1,
} worksrc_chain_t;

/* Configure before registering. `devfee_pool` / `devfee_worker` may be NULL or
 * empty, in which case the dev-fee epoch is counted and reported but no share
 * is redirected -- see the comment in devfee.h about why that is the honest
 * default rather than silently claiming a fee that is not being taken. */
void worksrc_stratum_configure(worksrc_chain_t chain,
                               const char *host, int port,
                               const char *worker, const char *password,
                               const char *devfee_pool, const char *devfee_worker,
                               const char *devfee_password,
                               void (*log_sink)(const char *line));

/* The backend matching the chain passed to configure(). */
const worksrc_t *worksrc_stratum_backend(void);

/* Snapshot for status.json. Every field is a plain counter so the status page
 * can show why a pool-mode miner is or is not producing. */
typedef struct {
    int      connected, subscribed, authorized, has_job;
    double   difficulty;
    uint64_t jobs_received, shares_submitted, shares_accepted, shares_rejected;
    uint64_t reconnects;
    char     pool[192];
    char     job_id[64];
    char     last_error[192];
    char     last_reject[128];
} worksrc_stratum_status_t;

void worksrc_stratum_status(worksrc_stratum_status_t *out);

#endif /* WORKSRC_STRATUM_H */
