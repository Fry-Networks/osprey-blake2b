/* Stratum v1 client, Sia dialect.
 *
 * The Osprey's configured pool speaks the Sia flavour of Stratum v1 -- the one
 * SiaMining documents -- and serves Bitcoin Knots BLAKE2b work over it. That is
 * not a coincidence or a misconfiguration: this chain's stage-4 message IS a
 * standard 80-byte Sia work header, so a pool can hand Knots work to stock Sia
 * mining firmware unchanged. Verified against our own node:
 *
 *     tagged_hash("Bitcoin prevblock header, hashed", previousblockhash) with
 *     bytes 0..5 zeroed  ==  the pool's mining.notify prevhash, byte for byte,
 *     and the pool's nbits is the little-endian of the node's.
 *
 * Differences from Bitcoin's Stratum v1, all of which this file implements:
 *   - The coinbase is an "arbitrary transaction". Its hash is
 *     blake2b(0x00 || arbtx), and it is the RIGHTMOST merkle leaf, not the
 *     leftmost. Branch steps are blake2b(0x01 || branch || acc).
 *   - ntime and nonce are 64-bit, so 16 hex characters on the wire, not 8.
 *   - notify param 6 (version) is unused and arrives empty.
 *
 * This module owns the socket and the protocol only. Turning a job into the
 * FPGA's 168-byte work item is worksrc_stratum.c's business, because that is
 * where the chain-specific stage mapping belongs.
 *
 * Deliberately non-blocking and thread-free. The miner is a single polled loop
 * (there is no pthread anywhere in this program despite -pthread in CFLAGS),
 * and adding a receiver thread here would introduce the first shared-state race
 * in the codebase for no benefit -- stratum_poll() is called from the same loop
 * that drains the UART.
 */
#ifndef STRATUM_H
#define STRATUM_H

#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>     /* INET_ADDRSTRLEN */

#define STRATUM_MAX_BRANCHES 32
#define STRATUM_MAX_CB       512
#define STRATUM_MAX_EN1      32
#define STRATUM_MAX_EN2      32

typedef struct {
    char     job_id[64];
    uint8_t  prevhash[32];
    uint8_t  coinb1[STRATUM_MAX_CB];  size_t coinb1_len;
    uint8_t  coinb2[STRATUM_MAX_CB];  size_t coinb2_len;
    uint8_t  branches[STRATUM_MAX_BRANCHES][32];
    int      nbranches;
    uint8_t  ntime[8];                /* 64-bit, big-endian on the wire */
    uint32_t nbits;
    int      clean;
    uint64_t seq;                     /* bumps on every accepted notify */
} stratum_job_t;

typedef struct {
    /* ---- configuration ---- */
    char     host[192];
    char     addr[INET_ADDRSTRLEN];   /* resolved, cached across reconnects */
    int      port;
    char     worker[160];
    char     password[160];

    /* ---- connection ---- */
    int      fd;                      /* -1 when down */
    char     rx[262144];              /* line assembly; a notify with a full
                                       * merkle branch is a few KB at most, but
                                       * the buffer is generous because a stall
                                       * here silently desynchronises the stream */
    size_t   rx_len;

    /* ---- session ---- */
    uint8_t  extranonce1[STRATUM_MAX_EN1]; size_t en1_len;
    size_t   en2_size;
    double   difficulty;
    stratum_job_t job;
    int      have_job;
    int      subscribed, authorized;

    uint64_t next_id, sub_id, auth_id;

    /* ---- reconnection ---- */
    unsigned backoff_s;               /* current exponential backoff */
    uint64_t retry_at;                /* wall-clock second to try again */

    /* ---- observability (status.json) ---- */
    uint64_t jobs_received, shares_submitted, shares_accepted, shares_rejected;
    uint64_t reconnects;
    char     last_error[192];
    char     last_reject[128];
} stratum_t;

/* Install a log sink. The miner's logf_line() is static, so this module cannot
 * link to it directly; without a sink, stratum runs silently. */
void stratum_set_logger(void (*sink)(const char *line));

void stratum_init(stratum_t *s, const char *host, int port,
                  const char *worker, const char *password);

/* Service the connection: dial or re-dial if down, read whatever is pending,
 * dispatch it. Never blocks for more than a few milliseconds. `now` is
 * wall-clock seconds, so the caller's clock is the only one in play. */
void stratum_poll(stratum_t *s, uint64_t now);

/* A job is usable once we are subscribed, authorized, and a notify has landed. */
int stratum_ready(const stratum_t *s);

/* Submit a share. All three fields are the exact bytes that went into the
 * header, and are emitted as 16 hex characters each. Returns 0 if the request
 * was written to the socket (the pool's verdict arrives later, via poll). */
int stratum_submit(stratum_t *s, const char *job_id,
                   const uint8_t *en2, size_t en2_len,
                   const uint8_t ntime[8], const uint8_t nonce[8]);

void stratum_close(stratum_t *s);

/* Test seam, in the spirit of devfee_reset(): hand the dispatcher one complete
 * JSON line as if it had arrived on the socket. Lets selftest_stratum.c grade
 * the protocol decode against captured pool traffic with no network at all,
 * which is the only way that decode gets tested on a build host. */
void stratum_test_feed(stratum_t *s, const char *line);

/* Share target as the FPGA wants it: the top 64 bits of the 256-bit target
 * implied by the pool's current difficulty. Difficulty 1 is Bitcoin's
 * 0x00000000FFFF0000... , which is what the Sia stratum spec adopted. */
uint64_t stratum_target_top64(const stratum_t *s);

/* Full 256-bit share target, big-endian, for the software check before a
 * submit. Written to out[32]. */
void stratum_target_full(const stratum_t *s, uint8_t out[32]);

#endif /* STRATUM_H */
