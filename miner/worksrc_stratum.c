#include "worksrc_stratum.h"
#include "sia_stratum.h"
#include "stratum.h"
#include "devfee.h"
#include "work_item.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Two sessions, not one. The dev fee cannot be taken the way the GBT path takes
 * it -- there is no coinbase to redirect when the pool builds the block -- so
 * the only honest mechanism is to spend one job in twenty mining for the dev
 * account on its own connection. When no dev pool is configured the second
 * session is never dialled, the epoch is still counted, and status.json reports
 * the skip. That is deliberately visible: a fee that is advertised but silently
 * not taken is worse than one that is openly not taken. */
static stratum_t g_main;
static stratum_t g_dev;
static int       g_dev_configured;

static void (*g_log)(const char *);

static void wlog(const char *fmt, ...)
{
    if (!g_log) return;
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    g_log(line);
}

/* What the current work item was built from, so a candidate can be submitted
 * to the right session with the right job. */
static struct {
    stratum_t *sess;
    char       job_id[64];
    uint8_t    en2[STRATUM_MAX_EN2];
    size_t     en2_len;
    uint8_t    ntime[8];
    uint8_t    target[32];
    uint64_t   job_seq;
    int        is_dev;
    int        valid;
} g_cur;

static uint64_t g_en2_counter;

static worksrc_chain_t g_chain = WORKSRC_CHAIN_KNOTS;

void worksrc_stratum_configure(worksrc_chain_t chain,
                               const char *host, int port,
                               const char *worker, const char *password,
                               const char *devfee_pool, const char *devfee_worker,
                               const char *devfee_password,
                               void (*log_sink)(const char *line))
{
    g_chain = chain;
    g_log = log_sink;
    stratum_set_logger(log_sink);
    stratum_init(&g_main, host, port, worker, password && *password ? password : "x");

    g_dev_configured = 0;
    if (devfee_pool && *devfee_pool && devfee_worker && *devfee_worker) {
        char h[192];
        int  p = port;
        snprintf(h, sizeof h, "%s", devfee_pool);
        char *colon = strrchr(h, ':');
        if (colon) { *colon = '\0'; p = atoi(colon + 1); }
        stratum_init(&g_dev, h, p, devfee_worker,
                     devfee_password && *devfee_password ? devfee_password : "x");
        g_dev_configured = 1;
        wlog("stratum: dev-fee session configured (%s:%d)", h, p);
    } else {
        wlog("stratum: no dev-fee pool configured -- the %d%% epoch will be "
             "counted and reported, not redirected", DEVFEE_PERCENT);
    }
}

/* ------------------------------------------------------------------ source */

static void st_poll(uint64_t now)
{
    stratum_poll(&g_main, now);
    if (g_dev_configured) stratum_poll(&g_dev, now);
}

static int build_from(stratum_t *s, work_ctx_t *ctx, int is_dev)
{
    uint8_t en2[STRATUM_MAX_EN2];
    size_t  en2_len = s->en2_size ? s->en2_size : 8;
    if (en2_len > sizeof en2) return -1;

    /* Roll the extranonce2 per work item so two pushes never present the FPGA
     * with the same search space. Big-endian counter: the pool treats these
     * bytes as opaque, and a monotonic hex string is far easier to correlate
     * against a pool dashboard than a little-endian one. */
    uint64_t c = ++g_en2_counter;
    memset(en2, 0, en2_len);
    for (size_t i = 0; i < 8 && i < en2_len; ++i)
        en2[en2_len - 1 - i] = (uint8_t)((c >> (8 * i)) & 0xff);

    uint8_t root[32];
    if (g_chain == WORKSRC_CHAIN_SIA) {
        /* The Siacoin core takes the merkle root straight from the work item,
         * so neither the arbitrary transaction's length nor a merkle branch
         * constrains anything here. */
        if (sia_build_header(&s->job, s->extranonce1, s->en1_len, en2, en2_len,
                             ctx->ss4, root) != 0) {
            wlog("stratum: job %s could not be assembled", s->job.job_id);
            return -1;
        }
        memset(ctx->ss3, 0, STAGE3_LEN);   /* unused on this chain */
    } else {
        if (sia_build_stages(&s->job, s->extranonce1, s->en1_len, en2, en2_len,
                             ctx->ss3, ctx->ss4, root) != 0) {
            wlog("stratum: job %s does not fit stage 3 "
                 "(coinb1=%zu en1=%zu en2=%zu, need 51 total) -- skipping",
                 s->job.job_id, s->job.coinb1_len, s->en1_len, en2_len);
            return -1;
        }

        /* The Knots bitstream recomputes stage-4 slots 6..9 from stage 3 and
         * cannot fold a merkle branch, so a job carrying one would be mined
         * against the wrong root: every candidate would verify on-chip and fail
         * in software, forever. Refuse it and say why rather than look busy.
         * The Siacoin core above has no such limitation. */
        if (s->job.nbranches != 0) {
            wlog("stratum: job %s carries %d merkle branches; this bitstream folds "
                 "none (it derives the root from stage 3) -- skipping job",
                 s->job.job_id, s->job.nbranches);
            return -1;
        }
    }

    ctx->target_top64 = stratum_target_top64(s);
    ctx->valid = 1;

    g_cur.sess    = s;
    g_cur.en2_len = en2_len;
    memcpy(g_cur.en2,   en2,          en2_len);
    memcpy(g_cur.ntime, s->job.ntime, 8);
    stratum_target_full(s, g_cur.target);
    snprintf(g_cur.job_id, sizeof g_cur.job_id, "%s", s->job.job_id);
    g_cur.job_seq = s->job.seq;
    g_cur.is_dev  = is_dev;
    g_cur.valid   = 1;
    return 0;
}

/* What we last pushed to the FPGA, so a push happens when it is worth the cost
 * and not merely because the loop asked.
 *
 * Every push reloads the FPGA's nonce iterator and restarts the reply stream,
 * which costs a frame re-sync -- and the pool re-jobs every few seconds. Pushing
 * on each notify meant the board spent most of its time re-syncing instead of
 * grinding: 5 pushes in 20 s produced frames_ok=1, frames_bad=202,
 * candidates_verified=0. Solo mining never hit this because getblocktemplate was
 * polled every 30 s.
 *
 * A new job is only genuinely new work when the previous block changed. Within
 * one block the pool keeps issuing jobs that differ only in their arbitrary
 * transaction, and abandoning a half-ground extranonce2 for one of those buys
 * nothing. So: push on a new block, or after 30 s, whichever comes first. */
static uint8_t  g_last_prevhash[32];
static int      g_have_pushed;
static uint64_t g_last_push_at;

#define PUSH_MAX_AGE_S 30

static int st_get_work(work_ctx_t *ctx)
{
    stratum_t *s = &g_main;
    if (!stratum_ready(s)) return -1;

    uint64_t now = (uint64_t)time(NULL);
    int new_block = !g_have_pushed || memcmp(g_last_prevhash, s->job.prevhash, 32) != 0;
    int stale     = g_have_pushed && (now - g_last_push_at) >= PUSH_MAX_AGE_S;
    if (!new_block && !stale) return -1;

    /* Count the epoch only when work is actually about to be produced. Calling
     * this on every poll -- including the ones that return "nothing to do" --
     * inflated the job counter to 1157 in 20 seconds and made the dev-fee
     * numbers meaningless. */
    int want_dev = devfee_pool_epoch();
    if (want_dev) {
        if (g_dev_configured && stratum_ready(&g_dev) && build_from(&g_dev, ctx, 1) == 0) {
            memcpy(g_last_prevhash, s->job.prevhash, 32);
            g_have_pushed  = 1;
            g_last_push_at = now;
            return 0;
        }
        /* Could not honour the dev epoch. Record it so the number in
         * status.json is the number of dev jobs actually mined, not the number
         * that were scheduled. */
        devfee_pool_skip();
    }

    if (build_from(s, ctx, 0) != 0) return -1;
    memcpy(g_last_prevhash, s->job.prevhash, 32);
    g_have_pushed  = 1;
    g_last_push_at = now;
    return 0;
}

static int st_on_candidate(const work_ctx_t *ctx, uint64_t nonce, uint64_t hash_top64)
{
    uint64_t expect = (g_chain == WORKSRC_CHAIN_SIA)
                    ? sia_chain_expected_top64(ctx->ss4, nonce)
                    : sia_expected_top64(ctx->ss4, nonce);
    if (expect != hash_top64)
        return WORKSRC_CAND_BAD;

    uint8_t pow[32];
    if (g_chain == WORKSRC_CHAIN_SIA) sia_chain_pow_compare(ctx->ss4, nonce, pow);
    else                              sia_pow_compare(ctx->ss4, nonce, pow);
    if (!hash_meets_target(pow, g_cur.target))
        return WORKSRC_CAND_OK;

    if (!g_cur.valid || !g_cur.sess) return WORKSRC_CAND_OK;

    /* A job the pool has replaced is worthless: it will answer "stale" or
     * "job not found", which reads in the log like a protocol bug rather than
     * ordinary timing. Drop it quietly with a count instead. */
    if (g_cur.job_seq != g_cur.sess->job.seq) {
        wlog("stratum: solution for stale job %s discarded", g_cur.job_id);
        return WORKSRC_CAND_OK;
    }

    uint8_t nb[8];
    for (int i = 0; i < 8; ++i) nb[i] = (uint8_t)((nonce >> (8 * i)) & 0xff);

    if (stratum_submit(g_cur.sess, g_cur.job_id, g_cur.en2, g_cur.en2_len,
                       g_cur.ntime, nb) == 0) {
        if (g_cur.is_dev) devfee_pool_credit();
        return WORKSRC_CAND_SOLUTION;
    }
    return WORKSRC_CAND_OK;
}

/* Two backends over the same functions. They differ only in the name that shows
 * up in logs and status.json, and in the wire size of a work item -- which is
 * the one thing the mining loop cannot infer. */
static const worksrc_t g_backend_knots = {
    .name         = "stratum",
    .get_work     = st_get_work,
    .poll         = st_poll,
    .on_candidate = st_on_candidate,
    /* How often to ASK. get_work still declines unless the previous block hash
     * changed or the item is 30 s old, so this is a check interval, not a push
     * interval: a new block is picked up within five seconds without churning
     * the UART in between. */
    .refresh_s    = 5,
    .item_len     = WORK_ITEM_LEN,          /* 168 */
};

static const worksrc_t g_backend_sia = {
    .name         = "sia",
    .get_work     = st_get_work,
    .poll         = st_poll,
    .on_candidate = st_on_candidate,
    .refresh_s    = 5,
    .item_len     = STAGE4_LEN + 8,         /* 88: header + target, no stage 3 */
};

const worksrc_t *worksrc_stratum_backend(void)
{
    return (g_chain == WORKSRC_CHAIN_SIA) ? &g_backend_sia : &g_backend_knots;
}

void worksrc_stratum_status(worksrc_stratum_status_t *out)
{
    memset(out, 0, sizeof *out);
    out->connected       = g_main.fd >= 0;
    out->subscribed      = g_main.subscribed;
    out->authorized      = g_main.authorized;
    out->has_job         = g_main.have_job;
    out->difficulty      = g_main.difficulty;
    out->jobs_received   = g_main.jobs_received;
    out->shares_submitted= g_main.shares_submitted + (g_dev_configured ? g_dev.shares_submitted : 0);
    out->shares_accepted = g_main.shares_accepted  + (g_dev_configured ? g_dev.shares_accepted  : 0);
    out->shares_rejected = g_main.shares_rejected  + (g_dev_configured ? g_dev.shares_rejected  : 0);
    out->reconnects      = g_main.reconnects;
    /* Bounded host width: a pool name is far shorter than the field, and an
     * unbounded %s here makes the compiler (rightly) point out that host+port
     * can overrun. */
    snprintf(out->pool,        sizeof out->pool,        "%.150s:%d", g_main.host, g_main.port);
    snprintf(out->job_id,      sizeof out->job_id,      "%s", g_main.job.job_id);
    snprintf(out->last_error,  sizeof out->last_error,  "%s", g_main.last_error);
    snprintf(out->last_reject, sizeof out->last_reject, "%s", g_main.last_reject);
}
