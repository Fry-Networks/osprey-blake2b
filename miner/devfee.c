#include "devfee.h"

#include <stddef.h>

static uint64_t g_total;
static uint64_t g_dev;
static int      g_current_is_dev;

const char *devfee_next_payout(const char *user_address)
{
    g_total++;
    /* Counting from 1 means the first dev template is #20, not #0 -- the
     * operator gets the first nineteen. */
    g_current_is_dev = (g_total % DEVFEE_INTERVAL) == 0;
    if (g_current_is_dev) {
        g_dev++;
        return DEVFEE_ADDRESS;
    }
    /* No user address configured: fall back to the dev address rather than
     * building a coinbase with a NULL script. The caller is expected to supply
     * one; this only keeps a misconfiguration from producing an unspendable
     * block. */
    return user_address ? user_address : DEVFEE_ADDRESS;
}

int      devfee_current_is_dev(void)  { return g_current_is_dev; }
uint64_t devfee_templates_total(void) { return g_total; }
uint64_t devfee_templates_dev(void)   { return g_dev; }

/* ---------------------------------------------------------------- pool mode */

static uint64_t g_pool_jobs;
static uint64_t g_pool_dev_jobs;
static uint64_t g_pool_skipped;
static uint64_t g_pool_shares;

int devfee_pool_epoch(void)
{
    g_pool_jobs++;
    if ((g_pool_jobs % DEVFEE_INTERVAL) != 0) return 0;
    g_pool_dev_jobs++;
    return 1;
}

void devfee_pool_skip(void)   { g_pool_skipped++; }
void devfee_pool_credit(void) { g_pool_shares++; }

uint64_t devfee_pool_jobs(void)     { return g_pool_jobs; }
uint64_t devfee_pool_dev_jobs(void) { return g_pool_dev_jobs; }
uint64_t devfee_pool_skipped(void)  { return g_pool_skipped; }
uint64_t devfee_pool_shares(void)   { return g_pool_shares; }

void devfee_reset(void)
{
    g_total = 0;
    g_dev = 0;
    g_current_is_dev = 0;
    g_pool_jobs = 0;
    g_pool_dev_jobs = 0;
    g_pool_skipped = 0;
    g_pool_shares = 0;
}
