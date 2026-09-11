/* Osprey BLAKE2b miner — Zynq side.
 *
 * Feeds 168-byte work items to the VU35P over the PL AXI UartLite (/dev/uio8)
 * and verifies the 17-byte replies. Stages 1,2,5 of the Knots PoW run here;
 * stages 3,4 (BLAKE2b) run on the FPGA.
 *
 * Observability is HTTP-only — there is no SSH to this box. Everything of
 * interest lands in /var/www/html/blake2b/status.json.
 *
 * The prefilter COMPARES digest word H[3] as-is and REPORTS it byte-reversed.
 * Those are two different values with two different jobs: Bitcoin's compare
 * value is the digest reversed, so its most significant 8 bytes are
 * digest[31..24] read most-significant-first, which is H[3] unswapped; the
 * reported word is only the frame-integrity check expected_hash_top64() below
 * reproduces. An earlier bitstream inherited Sia's H[0] tap, and a later one
 * compared the byte-reversed word against an unreversed target -- both made
 * candidates uncorrelated with the target, and both were rebuilt.
 */
#define _GNU_SOURCE
#include "uio_uart.h"
#include "work_item.h"
#include "sha256.h"
#include "blake2b.h"
#include "bech32.h"
#include "block.h"
#include "coinbase.h"
#include "devfee.h"
#include "merkle.h"
#include "worksrc.h"
#include "worksrc_stratum.h"
#include "sia_stratum.h"

/* selftest_block.c */
int selftest_block_production(void);
/* selftest_stratum.c */
int selftest_stratum(void);

#include <arpa/inet.h>
#include <errno.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Which product this build is. Both binaries come from this source tree; the
 * banner is the first line in boot.log and saying the wrong name there sends
 * a reader to the wrong module's logs. */
#ifdef OSPREY_DEFAULT_ALGO_SIA
#define MINER_NAME "siacoin"
#else
#define MINER_NAME "blake2b"
#endif

#define DEFAULT_UART   "/dev/uio8"
#define DEFAULT_STATUS "/var/www/html/blake2b/status.json"
#define DEFAULT_LOG    "/var/www/html/blake2b/miner.log"
#define TX_TIMEOUT_US  200000
#define QUIET_IDLE_US  2000
#define QUIET_WAIT_US  500000
#define NONCE_GUARD    256      /* skip candidates this close to the seed (stage-3 settling) */

static struct {
    const char *uart_dev;
    const char *status_path;
    const char *log_path;
    const char *rpc_host;
    int         rpc_port;
    const char *rpc_user;
    const char *rpc_pass;
    unsigned    target_shift;   /* extra left-shift to inflate the target for bring-up */
    int         dry_run;        /* don't submit */
    int         synthetic;      /* build work locally instead of calling getblocktemplate */
    const char *payout_address; /* where block rewards go; dev fee overrides 1 in 20 */
    int         submit_test;    /* build a real block and offer it to the node */
    int         stratum_probe;  /* connect, grind one share in software, offer it */
    /* Pool mining. Absent --stratum the miner behaves exactly as before: the
     * work source stays "gbt" (or "synthetic"), and none of this is consulted. */
    const char *stratum_host;
    int         stratum_port;
    const char *worker;
    const char *pool_pass;
    const char *devfee_pool;
    const char *devfee_worker;
    const char *devfee_pass;
    /* Which chain's rules ride on the Sia stratum transport. The siacoin binary
     * is built with OSPREY_DEFAULT_ALGO_SIA so it defaults correctly; --algo
     * overrides either way, which is what makes a single source tree testable
     * for both without two mining loops. */
    int         chain;
} cfg = {
    DEFAULT_UART, DEFAULT_STATUS, DEFAULT_LOG,
    "127.0.0.1", 4001, NULL, NULL,
    BLAKE2B_TARGET_SHIFT_MAINNET, 1, 0, NULL, 0, 0,
    NULL, 0, NULL, NULL, NULL, NULL, NULL,
#ifdef OSPREY_DEFAULT_ALGO_SIA
    WORKSRC_CHAIN_SIA
#else
    WORKSRC_CHAIN_KNOTS
#endif
};

/* The selected work source. Set in main() before the mining loop; never NULL
 * once mining starts. */
static const worksrc_t *g_src;

static struct {
    uint64_t items_sent, frames_ok, frames_bad, candidates_verified;
    uint64_t started_at, last_template_height;
    char     phase[64];
    char     last_error[192];
    char     last_nonce[32], last_hash[32];
    int      st_vectors, st_uart, st_loopback;
    long     nonce_offset;
    char     merkle_root[72];
    char     payout_address[80];
    uint64_t blocks_submitted, blocks_accepted;
    char     last_submit[128];
} st = { .st_vectors = -1, .st_uart = -1, .st_loopback = -1, .nonce_offset = 97 };

/* The current template's block material, kept so a winning nonce can be turned
 * into a submittable block. Sized for the chain's 4 MB block limit. */
#define TPL_MAX_TX 8192
static struct {
    knots_header_t hdr;
    coinbase_t     cb;
    uint8_t        ids[(TPL_MAX_TX + 1) * 32];   /* [0] = coinbase txid */
    size_t         tx_count;                     /* excludes the coinbase */
    uint8_t        tx_data[4u * 1024u * 1024u];  /* raw txs, verbatim from GBT */
    size_t         tx_data_len;
    int            valid;
} g_tpl;

/* Hex helper taking an explicit length: the JSON fields are not NUL-terminated
 * where they end. */
static int hex2bin_n(const char *hex, uint8_t *out, size_t nbytes)
{
    for (size_t i = 0; i < nbytes; ++i) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static uint64_t now_s(void) { return (uint64_t)time(NULL); }

static void logf_line(const char *fmt, ...)
{
    va_list ap;
    FILE *f = fopen(cfg.log_path, "a");
    char buf[512];
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    fprintf(stderr, "%s\n", buf);
    if (f) { fprintf(f, "[%llu] %s\n", (unsigned long long)now_s(), buf); fclose(f); }
}

/* The pool section of status.json, or "" in solo mode.
 *
 * The dev-fee numbers here are deliberately four separate counters rather than
 * one percentage. In pool mode the fee is taken by mining one job in twenty for
 * the developer's own pool account, and when no dev pool is configured that job
 * cannot be redirected -- so "scheduled" and "actually mined" are different
 * numbers, and collapsing them would report a fee that is not being taken. This
 * file is served unauthenticated over HTTP and is the only window into the box;
 * a number that quietly means something other than what it says is worse here
 * than a missing one. */
static const char *pool_json(void)
{
    static char buf[1024];
    /* Both pool backends report here; only the solo sources have nothing to say. */
    if (!g_src || (strcmp(g_src->name, "stratum") != 0 &&
                   strcmp(g_src->name, "sia") != 0)) return "";

    worksrc_stratum_status_t p;
    worksrc_stratum_status(&p);
    snprintf(buf, sizeof buf,
        "  \"pool\": {\n"
        "    \"url\": \"%s\", \"connected\": %s, \"authorized\": %s, \"has_job\": %s,\n"
        "    \"difficulty\": %g, \"job_id\": \"%s\", \"jobs_received\": %llu,\n"
        "    \"shares_submitted\": %llu, \"shares_accepted\": %llu, \"shares_rejected\": %llu,\n"
        "    \"reconnects\": %llu, \"last_reject\": \"%s\"\n"
        "  },\n"
        "  \"devfee_pool_jobs\": %llu,\n"
        "  \"devfee_pool_dev_jobs\": %llu,\n"
        "  \"devfee_pool_skipped\": %llu,\n"
        "  \"devfee_pool_shares\": %llu,\n",
        p.pool, p.connected ? "true" : "false", p.authorized ? "true" : "false",
        p.has_job ? "true" : "false", p.difficulty, p.job_id,
        (unsigned long long)p.jobs_received,
        (unsigned long long)p.shares_submitted,
        (unsigned long long)p.shares_accepted,
        (unsigned long long)p.shares_rejected,
        (unsigned long long)p.reconnects, p.last_reject,
        (unsigned long long)devfee_pool_jobs(),
        (unsigned long long)devfee_pool_dev_jobs(),
        (unsigned long long)devfee_pool_skipped(),
        (unsigned long long)devfee_pool_shares());
    return buf;
}

static void write_status(uio_uart_t *u)
{
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s.tmp", cfg.status_path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f,
        "{\n"
        "  \"phase\": \"%s\",\n"
        "  \"uptime_s\": %llu,\n"
        "  \"uart_dev\": \"%s\",\n"
        "  \"selftest\": { \"vectors\": %d, \"uart\": %d, \"loopback\": %d },\n"
        "  \"nonce_offset\": %ld,\n"
        "  \"target_shift\": %u,\n"
        "  \"template_height\": %llu,\n"
        "  \"items_sent\": %llu,\n"
        "  \"frames_ok\": %llu,\n"
        "  \"frames_bad\": %llu,\n"
        "  \"candidates_verified\": %llu,\n"
        "  \"uart\": { \"rx_bytes\": %llu, \"tx_bytes\": %llu, \"overruns\": %llu, \"tx_stall_us\": %llu },\n"
        "  \"last_nonce\": \"%s\",\n"
        "  \"last_hash_top64\": \"%s\",\n"
        "  \"merkle_root\": \"%s\",\n"
        "  \"payout_address\": \"%s\",\n"
        "  \"devfee_percent\": %d,\n"
        "  \"devfee_active\": %s,\n"
        "  \"devfee_templates_total\": %llu,\n"
        "  \"devfee_templates_dev\": %llu,\n"
        "  \"blocks_submitted\": %llu,\n"
        "  \"blocks_accepted\": %llu,\n"
        "  \"last_submit_result\": \"%s\",\n"
        "  \"worksrc\": \"%s\",\n"
        "%s"
        "  \"developer\": \"Fry Networks\",\n"
        "  \"last_error\": \"%s\"\n"
        "}\n",
        st.phase, (unsigned long long)(now_s() - st.started_at), cfg.uart_dev,
        st.st_vectors, st.st_uart, st.st_loopback,
        st.nonce_offset, cfg.target_shift,
        (unsigned long long)st.last_template_height,
        (unsigned long long)st.items_sent, (unsigned long long)st.frames_ok,
        (unsigned long long)st.frames_bad, (unsigned long long)st.candidates_verified,
        u ? (unsigned long long)u->rx_bytes : 0ULL,
        u ? (unsigned long long)u->tx_bytes : 0ULL,
        u ? (unsigned long long)u->overruns : 0ULL,
        u ? (unsigned long long)u->tx_stall_us : 0ULL,
        st.last_nonce, st.last_hash,
        st.merkle_root, st.payout_address,
        DEVFEE_PERCENT, devfee_current_is_dev() ? "true" : "false",
        (unsigned long long)devfee_templates_total(),
        (unsigned long long)devfee_templates_dev(),
        (unsigned long long)st.blocks_submitted,
        (unsigned long long)st.blocks_accepted,
        st.last_submit,
        g_src ? g_src->name : "none",
        pool_json(),
        st.last_error);
    fclose(f);
    rename(tmp, cfg.status_path);
}

/* ------------------------------------------------------------------ */
/* Minimal JSON-RPC over HTTP. No external deps; we need five fields.   */
/* ------------------------------------------------------------------ */

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64(const char *in, char *out, size_t outsz)
{
    size_t n = strlen(in), o = 0;
    for (size_t i = 0; i < n && o + 4 < outsz; i += 3) {
        uint32_t v = (uint32_t)(unsigned char)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)(unsigned char)in[i + 1] << 8;
        if (i + 2 < n) v |= (uint32_t)(unsigned char)in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = (i + 1 < n) ? B64[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < n) ? B64[v & 63] : '=';
    }
    out[o] = 0;
}

/* Numeric-IP only, deliberately.
 *
 * getaddrinfo() in a -static binary pulls in NSS, which then needs the *runtime*
 * glibc shared objects to match the ones it was linked against. We build on
 * glibc 2.39 and the Osprey runs Ubuntu 16.04 (glibc 2.23), so that would fail
 * on the device. inet_pton() has no such dependency, and --rpc-host is always
 * the LAN IP of the portproxy. */
static char *rpc_call(const char *body, size_t *outlen)
{
    struct sockaddr_in sa;
    char req[1024], auth[256], authb64[512];
    /* 4 MiB, not 256 KiB.
     *
     * A mainnet getblocktemplate response is dominated by the transactions
     * array: measured at 581,678 bytes against a full mempool, and it grows from
     * there. The five scalars this miner needs sit AFTER that array -- height,
     * curtime and bits were at offsets ~581,5xx -- so a 256 KiB buffer truncated
     * the body before any of them arrived and get_template() reported
     * "template parse failed", which reads like a JSON problem and is actually a
     * capacity one. */
    static char resp[4u * 1024u * 1024u];
    int fd = -1;
    size_t got = 0;
    int truncated = 0;

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)cfg.rpc_port);
    if (inet_pton(AF_INET, cfg.rpc_host, &sa.sin_addr) != 1) {
        snprintf(st.last_error, sizeof st.last_error,
                 "--rpc-host must be a numeric IPv4 address, got '%s'", cfg.rpc_host);
        return NULL;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return NULL;
    }

    snprintf(auth, sizeof auth, "%s:%s",
             cfg.rpc_user ? cfg.rpc_user : "", cfg.rpc_pass ? cfg.rpc_pass : "");
    b64(auth, authb64, sizeof authb64);

    int n = snprintf(req, sizeof req,
        "POST / HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\n"
        "Content-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
        cfg.rpc_host, authb64, strlen(body));
    if (write(fd, req, (size_t)n) < 0 || write(fd, body, strlen(body)) < 0) {
        close(fd);
        return NULL;
    }

    for (;;) {
        ssize_t k = read(fd, resp + got, sizeof resp - got - 1);
        if (k <= 0) break;
        got += (size_t)k;
        if (got >= sizeof resp - 1) { truncated = 1; break; }
    }
    close(fd);
    resp[got] = 0;

    /* Say so loudly. A silently truncated body surfaces downstream as
     * "template parse failed", which sends you looking at the JSON parser
     * instead of at the buffer. */
    if (truncated) {
        snprintf(st.last_error, sizeof st.last_error,
                 "RPC response hit the %zu-byte buffer and was truncated",
                 sizeof resp);
        logf_line("%s", st.last_error);
    }
    if (outlen) *outlen = got;
    return resp;
}

/* Extract "key": <number>. Returns 0 on success. */
static int json_num(const char *s, const char *key, long long *out)
{
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p) return -1;
    *out = strtoll(p + 1, NULL, 10);
    return 0;
}

/* Extract "key": "<string>". Returns 0 on success. */
static int json_str(const char *s, const char *key, char *out, size_t outsz)
{
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p) return -1;
    p = strchr(p, '"');
    if (!p) return -1;
    const char *e = strchr(++p, '"');
    if (!e || (size_t)(e - p) >= outsz) return -1;
    memcpy(out, p, (size_t)(e - p));
    out[e - p] = 0;
    return 0;
}

static int hex2bin(const char *hex, uint8_t *out, size_t outlen)
{
    if (strlen(hex) != outlen * 2) return -1;
    for (size_t i = 0; i < outlen; ++i) {
        unsigned v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* Pull a template and fill a header. Merkle root is left zero: we are not
 * building a coinbase, so a real submitblock is out of reach — this is a
 * datapath bring-up, and the metric is verified candidates, not shares. */
/* Deterministic local work, for bring-up.
 *
 * The datapath test does not need a real template — it needs *a* well-formed
 * header. Using this instead of getblocktemplate means no RPC credentials have
 * to be shipped to the device at all, which keeps secrets out of the deploy
 * repo. The counter varies m_extranonce so each roll sweeps a different space. */
static int synthetic_template(knots_header_t *h, uint64_t counter)
{
    knots_header_init(h);
    h->nVersion = 0x20000000u;
    h->nBits    = 0x1903c2d4u;          /* real mainnet bits, so the target math is exercised */
    h->nTime    = (uint32_t)now_s();
    h->m_height = 969912;
    for (int i = 0; i < 8; ++i)
        h->m_extranonce[i] = (uint8_t)(counter >> (8 * i));
    /* A recognisable but non-trivial prevblock so stage-1/2 do real work. */
    for (int i = 0; i < 32; ++i)
        h->hashPrevBlock[i] = (uint8_t)(0xA5 ^ (i * 7) ^ (uint8_t)counter);
    st.last_template_height = 969912;
    return 0;
}

/* Serialise the current template's block with the winning header and offer it to
 * the node.
 *
 * The node's reply is the only honest verdict available: "high-hash" means the
 * block parsed and only the PoW was short, whereas a parse or bad-txns error
 * means our serialisation is wrong. Those look identical from here without
 * asking, which is why the raw result string is recorded verbatim. */
static int submit_block(const knots_header_t *winner)
{
    if (!g_tpl.valid) {
        snprintf(st.last_submit, sizeof st.last_submit, "no template held");
        return -1;
    }

    static uint8_t blk[4u * 1024u * 1024u + 4096u];
    int blen = block_serialize(winner, g_tpl.cb.raw, g_tpl.cb.raw_len,
                               g_tpl.tx_data, g_tpl.tx_data_len, g_tpl.tx_count,
                               blk, sizeof blk);
    if (blen <= 0) {
        snprintf(st.last_submit, sizeof st.last_submit, "serialise failed");
        return -1;
    }

    static char body[2u * (4u * 1024u * 1024u + 4096u) + 128u];
    int o = snprintf(body, sizeof body,
                     "{\"jsonrpc\":\"1.0\",\"id\":\"osprey\",\"method\":\"submitblock\",\"params\":[\"");
    for (int i = 0; i < blen; ++i) o += snprintf(body + o, 3, "%02x", blk[i]);
    snprintf(body + o, sizeof body - (size_t)o, "\"]}");

    st.blocks_submitted++;
    char *r = rpc_call(body, NULL);
    if (!r) {
        snprintf(st.last_submit, sizeof st.last_submit, "rpc call failed");
        logf_line("SUBMIT: rpc call failed (block %d bytes)", blen);
        return -1;
    }
    /* submitblock returns null on ACCEPTANCE and a reason string otherwise. */
    const char *res = strstr(r, "\"result\":");
    if (res && strncmp(res + 9, "null", 4) == 0) {
        st.blocks_accepted++;
        snprintf(st.last_submit, sizeof st.last_submit, "ACCEPTED");
        logf_line("SUBMIT: BLOCK ACCEPTED (%d bytes, height %llu)",
                  blen, (unsigned long long)st.last_template_height);
        return 0;
    }
    const char *body_start = res ? res : r;
    snprintf(st.last_submit, sizeof st.last_submit, "%.100s", body_start);
    logf_line("SUBMIT: rejected (%d bytes): %.160s", blen, body_start);
    return -1;
}

static int get_template(knots_header_t *h)
{
    const char *body =
        "{\"jsonrpc\":\"1.0\",\"id\":\"osprey\",\"method\":\"getblocktemplate\","
        "\"params\":[{\"rules\":[\"segwit\",\"blake2b\"]}]}";
    char *r = rpc_call(body, NULL);
    if (!r) { snprintf(st.last_error, sizeof st.last_error, "rpc connect failed"); return -1; }

    long long height = 0, curtime = 0, version = 0;
    char bits[32] = {0}, prev[80] = {0};
    if (json_num(r, "height", &height) || json_num(r, "curtime", &curtime) ||
        json_num(r, "version", &version) ||
        json_str(r, "bits", bits, sizeof bits) ||
        json_str(r, "previousblockhash", prev, sizeof prev)) {
        snprintf(st.last_error, sizeof st.last_error, "template parse failed");
        return -1;
    }

    knots_header_init(h);
    h->nVersion = (uint32_t)version;
    h->nTime    = (uint32_t)curtime;
    h->nBits    = (uint32_t)strtoul(bits, NULL, 16);
    h->m_height = (int32_t)height;

    uint8_t pb[32];
    if (hex2bin(prev, pb, 32) != 0) {
        snprintf(st.last_error, sizeof st.last_error, "prevhash parse failed");
        return -1;
    }
    /* getblocktemplate gives display order; the struct wants wire order. */
    for (int i = 0; i < 32; ++i) h->hashPrevBlock[i] = pb[31 - i];

    st.last_template_height = (uint64_t)height;

    /* ---- coinbase + merkle root ------------------------------------------
     *
     * Everything above only identifies which block we are building on. What
     * makes the result a *winnable* block is below: without a coinbase the
     * merkle root stays zero and a solved header corresponds to nothing.
     *
     * The transactions array is walked by scanning for "txid":" and "data":"
     * in order. Both appear exactly once per entry and in array order, so the
     * n-th of each belong together. This avoids pulling in a JSON parser for a
     * 456 KB document on a device with no package manager. */
    long long cbvalue = 0;
    if (json_num(r, "coinbasevalue", &cbvalue) != 0 || cbvalue <= 0) {
        snprintf(st.last_error, sizeof st.last_error, "template has no coinbasevalue");
        return -1;
    }
    char wc[256] = {0};
    json_str(r, "default_witness_commitment", wc, sizeof wc);   /* optional */

    g_tpl.tx_count = 0;
    g_tpl.tx_data_len = 0;

    /* ids[0] is reserved for the coinbase txid, filled in after it is built. */
    const char *p = r;
    while (g_tpl.tx_count < TPL_MAX_TX) {
        const char *tx = strstr(p, "\"txid\":\"");
        if (!tx) break;
        tx += 8;
        uint8_t disp[32];
        if (hex2bin_n(tx, disp, 32) != 0) break;
        /* Display order in JSON, internal order in the tree. */
        uint8_t *slot = g_tpl.ids + (g_tpl.tx_count + 1) * 32;
        for (int i = 0; i < 32; ++i) slot[i] = disp[31 - i];

        const char *dt = strstr(p, "\"data\":\"");
        if (!dt) break;
        dt += 8;
        const char *end = strchr(dt, '"');
        if (!end) break;
        size_t nbytes = (size_t)(end - dt) / 2;
        if (g_tpl.tx_data_len + nbytes > sizeof g_tpl.tx_data) {
            snprintf(st.last_error, sizeof st.last_error,
                     "template transactions exceed the %zu-byte block buffer",
                     sizeof g_tpl.tx_data);
            return -1;
        }
        if (hex2bin_n(dt, g_tpl.tx_data + g_tpl.tx_data_len, nbytes) != 0) break;
        g_tpl.tx_data_len += nbytes;
        g_tpl.tx_count++;
        p = (tx > dt) ? tx : dt;
    }

    const char *payout = devfee_next_payout(cfg.payout_address);
    snprintf(st.payout_address, sizeof st.payout_address, "%s", payout);
    /* Roll the extranonce per template so two templates never present the FPGA
     * with identical work. */
    if (coinbase_build(&g_tpl.cb, payout, (uint64_t)cbvalue, (int32_t)height,
                       devfee_templates_total(), wc[0] ? wc : NULL) != 0) {
        snprintf(st.last_error, sizeof st.last_error,
                 "coinbase build failed (payout address rejected?)");
        return -1;
    }
    memcpy(g_tpl.ids, g_tpl.cb.txid, 32);

    if (merkle_root(g_tpl.ids, g_tpl.tx_count + 1, h->hashMerkleRoot) != 0) {
        snprintf(st.last_error, sizeof st.last_error, "merkle root failed");
        return -1;
    }
    /* v2 headers carry the count themselves, and it includes the coinbase. */
    h->m_txcount = (uint16_t)(g_tpl.tx_count + 1);
    g_tpl.hdr = *h;
    g_tpl.valid = 1;

    for (int i = 0; i < 32; ++i)
        snprintf(st.merkle_root + 2 * i, 3, "%02x", h->hashMerkleRoot[31 - i]);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Verification                                                        */
/* ------------------------------------------------------------------ */

/* The RTL REPORTS byte-reversed digest word H[3], i.e. hash_b[24..31] read
 * big-endian, and this reproduces it. Equality here proves the part computed
 * the digest correctly -- it is a frame-integrity check, nothing more.
 *
 * It is NOT the value the FPGA compares against the target, and this comment
 * used to claim it was. Bitcoin's compare value is the digest reversed
 * (final[31-i] = hash_b[i]), so its top 8 bytes are hash_b[31..24] read
 * most-significant-first -- and because BLAKE2b serialises h[3] LITTLE-endian
 * into hash_b[24..31], that is H[3] UNSWAPPED, not byteswapped. Getting that
 * backwards is what made the RTL compare a permuted value against an
 * unpermuted target; see the Verify block in OspreyBlake2bStage4Core.vhd, which
 * now compares Hash0 while still reporting Hash0_be.
 *
 * So the two words differ on purpose, and this function must keep matching the
 * REPORTED one. An earlier bitstream additionally tapped H[0] -- Sia's word --
 * and this function matched it, so both sides were wrong together and agreed
 * with each other; that tap was fixed separately. */
static uint64_t expected_hash_top64(const knots_header_t *h)
{
    uint8_t ss3[STAGE3_LEN], ss4[STAGE4_LEN], ha[32], hb[32];
    uint64_t v = 0;
    if (stage_inputs(h, ss3, ss4, ha) != 0) return 0;
    blake2b_nokey(ss4, STAGE4_LEN, hb, 32);
    for (int i = 24; i < 32; ++i) v = (v << 8) | hb[i];
    return v;
}

/* ------------------------------------------------------------------ */
/* Work sources                                                        */
/* ------------------------------------------------------------------ */
/* Thin adapters over the functions above, nothing more. get_template(),
 * submit_block() and synthetic_template() are untouched and keep their exact
 * previous behaviour -- the seam is the vtable, not a rewrite of the solo path,
 * so a bug in pool mode cannot change how solo mining behaves.
 *
 * The header the current work item was built from lives here rather than in the
 * mining loop, because that is the one piece of state a candidate needs and it
 * belongs to whichever source produced it. */
static knots_header_t g_gbt_hdr;

static int gbt_build(work_ctx_t *ctx, int synthetic)
{
    knots_header_t h;
    uint64_t t = now_s();

    if ((synthetic ? synthetic_template(&h, t) : get_template(&h)) != 0) return -1;

    /* Vary the swept space per push, as the loop did before this moved. */
    h.m_extranonce[0] = (uint8_t)(t & 0xff);
    h.m_extranonce[1] = (uint8_t)((t >> 8) & 0xff);

    uint8_t hash_a[32];
    if (stage_inputs(&h, ctx->ss3, ctx->ss4, hash_a) != 0) return -1;

    ctx->target_top64 = target_top64_from_bits(h.nBits, cfg.target_shift);
    ctx->valid = 1;
    g_gbt_hdr = h;
    return 0;
}

static int gbt_get_work(work_ctx_t *ctx)       { return gbt_build(ctx, 0); }
static int synthetic_get_work(work_ctx_t *ctx) { return gbt_build(ctx, 1); }

static int gbt_on_candidate(const work_ctx_t *ctx, uint64_t nonce, uint64_t hash_top64)
{
    (void)ctx;
    knots_header_t c = g_gbt_hdr;
    c.nNonce   = (uint32_t)(nonce & 0xffffffffu);
    c.m_nonce2 = (uint32_t)(nonce >> 32);

    if (expected_hash_top64(&c) != hash_top64) return WORKSRC_CAND_BAD;

    uint8_t pow[32], tgt[32];
    if (get_pow_hash(&c, pow) != 0) return WORKSRC_CAND_OK;

    compact_to_target_shifted(c.nBits, BLAKE2B_TARGET_SHIFT_MAINNET, tgt);
    if (!hash_meets_target(pow, tgt)) return WORKSRC_CAND_OK;

    logf_line("SOLUTION nonce=%016llx (submit=%s)",
              (unsigned long long)nonce, cfg.dry_run ? "no" : "yes");
    if (!cfg.dry_run) {
        /* Only a candidate found at real difficulty is a block. A bring-up run
         * with an inflated target produces them constantly, and submitting
         * those would hammer the node with work it must decode and reject. */
        if (cfg.target_shift == BLAKE2B_TARGET_SHIFT_MAINNET)
            submit_block(&c);
        else
            logf_line("SUBMIT skipped: target_shift=%u is inflated "
                      "(mainnet is %u), so this is not a block",
                      cfg.target_shift, (unsigned)BLAKE2B_TARGET_SHIFT_MAINNET);
    }
    return WORKSRC_CAND_SOLUTION;
}

static const worksrc_t g_worksrc_gbt = {
    .name = "gbt", .get_work = gbt_get_work, .poll = NULL,
    .on_candidate = gbt_on_candidate, .refresh_s = 30,
    .item_len = WORK_ITEM_LEN,
};

static const worksrc_t g_worksrc_synthetic = {
    .name = "synthetic", .get_work = synthetic_get_work, .poll = NULL,
    .on_candidate = gbt_on_candidate, .refresh_s = 30,
    .item_len = WORK_ITEM_LEN,
};

/* stratum.c and worksrc_stratum.c cannot call logf_line(), which is static, so
 * they are handed this. */
static void worksrc_log_sink(const char *line) { logf_line("%s", line); }

/* ------------------------------------------------------------------ */
/* Selftests                                                           */
/* ------------------------------------------------------------------ */

static int selftest_vectors(void)
{
    /* SHA-256("abc") */
    static const uint8_t sha_abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
    /* BLAKE2b-512("abc"), RFC 7693 appendix A */
    static const uint8_t b2_abc[64] = {
        0xba,0x80,0xa5,0x3f,0x98,0x1c,0x4d,0x0d,0x6a,0x27,0x97,0xb6,0x9f,0x12,0xf6,0xe9,
        0x4c,0x21,0x2f,0x14,0x68,0x5a,0xc4,0xb7,0x4b,0x12,0xbb,0x6f,0xdb,0xff,0xa2,0xd1,
        0x7d,0x87,0xc5,0x39,0x2a,0xab,0x79,0x2d,0xc2,0x52,0xd5,0xde,0x45,0x33,0xcc,0x95,
        0x18,0xd3,0x8a,0xa8,0xdb,0xf1,0x92,0x5a,0xb9,0x23,0x86,0xed,0xd4,0x00,0x99,0x23 };
    uint8_t out[64];
    int ok = 1;

    sha256((const uint8_t *)"abc", 3, out);
    if (memcmp(out, sha_abc, 32) != 0) { logf_line("SELFTEST sha256(abc) FAIL"); ok = 0; }

    blake2b_nokey((const uint8_t *)"abc", 3, out, 64);
    if (memcmp(out, b2_abc, 64) != 0) { logf_line("SELFTEST blake2b(abc) FAIL"); ok = 0; }

    /* Null header must produce a 168-byte item and a self-consistent PoW hash. */
    knots_header_t h;
    uint8_t item[WORK_ITEM_LEN], pow[32];
    knots_header_init(&h);
    h.nBits = 0x1903c2d4u;
    h.m_height = 969859;
    if (build_work_item(&h, target_top64_from_bits(h.nBits, cfg.target_shift), item) != 0) {
        logf_line("SELFTEST build_work_item FAIL"); ok = 0;
    }
    if (get_pow_hash(&h, pow) != 0) { logf_line("SELFTEST get_pow_hash FAIL"); ok = 0; }

    /* target_top64 for mainnet bits at shift 22 — matches build_work_item.py. */
    uint64_t t = target_top64_from_bits(0x1903c2d4u, 22);
    if (t != 0x0000000000f0b500ULL) {
        logf_line("SELFTEST target_top64 FAIL got=%016llx want=0000000000f0b500",
                  (unsigned long long)t);
        ok = 0;
    }

    logf_line("SELFTEST vectors %s", ok ? "PASS" : "FAIL");
    return ok ? 0 : -1;
}

static int selftest_uart(uio_uart_t *u)
{
    uint32_t s = uart_stat(u);
    logf_line("SELFTEST uart: STAT=0x%08x rx_valid=%d tx_empty=%d tx_full=%d overrun=%d",
              s, !!(s & STAT_RX_VALID), !!(s & STAT_TX_EMPTY),
              !!(s & STAT_TX_FULL), !!(s & STAT_OVERRUN));
    uart_reset_fifos(u);
    usleep(1000);
    s = uart_stat(u);
    /* After reset TX must read empty; if not, the mapping is wrong. */
    if (!(s & STAT_TX_EMPTY)) {
        logf_line("SELFTEST uart FAIL: TX not empty after reset (STAT=0x%08x)", s);
        return -1;
    }
    logf_line("SELFTEST uart PASS");
    return 0;
}

/* Dump raw RX bytes so the stream can be inspected instead of guessed at.
 *
 * The loopback resync failed at all 168 phases, which is itself evidence: it
 * reads 17 bytes at an arbitrary offset into a continuous result stream, so
 * roughly 1 attempt in 17 should have landed frame-aligned by luck and reported
 * flag=1. Zero hits in 168 tries says the bytes are probably not well-formed
 * frames, which points at the wire rather than at alignment. Telling those apart
 * needs the actual bytes.
 *
 * Also reports where 0x01 lands modulo 17. If the FPGA is emitting real frames
 * the flag byte is at a fixed residue and this shows up as one dominant bucket,
 * which additionally gives the read alignment for free. */
static int selftest_rxdump(uio_uart_t *u)
{
    knots_header_t h;
    uint8_t item[WORK_ITEM_LEN];
    enum { NDUMP = 512 };
    static uint8_t buf[NDUMP];

    knots_header_init(&h);
    h.nBits = 0x1903c2d4u;
    h.m_height = 969859;
    if (build_work_item(&h, 0xFFFFFFFFFFFFFFFFULL, item) != 0) return -1;

    uart_reset_fifos(u);
    uart_purge_rx(u);
    if (uart_wait_quiet(u, QUIET_IDLE_US, QUIET_WAIT_US) != 0)
        logf_line("rxdump: quiet gate timed out, continuing");
    if (uart_write(u, item, WORK_ITEM_LEN, TX_TIMEOUT_US) != 0) {
        logf_line("SELFTEST rxdump FAIL: TX stalled");
        return -1;
    }
    st.items_sent++;

    size_t got = 0;
    uint64_t deadline = now_s() + 5;
    while (now_s() <= deadline && got < NDUMP) {
        uint8_t b;
        if (uart_get_nb(u, &b)) buf[got++] = b;
    }
    logf_line("rxdump: %u bytes in <=5s", (unsigned)got);
    if (got == 0) {
        logf_line("SELFTEST rxdump FAIL: nothing received");
        return -1;
    }

    for (size_t off = 0; off < got; off += 32) {
        char line[3 * 32 + 1];
        size_t n = (got - off < 32) ? got - off : 32;
        for (size_t i = 0; i < n; ++i) snprintf(line + 3 * i, 4, "%02x ", buf[off + i]);
        line[3 * n] = 0;
        logf_line("rx[%04u] %s", (unsigned)off, line);
    }

    unsigned bucket[RESULT_LEN] = { 0 }, distinct[256] = { 0 };
    for (size_t i = 0; i < got; ++i) {
        distinct[buf[i]]++;
        if (buf[i] == 0x01) bucket[i % RESULT_LEN]++;
    }
    unsigned nd = 0;
    for (int i = 0; i < 256; ++i) if (distinct[i]) nd++;
    int best = 0;
    for (int i = 1; i < RESULT_LEN; ++i) if (bucket[i] > bucket[best]) best = i;
    logf_line("rxdump: distinct byte values=%u (a stuck or garbled line shows very few)", nd);
    logf_line("rxdump: 0x01 counts by offset mod %d, best residue=%d count=%u",
              RESULT_LEN, best, bucket[best]);
    return 0;
}

/* Lock onto the 17-byte frame period in a continuous result stream.
 *
 * The FPGA transmits back to back whenever candidates are dense, so there is no
 * idle gap to frame on and a reader that simply grabs 17 bytes starts at an
 * arbitrary offset. The flag byte is 0x01 at a fixed position in every frame,
 * so its index modulo 17 is constant: histogram a burst, take the dominant
 * residue, then discard the few bytes needed to land on a frame boundary.
 *
 * This replaces a resync that could not have worked. It shifted the FPGA's
 * RECEIVE phase (uart_put of a pad byte into the free-running mod-168 counter)
 * to fix a misalignment in what we were READING, and then retried 168 times --
 * whereas pure luck on a 17-byte period should have succeeded about one attempt
 * in seventeen. */
static int frame_sync(uio_uart_t *u, unsigned timeout_s,
                      uint8_t *out_buf, size_t *out_len)
{
    enum { NSYNC = 512 };
    static uint8_t buf[NSYNC];
    size_t got = 0;
    uint64_t deadline = now_s() + timeout_s;
    unsigned idle_us = 0;

    if (out_len) *out_len = 0;

    /* Sparse stream: frame on the idle gap.
     *
     * Once the target is realistic, candidates are rare and the line goes quiet
     * between frames, so the first byte after a gap necessarily starts one --
     * far more direct than a histogram, and it needs a single frame rather than
     * four. A byte takes 86.8us at 115200 8N1, so a few ms of silence cannot
     * fall inside a frame. Returning here leaves the FIFO empty and the next
     * read aligned by construction. */
    while (now_s() <= deadline) {
        uint8_t b;
        if (uart_get_nb(u, &b)) {
            idle_us = 0;
            if (got < NSYNC) buf[got++] = b;
        } else {
            usleep(200);
            idle_us += 200;
            if (idle_us >= 3000 && got > 0) {
                /* Hand back the frame we just consumed. Aligning on a gap means
                 * reading up TO the gap, so those bytes end on a frame boundary
                 * and the last RESULT_LEN of them are a complete frame. Dropping
                 * them was fatal when the part emits only one frame per work
                 * item -- which is what a rotated item does, since its garbage
                 * target leaves Success permanently asserted and the transmitter
                 * fires on the rising edge. The caller then read zero bytes and
                 * every phase looked dead. */
                if (out_buf && out_len) {
                    memcpy(out_buf, buf, got);
                    *out_len = got;
                }
                logf_line("frame_sync: idle gap after %u bytes — aligned on the gap",
                          (unsigned)got);
                return 0;
            }
        }
        if (got >= NSYNC) break;
    }

    /* Dense stream: no gap ever appeared, so fall back to the periodicity of the
     * flag byte. */
    if (got < RESULT_LEN * 4u) {
        logf_line("frame_sync: only %u bytes and no idle gap, need at least %u "
                  "to find the period", (unsigned)got, (unsigned)(RESULT_LEN * 4u));
        return -1;
    }

    unsigned bucket[RESULT_LEN] = { 0 };
    for (size_t i = 0; i < got; ++i)
        if (buf[i] == 0x01) bucket[i % RESULT_LEN]++;

    int best = 0;
    for (int i = 1; i < RESULT_LEN; ++i)
        if (bucket[i] > bucket[best]) best = i;

    /* Demand a clear winner. 0x01 also turns up inside nonces and hashes, so a
     * flat histogram means the stream is not framed and aligning to the noisiest
     * bucket would just manufacture plausible-looking garbage. */
    unsigned frames = (unsigned)(got / RESULT_LEN);
    if (bucket[best] * 2u < frames) {
        logf_line("frame_sync: no dominant residue (best=%d count=%u over ~%u frames)"
                  " — stream is not framed", best, bucket[best], frames);
        return -1;
    }

    unsigned skip = (unsigned)(((best - (int)(got % RESULT_LEN)) + RESULT_LEN) % RESULT_LEN);
    uint64_t skip_deadline = now_s() + 2;
    for (unsigned i = 0; i < skip; ) {
        uint8_t b;
        if (uart_get_nb(u, &b)) i++;
        else if (now_s() > skip_deadline) return -1;
    }
    /* Hand back a run of ALIGNED frames.
     *
     * The gap path fills out_buf and this one used to return with out_len still
     * zero, so the caller saw no data, skipped verification entirely and simply
     * rotated to the next phase -- while this function was reporting a perfect
     * 30/30 flag lock. The alignment was right and the bytes were being thrown
     * away. Everything after the skip above is on a frame boundary, so read a
     * few frames' worth and return them. */
    size_t want = RESULT_LEN * 8;
    if (out_buf && out_len) {
        size_t n = 0;
        uint64_t rd_deadline = now_s() + 3;
        while (n < want && now_s() <= rd_deadline) {
            uint8_t b;
            if (uart_get_nb(u, &b)) out_buf[n++] = b;
        }
        *out_len = n;
        logf_line("frame_sync: locked residue=%d (%u/%u frames carried the flag), "
                  "skipped %u, returning %u aligned bytes",
                  best, bucket[best], frames, skip, (unsigned)n);
    } else {
        logf_line("frame_sync: locked residue=%d (%u/%u frames carried the flag), skipped %u",
                  best, bucket[best], frames, skip);
    }
    return 0;
}

static int loopback_verify(knots_header_t *hp, int phase,
                           uint64_t *prev_nonce, int *prev_nonce_valid,
                           const uint8_t *buf, size_t len);

/* Search the FPGA's receive byte phase, framing and verifying at each one, until
 * a reported hash can be reproduced in software. */
static int selftest_loopback(uio_uart_t *u)
{
    knots_header_t h;
    uint8_t item[WORK_ITEM_LEN];   /* frames are read inside loopback_verify */

    knots_header_init(&h);
    h.nBits = 0x1903c2d4u;
    h.m_height = 969859;
    /* Not a MAX target. The prefilter is a 64-bit compare, so a max target makes
     * every nonce a candidate: the part transmits flat out, there is no idle gap
     * to frame on, and the first frames all report nonces still adjacent to
     * kNonceSeed where stage 3's hash_a has not settled.
     *
     * But it must not be too hard either, and that is what made the phase search
     * fail at all 168 phases. tx_bytes confirms the search stepped correctly --
     * 168 * (168 + 1) = 28392 bytes, so every residue was visited -- yet the one
     * correct phase produced no frame inside the window, because at the correct
     * phase the target is the hard one we asked for while every WRONG phase
     * feeds the core a rotated, effectively random target that is usually far
     * looser. The search was systematically skipping the only phase that
     * mattered and lingering on the ones that could never verify.
     *
     * 0x00FF... passes roughly one hash in 256, so frames arrive promptly at the
     * correct phase, while still toggling Success per nonce rather than pinning
     * it high (a permanently-true Success yields a single frame, since the
     * transmitter fires on the rising edge). */
    if (build_work_item(&h, 0x00FFFFFFFFFFFFFFULL, item) != 0) return -1;

    /* There are TWO independent misalignments and they need different cures.
     *
     * The FPGA's receiver is a free-running mod-168 byte counter with no framing
     * at all, so our 168 bytes only assemble into the intended work item if the
     * counter happened to be at zero. Otherwise the core sees a ROTATION of what
     * we sent -- a garbage message and, worse, a garbage TargetTop64, which is
     * why one probe returned nothing at all while the next returned a burst even
     * though the first used a max target that must pass every hash. Sending one
     * pad byte advances that counter by one, so the phase is searchable.
     *
     * The second misalignment is on our side, reading a 17-byte frame out of the
     * reply stream, and frame_sync() handles that.
     *
     * Only a reproduced hash proves the phase is right: a rotated item still
     * yields flag=1 frames, so the flag byte alone proves nothing. The whole
     * verification therefore sits inside the phase loop. */
    uint64_t prev_nonce = 0;
    int prev_nonce_valid = 0;

    for (int phase = 0; phase < WORK_ITEM_LEN; ++phase) {
        /* Deliberately NOT uart_reset_fifos() here. That asserts CTRL_RST_TX,
         * and uart_write only queues into a 16-deep FIFO while 168 bytes take
         * 168 * 86.8us = 14.6ms to actually clock out. Resetting TX at the top
         * of the next phase truncates a work item still in flight, so the FPGA
         * receives some arbitrary number of bytes and its free-running counter
         * moves by an unpredictable amount -- which makes the phase search step
         * by an unknown stride and explains why all 168 phases could fail. Only
         * the receive side is cleared. */
        uart_purge_rx(u);
        if (uart_wait_quiet(u, QUIET_IDLE_US, QUIET_WAIT_US) != 0)
            logf_line("loopback: quiet gate timed out, continuing");

        if (uart_write(u, item, WORK_ITEM_LEN, TX_TIMEOUT_US) != 0) {
            logf_line("SELFTEST loopback FAIL: TX stalled at phase %d", phase);
            return -1;
        }
        /* Let the whole item reach the wire before doing anything else, so the
         * byte count the FPGA sees is exactly what we intended to send. */
        if (uart_drain_tx(u, 500000) != 0)
            logf_line("loopback: TX did not drain at phase %d", phase);
        st.items_sent++;

        static uint8_t rxbuf[512];
        size_t rxlen = 0;
        int synced = (frame_sync(u, 2, rxbuf, &rxlen) == 0);

        /* Dump the first few phases verbatim. A phase that yields bytes but no
         * frame-shaped window is the interesting case, and guessing at it has
         * already cost several build cycles. */
        if (phase < 3 && rxlen > 0) {
            char line[3 * 32 + 1];
            for (size_t o = 0; o < rxlen; o += 32) {
                size_t n = (rxlen - o < 32) ? rxlen - o : 32;
                for (size_t i = 0; i < n; ++i)
                    snprintf(line + 3 * i, 4, "%02x ", rxbuf[o + i]);
                line[3 * n] = 0;
                logf_line("loopback phase %d rx[%03u] %s", phase, (unsigned)o, line);
            }
        }

        /* Debug echo frames (flag 0x02) report what the core actually parsed out
         * of the work item. Comparing them with what we transmitted shows the
         * receive rotation directly instead of inferring it. */
        for (size_t w = 0; w + RESULT_LEN <= rxlen; ++w) {
            if (rxbuf[w] != 0x02) continue;
            uint64_t echo_tgt = 0, echo_slot0 = 0, sent_slot0 = 0;
            for (int k = 7; k >= 0; --k) {
                echo_tgt   = (echo_tgt   << 8) | rxbuf[w + 1 + k];
                echo_slot0 = (echo_slot0 << 8) | rxbuf[w + 9 + k];
                sent_slot0 = (sent_slot0 << 8) | item[k];
            }
            logf_line("loopback: phase %d ECHO parsed target=%016llx slot0=%016llx | "
                      "sent target=%016llx slot0=%016llx%s",
                      phase,
                      (unsigned long long)echo_tgt, (unsigned long long)echo_slot0,
                      (unsigned long long)0x00FFFFFFFFFFFFFFULL,
                      (unsigned long long)sent_slot0,
                      (echo_tgt == 0x00FFFFFFFFFFFFFFULL && echo_slot0 == sent_slot0)
                          ? "  <== RECEIVE PHASE CORRECT" : "");
        }

        if (synced && rxlen >= RESULT_LEN &&
            loopback_verify(&h, phase, &prev_nonce, &prev_nonce_valid,
                            rxbuf, rxlen) == 0)
            return 0;

        /* Advance the FPGA's receive phase by exactly one byte and try again.
         * Drained for the same reason as the item above: the next iteration must
         * not disturb a byte still on its way out. */
        uart_put(u, 0x00, TX_TIMEOUT_US);
        uart_drain_tx(u, 100000);
    }
    logf_line("SELFTEST loopback FAIL: no receive phase in %d reproduced a hash",
              WORK_ITEM_LEN);
    return -1;
}

/* Read a few frames at the current phase and try to reproduce one in software.
 * Returns 0 as soon as a hash matches, which simultaneously proves the receive
 * phase, the framing, the digest word and the nonce pipeline offset. */
/* Try every 17-byte window in whatever frame_sync collected.
 *
 * The buffer can contain a stale fragment from the previous phase as well as
 * this phase's frame, and which end is stale varies -- assuming the first 17
 * bytes and assuming the last 17 were both wrong in practice. Scanning removes
 * the guess. It cannot produce a false positive: a window only counts if its
 * flag byte is 1 AND some pipeline offset makes its reported hash reproduce
 * exactly in software, and that conjunction is far too specific to hit by
 * chance on misaligned bytes. */
static int loopback_verify(knots_header_t *hp, int phase,
                           uint64_t *prev_nonce, int *prev_nonce_valid,
                           const uint8_t *buf, size_t len)
{
    knots_header_t h = *hp;
    unsigned flagged = 0;

    for (size_t w = 0; w + RESULT_LEN <= len; ++w) {
        if (buf[w] != 0x01) continue;          /* flag byte of a result frame */

        fpga_result_t r;
        parse_result(buf + w, &r);
        if (!r.success) continue;
        flagged++;

        uint64_t from_seed = 0ULL - r.nonce;   /* kNonceSeed is all ones */
        if (from_seed < NONCE_GUARD) continue; /* stage 3 still settling */

        /* Calibrate the nonce pipeline offset. The RTL compensates by a
         * hand-derived 97 cycles; search a window and keep whichever offset
         * makes the recomputed digest word reproduce the reported hash. */
        for (long off = 0; off < 512; ++off) {
            uint64_t cand = r.nonce + (uint64_t)off;
            h.nNonce   = (uint32_t)(cand & 0xffffffffu);
            h.m_nonce2 = (uint32_t)(cand >> 32);
            if (expected_hash_top64(&h) != r.hash_top64) continue;

            st.nonce_offset = off;
            logf_line("SELFTEST loopback PASS: receive phase %d, byte window %u, "
                      "nonce_offset=%ld, nonce=%016llx hash=%016llx reproduced "
                      "in software", phase, (unsigned)w, off,
                      (unsigned long long)r.nonce,
                      (unsigned long long)r.hash_top64);
            if (*prev_nonce_valid)
                logf_line("loopback: %llu nonces since the previous candidate",
                          (unsigned long long)(r.nonce - *prev_nonce));
            *prev_nonce = r.nonce;
            *prev_nonce_valid = 1;
            st.st_loopback = 0;
            return 0;
        }
    }
    if (flagged)
        logf_line("loopback: phase %d had %u flag-1 windows in %u bytes, none "
                  "reproduced", phase, flagged, (unsigned)len);
    return -1;
}

/* ------------------------------------------------------------------ */

static void usage(void)
{
    fprintf(stderr,
        "usage: blake2b [options]\n"
        "  --uart DEV           default %s\n"
        "  --rpc-host HOST      default 127.0.0.1\n"
        "  --rpc-port PORT      default 4001\n"
        "  --rpc-user USER\n"
        "  --rpc-pass PASS      visible in /proc/<pid>/cmdline; prefer --rpc-pass-env\n"
        "  --rpc-pass-env VAR   read the RPC password from environment VAR\n"
        "  --target-shift N     target left-shift; raise above 22 to inflate for bring-up\n"
        "  --status PATH        default %s\n"
        "  --log PATH           default %s\n"
        "  --submit             actually submit (default: dry run)\n"
        "  --synthetic-work     build work locally; no RPC, no credentials needed\n"
        "  --payout-address A   bech32 address for the coinbase (default: dev fee address)\n"
        "  --submit-test        build a block from a live template and offer it to\n"
        "                       the node; it must be rejected high-hash, not unparsed\n"
        "  --selftest WHAT      vectors | block | stratum | uart | loopback | rxdump | all\n"
        "\n"
        " pool mining (Sia-dialect Stratum v1); without --stratum nothing here applies\n"
        "  --stratum HOST:PORT  mine to a pool instead of getblocktemplate\n"
        "  --worker NAME        pool worker name\n"
        "  --pool-pass PASS     visible in /proc/<pid>/cmdline; prefer --pool-pass-env\n"
        "  --pool-pass-env VAR  read the pool password from environment VAR\n"
        "  --devfee-pool H:P    dev-fee pool for the 1-in-%d job; empty = fee counted,\n"
        "                       reported, and NOT taken\n"
        "  --devfee-worker NAME dev-fee worker name\n"
        "  --devfee-pass PASS   dev-fee pool password\n"
        "  --stratum-probe      connect, grind one share in software and offer it;\n"
        "                       proves the pool path with no FPGA involved\n"
        "  --algo WHICH         sia | knots. Which chain's compare rule and work-item\n"
        "                       layout to use on top of the Sia stratum transport.\n"
        "                       Defaults to the one this binary was built for.\n",
        DEFAULT_UART, DEFAULT_STATUS, DEFAULT_LOG, DEVFEE_INTERVAL);
}

int main(int argc, char **argv)
{
    const char *selftest = NULL;
    uio_uart_t u;

    st.started_at = now_s();
    snprintf(st.phase, sizeof st.phase, "starting");

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--uart") && i + 1 < argc)             cfg.uart_dev = argv[++i];
        else if (!strcmp(argv[i], "--rpc-host") && i + 1 < argc)    cfg.rpc_host = argv[++i];
        else if (!strcmp(argv[i], "--rpc-port") && i + 1 < argc)    cfg.rpc_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rpc-user") && i + 1 < argc)    cfg.rpc_user = argv[++i];
        else if (!strcmp(argv[i], "--rpc-pass") && i + 1 < argc)    cfg.rpc_pass = argv[++i];
        /* Prefer this over --rpc-pass: an argv password is visible to every
         * local user via /proc/<pid>/cmdline, and this box serves an
         * unauthenticated status surface. */
        else if (!strcmp(argv[i], "--rpc-pass-env") && i + 1 < argc) {
            const char *v = getenv(argv[++i]);
            if (v && *v) cfg.rpc_pass = v;
        }
        else if (!strcmp(argv[i], "--target-shift") && i + 1 < argc) cfg.target_shift = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--status") && i + 1 < argc)      cfg.status_path = argv[++i];
        else if (!strcmp(argv[i], "--log") && i + 1 < argc)         cfg.log_path = argv[++i];
        else if (!strcmp(argv[i], "--submit"))                      cfg.dry_run = 0;
        else if (!strcmp(argv[i], "--synthetic-work"))              cfg.synthetic = 1;
        else if (!strcmp(argv[i], "--payout-address") && i + 1 < argc) cfg.payout_address = argv[++i];
        else if (!strcmp(argv[i], "--submit-test"))                 cfg.submit_test = 1;
        else if (!strcmp(argv[i], "--selftest") && i + 1 < argc)    selftest = argv[++i];
        /* ---- pool mining ---- */
        else if (!strcmp(argv[i], "--stratum") && i + 1 < argc) {
            /* Split on the LAST colon so an IPv6 literal, should one ever be
             * configured, does not silently lose its address. */
            static char hostbuf[192];
            snprintf(hostbuf, sizeof hostbuf, "%s", argv[++i]);
            char *colon = strrchr(hostbuf, ':');
            if (!colon || !colon[1]) {
                fprintf(stderr, "--stratum wants HOST:PORT, got '%s'\n", hostbuf);
                return 2;
            }
            *colon = '\0';
            cfg.stratum_host = hostbuf;
            cfg.stratum_port = atoi(colon + 1);
        }
        else if (!strcmp(argv[i], "--worker") && i + 1 < argc)        cfg.worker = argv[++i];
        else if (!strcmp(argv[i], "--pool-pass") && i + 1 < argc)     cfg.pool_pass = argv[++i];
        else if (!strcmp(argv[i], "--pool-pass-env") && i + 1 < argc) {
            const char *v = getenv(argv[++i]);
            if (v && *v) cfg.pool_pass = v;
        }
        else if (!strcmp(argv[i], "--devfee-pool") && i + 1 < argc)   cfg.devfee_pool = argv[++i];
        else if (!strcmp(argv[i], "--devfee-worker") && i + 1 < argc) cfg.devfee_worker = argv[++i];
        else if (!strcmp(argv[i], "--devfee-pass") && i + 1 < argc)   cfg.devfee_pass = argv[++i];
        else if (!strcmp(argv[i], "--stratum-probe"))                 cfg.stratum_probe = 1;
        else if (!strcmp(argv[i], "--algo") && i + 1 < argc) {
            const char *a = argv[++i];
            if      (!strcmp(a, "sia"))                  cfg.chain = WORKSRC_CHAIN_SIA;
            else if (!strcmp(a, "knots") || !strcmp(a, "blake2b"))
                                                         cfg.chain = WORKSRC_CHAIN_KNOTS;
            else { fprintf(stderr, "--algo wants sia | knots, got '%s'\n", a); return 2; }
        }
        else if (!strcmp(argv[i], "--dump-item")) {
            /* Emit the canonical work item as hex so it can be diffed against
             * zynq/build_work_item.py. Header matches that script's example:
             * all-default fields, nBits=0x1903c2d4, m_height=969859. */
            knots_header_t dh;
            uint8_t di[WORK_ITEM_LEN];
            knots_header_init(&dh);
            dh.nBits = 0x1903c2d4u;
            dh.m_height = 969859;
            if (build_work_item(&dh, target_top64_from_bits(dh.nBits, 22), di) != 0) return 1;
            for (int k = 0; k < WORK_ITEM_LEN; ++k) printf("%02x", di[k]);
            printf("\n");
            return 0;
        }
        else { usage(); return 2; }
    }

    /* Register the sources and pick one. --stratum wins, then --synthetic-work,
     * then the historical default. Nothing below this line changes behaviour
     * for a command line that does not mention a pool. */
    worksrc_register(&g_worksrc_gbt);
    worksrc_register(&g_worksrc_synthetic);
    const char *want = cfg.synthetic ? "synthetic" : "gbt";
    if (cfg.stratum_host) {
        worksrc_stratum_configure((worksrc_chain_t)cfg.chain,
                                  cfg.stratum_host, cfg.stratum_port,
                                  cfg.worker ? cfg.worker : "osprey",
                                  cfg.pool_pass,
                                  cfg.devfee_pool, cfg.devfee_worker, cfg.devfee_pass,
                                  worksrc_log_sink);
        const worksrc_t *b = worksrc_stratum_backend();
        worksrc_register(b);
        want = b->name;
    }
    g_src = worksrc_find(want);
    if (!g_src) { fprintf(stderr, "no work source (have: %s)\n", worksrc_list()); return 2; }

    if (cfg.stratum_host)
        logf_line("%s miner starting: uart=%s worksrc=%s pool=%s:%d worker=%s "
                  "target_shift=%u dry_run=%d",
                  MINER_NAME, cfg.uart_dev, g_src->name, cfg.stratum_host, cfg.stratum_port,
                  cfg.worker ? cfg.worker : "osprey", cfg.target_shift, cfg.dry_run);
    else
        logf_line("%s miner starting: uart=%s worksrc=%s rpc=%s:%d target_shift=%u dry_run=%d",
                  MINER_NAME, cfg.uart_dev, g_src->name,
                  cfg.rpc_host, cfg.rpc_port, cfg.target_shift, cfg.dry_run);

    /* Live serialisation proof: pull a real template, build the real block, and
     * offer it to the node. The PoW will not be met, so the ONLY acceptable
     * rejection is "high-hash" -- that means the node parsed the whole thing and
     * merely disagreed about the hash. A parse or bad-txns error would mean the
     * v2 serialisation is wrong, and the two are indistinguishable from here
     * without asking the node. */
    if (cfg.submit_test) {
        knots_header_t h;
        if (get_template(&h) != 0) {
            printf("SUBMIT-TEST: template fetch failed: %s\n", st.last_error);
            return 1;
        }
        printf("SUBMIT-TEST: height=%llu txs=%zu merkle=%s payout=%s\n",
               (unsigned long long)st.last_template_height,
               g_tpl.tx_count + 1, st.merkle_root, st.payout_address);
        submit_block(&h);
        printf("SUBMIT-TEST: submitted=%llu result=%s\n",
               (unsigned long long)st.blocks_submitted, st.last_submit);
        if (strstr(st.last_submit, "high-hash")) {
            printf("SUBMIT-TEST: PASS - node parsed the block, rejected only the PoW\n");
            return 0;
        }
        printf("SUBMIT-TEST: FAIL - expected high-hash; anything else means the "
               "serialisation is wrong\n");
        return 1;
    }

    /* Live proof of the pool path, with no FPGA involved: connect, take a real
     * job, grind it in software, and offer the share. The counterpart of
     * --submit-test for solo mining -- it answers "is what we send something
     * the pool accepts", which nothing else can answer, because the FPGA's
     * prefilter and the pool's difficulty are independent problems.
     *
     * Run it against zynq/stratum_test_server.py for a deterministic answer;
     * the production pool pins difficulty at 4096, where a software grind would
     * take days. */
    if (cfg.stratum_probe) {
        if (!cfg.stratum_host) { fprintf(stderr, "--stratum-probe needs --stratum\n"); return 2; }

        printf("STRATUM-PROBE: connecting to %s:%d as %s\n",
               cfg.stratum_host, cfg.stratum_port, cfg.worker ? cfg.worker : "osprey");

        work_ctx_t ctx;
        memset(&ctx, 0, sizeof ctx);
        uint64_t deadline = now_s() + 45;
        while (now_s() < deadline) {
            g_src->poll(now_s());
            if (g_src->get_work(&ctx) == 0) break;
            usleep(50000);
        }
        if (!ctx.valid) {
            printf("STRATUM-PROBE: FAIL - no job within 45s\n");
            return 1;
        }

        worksrc_stratum_status_t ps;
        worksrc_stratum_status(&ps);
        printf("STRATUM-PROBE: job=%s difficulty=%g target_top64=%016llx\n",
               ps.job_id, ps.difficulty, (unsigned long long)ctx.target_top64);

        /* Grind the same 64-bit slot the FPGA would. The software check here is
         * the full 256-bit share target, not the 64-bit prefilter, so a share
         * that passes is a share the pool must accept. */
        uint64_t n = 0, found = 0;
        int have = 0;
        uint64_t stop = now_s() + 120;
        for (; n < (uint64_t)1 << 40; ++n) {
            /* Stand in for the FPGA: report the word the core would report for
             * this nonce, on THIS chain. Using the other chain's word here would
             * make on_candidate reject every nonce as unverifiable, which reads
             * as a broken pipeline rather than a probe bug. */
            uint64_t word = (cfg.chain == WORKSRC_CHAIN_SIA)
                          ? sia_chain_expected_top64(ctx.ss4, n)
                          : sia_expected_top64(ctx.ss4, n);
            if (g_src->on_candidate(&ctx, n, word) == WORKSRC_CAND_SOLUTION) {
                found = n; have = 1; break;
            }
            if ((n & 0xfffff) == 0 && now_s() > stop) break;
        }
        if (!have) {
            printf("STRATUM-PROBE: FAIL - no share in %llu hashes\n",
                   (unsigned long long)n);
            return 1;
        }
        printf("STRATUM-PROBE: share found after %llu hashes, nonce=%016llx\n",
               (unsigned long long)n, (unsigned long long)found);

        /* The verdict arrives asynchronously; poll until it lands. */
        deadline = now_s() + 30;
        while (now_s() < deadline) {
            g_src->poll(now_s());
            worksrc_stratum_status(&ps);
            if (ps.shares_accepted || ps.shares_rejected) break;
            usleep(50000);
        }
        worksrc_stratum_status(&ps);
        printf("STRATUM-PROBE: submitted=%llu accepted=%llu rejected=%llu%s%s\n",
               (unsigned long long)ps.shares_submitted,
               (unsigned long long)ps.shares_accepted,
               (unsigned long long)ps.shares_rejected,
               ps.last_reject[0] ? " reason=" : "", ps.last_reject);
        if (ps.shares_accepted) {
            printf("STRATUM-PROBE: PASS - the pool accepted a share built by this miner\n");
            return 0;
        }
        printf("STRATUM-PROBE: FAIL - the share was not accepted\n");
        return 1;
    }

    /* Block-production tests need no hardware either, and a failure here means
     * a coinbase that could burn a reward -- so they gate everything else. */
    if (selftest && !strcmp(selftest, "block")) {
        return selftest_block_production() ? 1 : 0;
    }

    /* Stratum decode is pure computation -- no socket, no hardware -- so it
     * runs anywhere, including on the build host. It is graded here rather than
     * only under --selftest stratum because a miner that ships with a broken
     * job decode produces zero shares and looks exactly like a dead pool. */
    if (selftest && !strcmp(selftest, "stratum")) {
        return selftest_stratum() ? 1 : 0;
    }

    /* Vector tests need no hardware — run them first so a bad build is obvious. */
    if (!selftest || !strcmp(selftest, "vectors") || !strcmp(selftest, "all")) {
        snprintf(st.phase, sizeof st.phase, "selftest:vectors");
        st.st_vectors = selftest_vectors();
        if (st.st_vectors == 0) st.st_vectors = selftest_block_production();
        write_status(NULL);
        if (selftest && !strcmp(selftest, "vectors")) return st.st_vectors ? 1 : 0;
        if (st.st_vectors != 0) {
            snprintf(st.last_error, sizeof st.last_error, "vector selftest failed");
            write_status(NULL);
            return 1;
        }
    }

    if (uart_open(&u, cfg.uart_dev) != 0) {
        snprintf(st.last_error, sizeof st.last_error, "Cannot mmap UART %s", cfg.uart_dev);
        st.st_uart = -1;
        write_status(NULL);
        return 1;
    }

    snprintf(st.phase, sizeof st.phase, "selftest:uart");
    st.st_uart = selftest_uart(&u);
    write_status(&u);
    if (selftest && !strcmp(selftest, "uart")) { uart_close(&u); return st.st_uart ? 1 : 0; }

    if (selftest && !strcmp(selftest, "rxdump")) {
        snprintf(st.phase, sizeof st.phase, "selftest:rxdump");
        int rc = selftest_rxdump(&u);
        write_status(&u);
        uart_close(&u);
        return rc ? 1 : 0;
    }

    /* The loopback calibration is Knots-specific, and on the Siacoin bitstream
     * it is not merely inapplicable -- it is actively harmful.
     *
     * It builds a 168-byte Knots work item, sweeps 168 receive phases and
     * verifies by reproducing a Knots hash, none of which the Siacoin core can
     * satisfy. Worse, the FPGA's receiver is a free-running mod-N byte counter
     * with no framing: N is 88 there, and 168 mod 88 = 80, so every probe would
     * leave the counter rotated by 80 bytes and permanently misalign the real
     * work items that follow. Running it cost 3 s x 168 phases = 8.4 minutes per
     * attempt, and with Restart=always the module simply looped forever without
     * ever reaching its mining loop.
     *
     * Skipping it is also safe in a way it is not for Knots. The loader has just
     * programmed the part, so the receive counter is at zero; sending exactly
     * item_len bytes per item and never dropping one (the TX_FULL gate) keeps it
     * there. The phase search exists to recover from an alignment inherited from
     * whatever ran before, which a fresh bitstream load has already done.
     *
     * What the loopback would have proven -- that the FPGA's reported word can
     * be reproduced in software -- the mining loop proves continuously through
     * candidates_verified, and the RTL itself is gated by tb_sia_core's 300/300
     * against an independent oracle. */
    if (cfg.chain == WORKSRC_CHAIN_SIA) {
        st.st_loopback = 0;
        /* Same pipeline depth and the same NonceOut compensation as the Knots
         * core, where the calibration empirically lands on 0. Logged as an
         * assumption because it is one: if it were wrong, every candidate would
         * fail to reproduce and candidates_verified would stay at zero. */
        st.nonce_offset = 0;
        logf_line("loopback: SKIPPED on the sia chain -- the probe is a 168-byte "
                  "Knots item and this core takes 88, so it would rotate the "
                  "FPGA's receive counter by 80 bytes. nonce_offset assumed 0; "
                  "watch candidates_verified to confirm.");
        write_status(&u);
    } else {
        snprintf(st.phase, sizeof st.phase, "selftest:loopback");
        st.st_loopback = selftest_loopback(&u);
        write_status(&u);
        if (selftest && (!strcmp(selftest, "loopback") || !strcmp(selftest, "all"))) {
            uart_close(&u);
            return st.st_loopback ? 1 : 0;
        }
        if (st.st_loopback != 0) {
            snprintf(st.last_error, sizeof st.last_error, "loopback failed; FPGA not answering");
            write_status(&u);
            uart_close(&u);
            return 1;
        }
    }

    /* ---- mining loop ---- */
    snprintf(st.phase, sizeof st.phase, "mining");
    work_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    uint8_t item[WORK_ITEM_LEN], frame[RESULT_LEN];
    size_t got = 0;
    int synced = 0, bad_run = 0;
    uint64_t last_template = 0, last_status = 0;
    int have_work = 0;

    for (;;) {
        uint64_t t = now_s();

        /* Let the source service its own I/O. For gbt this is NULL; for a pool
         * it is where the socket gets read, so it must run every pass and never
         * block -- the UART drain below is the real-time obligation here. */
        if (g_src->poll) g_src->poll(t);

        /* Roll work on a new template. Never resend on Success: Enable stays
         * high and the FPGA keeps grinding; resending would reload the nonce
         * iterator to the seed and re-find the same candidate forever. */
        if (!have_work || t - last_template >= g_src->refresh_s) {
            work_ctx_t next;
            memset(&next, 0, sizeof next);
            if (g_src->get_work(&next) == 0) {
                size_t ilen = worksrc_pack_item(&next, g_src->item_len, item);
                if (ilen == 0) {
                    snprintf(st.last_error, sizeof st.last_error,
                             "work source %s asked for a %zu-byte item, which has no layout",
                             g_src->name, g_src->item_len);
                    logf_line("%s", st.last_error);
                    last_template = t;
                    continue;
                }
                if (uart_wait_quiet(&u, QUIET_IDLE_US, QUIET_WAIT_US) != 0)
                    logf_line("quiet gate timed out before work push");
                if (uart_write(&u, item, ilen, TX_TIMEOUT_US) == 0) {
                    uart_drain_tx(&u, 500000);
                    ctx = next;
                    st.items_sent++;
                    have_work = 1;
                    got = 0;
                    /* A new item reloads the nonce iterator and restarts the
                     * reply stream, so the old frame boundary is gone. Re-sync
                     * rather than carrying the previous alignment forward:
                     * without this, every push cost one straddled frame, which
                     * showed up as frames_bad tracking items_sent almost
                     * one-for-one. */
                    synced = 0;
                    logf_line("work pushed: src=%s height=%llu target_top64=%016llx",
                              g_src->name,
                              (unsigned long long)st.last_template_height,
                              (unsigned long long)next.target_top64);
                } else {
                    snprintf(st.last_error, sizeof st.last_error, "TX stalled pushing work");
                    logf_line("%s", st.last_error);
                }
            }
            last_template = t;
        }

        /* Frame onto the reply stream once, right after the first item goes out.
         * The loop below stays aligned on its own because it never drops a byte,
         * but it has to START on a frame boundary; without this it begins at an
         * arbitrary offset and every 17 bytes it assembles is a straddle of two
         * real frames, which reads as a total verification failure. */
        if (!synced && have_work) {
            if (frame_sync(&u, 5, NULL, NULL) == 0) { synced = 1; got = 0; }
            else logf_line("main: frame_sync failed, retrying on next template");
        }

        /* Drain continuously — the frame is 17 bytes and the FIFO is 16 deep,
         * so it can never hold a whole frame. */
        uint8_t b;
        while (uart_get_nb(&u, &b)) {
            frame[got++] = b;
            if (got == RESULT_LEN) {
                got = 0;
                fpga_result_t r;
                if (parse_result(frame, &r) != 0) {
                    st.frames_bad++;
                    /* A single dropped byte -- an OVERRUN, of which this link
                     * produces some -- shifts every subsequent frame by one and
                     * never recovers on its own. Treat a short run of unparseable
                     * frames as loss of alignment and re-sync. */
                    if (++bad_run >= 3) { synced = 0; bad_run = 0; got = 0; }
                    continue;
                }
                bad_run = 0;
                st.frames_ok++;

                uint64_t cand = r.nonce + (uint64_t)st.nonce_offset;

                snprintf(st.last_nonce, sizeof st.last_nonce, "%016llx",
                         (unsigned long long)cand);
                snprintf(st.last_hash, sizeof st.last_hash, "%016llx",
                         (unsigned long long)r.hash_top64);

                /* Verification and submission belong to the source: solo mining
                 * compares against the network target and serialises a whole
                 * block, a pool compares against the share target and sends
                 * mining.submit. Neither rule generalises to the other. */
                int verdict = g_src->on_candidate(&ctx, cand, r.hash_top64);
                if (verdict == WORKSRC_CAND_BAD) {
                    st.frames_bad++;
                    /* Name the word this chain actually taps. The two cores use
                     * different digest words, and a message asserting the wrong
                     * one sends the reader looking for a bug that is not there. */
                    snprintf(st.last_error, sizeof st.last_error,
                             "hash_top64 mismatch (prefilter word is %s)",
                             cfg.chain == WORKSRC_CHAIN_SIA ? "H[0]" : "H[3]");
                } else {
                    st.candidates_verified++;
                }
            }
        }

        if (t - last_status >= 5) { write_status(&u); last_status = t; }
        usleep(200);
    }

    uart_close(&u);
    return 0;
}

