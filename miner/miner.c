/* Osprey BLAKE2b miner — Zynq side.
 *
 * Feeds 168-byte work items to the VU35P over the PL AXI UartLite (/dev/uio8)
 * and verifies the 17-byte replies. Stages 1,2,5 of the Knots PoW run here;
 * stages 3,4 (BLAKE2b) run on the FPGA.
 *
 * Observability is HTTP-only — there is no SSH to this box. Everything of
 * interest lands in /var/www/html/blake2b/status.json.
 *
 * The prefilter reports byte-reversed digest word H[3], which is the word
 * Bitcoin's target convention needs: the reference reverses the digest, so the
 * compare value's most significant 8 bytes are digest[31..24]. An earlier
 * bitstream inherited Sia's H[0] tap, whose candidates were uncorrelated with
 * the target, and was rebuilt.
 */
#define _GNU_SOURCE
#include "uio_uart.h"
#include "work_item.h"
#include "sha256.h"
#include "blake2b.h"

#include <arpa/inet.h>
#include <errno.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

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
} cfg = {
    DEFAULT_UART, DEFAULT_STATUS, DEFAULT_LOG,
    "127.0.0.1", 4001, NULL, NULL,
    BLAKE2B_TARGET_SHIFT_MAINNET, 1, 0
};

static struct {
    uint64_t items_sent, frames_ok, frames_bad, candidates_verified;
    uint64_t started_at, last_template_height;
    char     phase[64];
    char     last_error[192];
    char     last_nonce[32], last_hash[32];
    int      st_vectors, st_uart, st_loopback;
    long     nonce_offset;
} st = { .st_vectors = -1, .st_uart = -1, .st_loopback = -1, .nonce_offset = 97 };

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
        st.last_nonce, st.last_hash, st.last_error);
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
    static char resp[262144];
    int fd = -1;
    size_t got = 0;

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
        if (got >= sizeof resp - 1) break;
    }
    close(fd);
    resp[got] = 0;
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
    return 0;
}

/* ------------------------------------------------------------------ */
/* Verification                                                        */
/* ------------------------------------------------------------------ */

/* The RTL prefilter reports byte-reversed digest word H[3], i.e. hash_b[24..31]
 * read big-endian. See OspreyBlake2bStage4Core.vhd Hash0/Hash0_be.
 *
 * This read hb[0..7] -- H[0] -- to match the old RTL, which had inherited Sia's
 * tap. Both sides were wrong in the same direction, so they agreed with each
 * other and disagreed with Bitcoin. Fixing only the RTL would have left every
 * candidate failing verification here, which looks exactly like a broken
 * datapath. Bitcoin's compare value is the digest reversed
 * (final[31-i] = hash_b[i]), so its top 8 bytes are hash_b[31..24], which is
 * H[3] byteswapped. */
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
        "  --rpc-pass PASS\n"
        "  --target-shift N     target left-shift; raise above 22 to inflate for bring-up\n"
        "  --status PATH        default %s\n"
        "  --log PATH           default %s\n"
        "  --submit             actually submit (default: dry run)\n"
        "  --synthetic-work     build work locally; no RPC, no credentials needed\n"
        "  --selftest WHAT      vectors | uart | loopback | rxdump | all\n",
        DEFAULT_UART, DEFAULT_STATUS, DEFAULT_LOG);
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
        else if (!strcmp(argv[i], "--target-shift") && i + 1 < argc) cfg.target_shift = (unsigned)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--status") && i + 1 < argc)      cfg.status_path = argv[++i];
        else if (!strcmp(argv[i], "--log") && i + 1 < argc)         cfg.log_path = argv[++i];
        else if (!strcmp(argv[i], "--submit"))                      cfg.dry_run = 0;
        else if (!strcmp(argv[i], "--synthetic-work"))              cfg.synthetic = 1;
        else if (!strcmp(argv[i], "--selftest") && i + 1 < argc)    selftest = argv[++i];
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

    logf_line("blake2b miner starting: uart=%s worksrc=%s rpc=%s:%d target_shift=%u dry_run=%d",
              cfg.uart_dev, cfg.synthetic ? "synthetic" : "gbt",
              cfg.rpc_host, cfg.rpc_port, cfg.target_shift, cfg.dry_run);

    /* Vector tests need no hardware — run them first so a bad build is obvious. */
    if (!selftest || !strcmp(selftest, "vectors") || !strcmp(selftest, "all")) {
        snprintf(st.phase, sizeof st.phase, "selftest:vectors");
        st.st_vectors = selftest_vectors();
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

    /* ---- mining loop ---- */
    snprintf(st.phase, sizeof st.phase, "mining");
    knots_header_t h;
    uint8_t item[WORK_ITEM_LEN], frame[RESULT_LEN];
    size_t got = 0;
    int synced = 0, bad_run = 0;
    uint64_t last_template = 0, last_status = 0;
    int have_work = 0;

    for (;;) {
        uint64_t t = now_s();

        /* Roll work on a new template. Never resend on Success: Enable stays
         * high and the FPGA keeps grinding; resending would reload the nonce
         * iterator to the seed and re-find the same candidate forever. */
        if (!have_work || t - last_template >= 30) {
            int got_work = cfg.synthetic ? synthetic_template(&h, t) : get_template(&h);
            if (got_work == 0) {
                h.m_extranonce[0] = (uint8_t)(t & 0xff);   /* vary the swept space */
                h.m_extranonce[1] = (uint8_t)((t >> 8) & 0xff);
                uint64_t tgt = target_top64_from_bits(h.nBits, cfg.target_shift);
                if (build_work_item(&h, tgt, item) == 0) {
                    if (uart_wait_quiet(&u, QUIET_IDLE_US, QUIET_WAIT_US) != 0)
                        logf_line("quiet gate timed out before work push");
                    if (uart_write(&u, item, WORK_ITEM_LEN, TX_TIMEOUT_US) == 0) {
                        uart_drain_tx(&u, 500000);
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
                        logf_line("work pushed: height=%llu bits=%08x target_top64=%016llx",
                                  (unsigned long long)st.last_template_height,
                                  h.nBits, (unsigned long long)tgt);
                    } else {
                        snprintf(st.last_error, sizeof st.last_error, "TX stalled pushing work");
                        logf_line("%s", st.last_error);
                    }
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
                knots_header_t c = h;
                c.nNonce   = (uint32_t)(cand & 0xffffffffu);
                c.m_nonce2 = (uint32_t)(cand >> 32);

                snprintf(st.last_nonce, sizeof st.last_nonce, "%016llx",
                         (unsigned long long)cand);
                snprintf(st.last_hash, sizeof st.last_hash, "%016llx",
                         (unsigned long long)r.hash_top64);

                if (expected_hash_top64(&c) == r.hash_top64) {
                    st.candidates_verified++;
                    uint8_t pow[32], tgt[32];
                    if (get_pow_hash(&c, pow) == 0) {
                        compact_to_target_shifted(c.nBits, BLAKE2B_TARGET_SHIFT_MAINNET, tgt);
                        if (hash_meets_target(pow, tgt)) {
                            logf_line("SOLUTION nonce=%016llx (submit=%s)",
                                      (unsigned long long)cand, cfg.dry_run ? "no" : "yes");
                        }
                    }
                } else {
                    st.frames_bad++;
                    snprintf(st.last_error, sizeof st.last_error,
                             "hash_top64 mismatch (prefilter word is H[3])");
                }
            }
        }

        if (t - last_status >= 5) { write_status(&u); last_status = t; }
        usleep(200);
    }

    uart_close(&u);
    return 0;
}

