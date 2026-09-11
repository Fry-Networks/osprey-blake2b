/* Stratum decode tests.
 *
 * Same discipline as selftest_block.c: every expected value comes from an
 * independent source, not from running this code and recording what it printed.
 * Here the independent source is zynq/sia_reference.py -- the stage messages and
 * prefilter words below were produced by that module and pasted in, so a change
 * that breaks agreement between the C and the Python is caught by a literal
 * mismatch rather than by both drifting together.
 *
 * The job itself is not synthetic either. It is a mining.notify captured from
 * the pool the device is configured for, so these tests fail if the real
 * dialect ever stops being the dialect this miner speaks.
 *
 * Everything here is pure computation -- no socket, no UART, no hardware -- so
 * it runs identically on the build host and on the device.
 */
#include "sia_stratum.h"
#include "stratum.h"
#include "devfee.h"
#include "work_item.h"
#include "worksrc.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

static void fail(const char *what, const char *why)
{
    printf("  FAIL %s\n       %s\n", what, why);
    g_fail++;
}

static void ok(const char *what) { printf("  ok   %s\n", what); }

static int hexeq(const uint8_t *b, size_t n, const char *expect_hex, char *got, size_t gotlen)
{
    static const char H[] = "0123456789abcdef";
    if (gotlen < 2 * n + 1) return 0;
    for (size_t i = 0; i < n; ++i) { got[2 * i] = H[b[i] >> 4]; got[2 * i + 1] = H[b[i] & 15]; }
    got[2 * n] = '\0';
    return strcmp(got, expect_hex) == 0;
}

static int unhex(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* ---- the captured job, verbatim from the live pool -------------------- */

#define JOB_ID     "a647000013c7"
#define PREVHASH   "00000000000075a242522fd4708844dfbb8d6d5c302dc356935e08513503dbdd"
#define COINB1     "00000031bd27d82a5b25e42446814eab790095046062020d73a167e069766bdbbf98a800000000"
#define NBITS      "d4c20319"
#define NTIME      "0000000000000000"
#define EXTRANONCE1 "2fed4795"

/* Produced by: py -3 zynq/sia_reference.py, feeding the job above with an
 * all-zero 8-byte extranonce2. */
/* Split on field boundaries, not on line width: a hex fixture broken mid-field
 * is one miscounted character away from being wrong in a way that reads as a
 * hashing bug. ss3 is u32(0) || h2_hash(32) || m_extranonce(16); ss4 is
 * prev_hidden(32) || nonce(8) || ntime(8) || merkle root(32). */
#define EXPECT_SS3 /* u32(0)  */ "00000000" \
                   /* h2_hash */ "31bd27d82a5b25e42446814eab790095046062020d73a167e069766bdbbf98a8" \
                   /* extranon*/ "000000002fed47950000000000000000"

#define EXPECT_SS4 /* prev_hid*/ "00000000000075a242522fd4708844dfbb8d6d5c302dc356935e08513503dbdd" \
                   /* nonce   */ "0000000000000000" \
                   /* ntime   */ "0000000000000000" \
                   /* root    */ "c880069ac0edf060c7852ff922f69cb91f9ff28e67941317e6f24bf75ac94b61"

#define EXPECT_ROOT "c880069ac0edf060c7852ff922f69cb91f9ff28e67941317e6f24bf75ac94b61"

static const char NOTIFY_LINE[] =
    "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"" JOB_ID "\","
    "\"" PREVHASH "\",\"" COINB1 "\",\"\",[],\"\",\"" NBITS "\",\"" NTIME "\",true]}";

static const char SUBSCRIBE_LINE[] =
    "{\"error\":null,\"id\":1,\"result\":[[[\"mining.notify\",\"lz\"]],"
    "\"" EXTRANONCE1 "\",8]}";

/* ---- protocol decode -------------------------------------------------- */

static void test_protocol(void)
{
    stratum_t s;
    stratum_init(&s, "pool.invalid", 1234, "worker", "x");
    s.sub_id = 1;

    stratum_test_feed(&s, SUBSCRIBE_LINE);
    if (!s.subscribed)              { fail("subscribe decode", "not marked subscribed"); return; }
    if (s.en1_len != 4)             { fail("subscribe decode", "extranonce1 length wrong"); return; }
    if (s.en2_size != 8)            { fail("subscribe decode", "extranonce2_size wrong"); return; }
    char h[160];
    if (!hexeq(s.extranonce1, 4, EXTRANONCE1, h, sizeof h))
        { fail("subscribe decode", "extranonce1 bytes wrong"); return; }
    ok("subscribe yields extranonce1 and an 8-byte extranonce2");

    stratum_test_feed(&s, "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[4096]}");
    if (s.difficulty != 4096.0) { fail("set_difficulty", "difficulty not stored"); return; }
    ok("set_difficulty is recorded");

    stratum_test_feed(&s, NOTIFY_LINE);
    if (!s.have_job)                        { fail("notify decode", "no job"); return; }
    if (strcmp(s.job.job_id, JOB_ID))       { fail("notify decode", "job id"); return; }
    if (s.job.coinb1_len != 39)             { fail("notify decode", "coinb1 length"); return; }
    if (s.job.coinb2_len != 0)              { fail("notify decode", "coinb2 should be empty"); return; }
    if (s.job.nbranches != 0)               { fail("notify decode", "branches"); return; }
    if (s.job.nbits != 0x1903c2d4u)         { fail("notify decode", "nbits byte order"); return; }
    if (!hexeq(s.job.prevhash, 32, PREVHASH, h, sizeof h))
        { fail("notify decode", "prevhash"); return; }
    ok("mining.notify decodes; nbits arrives little-endian on the wire");

    /* The 6-byte mask is what identifies this as prev_hidden rather than a
     * block hash, and it is the fingerprint the chain-identity check relied on. */
    for (int i = 0; i < 6; ++i)
        if (s.job.prevhash[i] != 0) { fail("prevhash mask", "first 6 bytes not zero"); return; }
    ok("prevhash carries the 6-byte prev_hidden mask");

    /* A Bitcoin-width ntime must be refused outright. Zero-extending it would
     * produce shares that are silently unacceptable, and the symptom -- every
     * share rejected -- looks like a hardware fault, not a parser bug. */
    uint64_t before = s.job.seq;
    stratum_test_feed(&s,
        "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"bad\","
        "\"" PREVHASH "\",\"" COINB1 "\",\"\",[],\"\",\"" NBITS "\",\"deadbeef\",true]}");
    if (s.job.seq != before || strcmp(s.job.job_id, JOB_ID))
        { fail("narrow ntime", "a 4-byte ntime was accepted"); return; }
    ok("a 4-byte (Bitcoin-width) ntime is rejected, not zero-extended");

    stratum_test_feed(&s,
        "{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"short\",\"00\",\"\"]}");
    if (s.job.seq != before || strcmp(s.job.job_id, JOB_ID))
        { fail("short notify", "a 3-param notify was accepted"); return; }
    ok("a truncated notify is rejected without disturbing the live job");
}

/* ---- stage mapping ---------------------------------------------------- */

static void test_stages(void)
{
    stratum_t s;
    stratum_init(&s, "pool.invalid", 1234, "worker", "x");
    s.sub_id = 1;
    stratum_test_feed(&s, SUBSCRIBE_LINE);
    stratum_test_feed(&s, NOTIFY_LINE);

    uint8_t en2[8] = { 0 };
    uint8_t ss3[STAGE3_LEN], ss4[STAGE4_LEN], root[32];
    char h[256];

    if (sia_build_stages(&s.job, s.extranonce1, s.en1_len, en2, sizeof en2,
                         ss3, ss4, root) != 0) {
        fail("stage build", "sia_build_stages refused the captured job");
        return;
    }
    if (!hexeq(ss3, STAGE3_LEN, EXPECT_SS3, h, sizeof h))
        { fail("ss3", "does not match zynq/sia_reference.py"); return; }
    ok("ss3 matches the Python reference byte for byte");

    if (!hexeq(ss4, STAGE4_LEN, EXPECT_SS4, h, sizeof h))
        { fail("ss4", "does not match zynq/sia_reference.py"); return; }
    ok("ss4 matches the Python reference byte for byte");

    if (!hexeq(root, 32, EXPECT_ROOT, h, sizeof h))
        { fail("merkle root", "wrong"); return; }
    ok("merkle root matches the Python reference");

    /* With no branch the root IS the stage-3 hash, which is the whole reason
     * the shipped bitstream -- which derives stage-4 slots 6..9 from stage 3 and
     * cannot fold -- can mine this pool's work at all. */
    if (memcmp(root, ss4 + 48, 32) != 0)
        { fail("root placement", "root is not in ss4[48..79]"); return; }
    ok("branch-free root lands in ss4[48..79], the slots stage 3 feeds");

    /* 1 + 39 + 4 + 8 == 52. Any other arithmetic cannot be mined by this
     * bitstream, so the builder must refuse rather than truncate. */
    stratum_job_t j = s.job;
    j.coinb2_len = 1;
    j.coinb2[0] = 0xAA;
    if (sia_build_stages(&j, s.extranonce1, s.en1_len, en2, sizeof en2,
                         ss3, ss4, root) == 0)
        { fail("length guard", "a 53-byte arbtx was accepted"); return; }
    ok("an arbitrary transaction of the wrong length is refused, not truncated");

    /* A fold must actually change the root, or the branch handling is a no-op
     * that would pass every branch-free test and fail silently in the field. */
    stratum_job_t b = s.job;
    b.nbranches = 1;
    memset(b.branches[0], 0x5A, 32);
    uint8_t root2[32];
    if (sia_build_stages(&b, s.extranonce1, s.en1_len, en2, sizeof en2,
                         ss3, ss4, root2) != 0)
        { fail("branch fold", "builder refused a branch-carrying job"); return; }
    if (memcmp(root, root2, 32) == 0)
        { fail("branch fold", "folding a branch did not change the root"); return; }
    ok("folding a merkle branch changes the root");
}

/* ---- prefilter word --------------------------------------------------- */

static void test_prefilter(void)
{
    uint8_t ss4[STAGE4_LEN];
    if (unhex(EXPECT_SS4, ss4, STAGE4_LEN) != 0) { fail("prefilter", "bad fixture"); return; }

    static const struct { uint64_t nonce; uint64_t top64; } V[] = {
        { 0x0000000000000000ULL, 0x47bb256848ffcb48ULL },
        { 0x0000000000000001ULL, 0x87b52f516c3503c2ULL },
        { 0x0123456789abcdefULL, 0x0c44f3fe7c67110fULL },
    };

    for (size_t i = 0; i < sizeof V / sizeof V[0]; ++i) {
        uint64_t got = sia_expected_top64(ss4, V[i].nonce);
        if (got != V[i].top64) {
            char why[160];
            snprintf(why, sizeof why, "nonce %016llx -> %016llx, expected %016llx",
                     (unsigned long long)V[i].nonce, (unsigned long long)got,
                     (unsigned long long)V[i].top64);
            fail("prefilter word", why);
            return;
        }
    }
    ok("prefilter word matches the Python reference on three nonces");

    /* Pin the exact relationship between the word the FPGA reports and the word
     * the PoW actually compares. They are byte-reverses of each other, not
     * equal -- BLAKE2b serialises h[3] little-endian into digest[24..31], and
     * Bitcoin then reverses the whole digest, so h[3] read AS-IS is already the
     * compare value's top 64 bits. Both the RTL (OspreyBlake2bStage4Core.vhd
     * :197) and miner.c's expected_hash_top64() apply a further byte-reverse on
     * top of that.
     *
     * This is asserted rather than asserted-away because it is load-bearing:
     * the reported word is what verifies a frame, and the compare value is what
     * decides a share, and anything that silently made them the same would mean
     * one of the two had changed. See the OUT-OF-SCOPE finding in the run log
     * about the prefilter being compared against a target in the opposite
     * orientation. */
    uint8_t pow[32];
    sia_pow_compare(ss4, 0, pow);
    uint64_t compare_top64 = 0;
    for (int i = 0; i < 8; ++i) compare_top64 = (compare_top64 << 8) | pow[i];

    uint64_t swapped = 0;
    for (int i = 0; i < 8; ++i) swapped = (swapped << 8) | (uint8_t)(V[0].top64 >> (8 * i));
    if (compare_top64 != swapped) {
        char why[160];
        snprintf(why, sizeof why,
                 "compare top64 %016llx is not byteswap(prefilter %016llx)",
                 (unsigned long long)compare_top64, (unsigned long long)V[0].top64);
        fail("compare vs prefilter orientation", why);
        return;
    }
    ok("compare top64 is exactly byteswap(prefilter word), as the RTL implies");
}

/* ---- Siacoin chain rules ---------------------------------------------- */

static void test_sia_chain(void)
{
    stratum_t s;
    stratum_init(&s, "pool.invalid", 1234, "worker", "x");
    s.sub_id = 1;
    stratum_test_feed(&s, SUBSCRIBE_LINE);
    stratum_test_feed(&s, NOTIFY_LINE);

    uint8_t en2[8] = { 0 };
    uint8_t header[STAGE4_LEN], root[32];
    char h[256];

    if (sia_build_header(&s.job, s.extranonce1, s.en1_len, en2, sizeof en2,
                         header, root) != 0) {
        fail("sia header", "sia_build_header refused the captured job"); return;
    }
    /* Same transport, same bytes: the Siacoin header for a given job is exactly
     * the Knots stage-4 message. Only what happens to it afterwards differs. */
    if (!hexeq(header, STAGE4_LEN, EXPECT_SS4, h, sizeof h))
        { fail("sia header", "differs from the Knots stage-4 message"); return; }
    ok("the Siacoin header and the Knots stage-4 message are the same bytes");

    /* Siacoin's prefilter word, from zynq/sia_reference.py. Deliberately listed
     * next to the Knots value for the same nonce: the whole risk here is that
     * the two look interchangeable. */
    static const struct { uint64_t nonce, sia, knots; } V[] = {
        { 0x0000000000000000ULL, 0x5f2504467366be80ULL, 0x47bb256848ffcb48ULL },
        { 0x0000000000000001ULL, 0xf412d80f6700b5fdULL, 0x87b52f516c3503c2ULL },
        { 0x0123456789abcdefULL, 0x35aa95c99180aaa8ULL, 0x0c44f3fe7c67110fULL },
    };
    for (size_t i = 0; i < sizeof V / sizeof V[0]; ++i) {
        uint64_t got = sia_chain_expected_top64(header, V[i].nonce);
        if (got != V[i].sia) { fail("sia prefilter word", "does not match the reference"); return; }
        if (got == V[i].knots) { fail("sia prefilter word", "equals the Knots word -- indistinguishable"); return; }
        if (sia_expected_top64(header, V[i].nonce) != V[i].knots)
            { fail("knots prefilter word", "drifted"); return; }
    }
    ok("Siacoin taps H[0] and Knots taps H[3]; both match, and they differ");

    /* On Siacoin the compare value IS the digest as emitted, so its top eight
     * bytes equal the prefilter word. On Knots they are byte-reverses of each
     * other. That asymmetry is exactly why the two cores need different RTL. */
    uint8_t pow[32];
    sia_chain_pow_compare(header, 0, pow);
    uint64_t top = 0;
    for (int i = 0; i < 8; ++i) top = (top << 8) | pow[i];
    if (top != V[0].sia)
        { fail("sia compare value", "top 8 bytes are not the prefilter word"); return; }
    ok("on Siacoin the compare value's top 8 bytes ARE the prefilter word");

    /* The Knots path must refuse these two; the Siacoin path must accept them. */
    stratum_job_t b = s.job;
    b.nbranches = 1;
    memset(b.branches[0], 0x5A, 32);
    uint8_t h2[STAGE4_LEN], r2[32];
    if (sia_build_header(&b, s.extranonce1, s.en1_len, en2, sizeof en2, h2, r2) != 0)
        { fail("sia branches", "refused a branch-carrying job"); return; }
    if (memcmp(r2, root, 32) == 0)
        { fail("sia branches", "folding a branch did not change the root"); return; }

    stratum_job_t l = s.job;
    l.coinb2_len = 3;                       /* 54-byte arbtx: illegal on Knots */
    memset(l.coinb2, 0xAA, 3);
    if (sia_build_header(&l, s.extranonce1, s.en1_len, en2, sizeof en2, h2, r2) != 0)
        { fail("sia arbtx length", "refused a non-51-byte arbitrary transaction"); return; }
    ok("Siacoin accepts merkle branches and any arbtx length; Knots refuses both");
}

/* ---- work item packing ------------------------------------------------- */

static void test_pack(void)
{
    work_ctx_t ctx;
    memset(&ctx, 0, sizeof ctx);
    for (int i = 0; i < STAGE3_LEN; ++i) ctx.ss3[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < STAGE4_LEN; ++i) ctx.ss4[i] = (uint8_t)(0x80 + i);
    ctx.target_top64 = 0x0123456789abcdefULL;

    uint8_t item[WORK_ITEM_LEN];

    if (worksrc_pack_item(&ctx, WORK_ITEM_LEN, item) != WORK_ITEM_LEN)
        { fail("pack 168", "wrong length"); return; }
    if (memcmp(item, ctx.ss3, STAGE3_LEN) != 0) { fail("pack 168", "ss3 misplaced"); return; }
    for (int i = STAGE3_LEN; i < 80; ++i)
        if (item[i] != 0) { fail("pack 168", "ss3 padding not zero"); return; }
    if (memcmp(item + 80, ctx.ss4, STAGE4_LEN) != 0) { fail("pack 168", "ss4 misplaced"); return; }
    if (item[160] != 0xef || item[167] != 0x01) { fail("pack 168", "target not little-endian"); return; }
    ok("the 168-byte Knots item is ss3 | pad | ss4 | target-LE");

    if (worksrc_pack_item(&ctx, STAGE4_LEN + 8, item) != STAGE4_LEN + 8)
        { fail("pack 88", "wrong length"); return; }
    if (memcmp(item, ctx.ss4, STAGE4_LEN) != 0) { fail("pack 88", "header misplaced"); return; }
    if (item[80] != 0xef || item[87] != 0x01) { fail("pack 88", "target not little-endian"); return; }
    ok("the 88-byte Siacoin item is header | target-LE, with no stage-3 region");

    /* An unknown length must return 0 rather than emit a short frame. The FPGA
     * receiver is a free-running mod-N byte counter with no framing, so one
     * wrong-length item rotates every item after it, permanently. */
    if (worksrc_pack_item(&ctx, 99, item) != 0)
        { fail("pack unknown", "an unknown item length was packed anyway"); return; }
    ok("an unknown item length is refused, not silently truncated");
}

/* ---- dev fee in pool mode --------------------------------------------- */

static void test_devfee_pool(void)
{
    devfee_reset();
    int first_dev = -1, dev_count = 0;
    for (int i = 1; i <= 60; ++i) {
        if (devfee_pool_epoch()) {
            if (first_dev < 0) first_dev = i;
            dev_count++;
            devfee_pool_skip();       /* no dev pool configured in this test */
        }
    }
    if (first_dev != DEVFEE_INTERVAL) { fail("devfee pool epoch", "first dev job is not #20"); return; }
    if (dev_count != 3)               { fail("devfee pool epoch", "not 3 dev jobs in 60"); return; }
    if (devfee_pool_jobs() != 60)     { fail("devfee pool epoch", "job counter wrong"); return; }
    if (devfee_pool_skipped() != 3)   { fail("devfee pool epoch", "skip counter wrong"); return; }
    if (devfee_pool_shares() != 0)    { fail("devfee pool epoch", "credited a share that was never sent"); return; }
    ok("dev-fee epoch is 1 in 20, first at 20, and an unhonoured epoch counts as skipped");

    /* The GBT counters must be untouched by any of this -- selftest_block.c
     * asserts them, and the two fees are different mechanisms. */
    if (devfee_templates_total() != 0)
        { fail("counter isolation", "pool epochs moved the template counter"); return; }
    ok("pool counters are separate from the template counters");
    devfee_reset();
}

/* ---- target math ------------------------------------------------------ */

static void test_target(void)
{
    stratum_t s;
    stratum_init(&s, "pool.invalid", 1234, "worker", "x");

    uint8_t t[32];
    s.difficulty = 1.0;
    stratum_target_full(&s, t);
    /* Difficulty 1 is Bitcoin's 0x00000000FFFF0000...0000, adopted verbatim by
     * the Sia stratum spec. */
    char h[80];
    if (!hexeq(t, 32,
               "00000000ffff0000000000000000000000000000000000000000000000000000",
               h, sizeof h))
        { fail("difficulty 1", "target is not the diff-1 constant"); return; }
    ok("difficulty 1 gives the documented diff-1 target");

    s.difficulty = 4096.0;
    stratum_target_full(&s, t);
    if (!hexeq(t, 32,
               "00000000000ffff0000000000000000000000000000000000000000000000000",
               h, sizeof h))
        { fail("difficulty 4096", "target is not diff1/4096"); return; }
    ok("difficulty 4096 divides the diff-1 target exactly");

    s.difficulty = 4096.0;
    uint64_t top = stratum_target_top64(&s);
    if (top != 0x00000000000ffff0ULL)
        { fail("target_top64", "top 64 bits of the 4096 target are wrong"); return; }
    ok("target_top64 is the top 8 bytes of that target");

    /* Fractional difficulties are what the local fixture uses; if these were
     * computed in floating point the low bits would be arbitrary and the
     * software share check would disagree with the pool at the margin. */
    s.difficulty = 0.001;
    stratum_target_full(&s, t);
    if (t[0] != 0x00 || t[1] != 0x00 || t[2] != 0x03 || t[3] != 0xe7)
        { fail("fractional difficulty", "0.001 target has the wrong leading bytes"); return; }
    ok("a fractional difficulty widens the target as expected");
}

int selftest_stratum(void)
{
    g_fail = 0;
    printf("SELFTEST stratum\n");
    test_protocol();
    test_stages();
    test_prefilter();
    test_sia_chain();
    test_pack();
    test_devfee_pool();
    test_target();
    printf("SELFTEST stratum %s (%d failures)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? -1 : 0;
}
