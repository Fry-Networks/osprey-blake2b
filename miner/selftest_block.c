/* Golden tests for the block-production additions.
 *
 * These are deliberately value-based rather than self-consistent: each expected
 * value comes from an independent source (BIP173 test vectors, a real mainnet
 * block, the field layout in vendor/knots block.h), not from running this code
 * and recording what it printed. A test that agrees with the implementation by
 * construction proves nothing -- that mistake has already cost this project two
 * shipped defects.
 */

#include "bech32.h"
#include "block.h"
#include "coinbase.h"
#include "devfee.h"
#include "merkle.h"
#include "sha256.h"
#include "work_item.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

static void okmsg(const char *name) { printf("  ok   %s\n", name); }

static void fail(const char *name, const char *why)
{
    printf("  FAIL %s: %s\n", name, why);
    g_fail++;
}

static void hexdump(const char *label, const uint8_t *b, size_t n)
{
    printf("       %s=", label);
    for (size_t i = 0; i < n; ++i) printf("%02x", b[i]);
    printf("\n");
}

static int eq(const uint8_t *a, const uint8_t *b, size_t n) { return memcmp(a, b, n) == 0; }

static int hexbin(const char *h, uint8_t *o, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1;
        o[i] = (uint8_t)v;
    }
    return 0;
}

/* ---- bech32 ----------------------------------------------------------- */

static void test_bech32(void)
{
    bech32_addr_t a;

    /* The dev fee address. Program independently derived with a reference
     * bech32 implementation before any of this C was written. */
    if (bech32_decode_addr(DEVFEE_ADDRESS, &a) != 0) { fail("bech32 devfee decode", "decode failed"); return; }
    uint8_t want[20];
    hexbin("12e023d773abcec4dbe4ebe90424ecac94e5a470", want, 20);
    if (a.witver != 0 || a.program_len != 20 || !eq(a.program, want, 20)) {
        fail("bech32 devfee program", "witness program mismatch");
        hexdump("got", a.program, a.program_len);
        return;
    }
    if (strcmp(a.hrp, "bc") != 0) { fail("bech32 devfee hrp", "not mainnet"); return; }
    okmsg("bech32 devfee address -> expected 20-byte program");

    /* BIP173 vector: this address must yield 0014 + the 20-byte hash. */
    uint8_t spk[64];
    int n = bech32_scriptpubkey(&a, spk, sizeof spk);
    if (n != 22 || spk[0] != 0x00 || spk[1] != 0x14 || !eq(spk + 2, want, 20))
        fail("bech32 scriptPubKey", "expected OP_0 PUSH20 <hash>");
    else
        okmsg("bech32 scriptPubKey is P2WPKH (0x00 0x14 ..)");

    /* Must REJECT a corrupted checksum. Silently accepting one is how a reward
     * gets paid to an address nobody controls. */
    char bad[128];
    snprintf(bad, sizeof bad, "%s", DEVFEE_ADDRESS);
    bad[strlen(bad) - 1] = (bad[strlen(bad) - 1] == 'e') ? 'q' : 'e';
    if (bech32_decode_addr(bad, &a) == 0) fail("bech32 bad checksum", "accepted a corrupted address");
    else okmsg("bech32 rejects a corrupted checksum");

    /* Mixed case is invalid per BIP173. */
    if (bech32_decode_addr("BC1QZTSZ84mn408vfklya05sgf8v4j2wtfrscszene", &a) == 0)
        fail("bech32 mixed case", "accepted mixed case");
    else
        okmsg("bech32 rejects mixed case");
}

/* ---- merkle ----------------------------------------------------------- */

static void test_merkle(void)
{
    /* Single element: the root is the element itself. */
    uint8_t one[32];
    memset(one, 0xab, 32);
    uint8_t root[32];
    uint8_t buf[32 * 4];
    memcpy(buf, one, 32);
    if (merkle_root(buf, 1, root) != 0 || !eq(root, one, 32)) fail("merkle single", "root != only element");
    else okmsg("merkle of one element is that element");

    /* Two elements: root = sha256d(a||b). Computed here independently of the
     * tree code. */
    uint8_t a32[32], b32[32];
    memset(a32, 0x11, 32); memset(b32, 0x22, 32);
    uint8_t cat[64], want[32];
    memcpy(cat, a32, 32); memcpy(cat + 32, b32, 32);
    sha256d(cat, 64, want);
    memcpy(buf, a32, 32); memcpy(buf + 32, b32, 32);
    if (merkle_root(buf, 2, root) != 0 || !eq(root, want, 32)) fail("merkle pair", "root != sha256d(a||b)");
    else okmsg("merkle of two elements is sha256d(a||b)");

    /* Three elements: the last is DUPLICATED (consensus quirk), so the root is
     * sha256d( sha256d(a||b) || sha256d(c||c) ). */
    uint8_t c32[32];
    memset(c32, 0x33, 32);
    uint8_t ab[32], cc[32], top[64], want3[32];
    memcpy(cat, a32, 32); memcpy(cat + 32, b32, 32); sha256d(cat, 64, ab);
    memcpy(cat, c32, 32); memcpy(cat + 32, c32, 32); sha256d(cat, 64, cc);
    memcpy(top, ab, 32); memcpy(top + 32, cc, 32);   sha256d(top, 64, want3);
    memcpy(buf, a32, 32); memcpy(buf + 32, b32, 32); memcpy(buf + 64, c32, 32);
    if (merkle_root(buf, 3, root) != 0 || !eq(root, want3, 32)) fail("merkle odd", "last element not duplicated");
    else okmsg("merkle duplicates the last element on an odd row");
}

/* ---- dev fee ---------------------------------------------------------- */

static void test_devfee(void)
{
    devfee_reset();
    const char *user = "bc1quser0000000000000000000000000000000000";
    int devs = 0;
    int first_dev = -1;
    for (int i = 1; i <= 60; ++i) {
        const char *a = devfee_next_payout(user);
        int is_dev = (strcmp(a, DEVFEE_ADDRESS) == 0);
        if (is_dev) { devs++; if (first_dev < 0) first_dev = i; }
        if (is_dev != devfee_current_is_dev()) { fail("devfee flag", "is_dev disagrees with the address"); return; }
    }
    if (devs != 3)          fail("devfee rate", "expected 3 dev templates in 60");
    else if (first_dev != DEVFEE_INTERVAL) fail("devfee phase", "first dev template was not #20");
    else if (devfee_templates_total() != 60 || devfee_templates_dev() != 3)
                             fail("devfee counters", "counters disagree with observed picks");
    else printf("  ok   devfee: 3/60 templates to dev (5%%), first at #%d\n", first_dev);
    devfee_reset();
}

/* ---- coinbase --------------------------------------------------------- */

static void test_coinbase(void)
{
    coinbase_t cb;
    /* Height 970278 and the real coinbasevalue seen on this chain. */
    if (coinbase_build(&cb, DEVFEE_ADDRESS, 312997000ULL, 970278, 0x1122334455667788ULL,
                       "6a24aa21a9ed1627fbbb3c68fa2088b10fffbd79c08c647e77f98ba5f4ef9fec4c50ed0000000000000000") != 0) {
        fail("coinbase build", "builder returned an error");
        return;
    }

    /* BIP34: scriptSig must begin with a minimally-encoded height push.
     * 970278 = 0xECE26, so little-endian that is 26 ce 0e and the push opcode
     * is 0x03. Offset 41 is the scriptSig LENGTH (0x0d = 13 = 1+3 height push
     * plus 1+8 extranonce push); the script itself starts at 42. */
    if (cb.stripped[41] != 0x0d ||
        cb.stripped[42] != 0x03 || cb.stripped[43] != 0x26 ||
        cb.stripped[44] != 0xce || cb.stripped[45] != 0x0e) {
        fail("coinbase BIP34 height", "height push is not minimal little-endian");
        hexdump("scriptSig head", cb.stripped + 41, 8);
    } else {
        okmsg("coinbase scriptSig starts with a minimal BIP34 height push");
    }

    /* Null prevout: 32 zero bytes then 0xffffffff. */
    uint8_t zero32[32] = {0};
    if (!eq(cb.stripped + 5, zero32, 32) ||
        cb.stripped[37] != 0xff || cb.stripped[40] != 0xff)
        fail("coinbase prevout", "input prevout is not null/0xffffffff");
    else
        okmsg("coinbase input has a null prevout");

    /* txid must be sha256d over the NO-WITNESS form. Recomputed here. */
    uint8_t want[32];
    sha256d(cb.stripped, cb.stripped_len, want);
    if (!eq(cb.txid, want, 32)) fail("coinbase txid", "txid is not sha256d(stripped)");
    else okmsg("coinbase txid == sha256d(non-witness serialisation)");

    /* The witness form must carry the segwit marker+flag and be longer. */
    if (cb.raw[4] != 0x00 || cb.raw[5] != 0x01)
        fail("coinbase witness marker", "expected 0x00 0x01 after version");
    else if (cb.raw_len <= cb.stripped_len)
        fail("coinbase witness length", "witness form is not longer than stripped");
    else
        okmsg("coinbase witness form carries the segwit marker/flag");

    /* The witness commitment must appear verbatim in the output set. */
    uint8_t wc[38];
    hexbin("6a24aa21a9ed1627fbbb3c68fa2088b10fffbd79c08c647e77f98ba5f4ef9fec4c50ed0000000000000000", wc, 38);
    int found = 0;
    for (size_t i = 0; i + 38 <= cb.stripped_len; ++i)
        if (eq(cb.stripped + i, wc, 38)) { found = 1; break; }
    if (!found) fail("coinbase witness commitment", "commitment not present in outputs");
    else okmsg("coinbase carries the template's witness commitment verbatim");

    /* A bad address must be refused, not silently paid to. */
    coinbase_t junk;
    if (coinbase_build(&junk, "bc1qnotarealaddressatall", 1, 1, 0, NULL) == 0)
        fail("coinbase bad address", "built a coinbase for an invalid address");
    else
        okmsg("coinbase refuses an invalid address");
}

/* ---- block header ----------------------------------------------------- */

static void test_block(void)
{
    knots_header_t h;
    knots_header_init(&h);
    h.nBits = 0x1903c2d4u;
    h.nTime = 0x11223344u;
    h.nNonce = 0xaabbccddu;
    h.m_height = 970278;
    h.m_txcount = 313;
    memset(h.hashMerkleRoot, 0x5a, 32);
    memset(h.hashPrevBlock, 0x7b, 32);

    uint8_t buf[256];
    int n = block_serialize_header(&h, buf, sizeof buf);
    if (n != BLOCK_HEADER_V2_LEN) { fail("block header length", "expected 164 bytes"); return; }
    okmsg("v2 header serialises to exactly 164 bytes");

    /* Version must carry the v2 flag. */
    uint32_t v = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    if (!(v & 0x80000000u)) fail("block header v2 flag", "VERSION_HEADER_V2_FLAG not set");
    else okmsg("header version carries the v2 flag");

    /* Field offsets, summed from the order in vendor/knots block.h:107 and :111:
     *   version@0 prev@4 merkle@36 time@68 bits@72 nonce@76
     *   nonce2@80 nonce3@84 extranonce@88 time_offset@104 txcount@108
     *   flags@110 clearbits@111 xor_key@112 height@128 mm_rhs@132  = 164
     * 313 = 0x0139 LE -> 39 01; 970278 = 0xECE26 LE -> 26 ce 0e 00. */
    if (memcmp(buf + 4, h.hashPrevBlock, 32) != 0)        fail("header prevblock offset", "prevblock not at 4");
    else if (memcmp(buf + 36, h.hashMerkleRoot, 32) != 0) fail("header merkle offset", "merkle root not at 36");
    else if (buf[108] != 0x39 || buf[109] != 0x01)        fail("header m_txcount offset", "txcount not at 108");
    else if (buf[128] != 0x26 || buf[129] != 0xce || buf[130] != 0x0e)
                                                          fail("header m_height offset", "height not at 128");
    else okmsg("header field offsets match block.h (prev@4 merkle@36 txcount@108 height@128)");

    /* A full block is header ++ compactsize ++ txs. */
    uint8_t cbraw[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    uint8_t txs[4]   = { 9, 9, 9, 9 };
    uint8_t blk[512];
    int bn = block_serialize(&h, cbraw, sizeof cbraw, txs, sizeof txs, 1, blk, sizeof blk);
    if (bn != BLOCK_HEADER_V2_LEN + 1 + 8 + 4) fail("block length", "unexpected total length");
    else if (blk[BLOCK_HEADER_V2_LEN] != 2)    fail("block tx count", "count should be 2 (coinbase + 1)");
    else okmsg("block = header ++ compactsize(ntx) ++ coinbase ++ txs");
}

int selftest_block_production(void)
{
    g_fail = 0;
    printf("SELFTEST block-production\n");
    test_bech32();
    test_merkle();
    test_devfee();
    test_coinbase();
    test_block();
    printf("SELFTEST block-production %s (%d failures)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? -1 : 0;
}
