#include "worksrc.h"

#include <stdio.h>
#include <string.h>

/* Four is the whole world: gbt, synthetic, stratum, and room for one more
 * without touching this file. A registry that has to grow past that is a sign
 * the miner has become something other than a miner. */
#define MAX_SOURCES 4

static const worksrc_t *g_sources[MAX_SOURCES];
static int g_count;

static void put_target_le(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}

size_t worksrc_pack_item(const work_ctx_t *ctx, size_t item_len,
                         uint8_t out[WORK_ITEM_LEN])
{
    memset(out, 0, WORK_ITEM_LEN);

    if (item_len == WORK_ITEM_LEN) {                 /* 168: Knots */
        memcpy(out,             ctx->ss3, STAGE3_LEN);
        memcpy(out + SLOTS * 8, ctx->ss4, STAGE4_LEN);
        put_target_le(out + 2 * SLOTS * 8, ctx->target_top64);
        return WORK_ITEM_LEN;
    }

    if (item_len == STAGE4_LEN + 8) {                /* 88: Siacoin */
        memcpy(out, ctx->ss4, STAGE4_LEN);
        put_target_le(out + STAGE4_LEN, ctx->target_top64);
        return STAGE4_LEN + 8;
    }

    return 0;
}

void worksrc_register(const worksrc_t *src)
{
    if (!src || !src->name || g_count >= MAX_SOURCES) return;
    for (int i = 0; i < g_count; ++i)
        if (!strcmp(g_sources[i]->name, src->name)) { g_sources[i] = src; return; }
    g_sources[g_count++] = src;
}

const worksrc_t *worksrc_find(const char *name)
{
    if (!name) return NULL;
    for (int i = 0; i < g_count; ++i)
        if (!strcmp(g_sources[i]->name, name)) return g_sources[i];
    return NULL;
}

const char *worksrc_list(void)
{
    static char buf[128];
    size_t o = 0;
    buf[0] = '\0';
    for (int i = 0; i < g_count; ++i) {
        int n = snprintf(buf + o, sizeof buf - o, "%s%s", o ? " | " : "", g_sources[i]->name);
        if (n < 0 || (size_t)n >= sizeof buf - o) break;
        o += (size_t)n;
    }
    return buf;
}
