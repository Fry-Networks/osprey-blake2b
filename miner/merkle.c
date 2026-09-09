#include "merkle.h"
#include "sha256.h"

#include <string.h>

int merkle_root(uint8_t *ids, size_t count, uint8_t out[32])
{
    if (!ids || !out || count == 0) return -1;

    while (count > 1) {
        size_t pairs = (count + 1) / 2;
        for (size_t i = 0; i < pairs; ++i) {
            uint8_t cat[64];
            memcpy(cat, ids + (2 * i) * 32, 32);
            /* Bitcoin duplicates the final element when the row is odd. This is
             * the CVE-2012-2459 quirk: it is consensus behaviour and must be
             * reproduced exactly, not "fixed". */
            if (2 * i + 1 < count) memcpy(cat + 32, ids + (2 * i + 1) * 32, 32);
            else                   memcpy(cat + 32, ids + (2 * i) * 32, 32);
            sha256d(cat, 64, ids + i * 32);
        }
        count = pairs;
    }
    memcpy(out, ids, 32);
    return 0;
}
