#include "dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_NS         4
#define DNS_PORT       53
#define DNS_BUF        1500
#define TYPE_A         1
#define TYPE_CNAME     5
#define CLASS_IN       1

/* ---------------------------------------------------------------- helpers */

static void seterr(char *err, size_t errlen, const char *fmt, ...)
{
    if (!err || !errlen) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

/* Read nameserver lines out of /etc/resolv.conf.
 *
 * Only "nameserver <dotted-quad>" is honoured. A resolv.conf naming an IPv6
 * server or a search domain is not an error -- those lines are simply skipped,
 * and if nothing usable is left the caller falls back to a public resolver
 * rather than failing the whole miner over DNS config. */
static int load_nameservers(char ns[][INET_ADDRSTRLEN])
{
    FILE *f = fopen("/etc/resolv.conf", "r");
    int n = 0;
    if (f) {
        char line[256];
        while (n < MAX_NS && fgets(line, sizeof line, f)) {
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (strncmp(p, "nameserver", 10) != 0) continue;
            p += 10;
            while (*p == ' ' || *p == '\t') p++;
            char *e = p;
            while (*e && *e != '\n' && *e != '\r' && *e != ' ' && *e != '\t') e++;
            *e = '\0';
            struct in_addr probe;
            if (inet_pton(AF_INET, p, &probe) != 1) continue;   /* skip IPv6 etc. */
            snprintf(ns[n], INET_ADDRSTRLEN, "%s", p);
            n++;
        }
        fclose(f);
    }
    /* A device with an empty or IPv6-only resolv.conf still needs to reach a
     * pool. Falling back is better than a miner that will not start, and the
     * fallback is only consulted when the configured servers produced nothing. */
    if (n == 0) {
        snprintf(ns[n++], INET_ADDRSTRLEN, "%s", "1.1.1.1");
        if (n < MAX_NS) snprintf(ns[n++], INET_ADDRSTRLEN, "%s", "8.8.8.8");
    }
    return n;
}

/* Encode "a.b.c" as \1a\1b\1c\0 into buf. Returns bytes written, or -1. */
static int encode_qname(const char *host, uint8_t *buf, size_t buflen)
{
    size_t o = 0;
    const char *p = host;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t len = dot ? (size_t)(dot - p) : strlen(p);
        if (len == 0 || len > 63) return -1;
        if (o + 1 + len + 1 > buflen) return -1;
        buf[o++] = (uint8_t)len;
        memcpy(buf + o, p, len);
        o += len;
        if (!dot) break;
        p = dot + 1;
    }
    if (o + 1 > buflen) return -1;
    buf[o++] = 0;
    return (int)o;
}

/* Skip one (possibly compressed) name at `off`. Returns the offset just past
 * it, or -1. Compression pointers are followed only for length purposes: a
 * pointer is always the last two bytes of a name, so the caller advances by 2. */
static int skip_name(const uint8_t *msg, int len, int off)
{
    while (off < len) {
        uint8_t l = msg[off];
        if (l == 0) return off + 1;
        if ((l & 0xc0) == 0xc0) return (off + 2 <= len) ? off + 2 : -1;
        if (l > 63) return -1;
        off += 1 + l;
    }
    return -1;
}

/* -------------------------------------------------------------- one query */

static int query_one(const char *server, const char *host, uint16_t id,
                     char *out, size_t outlen, unsigned timeout_ms,
                     char *err, size_t errlen)
{
    uint8_t q[DNS_BUF];
    int o = 0;

    /* header: id, RD=1, 1 question */
    q[o++] = (uint8_t)(id >> 8);  q[o++] = (uint8_t)(id & 0xff);
    q[o++] = 0x01;                q[o++] = 0x00;      /* flags: recursion desired */
    q[o++] = 0x00;                q[o++] = 0x01;      /* QDCOUNT = 1 */
    q[o++] = 0x00;                q[o++] = 0x00;      /* ANCOUNT */
    q[o++] = 0x00;                q[o++] = 0x00;      /* NSCOUNT */
    q[o++] = 0x00;                q[o++] = 0x00;      /* ARCOUNT */

    int qn = encode_qname(host, q + o, sizeof q - (size_t)o - 4);
    if (qn < 0) { seterr(err, errlen, "hostname too long for DNS: %s", host); return -1; }
    o += qn;
    q[o++] = 0x00; q[o++] = TYPE_A;
    q[o++] = 0x00; q[o++] = CLASS_IN;
    const int qlen = o;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { seterr(err, errlen, "dns socket: %s", strerror(errno)); return -1; }

    struct timeval tv;
    tv.tv_sec  = (time_t)(timeout_ms / 1000);
    tv.tv_usec = (suseconds_t)((timeout_ms % 1000) * 1000);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(DNS_PORT);
    if (inet_pton(AF_INET, server, &sa.sin_addr) != 1) {
        seterr(err, errlen, "bad nameserver %s", server);
        close(fd);
        return -1;
    }

    if (sendto(fd, q, (size_t)qlen, 0, (struct sockaddr *)&sa, sizeof sa) != qlen) {
        seterr(err, errlen, "dns sendto %s: %s", server, strerror(errno));
        close(fd);
        return -1;
    }

    uint8_t r[DNS_BUF];
    ssize_t n = recv(fd, r, sizeof r, 0);
    close(fd);
    if (n < 12) { seterr(err, errlen, "dns no reply from %s", server); return -1; }

    if (((r[0] << 8) | r[1]) != id) { seterr(err, errlen, "dns id mismatch"); return -1; }
    int rcode = r[3] & 0x0f;
    if (rcode != 0) { seterr(err, errlen, "dns rcode %d for %s", rcode, host); return -1; }

    int qd = (r[4] << 8) | r[5];
    int an = (r[6] << 8) | r[7];
    if (an <= 0) { seterr(err, errlen, "dns no answer for %s", host); return -1; }

    int off = 12;
    for (int i = 0; i < qd; ++i) {
        off = skip_name(r, (int)n, off);
        if (off < 0 || off + 4 > n) { seterr(err, errlen, "dns malformed question"); return -1; }
        off += 4;
    }

    /* Walk the answers and take the first A record. A CNAME chain is common
     * for pool hostnames and the A records for the target are normally in the
     * same response, so following the chain by name is unnecessary -- just keep
     * scanning past the CNAMEs. */
    for (int i = 0; i < an; ++i) {
        off = skip_name(r, (int)n, off);
        if (off < 0 || off + 10 > n) { seterr(err, errlen, "dns malformed answer"); return -1; }
        int type   = (r[off] << 8) | r[off + 1];
        int rdlen  = (r[off + 8] << 8) | r[off + 9];
        off += 10;
        if (off + rdlen > n) { seterr(err, errlen, "dns rdata overruns packet"); return -1; }
        if (type == TYPE_A && rdlen == 4) {
            struct in_addr a;
            memcpy(&a, r + off, 4);
            if (!inet_ntop(AF_INET, &a, out, (socklen_t)outlen)) {
                seterr(err, errlen, "dns inet_ntop: %s", strerror(errno));
                return -1;
            }
            return 0;
        }
        off += rdlen;   /* CNAME or anything else: keep looking */
    }

    seterr(err, errlen, "dns answer for %s carried no A record", host);
    return -1;
}

/* ------------------------------------------------------------------- API */

int dns_resolve_a(const char *host, char *out, size_t outlen,
                  unsigned timeout_ms, char *err, size_t errlen)
{
    if (!host || !*host) { seterr(err, errlen, "empty hostname"); return -1; }

    struct in_addr probe;
    if (inet_pton(AF_INET, host, &probe) == 1) {
        snprintf(out, outlen, "%s", host);
        return 0;
    }

    char ns[MAX_NS][INET_ADDRSTRLEN];
    int nns = load_nameservers(ns);

    /* The transaction id only has to be unpredictable enough that a stale reply
     * from a previous query is not mistaken for this one; this socket is
     * connectionless but short-lived and unbound to a fixed port. */
    static uint16_t seq;
    uint16_t id = (uint16_t)(((uintptr_t)host >> 4) ^ (uint16_t)(++seq * 2654435761u));

    char last[192];
    last[0] = '\0';
    for (int i = 0; i < nns; ++i) {
        char e[192];
        e[0] = '\0';
        if (query_one(ns[i], host, (uint16_t)(id + i), out, outlen,
                      timeout_ms, e, sizeof e) == 0)
            return 0;
        snprintf(last, sizeof last, "%s", e);
    }

    seterr(err, errlen, "resolve %s failed: %s", host, last[0] ? last : "no nameserver answered");
    return -1;
}
