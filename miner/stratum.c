/* MSG_NOSIGNAL and TCP_NODELAY: a SIGPIPE on a dropped pool connection would
 * kill a miner that is otherwise perfectly able to reconnect. */
#define _GNU_SOURCE

#include "stratum.h"
#include "dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define BACKOFF_MIN_S 2
#define BACKOFF_MAX_S 120
#define DNS_TIMEOUT_MS 4000

/* ------------------------------------------------------------------ log */

static void (*g_sink)(const char *);

void stratum_set_logger(void (*sink)(const char *line)) { g_sink = sink; }

static void slog(const char *fmt, ...)
{
    if (!g_sink) return;
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    g_sink(line);
}

/* ------------------------------------------------------------------ JSON
 *
 * A hand-rolled scanner, for the same reason miner.c scrapes getblocktemplate
 * with strstr: this program links -static and ships no dependencies, and a
 * stratum frame is a flat object whose params are a flat array. What miner.c's
 * json_num/json_str cannot do is index an array, and mining.notify is nine
 * positional parameters -- hence a real (if minimal) value walker rather than
 * another substring search. Every function takes a pointer AT a value and
 * returns a pointer just past it, so nesting is handled by construction.
 */

static const char *js_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

static const char *js_skip(const char *p)
{
    p = js_ws(p);
    switch (*p) {
    case '"': {
        p++;
        while (*p && *p != '"') p += (*p == '\\' && p[1]) ? 2 : 1;
        return *p ? p + 1 : NULL;
    }
    case '[':
    case '{': {
        char open = *p, close = (open == '[') ? ']' : '}';
        int depth = 0;
        while (*p) {
            if (*p == '"') {                 /* strings may contain brackets */
                p++;
                while (*p && *p != '"') p += (*p == '\\' && p[1]) ? 2 : 1;
                if (!*p) return NULL;
                p++;
                continue;
            }
            if (*p == open)  depth++;
            if (*p == close) { depth--; if (!depth) return p + 1; }
            p++;
        }
        return NULL;
    }
    default: {
        const char *s = p;
        while (*p && *p != ',' && *p != ']' && *p != '}' &&
               *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
        return (p > s) ? p : NULL;
    }
    }
}

/* `obj` points at '{'. Returns a pointer at the value for `key`, or NULL. */
static const char *js_get(const char *obj, const char *key)
{
    obj = js_ws(obj);
    if (*obj != '{') return NULL;
    const char *p = js_ws(obj + 1);
    if (*p == '}') return NULL;
    size_t klen = strlen(key);
    for (;;) {
        p = js_ws(p);
        if (*p != '"') return NULL;
        const char *ks = p + 1;
        const char *ke = ks;
        while (*ke && *ke != '"') ke += (*ke == '\\' && ke[1]) ? 2 : 1;
        if (!*ke) return NULL;
        int match = ((size_t)(ke - ks) == klen) && (memcmp(ks, key, klen) == 0);
        p = js_ws(ke + 1);
        if (*p != ':') return NULL;
        p = js_ws(p + 1);
        if (match) return p;
        p = js_skip(p);
        if (!p) return NULL;
        p = js_ws(p);
        if (*p == ',') { p++; continue; }
        return NULL;
    }
}

/* `arr` points at '['. Returns element `idx`, or NULL. */
static const char *js_elem(const char *arr, int idx)
{
    arr = js_ws(arr);
    if (*arr != '[') return NULL;
    const char *p = js_ws(arr + 1);
    if (*p == ']') return NULL;
    for (int i = 0; ; ++i) {
        if (i == idx) return p;
        p = js_skip(p);
        if (!p) return NULL;
        p = js_ws(p);
        if (*p != ',') return NULL;
        p = js_ws(p + 1);
    }
}

static int js_count(const char *arr)
{
    arr = js_ws(arr);
    if (*arr != '[') return -1;
    const char *p = js_ws(arr + 1);
    if (*p == ']') return 0;
    int n = 0;
    for (;;) {
        n++;
        p = js_skip(p);
        if (!p) return -1;
        p = js_ws(p);
        if (*p == ',') { p = js_ws(p + 1); continue; }
        return (*p == ']') ? n : -1;
    }
}

/* Copy a JSON string value (v points at '"') into out. Escapes are not
 * unescaped: every string this protocol carries is hex or an identifier, and
 * silently mangling one would be worse than passing it through. */
static int js_str(const char *v, char *out, size_t outlen)
{
    v = js_ws(v);
    if (*v != '"') return -1;
    v++;
    size_t o = 0;
    while (*v && *v != '"') {
        if (o + 1 >= outlen) return -1;
        out[o++] = *v++;
    }
    if (*v != '"') return -1;
    out[o] = '\0';
    return 0;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode a JSON hex string into bytes. An empty string decodes to zero bytes,
 * which is legitimate -- this pool sends coinb2 and version as "". */
static int js_hex(const char *v, uint8_t *out, size_t maxlen, size_t *outlen)
{
    char buf[2 * STRATUM_MAX_CB + 4];
    if (js_str(v, buf, sizeof buf) != 0) return -1;
    size_t n = strlen(buf);
    if (n % 2) return -1;
    if (n / 2 > maxlen) return -1;
    for (size_t i = 0; i < n / 2; ++i) {
        int hi = hexval(buf[2 * i]), lo = hexval(buf[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *outlen = n / 2;
    return 0;
}

static double js_num(const char *v) { return strtod(js_ws(v), NULL); }

static int js_true(const char *v)
{
    v = js_ws(v);
    return strncmp(v, "true", 4) == 0;
}

static void bin2hex(const uint8_t *b, size_t n, char *out)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) { out[2 * i] = H[b[i] >> 4]; out[2 * i + 1] = H[b[i] & 15]; }
    out[2 * n] = '\0';
}

/* -------------------------------------------------------------- target math
 *
 * Stratum difficulty 1 is Bitcoin's 0x00000000FFFF0000...0000, which the Sia
 * stratum spec adopted verbatim (it differs from Sia's own notion of
 * difficulty by ~2^32, which is exactly why the spec calls it out).
 *
 * The division is done bit by bit on the 256-bit value rather than in floating
 * point. A double carries 53 bits of mantissa, so a float divide would leave
 * the low ~11 bits of the top word arbitrary -- harmless for an accept rate,
 * but it would make the software share check disagree with the pool's at the
 * margin, and a share rejected for a reason we cannot reproduce locally is the
 * worst possible failure mode here.
 */
static void diff1_target(uint8_t out[32])
{
    memset(out, 0, 32);
    out[4] = 0xff;
    out[5] = 0xff;
}

/* out = in / divisor, both 256-bit big-endian. */
static void bn_div_u64(const uint8_t in[32], uint64_t divisor, uint8_t out[32])
{
    uint64_t rem = 0;
    memset(out, 0, 32);
    if (divisor == 0) return;
    for (int i = 0; i < 256; ++i) {
        int byte = i / 8, bit = 7 - (i % 8);
        rem = (rem << 1) | (uint64_t)((in[byte] >> bit) & 1);
        if (rem >= divisor) {
            rem -= divisor;
            out[byte] |= (uint8_t)(1u << bit);
        }
    }
}

/* out = in << 32, 256-bit big-endian (i.e. drop the top 4 bytes). */
static void bn_shl32(const uint8_t in[32], uint8_t out[32])
{
    memmove(out, in + 4, 28);
    memset(out + 28, 0, 4);
}

void stratum_target_full(const stratum_t *s, uint8_t out[32])
{
    double d = s->difficulty;
    /* Below this the shifted quotient would overflow 256 bits, and no pool
     * sends a difficulty anywhere near it. */
    if (!(d > 1e-9)) d = 1.0;

    uint64_t dscaled = (uint64_t)(d * 4294967296.0 + 0.5);   /* d * 2^32 */
    if (dscaled == 0) dscaled = 1;

    uint8_t one[32], q[32];
    diff1_target(one);
    bn_div_u64(one, dscaled, q);
    bn_shl32(q, out);
}

uint64_t stratum_target_top64(const stratum_t *s)
{
    uint8_t t[32];
    stratum_target_full(s, t);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | t[i];
    return v;
}

/* ------------------------------------------------------------------ socket */

static void drop(stratum_t *s, const char *why)
{
    if (s->fd >= 0) { close(s->fd); s->fd = -1; }
    s->subscribed = s->authorized = s->have_job = 0;
    s->rx_len = 0;
    if (why && *why) {
        snprintf(s->last_error, sizeof s->last_error, "%s", why);
        slog("stratum: disconnected (%s)", why);
    }
}

static int send_line(stratum_t *s, const char *line)
{
    if (s->fd < 0) return -1;
    size_t len = strlen(line);
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(s->fd, line + off, len - off, MSG_NOSIGNAL);
        if (n > 0) { off += (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        drop(s, "send failed");
        return -1;
    }
    return 0;
}

static void dial(stratum_t *s, uint64_t now)
{
    if (now < s->retry_at) return;

    if (s->addr[0] == '\0') {
        char err[192];
        if (dns_resolve_a(s->host, s->addr, sizeof s->addr, DNS_TIMEOUT_MS,
                          err, sizeof err) != 0) {
            s->addr[0] = '\0';
            snprintf(s->last_error, sizeof s->last_error, "%s", err);
            slog("stratum: %s", err);
            s->backoff_s = s->backoff_s ? (s->backoff_s * 2) : BACKOFF_MIN_S;
            if (s->backoff_s > BACKOFF_MAX_S) s->backoff_s = BACKOFF_MAX_S;
            s->retry_at = now + s->backoff_s;
            return;
        }
        slog("stratum: %s resolves to %s", s->host, s->addr);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { snprintf(s->last_error, sizeof s->last_error, "socket: %s", strerror(errno)); return; }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)s->port);
    if (inet_pton(AF_INET, s->addr, &sa.sin_addr) != 1) {
        close(fd);
        s->addr[0] = '\0';                    /* force a re-resolve next time */
        snprintf(s->last_error, sizeof s->last_error, "bad pool address");
        return;
    }

    /* A blocking connect with a bounded timeout, done the portable way: dial
     * non-blocking, then wait on writability. The miner's loop can afford the
     * few seconds this costs -- it happens once per reconnect, and the FPGA is
     * idle anyway while there is no work. */
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    int rc = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (rc != 0 && errno == EINPROGRESS) {
        fd_set w;
        FD_ZERO(&w);
        FD_SET(fd, &w);
        struct timeval tv = { .tv_sec = 8, .tv_usec = 0 };
        rc = select(fd + 1, NULL, &w, NULL, &tv);
        if (rc > 0) {
            int soerr = 0;
            socklen_t l = sizeof soerr;
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &l);
            rc = soerr ? -1 : 0;
            if (soerr) errno = soerr;
        } else {
            /* select() timed out or failed. errno still holds EINPROGRESS from
             * the connect() above, and reporting "Operation now in progress" as
             * the reason a connection FAILED is actively misleading -- it reads
             * like the dial is still running. Name what actually happened. */
            if (rc == 0) errno = ETIMEDOUT;
            rc = -1;
        }
    }
    if (rc != 0) {
        snprintf(s->last_error, sizeof s->last_error,
                 "connect %.120s:%d: %s", s->host, s->port, strerror(errno));
        slog("stratum: %s", s->last_error);
        close(fd);
        s->backoff_s = s->backoff_s ? (s->backoff_s * 2) : BACKOFF_MIN_S;
        if (s->backoff_s > BACKOFF_MAX_S) s->backoff_s = BACKOFF_MAX_S;
        s->retry_at = now + s->backoff_s;
        return;
    }

    fcntl(fd, F_SETFL, fl | O_NONBLOCK);      /* stay non-blocking for reads */
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

    s->fd = fd;
    s->rx_len = 0;
    s->backoff_s = 0;
    s->reconnects++;
    slog("stratum: connected to %s:%d (%s)", s->host, s->port, s->addr);

    char line[512];
    s->sub_id = ++s->next_id;
    snprintf(line, sizeof line,
             "{\"id\":%llu,\"method\":\"mining.subscribe\",\"params\":[\"osprey-blake2b/1.0\"]}\n",
             (unsigned long long)s->sub_id);
    if (send_line(s, line) != 0) return;

    s->auth_id = ++s->next_id;
    snprintf(line, sizeof line,
             "{\"id\":%llu,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}\n",
             (unsigned long long)s->auth_id, s->worker, s->password);
    send_line(s, line);
}

/* ---------------------------------------------------------------- dispatch */

static void on_subscribe(stratum_t *s, const char *result)
{
    /* result = [ [[ "mining.notify", <id> ], ...], <extranonce1 hex>, <en2 size> ] */
    const char *en1 = js_elem(result, 1);
    const char *sz  = js_elem(result, 2);
    if (!en1 || !sz) { slog("stratum: malformed subscribe result"); return; }

    if (js_hex(en1, s->extranonce1, sizeof s->extranonce1, &s->en1_len) != 0) {
        slog("stratum: subscribe extranonce1 is not hex");
        return;
    }
    double n = js_num(sz);
    if (n < 1 || n > (double)STRATUM_MAX_EN2) {
        slog("stratum: refusing extranonce2_size %g", n);
        return;
    }
    s->en2_size = (size_t)n;
    s->subscribed = 1;

    char h[2 * STRATUM_MAX_EN1 + 1];
    bin2hex(s->extranonce1, s->en1_len, h);
    slog("stratum: subscribed extranonce1=%s extranonce2_size=%zu", h, s->en2_size);
}

static void on_notify(stratum_t *s, const char *params)
{
    int n = js_count(params);
    if (n < 9) { slog("stratum: notify has %d params, need 9", n); return; }

    stratum_job_t j;
    memset(&j, 0, sizeof j);

    const char *p_job   = js_elem(params, 0);
    const char *p_prev  = js_elem(params, 1);
    const char *p_cb1   = js_elem(params, 2);
    const char *p_cb2   = js_elem(params, 3);
    const char *p_br    = js_elem(params, 4);
    const char *p_bits  = js_elem(params, 6);
    const char *p_ntime = js_elem(params, 7);
    const char *p_clean = js_elem(params, 8);
    if (!p_job || !p_prev || !p_cb1 || !p_cb2 || !p_br || !p_bits || !p_ntime) {
        slog("stratum: notify missing a parameter");
        return;
    }

    size_t got;
    if (js_str(p_job, j.job_id, sizeof j.job_id) != 0) { slog("stratum: bad job id"); return; }
    if (js_hex(p_prev, j.prevhash, 32, &got) != 0 || got != 32) {
        slog("stratum: prevhash is not 32 bytes"); return;
    }
    if (js_hex(p_cb1, j.coinb1, STRATUM_MAX_CB, &j.coinb1_len) != 0) {
        slog("stratum: coinb1 too long or not hex"); return;
    }
    if (js_hex(p_cb2, j.coinb2, STRATUM_MAX_CB, &j.coinb2_len) != 0) {
        slog("stratum: coinb2 too long or not hex"); return;
    }

    int nb = js_count(p_br);
    if (nb < 0 || nb > STRATUM_MAX_BRANCHES) { slog("stratum: %d merkle branches", nb); return; }
    for (int i = 0; i < nb; ++i) {
        const char *e = js_elem(p_br, i);
        if (!e || js_hex(e, j.branches[i], 32, &got) != 0 || got != 32) {
            slog("stratum: merkle branch %d is not 32 bytes", i);
            return;
        }
    }
    j.nbranches = nb;

    /* ntime is 64-bit here, not Bitcoin's 32. A pool that sent 4 bytes would be
     * speaking the wrong dialect entirely, so this is a hard reject rather than
     * a zero-extend -- mining on a misparsed timestamp produces shares that are
     * silently unacceptable and look like a hardware fault. */
    if (js_hex(p_ntime, j.ntime, 8, &got) != 0 || got != 8) {
        slog("stratum: ntime is %zu bytes, expected 8 (Sia dialect)", got);
        return;
    }

    uint8_t bits[4];
    if (js_hex(p_bits, bits, 4, &got) != 0 || got != 4) { slog("stratum: bad nbits"); return; }
    j.nbits = ((uint32_t)bits[3] << 24) | ((uint32_t)bits[2] << 16) |
              ((uint32_t)bits[1] << 8)  |  (uint32_t)bits[0];      /* wire is LE */

    j.clean = p_clean ? js_true(p_clean) : 1;
    j.seq   = s->job.seq + 1;

    s->job = j;
    s->have_job = 1;
    s->jobs_received++;
    slog("stratum: job %s branches=%d clean=%d nbits=%08x",
         j.job_id, j.nbranches, j.clean, j.nbits);
}

static void on_line(stratum_t *s, const char *line)
{
    const char *meth = js_get(line, "method");
    if (meth) {
        char m[64];
        if (js_str(meth, m, sizeof m) != 0) return;
        const char *params = js_get(line, "params");
        if (!params) return;
        if (!strcmp(m, "mining.notify")) {
            on_notify(s, params);
        } else if (!strcmp(m, "mining.set_difficulty")) {
            const char *d = js_elem(params, 0);
            if (d) {
                s->difficulty = js_num(d);
                slog("stratum: difficulty %g (target_top64=%016llx)",
                     s->difficulty, (unsigned long long)stratum_target_top64(s));
            }
        } else if (!strcmp(m, "mining.set_extranonce")) {
            /* Same payload shape as the tail of a subscribe result. A pool that
             * rotates the extranonce mid-session invalidates every in-flight
             * work item, so the job is dropped too -- mining on a stale
             * extranonce produces shares the pool cannot match to any job. */
            const char *e = js_elem(params, 0);
            const char *z = js_elem(params, 1);
            size_t got;
            if (e && js_hex(e, s->extranonce1, sizeof s->extranonce1, &got) == 0) {
                s->en1_len = got;
                if (z) {
                    double n = js_num(z);
                    if (n >= 1 && n <= (double)STRATUM_MAX_EN2) s->en2_size = (size_t)n;
                }
                s->have_job = 0;
                slog("stratum: extranonce rotated (%zu bytes), dropping current job",
                     s->en1_len);
            }
        } else if (!strcmp(m, "client.reconnect")) {
            drop(s, "pool asked us to reconnect");
        }
        return;
    }

    const char *idv = js_get(line, "id");
    if (!idv) return;
    uint64_t id = (uint64_t)js_num(idv);
    const char *res = js_get(line, "result");
    const char *err = js_get(line, "error");

    if (id == s->sub_id) {
        if (res && *js_ws(res) == '[') on_subscribe(s, res);
        else slog("stratum: subscribe rejected");
        return;
    }
    if (id == s->auth_id) {
        s->authorized = (res && js_true(res));
        slog("stratum: authorize %s", s->authorized ? "OK" : "REJECTED");
        if (!s->authorized) snprintf(s->last_error, sizeof s->last_error,
                                     "pool rejected worker %s", s->worker);
        return;
    }

    /* Anything else with an id is a submit verdict. */
    if (res && js_true(res)) {
        s->shares_accepted++;
        slog("stratum: share ACCEPTED (%llu/%llu)",
             (unsigned long long)s->shares_accepted,
             (unsigned long long)s->shares_submitted);
    } else {
        s->shares_rejected++;
        s->last_reject[0] = '\0';
        if (err && *js_ws(err) == '[') {
            const char *msg = js_elem(err, 1);
            if (msg) js_str(msg, s->last_reject, sizeof s->last_reject);
        }
        slog("stratum: share REJECTED (%s)",
             s->last_reject[0] ? s->last_reject : "no reason given");
    }
}

/* -------------------------------------------------------------------- API */

void stratum_init(stratum_t *s, const char *host, int port,
                  const char *worker, const char *password)
{
    memset(s, 0, sizeof *s);
    s->fd = -1;
    s->port = port;
    s->difficulty = 1.0;
    s->en2_size = 8;
    snprintf(s->host,     sizeof s->host,     "%s", host     ? host     : "");
    snprintf(s->worker,   sizeof s->worker,   "%s", worker   ? worker   : "");
    snprintf(s->password, sizeof s->password, "%s", password ? password : "x");
}

void stratum_poll(stratum_t *s, uint64_t now)
{
    if (s->fd < 0) { dial(s, now); return; }

    for (;;) {
        if (s->rx_len + 1 >= sizeof s->rx) {
            /* No newline in a full buffer means the peer is not speaking
             * line-delimited JSON at us; keeping the bytes would only wedge
             * the parser permanently. */
            drop(s, "rx overflow with no line terminator");
            return;
        }
        ssize_t n = recv(s->fd, s->rx + s->rx_len, sizeof s->rx - s->rx_len - 1, 0);
        if (n == 0) { drop(s, "pool closed the connection"); return; }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (errno == EINTR) continue;
            drop(s, strerror(errno));
            return;
        }
        s->rx_len += (size_t)n;
        s->rx[s->rx_len] = '\0';
    }

    char *start = s->rx;
    char *nl;
    while ((nl = memchr(start, '\n', (size_t)((s->rx + s->rx_len) - start))) != NULL) {
        *nl = '\0';
        if (nl > start) on_line(s, start);
        start = nl + 1;
        if (s->fd < 0) return;                 /* a handler dropped us */
    }
    size_t left = (size_t)((s->rx + s->rx_len) - start);
    memmove(s->rx, start, left);
    s->rx_len = left;
    s->rx[left] = '\0';
}

int stratum_ready(const stratum_t *s)
{
    return s->fd >= 0 && s->subscribed && s->authorized && s->have_job;
}

int stratum_submit(stratum_t *s, const char *job_id,
                   const uint8_t *en2, size_t en2_len,
                   const uint8_t ntime[8], const uint8_t nonce[8])
{
    if (s->fd < 0) return -1;

    char en2h[2 * STRATUM_MAX_EN2 + 1], nth[17], noh[17], line[1024];
    bin2hex(en2, en2_len, en2h);
    bin2hex(ntime, 8, nth);
    bin2hex(nonce, 8, noh);

    snprintf(line, sizeof line,
             "{\"id\":%llu,\"method\":\"mining.submit\",\"params\":"
             "[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]}\n",
             (unsigned long long)(++s->next_id),
             s->worker, job_id, en2h, nth, noh);

    if (send_line(s, line) != 0) return -1;
    s->shares_submitted++;
    slog("stratum: submit job=%s en2=%s ntime=%s nonce=%s", job_id, en2h, nth, noh);
    return 0;
}

void stratum_close(stratum_t *s) { drop(s, NULL); }

void stratum_test_feed(stratum_t *s, const char *line) { on_line(s, line); }
