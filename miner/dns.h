/* Minimal DNS A-record resolver.
 *
 * Why this file exists at all: the miner links -static so it can run on the
 * device's Ubuntu 16.04 userspace (see the Makefile header), and a -static
 * glibc cannot do NSS lookups -- getaddrinfo() in a static binary either fails
 * or drags in the build host's libnss_* at runtime, which the device does not
 * have. That is why rpc_call() refuses a non-numeric --rpc-host and says so:
 *
 *     "--rpc-host must be a numeric IPv4 address, got '%s'"
 *
 * A pool is a hostname, not an address, so the stratum backend needs a
 * resolver that does not go through NSS. This is that resolver: it reads
 * /etc/resolv.conf itself and speaks DNS over UDP directly, so it has no libc
 * dependency beyond sockets.
 *
 * Deliberately small. No caching beyond what the caller keeps, no AAAA (the
 * device has no working IPv6 route), no TCP fallback and no EDNS -- an A
 * record for a pool hostname fits in 512 bytes many times over. If a lookup
 * ever needs more than that, the right answer is a numeric address in the
 * config, not a bigger resolver here.
 */
#ifndef DNS_H
#define DNS_H

#include <stddef.h>
#include <stdint.h>

/* Resolve `host` to a dotted-quad in `out` (at least INET_ADDRSTRLEN bytes).
 *
 * A host that is already a dotted-quad is copied through untouched, so callers
 * can hand this whatever the operator configured without pre-checking.
 *
 * Returns 0 on success. On failure returns -1 and, if `err` is non-NULL,
 * writes a human-readable reason into it -- the caller surfaces that in
 * status.json, which is the only debugging surface this device has.
 *
 * Blocks for at most (timeout_ms) per nameserver tried.
 */
int dns_resolve_a(const char *host, char *out, size_t outlen,
                  unsigned timeout_ms, char *err, size_t errlen);

#endif /* DNS_H */
