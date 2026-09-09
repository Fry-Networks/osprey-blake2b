/* BLAKE2b (RFC 7693), unkeyed, configurable digest length.
 *
 * Host-side verification only. The FPGA does the production hashing; this exists
 * so every candidate the FPGA reports can be recomputed and checked before it is
 * ever submitted, and so --selftest can prove the C build agrees with the Python
 * golden reference.
 */
#ifndef OSPREY_BLAKE2B_H
#define OSPREY_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

/* Unkeyed BLAKE2b. outlen 1..64. Mirrors hashlib.blake2b(data, digest_size=outlen). */
void blake2b_nokey(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

#endif /* OSPREY_BLAKE2B_H */
