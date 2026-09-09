/* Knots v2 header -> 168-byte FPGA work item, and the 17-byte reply.
 *
 * This file is a transcription of zynq/build_work_item.py and must stay
 * byte-identical to it. --selftest=vectors compares against a golden item
 * emitted by that script; if you change anything here, re-run it.
 *
 * Split of CBlockHeader::GetHash:
 *   stages 1,2  SHA256d tagged hashes   -> here (ARM)
 *   stages 3,4  BLAKE2b                 -> the FPGA
 *   stage  5    XOR mask + byte reverse -> here (ARM)
 */
#ifndef OSPREY_WORK_ITEM_H
#define OSPREY_WORK_ITEM_H

#include <stddef.h>
#include <stdint.h>

#define STAGE3_LEN      52
#define STAGE4_LEN      80
#define SLOTS           10
#define WORK_ITEM_LEN   168
#define RESULT_LEN      17
#define BLAKE2B_TARGET_SHIFT_MAINNET 22

/* Mirrors blake2b_reference.py:KnotsBlockHeaderV2. */
typedef struct {
    uint32_t nVersion;
    uint8_t  hashPrevBlock[32];
    uint8_t  hashMerkleRoot[32];
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    uint32_t m_nonce2;
    uint32_t m_nonce3;
    uint8_t  m_extranonce[16];
    uint32_t m_time_offset;
    uint16_t m_txcount;
    uint8_t  m_flags;
    uint8_t  m_xor_key_mask_clear_bits;
    uint8_t  m_xor_key[16];
    int32_t  m_height;
    uint8_t  m_mm_rhs[32];
} knots_header_t;

typedef struct {
    int      success;      /* frame flag byte was 0x01 */
    uint64_t nonce;        /* slot-4 value: nNonce = lo32, m_nonce2 = hi32 */
    uint64_t hash_top64;   /* the FPGA's prefilter word, byte-reversed */
} fpga_result_t;

void knots_header_init(knots_header_t *h);

/* Stage-3 and stage-4 messages, plus hash_a. mode 0 only; returns -1 otherwise. */
int  stage_inputs(const knots_header_t *h,
                  uint8_t ss3[STAGE3_LEN], uint8_t ss4[STAGE4_LEN],
                  uint8_t hash_a[32]);

/* The exact 168 bytes to write to the FPGA. */
int  build_work_item(const knots_header_t *h, uint64_t target_top64,
                     uint8_t out[WORK_ITEM_LEN]);

/* Full PoW hash, all five stages in software. Mirrors get_pow_hash(). */
int  get_pow_hash(const knots_header_t *h, uint8_t out[32]);

/* 256-bit target from compact bits, shifted. Big-endian byte array. */
void compact_to_target_shifted(uint32_t nBits, unsigned shift, uint8_t out[32]);
uint64_t target_top64_from_bits(uint32_t nBits, unsigned shift);

/* Compare a 32-byte big-endian hash against a 32-byte big-endian target. */
int  hash_meets_target(const uint8_t hash_be[32], const uint8_t target_be[32]);

int  parse_result(const uint8_t buf[RESULT_LEN], fpga_result_t *r);

#endif /* OSPREY_WORK_ITEM_H */
