#include "blake2b.h"

#include <ledger_assert.h>
#include <stdint.h>
#include <string.h>

#include "sia.h"

void blake2b_init(cx_blake2b_t *S) {
    LEDGER_ASSERT(CX_OK == cx_blake2b_init_no_throw(S, 256), "blake2b_init failed");
}

void blake2b_update(cx_blake2b_t *S, const uint8_t *in, uint64_t inlen) {
    LEDGER_ASSERT(CX_OK == cx_hash_no_throw((cx_hash_t *)S, 0, in, inlen, NULL, 0), "blake2b_update failed");
}

void blake2b_final(cx_blake2b_t *S, uint8_t *out, uint64_t outlen) {
    uint8_t buf[32] = {0};
    LEDGER_ASSERT(CX_OK == cx_hash_no_throw((cx_hash_t *)S, CX_LAST, NULL, 0, buf, sizeof(buf)), "blake2b_final failed");
    memmove(out, buf, outlen);
}

void blake2b(uint8_t *out, uint64_t outlen, const uint8_t *in, uint64_t inlen) {
    cx_blake2b_t S;
    blake2b_init(&S);
    blake2b_update(&S, in, inlen);
    blake2b_final(&S, out, outlen);
}
