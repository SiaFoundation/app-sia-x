#include "blake2b.h"

#include <stdint.h>
#include <string.h>

#include "sia.h"

void blake2b_init(cx_blake2b_t *S) {
    if (cx_blake2b_init_no_throw(S, 256) != CX_OK) {
        THROW(SW_DEVELOPER_ERR);
    }
}

void blake2b_update(cx_blake2b_t *S, const uint8_t *in, uint64_t inlen) {
    if (cx_hash_no_throw((cx_hash_t *)S, 0, in, inlen, NULL, 0) != CX_OK) {
        THROW(SW_DEVELOPER_ERR);
    }
}

void blake2b_final(cx_blake2b_t *S, uint8_t *out, uint64_t outlen) {
    uint8_t buf[32];
    if (cx_hash_no_throw((cx_hash_t *)S, CX_LAST, NULL, 0, buf, sizeof(buf)) != CX_OK) {
        THROW(SW_DEVELOPER_ERR);
    }
    memmove(out, buf, outlen);
}

void blake2b(uint8_t *out, uint64_t outlen, const uint8_t *in, uint64_t inlen) {
    cx_blake2b_t S;
    blake2b_init(&S);
    blake2b_update(&S, in, inlen);
    blake2b_final(&S, out, outlen);
}
