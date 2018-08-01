#define BLAKE2B_BLOCKBYTES 128

// blake2b_state holds an incomplete BLAKE2B hash.
typedef struct {
	uint64_t h[8];
	uint64_t t;
	uint64_t f;
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    uint64_t buflen;
} blake2b_state;

// blake2b_init initializes a 256-bit unkeyed BLAKE2B hash.
void blake2b_init(blake2b_state *S);
// blake2b_update adds data to a BLAKE2B hash.
void blake2b_update(blake2b_state *S, const uint8_t *in, uint64_t inlen);
// blake2b_final outputs a finalized BLAKE2B hash.
void blake2b_final(blake2b_state *S, uint8_t *out, uint64_t outlen);

// blake2b is a helper function that outputs the BLAKE2B hash of in.
void blake2b(uint8_t *out, uint64_t outlen, const uint8_t *in, uint64_t inlen);