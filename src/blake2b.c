#include <stdint.h>
#include <os.h>

#define BLAKE2B_BLOCKBYTES 128

typedef struct {
	uint64_t h[8];
	uint64_t t;
	uint64_t f;
} blake2b_state;

static uint64_t rotr64(const uint64_t w, const unsigned c) {
	return (w >> c) | (w << (64 - c));
}

static const uint64_t blake2b_IV[8] = {
	0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
	0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
	0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
	0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t blake2b_sigma[12][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

#define G(r,i,a,b,c,d)                          \
	do {                                        \
		a = a + b + m[blake2b_sigma[r][2*i+0]]; \
		d = rotr64(d ^ a, 32);                  \
		c = c + d;                              \
		b = rotr64(b ^ c, 24);                  \
		a = a + b + m[blake2b_sigma[r][2*i+1]]; \
		d = rotr64(d ^ a, 16);                  \
		c = c + d;                              \
		b = rotr64(b ^ c, 63);                  \
	} while (0)

#define ROUND(r)                        \
	do {                                \
		G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
		G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
		G(r,2,v[ 2],v[ 6],v[10],v[14]); \
		G(r,3,v[ 3],v[ 7],v[11],v[15]); \
		G(r,4,v[ 0],v[ 5],v[10],v[15]); \
		G(r,5,v[ 1],v[ 6],v[11],v[12]); \
		G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
		G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
	} while (0)

static void blake2b_compress(blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES]) {
	uint64_t m[16];
	uint64_t v[16];

	// initialize m
	os_memmove(m, block, BLAKE2B_BLOCKBYTES);

	// initialize v
	os_memmove(v,   S->h,       64);
	os_memmove(v+8, blake2b_IV, 64);
	v[12] ^= S->t;
	v[14] ^= S->f;

	ROUND( 0);
	ROUND( 1);
	ROUND( 2);
	ROUND( 3);
	ROUND( 4);
	ROUND( 5);
	ROUND( 6);
	ROUND( 7);
	ROUND( 8);
	ROUND( 9);
	ROUND(10);
	ROUND(11);

	for (int i = 0; i < 8; i++) {
		S->h[i] ^= v[i] ^ v[i + 8];
	}
}

#undef G
#undef ROUND

// unkeyed 256-bit blake2b
void blake2b(uint8_t *out, uint64_t outlen, const uint8_t *in, uint64_t inlen) {
	// initialize state
	blake2b_state S;
	os_memmove(S.h, blake2b_IV, 8*8);
	S.t = S.f = 0;

	// S.h needs to be xor'ed with the blake2b parameter values; see
	// 'blake2b_params' in the reference implementation. Since these
	// parameters never change for us, we can hardcode the values to xor
	// against. And as it so happens, most of the parameters are zero-valued,
	// so we only need to xor the first element of S.h.
	S.h[0] ^= 16842784ULL;

	// compress full blocks
	uint64_t rem = inlen;
	while (rem > BLAKE2B_BLOCKBYTES) {
		S.t += BLAKE2B_BLOCKBYTES;
		blake2b_compress(&S, in + S.t);
		rem -= BLAKE2B_BLOCKBYTES;
	}
	// compress final (partial) block
	uint8_t buf[BLAKE2B_BLOCKBYTES];
	os_memset(buf, 0, sizeof(buf));
	os_memmove(buf, in + S.t, rem);
	S.t += rem; // NOTE: does not include padding
	S.f = (uint64_t)-1; // set last block flag
	blake2b_compress(&S, buf);

	// copy S.h into out
	os_memmove(out, S.h, outlen);
}
