#include "os.h"
#include "cx.h"
#include <stdbool.h>
#include <stdint.h>
#include "blake2b.h"
#include "sia.h"

void deriveSiaKeypair(uint32_t index, cx_ecfp_private_key_t *privateKey, cx_ecfp_public_key_t *publicKey) {
	uint8_t keySeed[32];
	cx_ecfp_private_key_t pk;

	// bip32 path for 44'/93'/n'/0'/0'
	uint32_t bip32Path[] = {44 | 0x80000000, 93 | 0x80000000, index | 0x80000000, 0x80000000, 0x80000000};
	os_perso_derive_node_bip32(CX_CURVE_Ed25519, bip32Path, 5, keySeed, NULL);

	cx_ecfp_init_private_key(CX_CURVE_Ed25519, keySeed, sizeof(keySeed), &pk);
	if (publicKey) {
		cx_ecfp_init_public_key(CX_CURVE_Ed25519, NULL, 0, publicKey);
		cx_ecfp_generate_pair(CX_CURVE_Ed25519, publicKey, &pk, 1);
	}
	if (privateKey) {
		*privateKey = pk;
	}
	os_memset(keySeed, 0, sizeof(keySeed));
	os_memset(&pk, 0, sizeof(pk));
}

void extractPubkeyBytes(unsigned char *keyBytes, cx_ecfp_public_key_t *publicKey) {
	for (int i = 0; i < 32; i++) {
		keyBytes[i] = publicKey->W[64 - i];
	}
	if (publicKey->W[32] & 1) {
		keyBytes[31] |= 0x80;
	}
}

void deriveAndSign(uint32_t index, const uint8_t *hash, uint8_t *signature) {
	cx_ecfp_private_key_t privateKey;
	deriveSiaKeypair(index, &privateKey, NULL);
	cx_eddsa_sign(&privateKey, CX_RND_RFC6979 | CX_LAST, CX_SHA512, hash, 32, NULL, 0, signature, 64, NULL);
	os_memset(&privateKey, 0, sizeof(privateKey));
}

void bin2hex(uint8_t *out, uint8_t *in, uint64_t inlen) {
	static uint8_t const hex[] = "0123456789abcdef";
	for (uint64_t i = 0; i < inlen; i++) {
		out[2*i+0] = hex[(in[i]>>4) & 0x0F];
		out[2*i+1] = hex[(in[i]>>0) & 0x0F];
	}
	out[2*inlen] = '\0';
}

void pubkeyToSiaAddress(uint8_t *out, cx_ecfp_public_key_t *publicKey) {
	// A Sia address is the Merkle root of a set of unlock conditions.
	// For a "standard" address, the unlock conditions are:
	//
	// - no timelock
	// - one public key
	// - one signature required
	//
	// For now, the Ledger will only be able to generate standard addresses.
	// We can add support for arbitrary unlock conditions later.

	// defined in RFC 6962
	const uint8_t leafHashPrefix = 0;
	const uint8_t nodeHashPrefix = 1;

	// encode the timelock, pubkey, and sigsrequired
	// TODO: can reuse buffers here to make this more efficient
	uint8_t timelockData[9];
	os_memset(timelockData, 0, sizeof(timelockData));
	timelockData[0] = leafHashPrefix;

	uint8_t pubkeyData[57];
	os_memset(pubkeyData, 0, sizeof(pubkeyData));
	pubkeyData[0] = leafHashPrefix;
	os_memmove(pubkeyData + 1, "ed25519", 7);
	pubkeyData[17] = 32;
	extractPubkeyBytes(pubkeyData + 25, publicKey);

	uint8_t sigsrequiredData[9];
	os_memset(sigsrequiredData, 0, sizeof(sigsrequiredData));
	sigsrequiredData[0] = leafHashPrefix;
	sigsrequiredData[1] = 1;


	// To calculate the Merkle root, we need a buffer large enough to hold two
	// hashes plus a special leading byte.
	uint8_t merkleData[65];
	merkleData[0] = nodeHashPrefix;
	// hash timelock into slot 1
	blake2b(merkleData+1, 32, timelockData, sizeof(timelockData));
	// hash pubkey into slot 2
	blake2b(merkleData+33, 32, pubkeyData, sizeof(pubkeyData));
	// join hashes into slot 1
	blake2b(merkleData+1, 32, merkleData, 65);
	// hash sigsrequired into slot 2
	blake2b(merkleData+33, 32, sigsrequiredData, sizeof(sigsrequiredData));
	// join hashes into slot 1, finishing Merkle root (unlock hash)
	blake2b(merkleData+1, 32, merkleData, 65);

	// hash the unlock hash to get a checksum
	uint8_t checksum[6];
	blake2b(checksum, sizeof(checksum), merkleData+1, 32);

	// convert the hash+checksum to hex
	bin2hex(out, merkleData+1, 32);
	bin2hex(out+64, checksum, sizeof(checksum));
}

int bin2dec(uint8_t *out, uint64_t n) {
	if (n == 0) {
		out[0] = '0';
		out[1] = '\0';
		return 1;
	}
	// determine final length
	int len = 0;
	for (uint64_t nn = n; nn != 0; nn /= 10) {
		len++;
	}
	// write digits in big-endian order
	for (int i = len-1; i >= 0; i--) {
		out[i] = (n % 10) + '0';
		n /= 10;
	}
	out[len] = '\0';
	return len;
}

int bin2b64(uint8_t *out, uint8_t *in, uint64_t inlen) {
    static uint8_t const b64Std[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (inlen == 0) {
        out[0] = '\0';
        return 0;
    }

    int di = 0;
    int si = 0;
    int n = (inlen / 3) * 3;
    while (si < n) {
        // convert 3 binary bytes into 4 base64 bytes
        uint32_t val = in[si+0]<<16 | in[si+1]<<8 | in[si+2];
        out[di+0] = b64Std[val>>18&0x3F];
        out[di+1] = b64Std[val>>12&0x3F];
        out[di+2] = b64Std[val>>6 &0x3F];
        out[di+3] = b64Std[val>>0 &0x3F];
        si += 3;
        di += 4;
    }
    // encode remaining bytes
    int remain = inlen - si;
    if (remain == 0) {
        return di;
    }
    uint32_t val = in[si+0] << 16;
    if (remain == 2) {
        val |= in[si+1] << 8;
    }
    out[di+0] = b64Std[val>>18&0x3F];
    out[di+1] = b64Std[val>>12&0x3F];
    if (remain == 2) {
        out[di+2] = b64Std[val>>6&0x3F];
        out[di+3] = '=';
    } else if (remain == 1) {
        out[di+2] = '=';
        out[di+3] = '=';
    }
    di += 4;
    out[di] = '\0';
    return di;
}

bool validCur(uint8_t *cur) {
	// only one byte of the length prefix may be used (this is sufficient to
	// encode integers up to 2^255, or about 10^76).
	return U8BE(cur, 0) < 256;
}

static void divWW10(uint64_t u1, uint64_t u0, uint64_t *q, uint64_t *r) {
	const uint64_t s = 60ULL;
	const uint64_t v = 11529215046068469760ULL;
	const uint64_t vn1 = 2684354560ULL;
	const uint64_t _B2 = 4294967296ULL;
	uint64_t un32 = u1<<s | u0>>(64-s);
	uint64_t un10 = u0 << s;
	uint64_t un1 = un10 >> 32;
	uint64_t un0 = un10 & (_B2-1);
	uint64_t q1 = un32 / vn1;
	uint64_t rhat = un32 - q1*vn1;

	while (q1 >= _B2) {
		q1--;
		rhat += vn1;
		if (rhat >= _B2) {
			break;
		}
	}

	uint64_t un21 = un32*_B2 + un1 - q1*v;
	uint64_t q0 = un21 / vn1;
	rhat = un21 - q0*vn1;

	while (q0 >= _B2) {
		q0--;
		rhat += vn1;
		if (rhat >= _B2) {
			break;
		}
	}

	*q = q1*_B2 + q0;
	*r = (un21*_B2 + un0 - q0*v) >> s;
}

static uint64_t quorem10(uint64_t nat[], int len) {
	uint64_t r = 0;
	for (int i = len - 1; i >= 0; i--) {
		divWW10(r, nat[i], &nat[i], &r);
	}
	return r;
}

int cur2dec(uint8_t *out, uint8_t *cur) {
	if (cur[0] == 0) {
		out[0] = '\0';
		return 0;
	}

	// convert big-endian uint8_t[] to little-endian uint64_t[]
	//
	// NOTE: the Sia encoding omits any leading zeros, so the first "uint64"
	// may not be a full 8 bytes. We handle this by treating the length prefix
	// as part of the first uint64. This is safe as long as the length prefix
	// has only 1 non-zero byte, which should be enforced elsewhere.
	uint64_t nat[32];
	int len = (cur[0] / 8) + (cur[0] % 8 != 0);
	cur += 8 - (len*8 - cur[0]);
	for (int i = 0; i < len; i++) {
		nat[len-i-1] = U8BE(cur, i*8);
	}

	// decode digits into buf, right-to-left
	uint8_t buf[192];
	int i = sizeof(buf);
	buf[--i] = '\0';
	while (len > 0) {
		buf[--i] = '0' + quorem10(nat, len);
		// normalize nat
		while (len > 0 && nat[len-1] == 0) {
			len--;
		}
	}

	// copy buf->out, trimming whitespace
	os_memmove(out, buf+i, sizeof(buf)-i);
	return sizeof(buf)-i-1;
}

#define SC_ZEROS 24

int cur2SC(uint8_t *outVal, uint8_t decLen) {
	if (decLen < SC_ZEROS+1) {
		// if < 1 SC, pad with leading zeros
		os_memmove(outVal + (SC_ZEROS-decLen)+2, outVal, decLen+1);
		os_memset(outVal, '0', SC_ZEROS+2-decLen);
		decLen = SC_ZEROS + 1;
	} else {
		os_memmove(outVal + (decLen-SC_ZEROS)+2, outVal + (decLen-SC_ZEROS+1), SC_ZEROS+1);
	}
	// add decimal point, trim trailing zeros, and add units
	outVal[decLen-SC_ZEROS] = '.';
	while (decLen > 0 && outVal[decLen] == '0') {
		decLen--;
	}
	if (outVal[decLen] == '.') {
		decLen--;
	}
	os_memmove(outVal + decLen + 1, " SC", 4);
	return decLen + 4;
}