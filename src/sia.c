#include "sia.h"

#include <cx.h>
#include <os.h>
#include <os_seed.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "blake2b.h"

void deriveSiaKeypair(uint32_t index, cx_ecfp_private_key_t *privateKey, cx_ecfp_public_key_t *publicKey) {
    uint8_t keySeed[64];
    cx_ecfp_private_key_t pk;

    // bip32 path for 44'/93'/n'/0'/0'
    uint32_t bip32Path[] = {44 | 0x80000000, 93 | 0x80000000, index | 0x80000000, 0x80000000, 0x80000000};
    if (os_derive_bip32_with_seed_no_throw(HDW_ED25519_SLIP10, CX_CURVE_Ed25519, bip32Path, 5, keySeed, NULL, NULL, 0)) {
        THROW(SW_DEVELOPER_ERR);
    }

    if (cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, keySeed, 32, &pk) != CX_OK) {
        THROW(SW_DEVELOPER_ERR);
    }
    if (publicKey) {
        if (cx_ecfp_init_public_key_no_throw(CX_CURVE_Ed25519, NULL, 0, publicKey) != CX_OK) {
            THROW(SW_DEVELOPER_ERR);
        }
        if (cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519, publicKey, &pk, 1) != CX_OK) {
            THROW(SW_DEVELOPER_ERR);
        }
    }
    if (privateKey) {
        *privateKey = pk;
    }
    explicit_bzero(keySeed, sizeof(keySeed));
    explicit_bzero(&pk, sizeof(pk));
}

void extractPubkeyBytes(unsigned char *dst, const cx_ecfp_public_key_t *publicKey) {
    for (int i = 0; i < 32; i++) {
        dst[i] = publicKey->W[64 - i];
    }
    if (publicKey->W[32] & 1) {
        dst[31] |= 0x80;
    }
}

void deriveAndSign(uint8_t *dst, uint32_t index, const uint8_t *hash) {
    cx_ecfp_private_key_t privateKey;
    deriveSiaKeypair(index, &privateKey, NULL);
    if (cx_eddsa_sign_no_throw(&privateKey, CX_SHA512, hash, 32, dst, 64) != CX_OK) {
        THROW(SW_DEVELOPER_ERR);
    }
    explicit_bzero(&privateKey, sizeof(privateKey));
}

void bin2hex(char *dst, const uint8_t *data, uint64_t inlen) {
    static uint8_t const hex[] = "0123456789abcdef";
    for (uint64_t i = 0; i < inlen; i++) {
        dst[2 * i + 0] = hex[(data[i] >> 4) & 0x0F];
        dst[2 * i + 1] = hex[(data[i] >> 0) & 0x0F];
    }
    dst[2 * inlen] = '\0';
}

void pubkeyToSiaAddress(char *dst, const cx_ecfp_public_key_t *publicKey) {
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
    memset(timelockData, 0, sizeof(timelockData));
    timelockData[0] = leafHashPrefix;

    uint8_t pubkeyData[57];
    memset(pubkeyData, 0, sizeof(pubkeyData));
    pubkeyData[0] = leafHashPrefix;
    memmove(pubkeyData + 1, "ed25519", 7);
    pubkeyData[17] = 32;
    extractPubkeyBytes(pubkeyData + 25, publicKey);

    uint8_t sigsrequiredData[9];
    memset(sigsrequiredData, 0, sizeof(sigsrequiredData));
    sigsrequiredData[0] = leafHashPrefix;
    sigsrequiredData[1] = 1;

    // To calculate the Merkle root, we need a buffer large enough to hold two
    // hashes plus a special leading byte.
    uint8_t merkleData[65];
    merkleData[0] = nodeHashPrefix;
    // hash timelock into slot 1
    blake2b(merkleData + 1, 32, timelockData, sizeof(timelockData));
    // hash pubkey into slot 2
    blake2b(merkleData + 33, 32, pubkeyData, sizeof(pubkeyData));
    // join hashes into slot 1
    blake2b(merkleData + 1, 32, merkleData, 65);
    // hash sigsrequired into slot 2
    blake2b(merkleData + 33, 32, sigsrequiredData, sizeof(sigsrequiredData));
    // join hashes into slot 1, finishing Merkle root (unlock hash)
    blake2b(merkleData + 1, 32, merkleData, 65);

    // hash the unlock hash to get a checksum
    uint8_t checksum[6];
    blake2b(checksum, sizeof(checksum), merkleData + 1, 32);

    // convert the hash+checksum to hex
    bin2hex(dst, merkleData + 1, 32);
    bin2hex(dst + 64, checksum, sizeof(checksum));
}

int bin2dec(char *dst, uint64_t n) {
    if (n == 0) {
        dst[0] = '0';
        dst[1] = '\0';
        return 1;
    }
    // determine final length
    int len = 0;
    for (uint64_t nn = n; nn != 0; nn /= 10) {
        len++;
    }
    // write digits in big-endian order
    for (int i = len - 1; i >= 0; i--) {
        dst[i] = (n % 10) + '0';
        n /= 10;
    }
    dst[len] = '\0';
    return len;
}

#define SC_ZEROS 24

int formatSC(char *buf, uint8_t decLen) {
    if (decLen < SC_ZEROS + 1) {
        // if < 1 SC, pad with leading zeros
        memmove(buf + (SC_ZEROS - decLen) + 2, buf, decLen + 1);
        memset(buf, '0', SC_ZEROS + 2 - decLen);
        decLen = SC_ZEROS + 1;
    } else {
        memmove(buf + (decLen - SC_ZEROS) + 1, buf + (decLen - SC_ZEROS), SC_ZEROS + 1);
    }
    // add decimal point, trim trailing zeros, and add units
    buf[decLen - SC_ZEROS] = '.';
    while (decLen > 0 && buf[decLen] == '0') {
        decLen--;
    }
    if (buf[decLen] == '.') {
        decLen--;
    }
    memmove(buf + decLen + 1, " SC", 4);
    return decLen + 4;
}
