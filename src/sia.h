#pragma once

#include <os.h>
#include <stdint.h>
#include <stdbool.h>

// exception codes
#define SW_DEVELOPER_ERR 0x6B00
#define SW_INVALID_PARAM 0x6B01
#define SW_IMPROPER_INIT 0x6B02
#define SW_USER_REJECTED 0x6985
#define SW_OK            0x9000

// bin2hex converts binary to hex and appends a final NUL byte.
void bin2hex(char *dst, const uint8_t *data, uint64_t inlen);

// bin2dec converts an unsigned integer to a decimal string and appends a
// final NUL byte. It returns the length of the string.
int bin2dec(char *dst, uint64_t n);

// formatSC converts a decimal string from Hastings to Siacoins. It returns the
// new length of the string.
int formatSC(char *buf, uint8_t decLen);

// extractPubkeyBytes converts a Ledger-style public key to a Sia-friendly
// 32-byte array.
void extractPubkeyBytes(unsigned char *dst, const cx_ecfp_public_key_t *publicKey);

// pubkeyToSiaAddress converts a Ledger pubkey to a Sia wallet address.
void pubkeyToSiaAddress(char *dst, const cx_ecfp_public_key_t *publicKey);

// deriveSiaKeypair derives an Ed25519 key pair from an index and the Ledger
// seed. Either privateKey or publicKey may be NULL.
void deriveSiaKeypair(uint32_t index, cx_ecfp_private_key_t *privateKey, cx_ecfp_public_key_t *publicKey);

// deriveAndSign derives an Ed25519 private key from an index and the
// Ledger seed, and uses it to produce a 64-byte signature of the provided
// 32-byte hash. The key is cleared from memory after signing.
void deriveAndSign(uint8_t *dst, uint32_t index, const uint8_t *hash);
