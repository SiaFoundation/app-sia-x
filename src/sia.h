// bin2hex converts binary to hex and appends a final NUL byte.
void bin2hex(uint8_t *out, uint8_t *in, uint64_t inlen);

// bin2b64 converts binary to base64 (standard encoding) and appends a final
// NUL byte. It returns the length of the string.
int bin2b64(uint8_t *out, uint8_t *in, uint64_t inlen);

// bin2dec converts an unsigned integer to a decimal string and appends a
// final NUL byte. It returns the length of the string.
int bin2dec(uint8_t *out, uint64_t n);

// blake2b computes the 256-bit unkeyed BLAKE2B hash of in.
void blake2b(uint8_t *out, uint64_t outlen, const uint8_t *in, uint64_t inlen);

// extractPubkeyBytes converts a Ledger-style public key to a Sia-friendly
// 32-byte array.
void extractPubkeyBytes(unsigned char *keyBytes, cx_ecfp_public_key_t *publicKey);

// pubkeyToSiaAddress converts a Ledger pubkey to a Sia wallet address.
void pubkeyToSiaAddress(uint8_t *out, cx_ecfp_public_key_t *publicKey);

// deriveSiaKeypair derives an Ed25519 key pair from an index and the Ledger
// seed. Either privateKey or publicKey may be NULL.
void deriveSiaKeypair(uint32_t index, cx_ecfp_private_key_t *privateKey, cx_ecfp_public_key_t *publicKey);

// deriveAndSign derives an Ed25519 private key from an index and the
// Ledger seed, and uses it to produce a 64-byte signature of the provided
// 32-byte hash. The key is cleared from memory after signing.
void deriveAndSign(uint32_t index, const uint8_t *hash, uint8_t *signature);
