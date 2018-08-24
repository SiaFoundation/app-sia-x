#include "os.h"
#include "cx.h"
#include <stdbool.h>
#include <stdint.h>
#include "blake2b.h"
#include "sia.h"

static void need_at_least(txn_state_t *txn, uint64_t n) {
	if ((txn->buflen - txn->pos) < n) {
		THROW(TXN_STATE_PARTIAL);
	}
}

static void seek(txn_state_t *txn, uint64_t n) {
	need_at_least(txn, n);
	txn->pos += n;
}

static void advance(txn_state_t *txn) {
	// if elem is covered, add it to the hash
	if (txn->elemType != TXN_ELEM_TXN_SIG) {
		blake2b_update(&txn->blake, txn->buf, txn->pos);
	} else if (txn->sliceIndex == txn->sigIndex && txn->pos >= 48) {
		// add just the ParentID, Timelock, and PublicKeyIndex
		blake2b_update(&txn->blake, txn->buf, 48);
	}

	txn->buflen -= txn->pos;
	os_memmove(txn->buf, txn->buf+txn->pos, txn->buflen);
	txn->pos = 0;
}

static uint64_t readInt(txn_state_t *txn) {
	need_at_least(txn, 8);
	uint64_t u = U8LE(txn->buf, txn->pos);
	seek(txn, 8);
	return u;
}

static void readCurrency(txn_state_t *txn, uint8_t *outVal) {
	uint64_t valLen = readInt(txn);
	need_at_least(txn, valLen);
	if (valLen > 16) {
		// 16 bytes is enough to store up to 2^128, much larger than we could ever need.
		THROW(TXN_STATE_ERR);
	}
	if (outVal) {
		txn->valLen = cur2dec(outVal, txn->buf+txn->pos-8);
	}
	seek(txn, valLen);
}

static void readHash(txn_state_t *txn, uint8_t *outAddr) {
	need_at_least(txn, 32);
	if (outAddr) {
		bin2hex(outAddr, txn->buf+txn->pos, 32);
		uint8_t checksum[6];
		blake2b(checksum, sizeof(checksum), txn->buf+txn->pos, 32);
		bin2hex(outAddr+64, checksum, sizeof(checksum));
	}
	seek(txn, 32);
}

static void readPrefixedBytes(txn_state_t *txn) {
	uint64_t len = readInt(txn);
	seek(txn, len);
}

static void readUnlockConditions(txn_state_t *txn) {
	readInt(txn); // Timelock
	uint64_t numKeys = readInt(txn); // PublicKeys
	while (numKeys --> 0) {
		seek(txn, 16);          // Algorithm
		readPrefixedBytes(txn); // Key
	}
	readInt(txn); // SignaturesRequired
}

static void readCoveredFields(txn_state_t *txn) {
	need_at_least(txn, 1);
	// for now, we require WholeTransaction = true
	if (txn->buf[txn->pos] != 1) {
		THROW(TXN_STATE_ERR);
	}
	seek(txn, 1);
	// all other fields must be empty
	for (int i = 0; i < 10; i++) {
		if (readInt(txn) != 0) {
			THROW(TXN_STATE_ERR);
		}
	}
}

// throws txnDecoderState_e
static void __txn_next_elem(txn_state_t *txn) {
	// if we're on a slice boundary, read the next length prefix and bump the
	// element type
	while (txn->sliceIndex == txn->sliceLen) {
		if (txn->elemType == TXN_ELEM_TXN_SIG) {
			// store final hash
			blake2b_final(&txn->blake, txn->sigHash, sizeof(txn->sigHash));
			THROW(TXN_STATE_FINISHED);
		}
		txn->sliceLen = readInt(txn);
		txn->sliceIndex = 0;
		txn->elemType++;
		advance(txn);
	}

	switch (txn->elemType) {
	// these elements should be displayed
	case TXN_ELEM_SC_OUTPUT:
		readCurrency(txn, txn->outVal); // Value
		readHash(txn, txn->outAddr);    // UnlockHash
		advance(txn);
		txn->sliceIndex++;
		THROW(TXN_STATE_READY);

	case TXN_ELEM_SF_OUTPUT:
		readCurrency(txn, txn->outVal); // Value
		readHash(txn, txn->outAddr);    // UnlockHash
		readCurrency(txn, NULL);        // ClaimStart
		advance(txn);
		txn->sliceIndex++;
		THROW(TXN_STATE_READY);

	case TXN_ELEM_MINER_FEE:
		readCurrency(txn, txn->outVal); // Value
		os_memmove(txn->outAddr, "[Miner Fee]", 12);
		advance(txn);
		txn->sliceIndex++;
		THROW(TXN_STATE_READY);

	// these elements should be decoded, but not displayed
	case TXN_ELEM_SC_INPUT:
		readHash(txn, NULL);       // ParentID
		readUnlockConditions(txn); // UnlockConditions
		advance(txn);
		txn->sliceIndex++;
		return;

	case TXN_ELEM_SF_INPUT:
		readHash(txn, NULL);       // ParentID
		readUnlockConditions(txn); // UnlockConditions
		readHash(txn, NULL);       // ClaimUnlockHash
		advance(txn);
		txn->sliceIndex++;
		return;

	case TXN_ELEM_TXN_SIG:
		readHash(txn, NULL);    // ParentID
		readInt(txn);           // PublicKeyIndex
		readInt(txn);           // Timelock
		readCoveredFields(txn); // CoveredFields
		readPrefixedBytes(txn); // Signature
		advance(txn);
		txn->sliceIndex++;
		return;

	// these elements should not be present
	case TXN_ELEM_FC:
	case TXN_ELEM_FCR:
	case TXN_ELEM_SP:
	case TXN_ELEM_ARB_DATA:
		if (txn->sliceLen != 0) {
			THROW(TXN_STATE_ERR);
		}
		return;
	}
}

txnDecoderState_e txn_next_elem(txn_state_t *txn) {
	txnDecoderState_e result;
	BEGIN_TRY {
		TRY {
			// read until we reach a displayable element or the end of the buffer
			for (;;) {
				__txn_next_elem(txn);
			}
		}
		CATCH_OTHER(e) {
			result = e;
		}
		FINALLY {
		}
	}
	END_TRY;
	if (txn->buflen + 255 > sizeof(txn->buf)) {
		// we filled the buffer to max capacity, but there still wasn't enough
		// to decode a full element. This generally means that the txn is
		// corrupt in some way, since elements shouldn't be very large.
		return TXN_STATE_ERR;
	}
	return result;
}

void txn_init(txn_state_t *txn, uint16_t sigIndex) {
	os_memset(txn, 0, sizeof(txn_state_t));
	txn->buflen = txn->pos = txn->sliceIndex = txn->sliceLen = txn->valLen = 0;
	txn->elemType = -1; // first increment brings it to SC_INPUT
	txn->sigIndex = sigIndex;

	// initialize hash state
	blake2b_init(&txn->blake);
}

void txn_update(txn_state_t *txn, uint8_t *in, uint8_t inlen) {
	// the buffer should never overflow; any elements should always be drained
	// before the next read.
	if (txn->buflen + inlen > sizeof(txn->buf)) {
		THROW(SW_DEVELOPER_ERR);
	}

	// append to the buffer
	os_memmove(txn->buf + txn->buflen, in, inlen);
	txn->buflen += inlen;

	// reset the seek position; if we previously threw TXN_STATE_PARTIAL, now
	// we can try decoding again from the beginning.
	txn->pos = 0;
}
