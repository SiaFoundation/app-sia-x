#ifndef TXN_H
#define TXN_H

#include <stdint.h>

#include "blake2b.h"

#ifdef TARGET_NANOS
#define MAX_ELEMS 16
#else
#define MAX_ELEMS 128
#endif

// macros for converting raw bytes to uint64_t
#define U8BE(buf, off) (((uint64_t)(U4BE(buf, off))     << 32) | ((uint64_t)(U4BE(buf, off + 4)) & 0xFFFFFFFF))
#define U8LE(buf, off) (((uint64_t)(U4LE(buf, off + 4)) << 32) | ((uint64_t)(U4LE(buf, off))     & 0xFFFFFFFF))

// txnDecoderState_e indicates a transaction decoder status
typedef enum {
    TXN_STATE_ERR = 1,  // invalid transaction (NOTE: it's illegal to THROW(0))
    TXN_STATE_PARTIAL,  // no elements have been fully decoded yet
    TXN_STATE_FINISHED, // reached end of transaction
} txnDecoderState_e;

// txnElemType_e indicates a transaction element type.
typedef enum {
	TXN_ELEM_SC_INPUT,
	TXN_ELEM_SC_OUTPUT,
	TXN_ELEM_FC,
	TXN_ELEM_FCR,
	TXN_ELEM_SP,
	TXN_ELEM_SF_INPUT,
	TXN_ELEM_SF_OUTPUT,
	TXN_ELEM_MINER_FEE,
	TXN_ELEM_ARB_DATA,
	TXN_ELEM_TXN_SIG,
} txnElemType_e;

typedef struct {
    txnElemType_e elemType; // type of most-recently-seen element

    uint8_t outVal[24];    // most-recently-seen currency value, Sia-encoded
    uint8_t outAddr[32];    // most-recently-seen address, Sia-encoded
} txn_elem_t;

// txn_state_t is a helper object for computing the SigHash of a streamed
// transaction.
typedef struct {
	uint8_t buf[510]; // holds raw tx bytes; large enough for two 0xFF reads
	uint16_t buflen;  // number of valid bytes in buf
	uint16_t pos;     // mid-decode offset; reset to 0 after each elem

	uint16_t elementIndex;
	txn_elem_t elements[MAX_ELEMS]; // only elements that will be displayed

	uint64_t sliceLen;      // most-recently-seen slice length prefix
	uint16_t sliceIndex;    // offset within current element slice

	uint16_t sigIndex;   // index of TxnSig being computed
    uint8_t changeAddr[77]; // change address
	cx_blake2b_t blake;  // hash state
	uint8_t sigHash[32]; // buffer to hold final hash
} txn_state_t;

// txn_init initializes a transaction decoder, preparing it to calculate the
// requested SigHash.
void txn_init(txn_state_t *txn, uint16_t sigIndex, uint32_t changeIndex);

// txn_update adds data to a transaction decoder.
void txn_update(txn_state_t *txn, uint8_t *in, uint8_t inlen);

// txn_parse decodes the the transaction. If elements
// is ready for display, txn_next_elem returns TXN_STATE_READY. If more data
// is required, it returns TXN_STATE_PARTIAL. If a decoding error is
// encountered, it returns TXN_STATE_ERR. If the transaction has been fully
// decoded, it returns TXN_STATE_FINISHED.
txnDecoderState_e txn_parse(txn_state_t *txn);

// txn takes the Sia-encoded address in src and converts it to a hex encoded
// readable address in dst
void format_address(char *dst, uint8_t *src);

// cur2dec converts a Sia-encoded currency value to a decimal string and
// appends a final NUL byte. It returns the length of the string. If the value
// is too large, it throws TXN_STATE_ERR.
int cur2dec(uint8_t *out, uint8_t *cur);

#endif /* TXN_H */