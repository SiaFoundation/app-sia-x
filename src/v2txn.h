#ifndef V2TXN_H
#define V2TXN_H

#include "txn.h"

// v2txn_init initializes a transaction decoder, preparing it to calculate the
// requested SigHash.
void v2txn_init(txn_state_t *txn, uint16_t sigIndex, uint32_t changeIndex);

// v2txn_update adds data to a transaction decoder.
void v2txn_update(txn_state_t *txn, uint8_t *in, uint8_t inlen);

// v2txn_parse decodes the the transaction. If elements
// is ready for display, txn_next_elem returns TXN_STATE_READY. If more data
// is required, it returns TXN_STATE_PARTIAL. If a decoding error is
// encountered, it returns TXN_STATE_ERR. If the transaction has been fully
// decoded, it returns TXN_STATE_FINISHED.
txnDecoderState_e v2txn_parse(txn_state_t *txn);

#endif /* V2TXN_H */