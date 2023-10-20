#ifndef TXN_WRAPPER_H
#define TXN_WRAPPER_H

#include "txn.h"

// Wrappers so that the appropriate function is called for updating
// transaction state depending on if the transaction is v1 or v2.

// txn_wrapper_init initializes a transaction decoder, preparing it to calculate the
// requested SigHash.  It will call txn_init if given a transaction with v2=false and
// v2txn_init if given a transaction where v2=true.
void txn_wrapper_init(txn_state_t *txn, uint16_t sigIndex, uint32_t changeIndex);

// txn_wrapper_update adds data to a transaction decoder.  It will call txn_update if given a transaction with v2=false and
// v2txn_update if given a transaction where v2=true.
void txn_wrapper_update(txn_state_t *txn, uint8_t *in, uint8_t inlen);

// txn_wrapper_next_elem decodes the next element of the transaction. If the
// element is ready for display, txn_next_elem returns TXN_STATE_READY. If more
// data is required, it returns TXN_STATE_PARTIAL. If a decoding error is
// encountered, it returns TXN_STATE_ERR. If the transaction has been fully
// decoded, it returns TXN_STATE_FINISHED.
txnDecoderState_e txn_wrapper_next_elem(txn_state_t *txn);


#endif /* TXN_WRAPPER_H */
