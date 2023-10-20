#include "txn_wrapper.h"

#include "txn.h"
#include "v2txn.h"

void txn_wrapper_init(txn_state_t *txn, uint16_t sigIndex, uint32_t changeIndex) {
    if (txn->v2) {
        v2txn_init(txn, sigIndex, changeIndex);
    } else {
        txn_init(txn, sigIndex, changeIndex);
    }
}

void txn_wrapper_update(txn_state_t *txn, uint8_t *in, uint8_t inlen) {
    if (txn->v2) {
        v2txn_update(txn, in, inlen);
    } else {
        txn_update(txn, in, inlen);
    }
}

txnDecoderState_e txn_wrapper_next_elem(txn_state_t *txn) {
    if (txn->v2) {
        return v2txn_next_elem(txn);
    } else {
        return txn_next_elem(txn);
    }
}
