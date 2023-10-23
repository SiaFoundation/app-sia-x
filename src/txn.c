#include "txn.h"

#include <os.h>
#include <string.h>

#include "sia.h"  // For SW_DEVELOPER_ERR. Should be removed.
#include "parse.h"

static void advance(txn_state_t *txn) {
    // if elem is covered, add it to the hash
    if (txn->elemType != TXN_ELEM_TXN_SIG) {
        blake2b_update(&txn->blake, txn->buf, txn->pos);
    } else if (txn->sliceIndex == txn->sigIndex && txn->pos >= 48) {
        // add just the ParentID, Timelock, and PublicKeyIndex
        blake2b_update(&txn->blake, txn->buf, 48);
    }

    txn->buflen -= txn->pos;
    memmove(txn->buf, txn->buf + txn->pos, txn->buflen);
    txn->pos = 0;
}

static void addReplayProtection(cx_blake2b_t *S) {
    // The official Sia Nano S app only signs transactions on the
    // Foundation-supported chain. To use the app on a different chain,
    // recompile the app with a different replayPrefix.
    static uint8_t const replayPrefix[] = {1};
    blake2b_update(S, replayPrefix, 1);
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
        txn->displayIndex = 0;
        txn->elemType++;
        advance(txn);

        // if we've reached the TransactionSignatures, check that sigIndex is
        // a valid index
        if ((txn->elemType == TXN_ELEM_TXN_SIG) && (txn->sigIndex >= txn->sliceLen)) {
            THROW(TXN_STATE_ERR);
        }
    }

    switch (txn->elemType) {
        // these elements should be displayed
        case TXN_ELEM_SC_OUTPUT:
            readCurrency(txn, txn->outVal);       // Value
            readHash(txn, (char *)txn->outAddr);  // UnlockHash
            advance(txn);
            txn->sliceIndex++;
            if (!memcmp(txn->outAddr, txn->changeAddr, sizeof(txn->outAddr))) {
                // do not display the change address or increment displayIndex
                return;
            }
            txn->displayIndex++;
            THROW(TXN_STATE_READY);

        case TXN_ELEM_SF_OUTPUT:
            readCurrency(txn, txn->outVal);       // Value
            readHash(txn, (char *)txn->outAddr);  // UnlockHash
            readCurrency(txn, NULL);              // ClaimStart
            advance(txn);
            txn->sliceIndex++;
            txn->displayIndex++;
            THROW(TXN_STATE_READY);

        case TXN_ELEM_MINER_FEE:
            readCurrency(txn, txn->outVal);  // Value
            memmove(txn->outAddr, "[Miner Fee]", 12);
            advance(txn);
            txn->sliceIndex++;
            THROW(TXN_STATE_READY);

        // these elements should be decoded, but not displayed
        case TXN_ELEM_SC_INPUT:
            readHash(txn, NULL);        // ParentID
            readUnlockConditions(txn);  // UnlockConditions
            addReplayProtection(&txn->blake);
            advance(txn);
            txn->sliceIndex++;
            return;

        case TXN_ELEM_SF_INPUT:
            readHash(txn, NULL);        // ParentID
            readUnlockConditions(txn);  // UnlockConditions
            readHash(txn, NULL);        // ClaimUnlockHash
            addReplayProtection(&txn->blake);
            advance(txn);
            txn->sliceIndex++;
            return;

        case TXN_ELEM_TXN_SIG:
            readHash(txn, NULL);     // ParentID
            readInt(txn);            // PublicKeyIndex
            readInt(txn);            // Timelock
            readCoveredFields(txn);  // CoveredFields
            readPrefixedBytes(txn);  // Signature
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
    // Like many transaction decoders, we use exceptions to jump out of deep
    // call stacks when we encounter an error. There are two important rules
    // for Ledger exceptions: declare modified variables as volatile, and do
    // not THROW(0). Presumably, 0 is the sentinel value for "no exception
    // thrown." So be very careful when throwing enums, since enums start at 0
    // by default.
    volatile txnDecoderState_e result;
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

void txn_init(txn_state_t *txn, uint16_t sigIndex, uint32_t changeIndex) {
    memset(txn, 0, sizeof(txn_state_t));
    txn->v2 = false;
    txn->buflen = txn->pos = txn->sliceIndex = txn->displayIndex = txn->sliceLen = txn->valLen = 0;
    txn->elemType = -1;  // first increment brings it to SC_INPUT
    txn->sigIndex = sigIndex;

    cx_ecfp_public_key_t publicKey = {0};
    deriveSiaKeypair(changeIndex, NULL, &publicKey);
    pubkeyToSiaAddress((char *)&txn->changeAddr, &publicKey);

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
    memmove(txn->buf + txn->buflen, in, inlen);
    txn->buflen += inlen;

    // reset the seek position; if we previously threw TXN_STATE_PARTIAL, now
    // we can try decoding again from the beginning.
    txn->pos = 0;
}
