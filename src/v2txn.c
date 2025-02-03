#include "txn.h"
#include "v2txn.h"

#include <os.h>
#include <string.h>

#include "sia.h"  // For SW_DEVELOPER_ERR. Should be removed.

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
    blake2b_update(&txn->blake, txn->buf, txn->pos);

    txn->buflen -= txn->pos;
    memmove(txn->buf, txn->buf + txn->pos, txn->buflen);
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
    if (outVal) {
        if (valLen > 16) {
            THROW(TXN_STATE_ERR);
        }
        outVal[0] = valLen;
        memmove(outVal + 1, txn->buf + txn->pos, valLen);
    }
    seek(txn, valLen);
}

static void readHash(txn_state_t *txn, char *outAddr) {
    need_at_least(txn, 32);
    if (outAddr) {
        memmove(outAddr, txn->buf + txn->pos, 32);
    }
    seek(txn, 32);
}

static void readPrefixedBytes(txn_state_t *txn) {
    uint64_t len = readInt(txn);
    seek(txn, len);
}

static void readUnlockConditions(txn_state_t *txn) {
    readInt(txn);                     // Timelock
    uint64_t numKeys = readInt(txn);  // PublicKeys
    while (numKeys-- > 0) {
        seek(txn, 16);           // Algorithm
        readPrefixedBytes(txn);  // Key
    }
    readInt(txn);  // SignaturesRequired
}

static void readMerkleProof(txn_state_t *txn) {
    const uint64_t len = readInt(txn);  // number of elements in the proof array
    for (uint64_t i = 0; i < len; i++) {
        seek(txn, 32);  // types.Hash256
    }
}

static void readStateElement(txn_state_t *txn) {
    readInt(txn);          // LeafIndex
    readMerkleProof(txn);  // MerkleProof
}

static void readPublicKey(txn_state_t *txn) {
    seek(txn, 32);
}

static void readSignatures(txn_state_t *txn) {
    const uint64_t len = readInt(txn);
    for (uint64_t i = 0; i < len; i++) {
        seek(txn, 64);
    }
}

static void readPreimages(txn_state_t *txn) {
    const uint64_t len = readInt(txn);
    for (uint64_t i = 0; i < len; i++) {
        seek(txn, 32);
    }
}

static void readSpendPolicy(txn_state_t *txn) {
    need_at_least(txn, 1);
    const uint8_t typ = txn->buf[txn->pos];
    seek(txn, 1);

    switch (typ) {
        case OP_INVALID:
            THROW(TXN_STATE_ERR);
            break;
        case OP_ABOVE:
            readInt(txn);  // uint64
            break;
        case OP_AFTER:
            readInt(txn);  // time.Time encoded as uint64
            break;
        case OP_PUBLICKEY:
            readPublicKey(txn);  // types.PublicKey
            break;
        case OP_HASH:
            readHash(txn, NULL);  // types.Hash256
            break;
        case OP_THRESHOLD:
            need_at_least(txn, 1);
            const uint8_t n = txn->buf[txn->pos];
            seek(txn, 1);

            for (uint8_t i = 0; i < n; i++) {
                readSpendPolicy(txn);
            }
            break;
        case OP_OPAQUE:
            readHash(txn, NULL);  // types.Address = types.Hash256
            break;
        case OP_UNLOCKCONDITIONS:
            readUnlockConditions(txn);  // types.UnlockConditions
            break;
    }
}

static void addReplayProtection(cx_blake2b_t *S) {
    // The official Sia app only signs transactions on the
    // Foundation-supported chain. To use the app on a different chain,
    // recompile the app with a different replayPrefix.
    static uint8_t const replayPrefix[] = {1};
    blake2b_update(S, replayPrefix, 1);
}

// throws txnDecoderState_e
static void __txn_next_elem(txn_state_t *txn) {
    // too many elements
    if (txn->elementIndex == MAX_ELEMS) {
        THROW(TXN_STATE_ERR);
    }
    // if we're on a slice boundary, read the next length prefix and bump the
    // element type
    while (txn->sliceIndex == txn->sliceLen) {
        if (txn->elements[txn->elementIndex].elemType == V2TXN_ELEM_MINER_FEE) {
            // store final hash
            blake2b_final(&txn->blake, txn->sigHash, sizeof(txn->sigHash));
            THROW(TXN_STATE_FINISHED);
        }
        // too many elements
        txn->sliceLen = readInt(txn);
        txn->sliceIndex = 0;
        txn->elements[txn->elementIndex].elemType++;
        advance(txn);

        // if we've reached the TransactionSignatures, check that sigIndex is
        // a valid index
        if ((txn->elements[txn->elementIndex].elemType == V2TXN_ELEM_MINER_FEE) &&
            (txn->sigIndex >= txn->sliceLen)) {
            THROW(TXN_STATE_ERR);
        }
    }

    switch (txn->elements[txn->elementIndex].elemType) {
        // these elements should be displayed
        case V2TXN_ELEM_SC_OUTPUT:
            readCurrency(txn, txn->elements[txn->elementIndex].outVal);        // Value
            readHash(txn, (char *) txn->elements[txn->elementIndex].outAddr);  // UnlockHash
            advance(txn);
            if (!memcmp(txn->elements[txn->elementIndex].outAddr,
                        txn->changeAddr,
                        sizeof(txn->elements[txn->elementIndex].outAddr))) {
                // do not display the change address or increment displayIndex
                return;
            }

            txn->sliceIndex++;
            txn->elements[txn->elementIndex + 1].elemType =
                txn->elements[txn->elementIndex].elemType;
            txn->elementIndex++;
            return;

        case V2TXN_ELEM_SF_OUTPUT:
            readCurrency(txn, txn->elements[txn->elementIndex].outVal);        // Value
            readHash(txn, (char *) txn->elements[txn->elementIndex].outAddr);  // UnlockHash
            readCurrency(txn, NULL);                                           // ClaimStart
            advance(txn);

            txn->sliceIndex++;
            txn->elements[txn->elementIndex + 1].elemType =
                txn->elements[txn->elementIndex].elemType;
            txn->elementIndex++;
            return;

        case V2TXN_ELEM_MINER_FEE:
            readCurrency(txn, txn->elements[txn->elementIndex].outVal);  // Value
            memmove(txn->elements[txn->elementIndex].outAddr, "[Miner Fee]", 12);
            advance(txn);
            return;

        // these elements should be decoded, but not displayed
        case V2TXN_ELEM_SC_INPUT:
            readHash(txn, NULL);      // Parent.ID
            readStateElement(txn);    // Parent.StateElement
            readCurrency(txn, NULL);  // Parent.SiacoinOutput.Value
            readHash(txn, NULL);      // Parent.SiacoinOutput.UnlockHash
            readInt(txn);             // Parent.MaturityHeight

            readSpendPolicy(txn);  // SatisfiedPolicy.Policy
            readSignatures(txn);   // SatisfiedPolicy.Signatures
            readPreimages(txn);    // SatisfiedPolicy.Preimages

            addReplayProtection(&txn->blake);
            advance(txn);
            txn->sliceIndex++;
            return;

        case V2TXN_ELEM_SF_INPUT:
            readHash(txn, NULL);      // Parent.ID
            readStateElement(txn);    // Parent.StateElement
            readInt(txn);             // Parent.SiafundOutput.Value
            readHash(txn, NULL);      // Parent.SiafundOutput.UnlockHash
            readCurrency(txn, NULL);  // Parent.ClaimStart

            readSpendPolicy(txn);  // SatisfiedPolicy.Policy
            readSignatures(txn);   // SatisfiedPolicy.Signatures
            readPreimages(txn);    // SatisfiedPolicy.Preimages

            addReplayProtection(&txn->blake);
            advance(txn);
            txn->sliceIndex++;
            return;

        // these elements should not be present
        case V2TXN_ELEM_FC:
        case V2TXN_ELEM_FC_REVISION:
        case V2TXN_ELEM_FC_RESOLUTION:
        case V2TXN_ELEM_ATTESTATION:
        case V2TXN_ELEM_ARB_DATA:
        case V2TXN_ELEM_NEW_FOUNDATION_ADDR:
            if (txn->sliceLen != 0) {
                THROW(TXN_STATE_ERR);
            }
            return;
    }
}

void v2txn_init(txn_state_t *txn, uint16_t sigIndex, uint32_t changeIndex) {
    memset(txn, 0, sizeof(txn_state_t));
    txn->sigIndex = sigIndex;

    txn->elementIndex = 0;
    txn->elements[txn->elementIndex].elemType =
        V2TXN_ELEM_SC_INPUT - 1;  // first increment brings it to V2TXN_ELEM_SC_INPUT

    uint8_t publicKey[65] = {0};
    deriveSiaPublicKey(changeIndex, publicKey);
    pubkeyToSiaAddress((char *) &txn->changeAddr, publicKey);

    // initialize hash state
    blake2b_init(&txn->blake);
}

void v2txn_update(txn_state_t *txn, uint8_t *in, uint8_t inlen) {
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

txnDecoderState_e v2txn_parse(txn_state_t *txn) {
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
