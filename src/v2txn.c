#include "v2txn.h"
#include "txn.h"

#include <os.h>
#include <string.h>
#include <limits.h>

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

static void writeUint64BE(uint8_t *buf, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        buf[7 - i] = (uint8_t) (value & 0xFF);
        value >>= 8;
    }
}

static void readCurrency(txn_state_t *txn, uint8_t *outVal) {
    need_at_least(txn, 16);  // 2 * sizeof(uint64_t) = 16

    const uint64_t lo = readInt(txn);
    const uint64_t hi = readInt(txn);

    // Encode in the same format as V1 (big-endian, trimmed)
    uint8_t buf[16];
    writeUint64BE(buf, hi);
    writeUint64BE(buf + 8, lo);

    // Trim leading zeros
    uint8_t *trimmed = buf;
    while (trimmed < buf + 16 && *trimmed == 0) {
        trimmed++;
    }

    size_t valLen = buf + 16 - trimmed;
    if (outVal) {
        outVal[0] = (uint8_t) valLen;
        memmove(outVal + 1, trimmed, valLen);
    }
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
        readHash(txn, NULL);
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
            PRINTF("OP_INVALID\n");
            THROW(TXN_STATE_ERR);
            break;
        case OP_ABOVE:
            PRINTF("OP_ABOVE\n");
            readInt(txn);  // uint64
            break;
        case OP_AFTER:
            PRINTF("OP_AFTER\n");
            readInt(txn);  // time.Time encoded as uint64
            break;
        case OP_PUBLICKEY:
            PRINTF("OP_PUBLICKEY\n");
            readPublicKey(txn);  // types.PublicKey
            break;
        case OP_HASH:
            PRINTF("OP_HASH\n");
            readHash(txn, NULL);  // types.Hash256
            break;
        case OP_THRESHOLD:
            PRINTF("OP_THRESHOLD\n");
            need_at_least(txn, 2);
            const uint8_t n = txn->buf[txn->pos];
            const uint8_t of = txn->buf[txn->pos + 1];
            seek(txn, 2);

            for (uint8_t i = 0; i < n; i++) {
                readSpendPolicy(txn);
            }
            break;
        case OP_OPAQUE:
            PRINTF("OP_OPAQUE\n");
            readHash(txn, NULL);  // types.Address = types.Hash256
            break;
        case OP_UNLOCKCONDITIONS:
            PRINTF("OP_UNLOCKCONDITIONS\n");
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
        PRINTF("BBBBBB\n");
        if (txn->elements[txn->elementIndex].elemType == V2TXN_ELEM_MINER_FEE) {
            // store final hash
            PRINTF("FINISHED!\n");
            blake2b_final(&txn->blake, txn->sigHash, sizeof(txn->sigHash));
            THROW(TXN_STATE_FINISHED);
        }

        // skip over field slices with no elements
        do {
            txn->elements[txn->elementIndex].elemType++;
            PRINTF("elemType: %d, field set: %d\n",
                   txn->elements[txn->elementIndex].elemType,
                   (txn->fields &
                    (1 << (txn->elements[txn->elementIndex].elemType - V2TXN_ELEM_SC_INPUT))) != 0);
        } while (txn->elements[txn->elementIndex].elemType < V2TXN_ELEM_MINER_FEE &&
                 (txn->fields &
                  (1 << (txn->elements[txn->elementIndex].elemType - V2TXN_ELEM_SC_INPUT))) == 0);

        if (txn->elements[txn->elementIndex].elemType <= V2TXN_ELEM_ARB_DATA) {
            txn->sliceLen = readInt(txn);
            txn->sliceIndex = 0;
        } else {
            txn->sliceLen = 0;
            txn->sliceIndex = 0;
        }

        advance(txn);
    }
    PRINTF("elemType: %d, txn->fields: %d\n",
           txn->elements[txn->elementIndex].elemType,
           txn->fields);

    switch (txn->elements[txn->elementIndex].elemType) {
        // these elements should be displayed
        case V2TXN_ELEM_SC_OUTPUT:
            PRINTF("V2TXN_ELEM_SC_OUTPUT\n");

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
            PRINTF("V2TXN_ELEM_SF_OUTPUT\n");

            readInt(txn);                                                      // Value
            readHash(txn, (char *) txn->elements[txn->elementIndex].outAddr);  // UnlockHash
            advance(txn);

            txn->sliceIndex++;
            txn->elements[txn->elementIndex + 1].elemType =
                txn->elements[txn->elementIndex].elemType;
            txn->elementIndex++;
            return;

        case V2TXN_ELEM_MINER_FEE:
            PRINTF("V2TXN_ELEM_MINER_FEE\n");

            readCurrency(txn, txn->elements[txn->elementIndex].outVal);  // Value
            memmove(txn->elements[txn->elementIndex].outAddr, "[Miner Fee]", 12);
            advance(txn);
            return;

        // these elements should be decoded, but not displayed
        case V2TXN_ELEM_SC_INPUT:
            PRINTF("V2TXN_ELEM_SC_INPUT\n");

            PRINTF("1\n");
            readHash(txn, NULL);  // Parent.ID
            PRINTF("2\n");
            readStateElement(txn);  // Parent.StateElement
            PRINTF("3\n");
            readCurrency(txn, NULL);  // Parent.SiacoinOutput.Value
            PRINTF("4\n");
            readHash(txn, NULL);  // Parent.SiacoinOutput.UnlockHash
            PRINTF("5\n");
            readInt(txn);  // Parent.MaturityHeight
            PRINTF("6\n");

            readSpendPolicy(txn);  // SatisfiedPolicy.Policy
            PRINTF("7\n");
            readSignatures(txn);  // SatisfiedPolicy.Signatures
            PRINTF("8\n");
            readPreimages(txn);  // SatisfiedPolicy.Preimages
            PRINTF("9\n");

            addReplayProtection(&txn->blake);
            advance(txn);
            txn->sliceIndex++;
            return;

        case V2TXN_ELEM_SF_INPUT:
            PRINTF("V2TXN_ELEM_SF_INPUT\n");

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
            PRINTF("ERRORING!");
            if (txn->sliceLen != 0) {
                THROW(TXN_STATE_ERR);
            }
            return;
    }
}

void v2txn_init(txn_state_t *txn, uint16_t sigIndex, uint32_t changeIndex, uint64_t fields) {
    memset(txn, 0, sizeof(txn_state_t));
    txn->sigIndex = sigIndex;
    txn->fields = fields;

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
