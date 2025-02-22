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
    need_at_least(txn, 16);

    const uint64_t lo = readInt(txn);
    const uint64_t hi = readInt(txn);

    // Encode in the same format as V1 (big-endian, trimmed)
    uint8_t buf[16] = {0};
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

static void writeUint64Currency(uint64_t value, uint8_t *outVal) {
    // Convert to big-endian
    uint8_t buf[8] = {0};
    writeUint64BE(buf, value);

    // Trim leading zeros
    uint8_t *trimmed = buf;
    while (trimmed < buf + 8 && *trimmed == 0) {
        trimmed++;
    }

    size_t valLen = buf + 8 - trimmed;
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

        if ((txn->elements[txn->elementIndex].elemType + 1) <= V2TXN_ELEM_ARB_DATA) {
            txn->sliceLen = readInt(txn);
            txn->sliceIndex = 0;
            advance(txn);
            txn->elements[txn->elementIndex].elemType++;
        } else {
            txn->sliceLen = 1;
            txn->sliceIndex = 0;
            txn->elements[txn->elementIndex].elemType++;
            // Either new foundation address or miner fee, thesse require their
            // own logic below since they are not slices.
            break;
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

        case V2TXN_ELEM_SF_OUTPUT: {
            const uint64_t value = readInt(txn);  // Value
            writeUint64Currency(value, txn->elements[txn->elementIndex].outVal);
            readHash(txn, (char *) txn->elements[txn->elementIndex].outAddr);  // UnlockHash
            advance(txn);

            txn->sliceIndex++;
            txn->elements[txn->elementIndex + 1].elemType =
                txn->elements[txn->elementIndex].elemType;
            txn->elementIndex++;
            return;
        }

        case V2TXN_ELEM_MINER_FEE:
            readCurrency(txn, txn->elements[txn->elementIndex].outVal);  // Value
            memmove(txn->elements[txn->elementIndex].outAddr, "[Miner Fee]", 12);
            advance(txn);

            txn->sliceIndex++;
            txn->elements[txn->elementIndex + 1].elemType =
                txn->elements[txn->elementIndex].elemType;
            txn->elementIndex++;
            return;

        // these elements should be decoded, but not displayed
        case V2TXN_ELEM_SC_INPUT:
            readHash(txn, NULL);  // Parent.ID
            advance(txn);

            txn->sliceIndex++;
            return;

        case V2TXN_ELEM_SF_INPUT:
            readHash(txn, NULL);  // Parent.ID
            advance(txn);

            txn->sliceIndex++;
            return;

        case V2TXN_ELEM_NEW_FOUNDATION_ADDR:
            need_at_least(txn, 1);
            const uint8_t set = txn->buf[txn->pos];
            if (set == 1) {
                // we do not support displaying new foundation address
                THROW(TXN_STATE_ERR);
            }
            seek(txn, 1);
            advance(txn);

            txn->sliceIndex++;
            return;

            // these elements should not be present
        case V2TXN_ELEM_FC:
        case V2TXN_ELEM_FC_REVISION:
        case V2TXN_ELEM_FC_RESOLUTION:
        case V2TXN_ELEM_ATTESTATION:
        case V2TXN_ELEM_ARB_DATA:
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

    {
        static const uint8_t sigInput[] =
            {'s', 'i', 'a', '/', 's', 'i', 'g', '/', 'i', 'n', 'p', 'u', 't', '|'};
        blake2b_update(&txn->blake, sigInput, sizeof(sigInput));
    }
    {
        static const uint8_t replayPrefix[] = {2};
        blake2b_update(&txn->blake, replayPrefix, sizeof(replayPrefix));
    }
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
