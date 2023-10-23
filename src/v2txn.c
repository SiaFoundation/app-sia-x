#include <os.h>
#include <string.h>

#include "sia.h"  // For SW_DEVELOPER_ERR. Should be removed.
#include "txn.h"
#include "parse.h"

static void advance(txn_state_t *v2txn) {
    blake2b_update(&v2txn->blake, v2txn->buf, v2txn->pos);

    v2txn->buflen -= v2txn->pos;
    memmove(v2txn->buf, v2txn->buf + v2txn->pos, v2txn->buflen);
    v2txn->pos = 0;
}

// throws txnDecoderState_e
static void __v2txn_next_elem(txn_state_t *v2txn) {
    // if we're on a slice boundary, read the next length prefix and bump the
    // element type
    while (v2txn->sliceIndex == v2txn->sliceLen) {
        if (v2txn->sliceLen == v2txn->sliceIndex) {
            if (v2txn->elemType == V2TXN_ELEM_MINER_FEE) {
                v2txn->sliceLen = 0;
                v2txn->sliceIndex = 0;
                v2txn->displayIndex = 0;

                blake2b_final(&v2txn->blake, v2txn->sigHash, sizeof(v2txn->sigHash));
                THROW(TXN_STATE_FINISHED);
            }
            v2txn->elemType++;
        }
        switch (v2txn->elemType) {
            case V2TXN_ELEM_SC_INPUT:
            case V2TXN_ELEM_SC_OUTPUT:
            case V2TXN_ELEM_SF_INPUT:
            case V2TXN_ELEM_SF_OUTPUT:
            case V2TXN_ELEM_FC:
            case V2TXN_ELEM_FC_REVISIONS:
            case V2TXN_ELEM_FC_RESOLUTIONS:
            case V2TXN_ELEM_ATTESTATIONS:
                v2txn->sliceLen = readInt(v2txn);
                v2txn->sliceIndex = 0;
                v2txn->displayIndex = 0;
                advance(v2txn);
                break;

            case V2TXN_ELEM_ARB_DATA:
                v2txn->sliceLen = 0;
                v2txn->sliceIndex = 0;
                v2txn->displayIndex = 0;
                if (readInt(v2txn) != 0) {
                    THROW(TXN_STATE_ERR);
                }
                advance(v2txn);
                break;

            case V2TXN_ELEM_FDN_ADDR:
                v2txn->sliceLen = 0;
                v2txn->sliceIndex = 0;
                v2txn->displayIndex = 0;
                if (readUint8(v2txn) != 0) {
                    THROW(TXN_STATE_ERR);
                }
                advance(v2txn);
                break;

            case V2TXN_ELEM_MINER_FEE:
                // all v2 transactions have miner fee
                v2txn->sliceLen = 1;
                v2txn->sliceIndex = 0;
                v2txn->displayIndex = 0;
                break;
        }
    }

    switch (v2txn->elemType) {
        // these elements should be displayed
        case V2TXN_ELEM_SC_OUTPUT:
            readCurrency(v2txn, v2txn->outVal);       // Value
            readHash(v2txn, (char *)v2txn->outAddr);  // UnlockHash
            if (!memcmp(v2txn->outAddr, v2txn->changeAddr, sizeof(v2txn->outAddr))) {
                // do not display the change address or increment displayIndex
                return;
            }
            advance(v2txn);

            v2txn->sliceIndex++;
            v2txn->displayIndex++;

            THROW(TXN_STATE_READY);
            break;

        case V2TXN_ELEM_SF_OUTPUT:
            readCurrency(v2txn, v2txn->outVal);       // Value
            readHash(v2txn, (char *)v2txn->outAddr);  // UnlockHash
            readCurrency(v2txn, NULL);                // ClaimStart
            advance(v2txn);

            v2txn->sliceIndex++;
            v2txn->displayIndex++;

            THROW(TXN_STATE_READY);
            break;

        case V2TXN_ELEM_MINER_FEE:
            readCurrency(v2txn, v2txn->outVal);  // Value
            memmove(v2txn->outAddr, "[Miner Fee]", 12);
            advance(v2txn);

            v2txn->sliceIndex++;
            THROW(TXN_STATE_READY);
            break;

        // these elements should be decoded, but not displayed
        case V2TXN_ELEM_SC_INPUT:
            readHash(v2txn, NULL);  // ParentID
            advance(v2txn);

            v2txn->sliceIndex++;
            break;

        case V2TXN_ELEM_SF_INPUT:
            readHash(v2txn, NULL);  // ParentID
            advance(v2txn);

            v2txn->sliceIndex++;
            break;

        // these elements should not be present
        case V2TXN_ELEM_FC:
        case V2TXN_ELEM_FC_REVISIONS:
        case V2TXN_ELEM_FC_RESOLUTIONS:
        case V2TXN_ELEM_ATTESTATIONS:
            if (v2txn->sliceLen != 0) {
                THROW(TXN_STATE_ERR);
            }
            break;
    }
}

txnDecoderState_e v2txn_next_elem(txn_state_t *v2txn) {
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
                __v2txn_next_elem(v2txn);
            }
        }
        CATCH_OTHER(e) {
            result = e;
        }
        FINALLY {
        }
    }
    END_TRY;
    if (v2txn->buflen + 255 > sizeof(v2txn->buf)) {
        // we filled the buffer to max capacity, but there still wasn't enough
        // to decode a full element. This generally means that the txn is
        // corrupt in some way, since elements shouldn't be very large.
        return TXN_STATE_ERR;
    }
    return result;
}

void v2txn_update(txn_state_t *v2txn, uint8_t *in, uint8_t inlen) {
    // the buffer should never overflow; any elements should always be drained
    // before the next read.
    if (v2txn->buflen + inlen > sizeof(v2txn->buf)) {
        THROW(SW_DEVELOPER_ERR);
    }

    // append to the buffer
    memmove(v2txn->buf + v2txn->buflen, in, inlen);
    v2txn->buflen += inlen;

    // reset the seek position; if we previously threw TXN_STATE_PARTIAL, now
    // we can try decoding again from the beginning.
    v2txn->pos = 0;
}

void v2txn_init(txn_state_t *v2txn, uint16_t sigIndex, uint32_t changeIndex) {
    memset(v2txn, 0, sizeof(txn_state_t));
    v2txn->v2 = true;
    v2txn->buflen = v2txn->pos = v2txn->sliceIndex = v2txn->displayIndex = v2txn->sliceLen = v2txn->valLen = 0;
    // v2txn->elemType = V2TXN_ELEM_SC_INPUT;
    v2txn->elemType = TXN_ELEM_TXN_SIG;
    v2txn->sigIndex = sigIndex;

    cx_ecfp_public_key_t publicKey = {0};
    deriveSiaKeypair(changeIndex, NULL, &publicKey);
    pubkeyToSiaAddress((char *)&v2txn->changeAddr, &publicKey);

    // initialize hash state
    blake2b_init(&v2txn->blake);

    static uint8_t const distinguisher[] = "sia/sig/input|";
    blake2b_update(&v2txn->blake, distinguisher, 14);

    static uint8_t const replayPrefix[] = {2};
    blake2b_update(&v2txn->blake, replayPrefix, 1);
}
