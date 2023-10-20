#include <os.h>
#include <string.h>

#include "sia.h"  // For SW_DEVELOPER_ERR. Should be removed.
#include "txn.h"

static void divWW10(uint64_t u1, uint64_t u0, uint64_t *q, uint64_t *r) {
    const uint64_t s = 60ULL;
    const uint64_t v = 11529215046068469760ULL;
    const uint64_t vn1 = 2684354560ULL;
    const uint64_t _B2 = 4294967296ULL;
    uint64_t un32 = u1 << s | u0 >> (64 - s);
    uint64_t un10 = u0 << s;
    uint64_t un1 = un10 >> 32;
    uint64_t un0 = un10 & (_B2 - 1);
    uint64_t q1 = un32 / vn1;
    uint64_t rhat = un32 - q1 * vn1;

    while (q1 >= _B2) {
        q1--;
        rhat += vn1;
        if (rhat >= _B2) {
            break;
        }
    }

    uint64_t un21 = un32 * _B2 + un1 - q1 * v;
    uint64_t q0 = un21 / vn1;
    rhat = un21 - q0 * vn1;

    while (q0 >= _B2) {
        q0--;
        rhat += vn1;
        if (rhat >= _B2) {
            break;
        }
    }

    *q = q1 * _B2 + q0;
    *r = (un21 * _B2 + un0 - q0 * v) >> s;
}

static uint64_t quorem10(uint64_t nat[], int len) {
    uint64_t r = 0;
    for (int i = len - 1; i >= 0; i--) {
        divWW10(r, nat[i], &nat[i], &r);
    }
    return r;
}

// cur2dec converts a Sia-encoded currency value to a decimal string and
// appends a final NUL byte. It returns the length of the string. If the value
// is too large, it throws TXN_STATE_ERR.
static int cur2dec(uint8_t *out, uint8_t *cur) {
    if (cur[0] == 0) {
        out[0] = '\0';
        return 0;
    }

    // sanity check the size of the value. The size (in bytes) is given in the
    // first byte; it should never be greater than 18 (18 bytes = 144 bits,
    // i.e. a value of 2^144 H, or 22 quadrillion SC).
    if (cur[0] > 18) {
        THROW(TXN_STATE_ERR);
    }

    // convert big-endian uint8_t[] to little-endian uint64_t[]
    //
    // NOTE: the Sia encoding omits any leading zeros, so the first "uint64"
    // may not be a full 8 bytes. We handle this by treating the length prefix
    // as part of the first uint64. This is safe as long as the length prefix
    // has only 1 non-zero byte, which should be enforced elsewhere.
    uint64_t nat[32];
    int len = (cur[0] / 8) + ((cur[0] % 8) != 0);
    cur += 8 - (len * 8 - cur[0]);
    for (int i = 0; i < len; i++) {
        nat[len - i - 1] = U8BE(cur, i * 8);
    }

    // decode digits into buf, right-to-left
    //
    // NOTE: buf must be large enough to hold the decimal representation of
    // 2^144, which has 44 digits.
    uint8_t buf[64];
    int i = sizeof(buf);
    buf[--i] = '\0';
    while (len > 0) {
        if (i <= 0) {
            THROW(TXN_STATE_ERR);
        }
        buf[--i] = '0' + quorem10(nat, len);
        // normalize nat
        while (len > 0 && nat[len - 1] == 0) {
            len--;
        }
    }

    // copy buf->out, trimming whitespace
    memmove(out, buf + i, sizeof(buf) - i);
    return sizeof(buf) - i - 1;
}

static void need_at_least(txn_state_t *v2txn, uint64_t n) {
    if ((v2txn->buflen - v2txn->pos) < n) {
        THROW(TXN_STATE_PARTIAL);
    }
}

static void seek(txn_state_t *v2txn, uint64_t n) {
    need_at_least(v2txn, n);
    v2txn->pos += n;
}

static void advance(txn_state_t *v2txn) {
    blake2b_update(&v2txn->blake, v2txn->buf, v2txn->pos);

    v2txn->buflen -= v2txn->pos;
    memmove(v2txn->buf, v2txn->buf + v2txn->pos, v2txn->buflen);
    v2txn->pos = 0;
}

static uint64_t readBool(txn_state_t *v2txn) {
    need_at_least(v2txn, 1);
    uint64_t u = v2txn->buf[v2txn->pos];
    seek(v2txn, 1);
    return u;
}

static uint64_t readInt(txn_state_t *v2txn) {
    need_at_least(v2txn, 8);
    uint64_t u = U8LE(v2txn->buf, v2txn->pos);
    seek(v2txn, 8);
    return u;
}

static void readCurrency(txn_state_t *v2txn, uint8_t *outVal) {
    uint64_t valLen = readInt(v2txn);
    need_at_least(v2txn, valLen);
    if (outVal) {
        v2txn->valLen = cur2dec(outVal, v2txn->buf + v2txn->pos - 8);
    }
    seek(v2txn, valLen);
}

static void readHash(txn_state_t *v2txn, char *outAddr) {
    need_at_least(v2txn, 32);
    if (outAddr) {
        bin2hex(outAddr, v2txn->buf + v2txn->pos, 32);
        uint8_t checksum[6];
        blake2b(checksum, sizeof(checksum), v2txn->buf + v2txn->pos, 32);
        bin2hex(outAddr + 64, checksum, sizeof(checksum));
    }
    seek(v2txn, 32);
}

static void readPrefixedBytes(txn_state_t *v2txn) {
    uint64_t len = readInt(v2txn);
    seek(v2txn, len);
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
                PRINTF("v2txn->elemType: %d, v2txn->sliceLen: %d\n", v2txn->elemType, v2txn->sliceLen);
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
                if (readBool(v2txn) != 0) {
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
            PRINTF("READING MINER FEE!\n");
            readCurrency(v2txn, v2txn->outVal);  // Value
            memmove(v2txn->outAddr, "[Miner Fee]", 12);
            PRINTF("READ MINER FEE: %d (%s)\n", strlen(v2txn->outVal), v2txn->outAddr);
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

    static uint8_t const distinguisher[] = {
        's', 'i', 'a', '/',
        's', 'i', 'g', '/', 'i', 'n', 'p', 'u', 't',
        '|',
    };
    blake2b_update(&v2txn->blake, distinguisher, 14);

    static uint8_t const replayPrefix[] = {2};
    blake2b_update(&v2txn->blake, replayPrefix, 1);
}
