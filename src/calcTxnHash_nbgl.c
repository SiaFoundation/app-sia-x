#ifndef HAVE_BAGL

#include <io.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <ux.h>

#include "blake2b.h"
#include "sia.h"
#include "sia_ux.h"
#include "txn.h"
#include "v2txn.h"
#include "nbgl_use_case.h"

static calcTxnHashContext_t *ctx = &global.calcTxnHashContext;

static void confirm_callback(bool confirm) {
    ctx->initialized = false;

    if (confirm) {
        if (ctx->sign) {
            uint8_t signature[64] = {0};
            deriveAndSign(signature, ctx->keyIndex, ctx->txn.sigHash);
            io_send_response_pointer(signature, sizeof(signature), SW_OK);
            nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle);
        } else {
            io_send_response_pointer(ctx->txn.sigHash, sizeof(ctx->txn.sigHash), SW_OK);
            nbgl_useCaseStatus("TRANSACTION HASHED", true, ui_idle);
        }
    } else {
        io_send_sw(SW_USER_REJECTED);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}

txnElemType_e element_type(uint8_t pairIndex) {
    if (ctx->lastSiacoinOutputIndex != USHRT_MAX &&
        (pairIndex / 2) <= ctx->lastSiacoinOutputIndex) {
        return TXN_ELEM_SC_OUTPUT;
    } else if (ctx->lastSiafundOutputIndex != USHRT_MAX &&
               (pairIndex / 2) <= ctx->lastSiafundOutputIndex) {
        return TXN_ELEM_SF_OUTPUT;
    }
    return TXN_ELEM_MINER_FEE;
}

static nbgl_contentTagValue_t *getTagValuePairs(uint8_t pairIndex) {
    static nbgl_contentTagValue_t contentTagValue = {0};
    txn_state_t *txn = &ctx->txn;
    uint8_t valLen = 0;
    uint16_t lastOutputIndex = 0;

    switch (element_type(pairIndex)) {
        case TXN_ELEM_SC_OUTPUT:
        case V2TXN_ELEM_SC_OUTPUT:
            // For each siacoin output, the user needs to see both
            // the destination address and the amount.
            ctx->elementIndex = pairIndex / 2;
            if (pairIndex % 2 == 0) {
                format_address(ctx->fullStr[0], txn->elements[ctx->elementIndex].outAddr);
                contentTagValue.item = "To";
                contentTagValue.value = ctx->fullStr[0];
            } else {
                valLen = cur2dec(ctx->fullStr[1], txn->elements[ctx->elementIndex].outVal);
                formatSC(ctx->fullStr[1], valLen);
                contentTagValue.item = "Amount (SC)";
                contentTagValue.value = ctx->fullStr[1];
            }
            contentTagValue.forcePageStart = false;
            break;
        case TXN_ELEM_SF_OUTPUT:
        case V2TXN_ELEM_SF_OUTPUT:
            // For each siacoin output, the user needs to see both
            // the destination address and the amount.
            ctx->elementIndex = pairIndex / 2;
            if (pairIndex % 2 == 0) {
                format_address(ctx->fullStr[0], txn->elements[ctx->elementIndex].outAddr);
                contentTagValue.item = "To";
                contentTagValue.value = ctx->fullStr[0];
            } else {
                cur2dec(ctx->fullStr[1], txn->elements[ctx->elementIndex].outVal);
                contentTagValue.item = "Amount (SF)";
                contentTagValue.value = ctx->fullStr[1];
            }
            contentTagValue.forcePageStart = false;
            break;

        case TXN_ELEM_MINER_FEE:
        case V2TXN_ELEM_MINER_FEE:
            lastOutputIndex = ctx->lastSiafundOutputIndex;
            if (lastOutputIndex == USHRT_MAX) {
                lastOutputIndex = ctx->lastSiacoinOutputIndex;
            }
            if (lastOutputIndex == USHRT_MAX) {
                lastOutputIndex = 0;
            } else {
                lastOutputIndex++;
            }

            ctx->elementIndex = pairIndex - lastOutputIndex;
            valLen = cur2dec(ctx->fullStr[0], txn->elements[ctx->elementIndex].outVal);
            formatSC(ctx->fullStr[0], valLen);
            contentTagValue.item = "Miner Fee Amount (SC)";
            contentTagValue.value = ctx->fullStr[0];
            contentTagValue.forcePageStart = true;
            break;

        default:
            // This should never happen.
            io_send_sw(SW_DEVELOPER_ERR);
            ui_idle();
            break;
    }

    return &contentTagValue;
}

static void zero_ctx(void) {
    explicit_bzero(ctx, sizeof(calcTxnHashContext_t));
}

// handleCalcTxnHash reads a signature index and a transaction, calculates the
// SigHash of the transaction, and optionally signs the hash using a specified
// key. The transaction is displayed piece-wise to the user.
uint16_t handleCalcTxnHash(
    uint8_t ins, uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength) {
    if ((p1 != P1_FIRST && p1 != P1_MORE) || (p2 != P2_DISPLAY_HASH && p2 != P2_SIGN_HASH)) {
        return SW_INVALID_PARAM;
    }

    if (p1 == P1_FIRST) {
        // If this is the first packet of a transaction, the transaction
        // context must not already be initialized. (Otherwise, an attacker
        // could fool the user by concatenating two transactions.)
        //
        // NOTE: ctx->initialized is set to false when the Sia app loads.
        if (ctx->initialized) {
            zero_ctx();
            return SW_IMPROPER_INIT;
        }
        explicit_bzero(ctx, sizeof(calcTxnHashContext_t));
        ctx->initialized = true;
        ctx->lastSiacoinOutputIndex = USHRT_MAX;
        ctx->lastSiafundOutputIndex = USHRT_MAX;

        // If this is the first packet, it will include the key index, sig
        // index, and change index in addition to the transaction data. Use
        // these to initialize the ctx and the transaction decoder.
        ctx->keyIndex = U4LE(dataBuffer, 0);  // NOTE: ignored if !ctx->sign
        dataBuffer += 4;
        dataLength -= 4;
        uint16_t sigIndex = U2LE(dataBuffer, 0);
        dataBuffer += 2;
        dataLength -= 2;
        uint32_t changeIndex = U4LE(dataBuffer, 0);
        dataBuffer += 4;
        dataLength -= 4;
        if (ins == INS_GET_TXN_HASH) {
            txn_init(&ctx->txn, sigIndex, changeIndex);
        } else {
            v2txn_init(&ctx->txn, sigIndex, changeIndex);
        }

        // Set ctx->sign according to P2.
        ctx->sign = (p2 & P2_SIGN_HASH);

        ctx->elemPart = 0;
    } else {
        // If this is not P1_FIRST, the transaction must have been
        // initialized previously.
        if (!ctx->initialized) {
            zero_ctx();
            return SW_IMPROPER_INIT;
        }
    }

    // Add the new data to transaction decoder.
    if (ins == INS_GET_TXN_HASH) {
        txn_update(&ctx->txn, dataBuffer, dataLength);
    } else {
        v2txn_update(&ctx->txn, dataBuffer, dataLength);
    }

    switch ((ins == INS_GET_TXN_HASH) ? txn_parse(&ctx->txn) : v2txn_parse(&ctx->txn)) {
        case TXN_STATE_ERR:
            // don't leave state lingering
            zero_ctx();
            return SW_INVALID_PARAM;
            break;
        case TXN_STATE_PARTIAL:
            return SW_OK;
            break;
        case TXN_STATE_FINISHED: {
            // Computes the number of pairs to display
            nbgl_contentTagValueList_t contentTagValueList = {0};
            for (uint16_t i = 0; i < ctx->txn.elementIndex; i++) {
                const txnElemType_e elemType = ctx->txn.elements[i].elemType;
                if (elemType == TXN_ELEM_SC_OUTPUT || elemType == V2TXN_ELEM_SC_OUTPUT) {
                    ctx->lastSiacoinOutputIndex = i;
                } else if (elemType == TXN_ELEM_SF_OUTPUT || elemType == V2TXN_ELEM_SF_OUTPUT) {
                    ctx->lastSiafundOutputIndex = i;
                }
                contentTagValueList.nbPairs +=
                    (elemType == TXN_ELEM_MINER_FEE || elemType == V2TXN_ELEM_MINER_FEE) ? 1 : 2;
            }
            contentTagValueList.callback = getTagValuePairs;
            nbgl_useCaseReview(TYPE_TRANSACTION,
                               &contentTagValueList,
                               &C_stax_app_sia_big,
                               (ctx->sign) ? "Sign Transaction" : "Hash Transaction",
                               NULL,
                               (ctx->sign) ? "Sign Transaction" : "Hash Transaction",
                               confirm_callback);
            break;
        }
    }

    return 0;
}

#endif /* HAVE_BAGL */
