#ifndef HAVE_BAGL

#include <io.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ux.h>

#include "blake2b.h"
#include "sia.h"
#include "sia_ux.h"
#include "txn.h"

static calcTxnHashContext_t *ctx = &global.calcTxnHashContext;

static void fmtTxnElem(void);
static uint16_t display_index(void);
static bool nav_callback(uint8_t page, nbgl_pageContent_t *content);
static void confirm_callback(bool confirm);

// Gets the current index number to be displayed in the UI
static uint16_t display_index(void) {
    txn_state_t *txn = &ctx->txn;
    uint16_t first_index_of_type = 0;
    const txnElemType_e current_type = txn->elements[ctx->elementIndex].elemType;
    for (uint16_t i = 0; i < txn->elementIndex; i++) {
        if (current_type == txn->elements[i].elemType) {
            first_index_of_type = i;
            break;
        }
    }
    return ctx->elementIndex - first_index_of_type + 1;
}

// This is a helper function that prepares an element of the transaction for
// display. It stores the type of the element in labelStr, and a human-
// readable representation of the element in fullStr. As in previous screens,
// partialStr holds the visible portion of fullStr.
static void fmtTxnElem(void) {
    txn_state_t *txn = &ctx->txn;

    switch (txn->elements[ctx->elementIndex].elemType) {
        case TXN_ELEM_SC_OUTPUT: {
            memmove(ctx->labelStr, "SC Output #", 11);
            bin2dec(ctx->labelStr + 11, display_index());
            // An element can have multiple screens. For each siacoin output, the
            // user needs to see both the destination address and the amount.
            // These are rendered in separate screens, and elemPart is used to
            // identify which screen is being viewed.
            format_address(ctx->fullStr[0], txn->elements[ctx->elementIndex].outAddr);
            const uint8_t valLen =
                cur2dec(ctx->fullStr[1], txn->elements[ctx->elementIndex].outVal);
            formatSC(ctx->fullStr[1], valLen);
            break;
        }

        case TXN_ELEM_SF_OUTPUT: {
            memmove(ctx->labelStr, "SF Output #", 11);
            bin2dec(ctx->labelStr + 11, display_index());
            format_address(ctx->fullStr[0], txn->elements[ctx->elementIndex].outAddr);
            cur2dec(ctx->fullStr[1], txn->elements[ctx->elementIndex].outVal);
            break;
        }

        case TXN_ELEM_MINER_FEE: {
            // Miner fees only have one part.
            memmove(ctx->labelStr, "Miner Fee #", 11);
            bin2dec(ctx->labelStr + 11, display_index());

            const uint8_t valLen =
                cur2dec(ctx->fullStr[0], txn->elements[ctx->elementIndex].outVal);
            formatSC(ctx->fullStr[0], valLen);
            break;
        }

        default:
            // This should never happen.
            io_send_sw(SW_DEVELOPER_ERR);
            ui_idle();
            break;
    }
}

static void confirm_callback(bool confirm) {
    ctx->finished = false;
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

static nbgl_layoutTagValue_t pairs[2];

static bool nav_callback(uint8_t page, nbgl_pageContent_t *content) {
    ctx->elementIndex = page;
    if (ctx->elementIndex >= ctx->txn.elementIndex) {
        content->type = INFO_LONG_PRESS;
        content->infoLongPress.icon = &C_stax_app_sia_big;
        if (ctx->sign) {
            content->infoLongPress.text = "Sign transaction";
            content->infoLongPress.longPressText = "Hold to sign";
        } else {
            content->infoLongPress.text = "Hash transaction";
            content->infoLongPress.longPressText = "Hold to hash";
        }
        return true;
    }

    fmtTxnElem();

    if (ctx->txn.elements[ctx->elementIndex].elemType == TXN_ELEM_MINER_FEE) {
        pairs[0].item = "Miner Fee Amount (SC)";
        pairs[0].value = ctx->fullStr[0];

        content->tagValueList.nbPairs = 1;
        content->tagValueList.pairs = &pairs[0];
    } else {
        pairs[0].item = "To";
        pairs[0].value = ctx->fullStr[0];
        if (ctx->txn.elements[ctx->elementIndex].elemType == TXN_ELEM_SC_OUTPUT) {
            pairs[1].item = "Amount (SC)";
        } else {
            pairs[1].item = "Amount (SF)";
        }
        pairs[1].value = ctx->fullStr[1];

        content->tagValueList.nbPairs = 2;
        content->tagValueList.pairs = &pairs[0];
    }

    content->title = ctx->labelStr;
    content->type = TAG_VALUE_LIST;
    content->tagValueList.callback = NULL;

    content->tagValueList.startIndex = 0;
    content->tagValueList.wrapping = false;
    content->tagValueList.smallCaseForValue = false;
    content->tagValueList.nbMaxLinesForValue = 0;

    return true;
}

static void begin_review(void) {
    nbgl_useCaseRegularReview(0,
                              ctx->txn.elementIndex + 1,
                              "Cancel",
                              NULL,
                              nav_callback,
                              confirm_callback);
}

static void cancel_review(void) {
    confirm_callback(false);
}

static void zero_ctx(void) {
    explicit_bzero(ctx, sizeof(calcTxnHashContext_t));
}

// handleCalcTxnHash reads a signature index and a transaction, calculates the
// SigHash of the transaction, and optionally signs the hash using a specified
// key. The transaction is displayed piece-wise to the user.
uint16_t handleCalcTxnHash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength) {
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
        txn_init(&ctx->txn, sigIndex, changeIndex);

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
    txn_update(&ctx->txn, dataBuffer, dataLength);

    switch (txn_parse(&ctx->txn)) {
        case TXN_STATE_ERR:
            // don't leave state lingering
            zero_ctx();
            return SW_INVALID_PARAM;
            break;
        case TXN_STATE_PARTIAL:
            return SW_OK;
            break;
        case TXN_STATE_FINISHED:
            nbgl_useCaseReviewStart(&C_stax_app_sia_big,
                                    (ctx->sign) ? "Sign Transaction" : "Hash Transaction",
                                    NULL,
                                    "Cancel",
                                    begin_review,
                                    cancel_review);
            break;
    }

    return 0;
}

#endif /* HAVE_BAGL */
