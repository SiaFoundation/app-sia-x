#ifndef HAVE_BAGL

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
        case TXN_ELEM_SC_OUTPUT:
            memmove(ctx->labelStr, "SC Output #", 11);
            bin2dec(ctx->labelStr + 11, display_index());
            // An element can have multiple screens. For each siacoin output, the
            // user needs to see both the destination address and the amount.
            // These are rendered in separate screens, and elemPart is used to
            // identify which screen is being viewed.
            memmove(ctx->fullStr[0], txn->elements[ctx->elementIndex].outAddr, sizeof(txn->elements[ctx->elementIndex].outAddr));
            memmove(ctx->fullStr[1], txn->elements[ctx->elementIndex].outVal, sizeof(txn->elements[ctx->elementIndex].outVal));
            formatSC(ctx->fullStr[1], txn->elements[ctx->elementIndex].valLen);
            break;

        case TXN_ELEM_SF_OUTPUT:
            memmove(ctx->labelStr, "SF Output #", 11);
            bin2dec(ctx->labelStr + 11, display_index());
            memmove(ctx->fullStr[0], txn->elements[ctx->elementIndex].outAddr, sizeof(txn->elements[ctx->elementIndex].outAddr));
            memmove(ctx->fullStr[1], txn->elements[ctx->elementIndex].outVal, sizeof(txn->elements[ctx->elementIndex].outVal));
            memmove(ctx->fullStr[1] + txn->elements[ctx->elementIndex].valLen, " SF", 4);
            break;

        case TXN_ELEM_MINER_FEE:
            // Miner fees only have one part.
            memmove(ctx->labelStr, "Miner Fee #", 11);
            bin2dec(ctx->labelStr + 11, display_index());
            memmove(ctx->fullStr[0], txn->elements[ctx->elementIndex].outVal, sizeof(txn->elements[ctx->elementIndex].outVal));
            formatSC(ctx->fullStr[0], txn->elements[ctx->elementIndex].valLen);
            break;

        default:
            // This should never happen.
            io_exchange_with_code(SW_DEVELOPER_ERR, 0);
            ui_idle();
            break;
    }
}

static void confirm_callback(bool confirm) {
    // The final page of hashing doesn't need to send reject because at that
    // point, the client has already received the hash.
    const bool finished = ctx->finished;
    ctx->finished = false;
    ctx->initialized = false;

    if (confirm) {
        if (ctx->sign) {
            deriveAndSign(G_io_apdu_buffer, ctx->keyIndex, ctx->txn.sigHash);
            io_exchange_with_code(SW_OK, 64);
            nbgl_useCaseStatus("TRANSACTION SIGNED", true, ui_idle);
        } else {
            nbgl_useCaseStatus("CONFIRMED HASH", true, ui_idle);
        }
    } else {
        if (!(!ctx->sign && finished)) {
            io_exchange_with_code(SW_USER_REJECTED, 0);
        }
        nbgl_useCaseStatus("Transaction Rejected", false, ui_idle);
    }
}

static nbgl_layoutTagValue_t pairs[3];

static bool nav_callback(uint8_t page, nbgl_pageContent_t *content) {
    UNUSED(page);
    ctx->elementIndex = page;
    if (ctx->elementIndex >= ctx->txn.elementIndex) {
        const bool wasFinished = ctx->finished;
        ctx->finished = true;

        content->type = INFO_LONG_PRESS;
        content->infoLongPress.icon = &C_stax_app_sia;
        if (ctx->sign) {
            memmove(ctx->fullStr[0], "with key #", 10);
            bin2dec(ctx->fullStr[0] + 10, ctx->keyIndex);
            memmove(ctx->fullStr[0] + 10 + (bin2dec(ctx->fullStr[0] + 10, ctx->keyIndex)), "?", 2);

            content->infoLongPress.text = "Sign Transaction";
            content->infoLongPress.longPressText = ctx->fullStr[0];
        } else {
            memmove(G_io_apdu_buffer, ctx->txn.sigHash, 32);
            // prevent this from being sent twice and causing device to hang
            if (!wasFinished) {
                io_exchange_with_code(SW_OK, 32);
            }
            bin2hex(ctx->fullStr[0], ctx->txn.sigHash, sizeof(ctx->txn.sigHash));

            content->infoLongPress.text = ctx->fullStr[0];
            content->infoLongPress.longPressText = "Confirm Hash";
        }
        return true;
    }

    fmtTxnElem();

    pairs[0].item = "Label";
    pairs[0].value = ctx->labelStr;

    if (ctx->txn.elements[ctx->elementIndex].elemType == TXN_ELEM_MINER_FEE) {
        pairs[1].item = "Value";
        pairs[1].value = ctx->fullStr[0];

        content->tagValueList.nbPairs = 2;
        content->tagValueList.pairs = &pairs;
    } else {
        pairs[1].item = "Address";
        pairs[1].value = ctx->fullStr[0];
        pairs[2].item = "Value";
        pairs[2].value = ctx->fullStr[1];

        content->tagValueList.nbPairs = 3;
        content->tagValueList.pairs = &pairs;
    }

    content->title = NULL;
    content->type = TAG_VALUE_LIST;
    content->tagValueList.callback = NULL;

    content->tagValueList.startIndex = 0;
    content->tagValueList.wrapping = false;
    content->tagValueList.smallCaseForValue = false;
    content->tagValueList.nbMaxLinesForValue = 0;

    return true;
}

// handleCalcTxnHash reads a signature index and a transaction, calculates the
// SigHash of the transaction, and optionally signs the hash using a specified
// key. The transaction is processed in a streaming fashion and displayed
// piece-wise to the user.
void handleCalcTxnHash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx __attribute__((unused))) {
    if ((p1 != P1_FIRST && p1 != P1_MORE) || (p2 != P2_DISPLAY_HASH && p2 != P2_SIGN_HASH)) {
        THROW(SW_INVALID_PARAM);
    }

    const bool prev_initialized = ctx->initialized;
    if (p1 == P1_FIRST) {
        // If this is the first packet of a transaction, the transaction
        // context must not already be initialized. (Otherwise, an attacker
        // could fool the user by concatenating two transactions.)
        //
        // NOTE: ctx->initialized is set to false when the Sia app loads.
        if (prev_initialized) {
            THROW(SW_IMPROPER_INIT);
        }
        ctx->elementIndex = 0;
        ctx->finished = false;
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
        if (!prev_initialized) {
            THROW(SW_IMPROPER_INIT);
        }
    }

    // Add the new data to transaction decoder.
    txn_update(&ctx->txn, dataBuffer, dataLength);

    *flags |= IO_ASYNCH_REPLY;
    switch (txn_parse(&ctx->txn)) {
        case TXN_STATE_ERR:
            io_exchange_with_code(SW_INVALID_PARAM, 0);
            break;
        case TXN_STATE_PARTIAL:
            io_exchange_with_code(SW_OK, 0);
            break;
        case TXN_STATE_FINISHED:
            nbgl_useCaseRegularReview(0, 0, "Cancel", NULL, nav_callback, confirm_callback);
            break;
    }
}

#endif /* HAVE_BAGL */