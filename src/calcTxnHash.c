#ifdef HAVE_BAGL
// This file contains the implementation of the calcTxnHash command. It is
// significantly more complicated than the other commands, mostly due to the
// transaction parsing.
//
// A high-level description of calcTxnHash is as follows. The user initiates
// the command on their computer by requesting the hash of a specific
// transaction. A flag in the request controls whether the resulting hash
// should be signed. The command handler then begins reading transaction data
// from the computer, in packets of up to 255 bytes at a time. The handler
// buffers this data until a full "element" in parsed. Depending on the type
// of the element, it may then be displayed to the user for comparison. Once
// all elements have been received and parsed, the final screen differs
// depending on whether a signature was requested. If so, the user is prompted
// to approve the signature; if they do, the signature is sent to the
// computer, and the app returns to the main menu. If no signature was
// requested, the transaction hash is immediately sent to the computer and
// displayed on a comparison screen. Pressing both buttons returns the user to
// the main menu.
//
// Keep this description in mind as you read through the implementation.

#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ux.h>
#include <io.h>

#include "blake2b.h"
#include "sia.h"
#include "sia_ux.h"
#include "txn.h"

static calcTxnHashContext_t *ctx = &global.calcTxnHashContext;

static void fmtTxnElem(void);
static uint16_t display_index(void);
static unsigned int ui_calcTxnHash_elem_button(void);
static unsigned int io_seproxyhal_touch_txn_hash_ok(void);

UX_STEP_CB(ux_compare_hash_flow_1_step,
           bnnn_paging,
           ui_idle(),
           {"Compare Hash:", global.calcTxnHashContext.fullStr[0]});

UX_FLOW(ux_compare_hash_flow, &ux_compare_hash_flow_1_step);

UX_STEP_NOCB(ux_sign_txn_flow_1_step, nn, {"Sign this txn", global.calcTxnHashContext.fullStr[0]});

UX_STEP_VALID(ux_sign_txn_flow_2_step,
              pb,
              io_seproxyhal_touch_txn_hash_ok(),
              {&C_icon_validate_14, "Approve"});

UX_STEP_VALID(ux_sign_txn_flow_3_step, pb, io_reject(), {&C_icon_crossmark, "Reject"});

// Flow for the signing transaction menu:
// #1 screen: "Sign this txn?"
// #2 screen: approve
// #3 screen: reject
UX_FLOW(ux_sign_txn_flow,
        &ux_sign_txn_flow_1_step,
        &ux_sign_txn_flow_2_step,
        &ux_sign_txn_flow_3_step);

// We use one generic step for each element so we don't have to make
// separate UX_FLOWs for SC outputs, SF outputs, miner fees, etc
UX_STEP_CB(ux_show_txn_elem_1_step,
           bnnn_paging,
           ui_calcTxnHash_elem_button(),
           {global.calcTxnHashContext.labelStr, global.calcTxnHashContext.fullStr[0]});

// For each element of the transaction (sc outputs, sf outputs, miner fees),
// we show the data paginated for confirmation purposes. When the user
// confirms that element, they are shown the next element until
// they finish all the elements and are given the option to approve/reject.
UX_FLOW(ux_show_txn_elem_flow, &ux_show_txn_elem_1_step);
static unsigned int io_seproxyhal_touch_txn_hash_ok(void) {
    uint8_t signature[64] = {0};
    deriveAndSign(signature, ctx->keyIndex, ctx->txn.sigHash);
    io_send_response_pointer(signature, sizeof(signature), SW_OK);
    ui_idle();
    return 0;
}

static unsigned int ui_calcTxnHash_elem_button(void) {
    if (ctx->elementIndex >= ctx->txn.elementIndex) {
        // We've finished decoding the transaction, and all elements have
        // been displayed.
        if (ctx->sign) {
            // If we're signing the transaction, prepare and display the
            // approval screen.
            memmove(ctx->fullStr[0], "with key #", 10);
            memmove(ctx->fullStr[0] + 10 + (bin2dec(ctx->fullStr[0] + 10, ctx->keyIndex)), "?", 2);
            ux_flow_init(0, ux_sign_txn_flow, NULL);
        } else {
            // If we're just computing the hash, send it immediately and
            // display the comparison screen
            io_send_response_pointer(ctx->txn.sigHash, sizeof(ctx->txn.sigHash), SW_OK);
            bin2hex(ctx->fullStr[0], ctx->txn.sigHash, sizeof(ctx->txn.sigHash));
            ux_flow_init(0, ux_compare_hash_flow, NULL);
        }
        // Reset the initialization state.
        ctx->elementIndex = 0;
        ctx->initialized = false;
        return 0;
    }

    fmtTxnElem();
    ux_flow_init(0, ux_show_txn_elem_flow, NULL);
    return 0;
}

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
            if (ctx->elemPart == 0) {
                format_address(ctx->fullStr[0], txn->elements[ctx->elementIndex].outAddr);
                ctx->elemPart++;
            } else {
                const uint8_t valLen =
                    cur2dec(ctx->fullStr[0], txn->elements[ctx->elementIndex].outVal);
                formatSC(ctx->fullStr[0], valLen);
                ctx->elemPart = 0;

                ctx->elementIndex++;
            }
            break;
        }
        case TXN_ELEM_SF_OUTPUT: {
            memmove(ctx->labelStr, "SF Output #", 11);
            bin2dec(ctx->labelStr + 11, display_index());
            if (ctx->elemPart == 0) {
                format_address(ctx->fullStr[0], txn->elements[ctx->elementIndex].outAddr);
                ctx->elemPart++;
            } else {
                const uint8_t valLen =
                    cur2dec(ctx->fullStr[0], txn->elements[ctx->elementIndex].outVal);
                memmove(ctx->fullStr[0] + valLen, " SF", 4);
                ctx->elemPart = 0;

                ctx->elementIndex++;
            }
            break;
        }
        case TXN_ELEM_MINER_FEE: {
            // Miner fees only have one part.
            memmove(ctx->labelStr, "Miner Fee #", 11);
            bin2dec(ctx->labelStr + 11, display_index());

            const uint8_t valLen =
                cur2dec(ctx->fullStr[0], txn->elements[ctx->elementIndex].outVal);
            formatSC(ctx->fullStr[0], valLen);

            ctx->elemPart = 0;
            ctx->elementIndex++;
            break;
        }
        default: {
            // This should never happen.
            io_send_sw(SW_DEVELOPER_ERR);
            ui_idle();
            break;
        }
    }
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
        zero_ctx();
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

    // Attempt to decode the next element of the transaction. Note that this
    // code is essentially identical to ui_calcTxnHash_elem_button. Sadly,
    // there doesn't seem to be a clean way to avoid this duplication.
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
            fmtTxnElem();
            ux_flow_init(0, ux_show_txn_elem_flow, NULL);
            break;
    }

    return 0;
}

#endif /* HAVE_BAGL */