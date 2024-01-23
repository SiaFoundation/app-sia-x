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

UX_STEP_VALID(ux_sign_txn_flow_3_step, pb, io_seproxyhal_cancel(), {&C_icon_crossmark, "Reject"});

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
    deriveAndSign(G_io_apdu_buffer, ctx->keyIndex, ctx->txn.sigHash);
    io_exchange_with_code(SW_OK, 64);
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
            memmove(G_io_apdu_buffer, ctx->txn.sigHash, 32);
            io_exchange_with_code(SW_OK, 32);
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
            io_exchange_with_code(SW_DEVELOPER_ERR, 0);
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
// key. The transaction is processed in a streaming fashion and displayed
// piece-wise to the user.
void handleCalcTxnHash(uint8_t p1,
                       uint8_t p2,
                       uint8_t *dataBuffer,
                       uint16_t dataLength,
                       volatile unsigned int *flags,
                       volatile unsigned int *tx __attribute__((unused))) {
    if ((p1 != P1_FIRST && p1 != P1_MORE) || (p2 != P2_DISPLAY_HASH && p2 != P2_SIGN_HASH)) {
        THROW(SW_INVALID_PARAM);
    }

    if (p1 == P1_FIRST) {
        // If this is the first packet of a transaction, the transaction
        // context must not already be initialized. (Otherwise, an attacker
        // could fool the user by concatenating two transactions.)
        //
        // NOTE: ctx->initialized is set to false when the Sia app loads.
        if (ctx->initialized) {
            zero_ctx();
            THROW(SW_IMPROPER_INIT);
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
            THROW(SW_IMPROPER_INIT);
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
            THROW(SW_INVALID_PARAM);
            break;
        case TXN_STATE_PARTIAL:
            THROW(SW_OK);
            break;
        case TXN_STATE_FINISHED:
            *flags |= IO_ASYNCH_REPLY;
            fmtTxnElem();
            ux_flow_init(0, ux_show_txn_elem_flow, NULL);
            break;
    }

    // The above code does something strange: it calls io_exchange
    // directly from the command handler. You might wonder: why not
    // just prepare the APDU buffer and let sia_main call io_exchange?
    // The answer, surprisingly, is that we also need to call
    // UX_DISPLAY, and UX_DISPLAY affects io_exchange in subtle ways.
    // To understand why, we'll need to dive deep into the Nano S
    // firmware. I recommend that you don't skip this section, even
    // though it's lengthy, because it will save you a lot of
    // frustration when you go "off the beaten path" in your own app.
    //
    // Recall that the Nano S has two chips. Your app (and the Ledger
    // OS, BOLOS) runs on the Secure Element. The SE is completely
    // self-contained; it doesn't talk to the outside world at all. It
    // only talks to the other chip, the MCU. The MCU is what
    // processes button presses, renders things on screen, and
    // exchanges APDU packets with the computer. The communication
    // layer between the SE and the MCU is called SEPROXYHAL. There
    // are some nice diagrams in the "Hardware Architecture" section
    // of Ledger's docs that will help you visualize all this.
    //
    // The SEPROXYHAL protocol, like any communication protocol,
    // specifies exactly when each party is allowed to talk.
    // Communication happens in a loop: first the MCU sends an Event,
    // then the SE replies with zero or more Commands, and finally the
    // SE sends a Status to indicate that it has finished processing
    // the Event, completing one iteration:
    //
    //    Event -> Commands -> Status -> Event -> Commands -> ...
    //
    // For our purposes, an "Event" is a request APDU, and a "Command"
    // is a response APDU. (There are other types of Events and
    // Commands, such as button presses, but they aren't relevant
    // here.) As for the Status, there is a "General" Status and a
    // "Display" Status. A General Status tells the MCU to send the
    // response APDU, and a Display Status tells it to render an
    // element on the screen. Remember, it's "zero or more Commands,"
    // so it's legal to send just a Status without any Commands.
    //
    // You may have some picture of the problem now. Imagine we
    // prepare the APDU buffer, then call UX_DISPLAY, and then let
    // sia_main send the APDU with io_exchange. What happens at the
    // SEPROXYHAL layer? First, UX_DISPLAY will send a Display Status.
    // Then, io_exchange will send a Command and a General Status. But
    // no Event was processed between the two Statuses! This causes
    // SEPROXYHAL to freak out and crash, forcing you to reboot your
    // Nano S.
    //
    // So why does calling io_exchange before UX_DISPLAY fix the
    // problem? Won't we just end up sending two Statuses again? The
    // secret is that io_exchange_with_code uses the
    // IO_RETURN_AFTER_TX flag. Previously, the only thing we needed
    // to know about IO_RETURN_AFTER_TX is that it sends a response
    // APDU without waiting for the next request APDU. But it has one
    // other important property: it tells io_exchange not to send a
    // Status! So the only Status we send comes from UX_DISPLAY. This
    // preserves the ordering required by SEPROXYHAL.
    //
    // Lastly: what if we prepare the APDU buffer in the handler, but
    // with the IO_RETURN_AFTER_TX flag set? Will that work?
    // Unfortunately not. io_exchange won't send a status, but it
    // *will* send a Command containing the APDU, so we still end up
    // breaking the correct SEPROXYHAL ordering.
    //
    // Here's a list of rules that will help you debug similar issues:
    //
    // - Always preserve the order: Event -> Commands -> Status
    // - UX_DISPLAY sends a Status
    // - io_exchange sends a Command and a Status
    // - IO_RETURN_AFTER_TX makes io_exchange not send a Status
    // - IO_ASYNCH_REPLY (or tx=0) makes io_exchange not send a Command
    //
    // Okay, that second rule isn't 100% accurate. UX_DISPLAY doesn't
    // necessarily send a single Status: it sends a separate Status
    // for each element you render! The reason this works is that the
    // MCU replies to each Display Status with a Display Processed
    // Event. That means you can call UX_DISPLAY many times in a row
    // without disrupting SEPROXYHAL. Anyway, as far as we're
    // concerned, it's simpler to think of UX_DISPLAY as sending just
    // a single Status.
}

// It is not necessary to completely understand this handler to write your own
// Nano S app; much of it is Sia-specific and will not generalize to other
// apps. The important part is knowing how to structure handlers that involve
// multiple APDU exchanges. If you would like to dive deeper into how the
// handler buffers transaction data and parses elements, proceed to txn.c.
// Otherwise, this concludes the walkthrough. Feel free to fork this app and
// modify it to suit your own needs.
#endif /* HAVE_BAGL */