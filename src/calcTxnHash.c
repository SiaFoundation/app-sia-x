#include <stdint.h>
#include <stdbool.h>
#include "os.h"
#include "cx.h"
#include "os_io_seproxyhal.h"
#include "glyphs.h"
#include "blake2b.h"
#include "sia.h"
#include "ux.h"

extern union {
	getPublicKeyContext_t getPublicKeyContext;
	signHashContext_t signHashContext;
	calcTxnHashContext_t calcTxnHashContext;
} global;



const bagl_element_t ui_calcTxnHash_compare[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
	UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
	UI_TEXT(0x00, 0, 12, 128, "Compare Hash:"),
	UI_TEXT(0x00, 0, 26, 128, global.calcTxnHashContext.partialStr),
};

const bagl_element_t* ui_prepro_calcTxnHash_compare(const bagl_element_t *element) {
	calcTxnHashContext_t *ctx = &global.calcTxnHashContext;

	// don't display arrows if we're at the end
	if ((element->component.userid == 1 && ctx->displayIndex == 0) ||
	    (element->component.userid == 2 && ctx->displayIndex == ctx->elemLen-12)) {
		return 0;
	}
	return element;
}

unsigned int ui_calcTxnHash_compare_button(unsigned int button_mask, unsigned int button_mask_counter) {
	calcTxnHashContext_t *ctx = &global.calcTxnHashContext;

	switch (button_mask) {
	case BUTTON_LEFT:
	case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
		if (ctx->displayIndex > 0) {
			ctx->displayIndex--;
		}
		os_memmove(ctx->partialStr, ctx->fullStr+ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_RIGHT:
	case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
		if (ctx->displayIndex < ctx->elemLen-12) {
			ctx->displayIndex++;
		}
		os_memmove(ctx->partialStr, ctx->fullStr+ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
		ui_idle();
		break;
	}
	return 0;
}

const bagl_element_t ui_calcTxnHash_sign[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
	UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
	UI_TEXT(0x00, 0, 12, 128, "Sign this Txn"),
	UI_TEXT(0x00, 0, 26, 128, global.calcTxnHashContext.fullStr),
};

unsigned int ui_calcTxnHash_sign_button(unsigned int button_mask, unsigned int button_mask_counter) {
	calcTxnHashContext_t *ctx = &global.calcTxnHashContext;

	switch (button_mask) {
	case BUTTON_EVT_RELEASED | BUTTON_LEFT: // REJECT
		io_exchange_with_code(SW_USER_REJECTED, 0);
		ui_idle();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPROVE
		deriveAndSign(ctx->keyIndex, ctx->txn.sigHash, G_io_apdu_buffer);
		io_exchange_with_code(SW_OK, 64);
		ui_idle();
		break;
	}
	return 0;
}

const bagl_element_t ui_calcTxnHash_elem[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
	UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
	UI_TEXT(0x00, 0, 12, 128, global.calcTxnHashContext.labelStr),
	UI_TEXT(0x00, 0, 26, 128, global.calcTxnHashContext.partialStr),
};

const bagl_element_t* ui_prepro_calcTxnHash_elem(const bagl_element_t *element) {
	calcTxnHashContext_t *ctx = &global.calcTxnHashContext;

	// don't display arrows if we're at the end
	if ((element->component.userid == 1 && ctx->displayIndex == 0) ||
	    (element->component.userid == 2 && ((ctx->elemLen < 12) || (ctx->displayIndex == ctx->elemLen-12)))) {
		return 0;
	}
	return element;
}

// helper function for displayNextElem
void fmtTxnElem(calcTxnHashContext_t *ctx) {
	txn_state_t *txn = &ctx->txn;

	switch (txn->elemType) {
	case TXN_ELEM_SC_OUTPUT:
		os_memmove(ctx->labelStr, "Siacoin Output #", 16);
		bin2dec(ctx->labelStr+16, txn->sliceIndex);
		if (ctx->elemPart == 0) {
			os_memmove(ctx->fullStr, txn->outAddr, sizeof(txn->outAddr));
			os_memmove(ctx->partialStr, ctx->fullStr, 12);
			ctx->elemLen = 76;
			ctx->elemPart++;
		} else {
			os_memmove(ctx->fullStr, txn->outVal, sizeof(txn->outVal));
			ctx->elemLen = cur2SC(ctx->fullStr, txn->valLen);
			os_memmove(ctx->partialStr, ctx->fullStr, 12);
			ctx->elemPart = 0;
		}
		break;

	case TXN_ELEM_SF_OUTPUT:
		os_memmove(ctx->labelStr, "Siafund Output #", 16);
		bin2dec(ctx->labelStr+16, txn->sliceIndex);
		if (ctx->elemPart == 0) {
			os_memmove(ctx->fullStr, txn->outAddr, sizeof(txn->outAddr));
			os_memmove(ctx->partialStr, ctx->fullStr, 12);
			ctx->elemLen = 76;
			ctx->elemPart++;
		} else {
			os_memmove(ctx->fullStr, txn->outVal, sizeof(txn->outVal));
			os_memmove(ctx->partialStr, ctx->fullStr, 12);
			ctx->elemLen = txn->valLen;
			ctx->elemPart = 0;
		}
		break;

	case TXN_ELEM_MINER_FEE:
		os_memmove(ctx->labelStr, "Miner Fee #", 11);
		bin2dec(ctx->labelStr+11, txn->sliceIndex);
		os_memmove(ctx->fullStr, txn->outVal, sizeof(txn->outVal));
		ctx->elemLen = cur2SC(ctx->fullStr, txn->valLen);
		os_memmove(ctx->partialStr, ctx->fullStr, 12);
		ctx->elemPart = 0;
		break;

	default:
		io_exchange_with_code(SW_DEVELOPER_ERR, 0);
		ui_idle();
		break;
	}

	ctx->displayIndex = 0;
}


unsigned int ui_calcTxnHash_elem_button(unsigned int button_mask, unsigned int button_mask_counter) {
	calcTxnHashContext_t *ctx = &global.calcTxnHashContext;

	switch (button_mask) {
	case BUTTON_LEFT:
	case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
		if (ctx->displayIndex > 0) {
			ctx->displayIndex--;
		}
		os_memmove(ctx->partialStr, ctx->fullStr+ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_RIGHT:
	case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
		if (ctx->displayIndex < ctx->elemLen-12) {
			ctx->displayIndex++;
		}
		os_memmove(ctx->partialStr, ctx->fullStr+ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
		if (ctx->elemPart > 0) {
			// display next part of element
			fmtTxnElem(ctx);
			UX_REDISPLAY();
			break;
		}
		switch (txn_next_elem(&ctx->txn)) {
		case TXN_STATE_ERR:
			io_exchange_with_code(SW_INVALID_PARAM, 0);
			ui_idle();
			break;
		case TXN_STATE_PARTIAL:
			// not enough data to decode the next element; request more
			io_exchange_with_code(SW_OK, 0);
			break;
		case TXN_STATE_READY:
			// an element is ready for display; display it
			ctx->elemPart = 0;
			fmtTxnElem(ctx);
			UX_REDISPLAY();
			break;
		case TXN_STATE_FINISHED:
			// all elements have been displayed
			if (ctx->sign) {
				// display key index and prompt for approval
				os_memmove(ctx->fullStr, "with Key #", 10);
				bin2dec(ctx->fullStr+10, ctx->keyIndex);
				UX_DISPLAY(ui_calcTxnHash_sign, NULL);
			} else {
				// send hash and display comparison screen
				os_memmove(G_io_apdu_buffer, ctx->txn.sigHash, 32);
				io_exchange_with_code(SW_OK, 32);
				bin2hex(ctx->fullStr, ctx->txn.sigHash, sizeof(ctx->txn.sigHash));
				os_memmove(ctx->partialStr, ctx->fullStr, 12);
				ctx->elemLen = 64;
				ctx->displayIndex = 0;
				UX_DISPLAY(ui_calcTxnHash_compare, ui_prepro_calcTxnHash_compare);
			}
			break;
		}
		break;
	}
	return 0;
}

// APDU parameters
#define P1_FIRST        0x00 // 1st packet of multi-packet transfer
#define P1_MORE         0x80 // nth packet of multi-packet transfer
#define P2_DISPLAY_HASH 0x00 // display transaction hash
#define P2_SIGN_HASH    0x01 // sign transaction hash

// handleCalcTxnHash reads a signature index and a transaction, calculates the
// SigHash of the transaction, and optionally signs the hash using a specified
// key. The transaction is processed in a streaming fashion and displayed
// piece-wise to the user.
void handleCalcTxnHash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
	calcTxnHashContext_t *ctx = &global.calcTxnHashContext;

	if ((p1 != P1_FIRST && p1 != P1_MORE) || (p2 != P2_DISPLAY_HASH && p2 != P2_SIGN_HASH)) {
		THROW(SW_INVALID_PARAM);
	}

	if (p1 == P1_FIRST) {
		// initialize ctx state with P2 and key index
		ctx->partialStr[12] = '\0';
		ctx->elemPart = ctx->elemLen = ctx->displayIndex = 0;
		ctx->sign = (p2 == P2_SIGN_HASH);
		ctx->keyIndex = U4LE(dataBuffer, 0); // NOTE: ignored if !ctx->sign
		dataBuffer += 4; dataLength -= 4;

		// initialize txn decoder state with SigIndex
		//
		// TODO: for full generality we should be reading the CoveredFields as
		// well. For now, assume WholeTransaction = true.
		txn_init(&ctx->txn, U2LE(dataBuffer, 0));
		dataBuffer += 2; dataLength -= 2;
	} else if (p1 != P1_MORE) {
		THROW(SW_INVALID_PARAM); // after first exchange, p1 should always indicate more
	}

	// add new data to txn decoder
	txn_update(&ctx->txn, dataBuffer, dataLength);

	// if a new element is ready, switch to display mode
	switch (txn_next_elem(&ctx->txn)) {
	case TXN_STATE_ERR:
		THROW(SW_INVALID_PARAM);
	case TXN_STATE_PARTIAL:
		// not enough data to decode the next element; request more
		THROW(SW_OK);
	case TXN_STATE_READY:
		// an element is ready for display; display it
		ctx->elemPart = 0;
		fmtTxnElem(ctx);
		UX_DISPLAY(ui_calcTxnHash_elem, ui_prepro_calcTxnHash_elem);
		*flags |= IO_ASYNCH_REPLY;
		break;
	case TXN_STATE_FINISHED:
		// all elements have been displayed
		if (ctx->sign) {
			// display key index and prompt for approval
			os_memmove(ctx->fullStr, "with Key #", 10);
			bin2dec(ctx->fullStr+10, ctx->keyIndex);
			UX_DISPLAY(ui_calcTxnHash_sign, NULL);
			*flags |= IO_ASYNCH_REPLY;
		} else {
			// send hash and display comparison screen
			os_memmove(G_io_apdu_buffer, ctx->txn.sigHash, 32);
			io_exchange_with_code(SW_OK, 32);
			bin2hex(ctx->fullStr, ctx->txn.sigHash, sizeof(ctx->txn.sigHash));
			os_memmove(ctx->partialStr, ctx->fullStr, 12);
			ctx->elemLen = 64;
			ctx->displayIndex = 0;
			UX_DISPLAY(ui_calcTxnHash_compare, ui_prepro_calcTxnHash_compare);
		}
		break;
	}
}
