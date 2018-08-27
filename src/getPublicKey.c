#include <stdint.h>
#include <stdbool.h>
#include "os.h"
#include "cx.h"
#include "os_io_seproxyhal.h"
#include "glyphs.h"
#include "blake2b.h"
#include "sia.h"
#include "ux.h"

// get a pointer to getPublicKey's state variables
extern union {
	getPublicKeyContext_t getPublicKeyContext;
	signHashContext_t signHashContext;
	calcTxnHashContext_t calcTxnHashContext;
} global;
static getPublicKeyContext_t *ctx = &global.getPublicKeyContext;

const bagl_element_t ui_getPublicKey_compare[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
	UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
	UI_TEXT(0x00, 0, 12, 128, global.getPublicKeyContext.typeStr),
	UI_TEXT(0x00, 0, 26, 128, global.getPublicKeyContext.partialStr),
};

const bagl_element_t* ui_prepro_getPublicKey_compare(const bagl_element_t *element) {
	int fullSize = ctx->genAddr ? 76 : 44;

	// don't display arrows if we're at the end
	if ((element->component.userid == 1 && ctx->displayIndex == 0) ||
	    (element->component.userid == 2 && ctx->displayIndex == fullSize-12)) {
		return 0;
	}
	return element;
}

unsigned int ui_getPublicKey_compare_button(unsigned int button_mask, unsigned int button_mask_counter) {
	int fullSize = ctx->genAddr ? 76 : 44;
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
		if (ctx->displayIndex < fullSize-12) {
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

const bagl_element_t ui_getPublicKey_approve[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
	UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
	UI_TEXT(0x00, 0, 12, 128, global.getPublicKeyContext.typeStr),
	UI_TEXT(0x00, 0, 26, 128, global.getPublicKeyContext.keyStr),
};

unsigned int ui_getPublicKey_approve_button(unsigned int button_mask, unsigned int button_mask_counter) {
	uint16_t tx = 0;
	cx_ecfp_public_key_t publicKey;
	switch (button_mask) {
	case BUTTON_EVT_RELEASED | BUTTON_LEFT: // REJECT
		io_exchange_with_code(SW_USER_REJECTED, tx);
		ui_idle();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPROVE
		// derive pubkey and address
		deriveSiaKeypair(ctx->keyIndex, NULL, &publicKey);
		extractPubkeyBytes(G_io_apdu_buffer + tx, &publicKey);
		tx += 32;
		pubkeyToSiaAddress(G_io_apdu_buffer + tx, &publicKey);
		tx += 76;

		// prepare comparison screen
		if (ctx->genAddr) {
			os_memmove(ctx->typeStr, "Compare:", 9);
			os_memmove(ctx->fullStr, G_io_apdu_buffer + 32, 76);
			ctx->fullStr[76] = '\0';
		} else {
			os_memmove(ctx->typeStr, "Compare:", 9);
			bin2b64(ctx->fullStr, G_io_apdu_buffer, 32);
		}
		os_memmove(ctx->partialStr, ctx->fullStr, 12);
		ctx->partialStr[12] = '\0';

		// send response
		io_exchange_with_code(SW_OK, tx);

		// display comparison screen
		ctx->displayIndex = 0;
		UX_DISPLAY(ui_getPublicKey_compare, ui_prepro_getPublicKey_compare);
		break;
	}
	return 0;
}

// APDU parameters
#define P2_DISPLAY_ADDRESS 0x00
#define P2_DISPLAY_PUBKEY  0x01

// handleGetPublicKey reads a key index, derives the corresponding public key,
// converts it to a Sia address, stores the address in the global context, and
// displays the getPublicKey UI.
void handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
	if ((p2 != P2_DISPLAY_ADDRESS) && (p2 != P2_DISPLAY_PUBKEY)) {
		THROW(SW_INVALID_PARAM);
	}

	// read key index and genAddr flag
	ctx->keyIndex = U4LE(dataBuffer, 0);
	ctx->genAddr = (p2 == P2_DISPLAY_ADDRESS);

	if (p2 == P2_DISPLAY_ADDRESS) {
		os_memmove(ctx->typeStr, "Generate Address", 17);
		os_memmove(ctx->keyStr, "from Key #", 10);
		int n = bin2dec(ctx->keyStr+10, ctx->keyIndex);
		os_memmove(ctx->keyStr+10+n, "?", 2);
	} else if (p2 == P2_DISPLAY_PUBKEY) {
		os_memmove(ctx->typeStr, "Generate Public", 16);
		os_memmove(ctx->keyStr, "Key #", 5);
		int n = bin2dec(ctx->keyStr+5, ctx->keyIndex);
		os_memmove(ctx->keyStr+5+n, "?", 2);
	}

	// display approval screen
	UX_DISPLAY(ui_getPublicKey_approve, NULL);

	*flags |= IO_ASYNCH_REPLY;
}
