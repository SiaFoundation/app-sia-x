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

const bagl_element_t ui_signHash_approve[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
	UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
	UI_TEXT(0x00, 0, 12, 128, "Sign this Hash"),
	UI_TEXT(0x00, 0, 26, 128, global.signHashContext.indexStr),
};

unsigned int ui_signHash_approve_button(unsigned int button_mask, unsigned int button_mask_counter) {
	signHashContext_t *ctx = &global.signHashContext;
	uint16_t tx = 0;
	switch (button_mask) {
	case BUTTON_EVT_RELEASED | BUTTON_LEFT: // REJECT
		io_exchange_with_code(SW_USER_REJECTED, tx);
		ui_idle();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPROVE
		deriveAndSign(ctx->keyIndex, ctx->hash, G_io_apdu_buffer);
		tx += 64;
		io_exchange_with_code(SW_OK, tx);
		ui_idle();
		break;
	}
	return 0;
}

const bagl_element_t ui_signHash_compare[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
	UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
	UI_TEXT(0x00, 0, 12, 128, "Compare Hashes:"),
	UI_TEXT(0x00, 0, 26, 128, global.signHashContext.partialHashStr),
};

const bagl_element_t* ui_prepro_signHash_compare(const bagl_element_t *element) {
	signHashContext_t *ctx = &global.signHashContext;

	// don't display arrows if we're at the end
	if ((element->component.userid == 1 && ctx->displayIndex == 0) ||
	    (element->component.userid == 2 && ctx->displayIndex == sizeof(ctx->hexHash)-12)) {
		return 0;
	}
	return element;
}

unsigned int ui_signHash_compare_button(unsigned int button_mask, unsigned int button_mask_counter) {
	signHashContext_t *ctx = &global.signHashContext;

	switch (button_mask) {
	case BUTTON_LEFT:
	case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
		if (ctx->displayIndex > 0) {
			ctx->displayIndex--;
		}
		os_memmove(ctx->partialHashStr, ctx->hexHash+ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_RIGHT:
	case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
		if (ctx->displayIndex < sizeof(ctx->hexHash)-12) {
			ctx->displayIndex++;
		}
		os_memmove(ctx->partialHashStr, ctx->hexHash+ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
		// display approval screen
		UX_DISPLAY(ui_signHash_approve, NULL);
		break;
	}
	return 0;
}

// handleSignHash reads a key index and a hash, stores them in the global
// context, and displays the signHash UI.
void handleSignHash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
	signHashContext_t *ctx = &global.signHashContext;

	// read key index
	ctx->keyIndex = U4LE(dataBuffer, 0);
	os_memmove(ctx->indexStr, "with Key #", 10);
	int n = bin2dec(ctx->indexStr+10, ctx->keyIndex);
	os_memmove(ctx->indexStr+10+n, "?", 2);

	// read hash to sign
	os_memmove(ctx->hash, dataBuffer+4, 32);

	// convert hash to hex and display the first 12 hex digits
	bin2hex(ctx->hexHash, ctx->hash, 32);
	os_memmove(ctx->partialHashStr, ctx->hexHash, 12);
	ctx->partialHashStr[12] = '\0';
	ctx->displayIndex = 0;

	// display comparison screen
	UX_DISPLAY(ui_signHash_compare, ui_prepro_signHash_compare);

	*flags |= IO_ASYNCH_REPLY;
}
