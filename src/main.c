/*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include <stdint.h>
#include <stdbool.h>
#include "os.h"
#include "cx.h"
#include "os_io_seproxyhal.h"
#include "glyphs.h"
#include "sia.h"

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

typedef struct getPublicKeyContext_t {
	cx_ecfp_public_key_t publicKey;
	uint8_t indexStr[40]; // for display; NUL-terminated (variable-length)
	uint8_t addrStr[77]; // for display; NUL-terminated
} getPublicKeyContext_t;

typedef struct signHashContext_t {
	uint32_t keyIndex;
	uint8_t indexStr[40]; // for display; NUL-terminated (variable-length)
	uint8_t hash[32];
	uint8_t hashStr[65]; // for display; NUL-terminated
} signHashContext_t;

union {
	getPublicKeyContext_t getPublicKeyContext;
	signHashContext_t signHashContext;
} global;

// magic global variable implicitly referenced by the UX_ macros
ux_state_t ux;

// most screens have multiple "steps." ux_step selects which step is currently
// displayed; only bagl_elements whose userid field matches ux_step are
// displayed. ux_step_count is the total number of steps, so that we can cycle
// via ux_step = (ux_step+1) % ux_step_count.
unsigned int ux_step;
unsigned int ux_step_count;

const ux_menu_entry_t menu_main[];

const ux_menu_entry_t menu_about[] = {
	{NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
	{menu_main, NULL, 2, &C_icon_back, "Back", NULL, 61, 40},
	UX_MENU_END
};

const ux_menu_entry_t menu_main[] = {
	{NULL, NULL, 0, NULL, "Waiting for", "commands...", 0, 0},
	{menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
	{NULL, os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
	UX_MENU_END
};

void ui_idle(void) {
	UX_MENU_DISPLAY(0, menu_main, NULL);
}

const bagl_element_t ui_getPublicKey[] = {
	{
		// component       userid, x,   y,  width, height, stroke, radius, fill,      fg,       bg,       font, icon
		{  BAGL_RECTANGLE, 0x00,   0,   0,  128,   32,     0,      0,      BAGL_FILL, 0x000000, 0xFFFFFF, 0,    0   },
		// text, if component is a BAGL_LABELINE
		NULL,
		// these fields only apply to the Ledger Blue
		0, 0, 0, NULL, NULL, NULL
	},

	{
		// component       userid, x,   y,   width, height, stroke, radius, fill,      fg,       bg,       font, icon
		{  BAGL_ICON,      0x00,   3,   12,  7,     7,      0,      0,      0,         0xFFFFFF, 0x000000, 0,    BAGL_GLYPH_ICON_CROSS},
		NULL,
		0, 0, 0, NULL, NULL, NULL
	},
	{
		// component       userid, x,   y,   width, height, stroke, radius, fill,      fg,       bg,       font, icon
		{  BAGL_ICON,      0x00,   117, 13,  8,     6,      0,      0,      0,         0xFFFFFF, 0x000000, 0,    BAGL_GLYPH_ICON_CHECK},
		NULL,
		0, 0, 0, NULL, NULL, NULL
	},

	{
		// component       userid, x,   y,   width, height, stroke, radius, fill,      fg,       bg,       font,                                                            icon
		{  BAGL_LABELINE,  0x01,   0,   12,  128,   12,     0,      0,      0,         0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0   },
		"Confirm",
		0, 0, 0, NULL, NULL, NULL
	},
	{
		// component       userid, x,   y,   width, height, stroke, radius, fill,      fg,       bg,       font,                                                            icon
		{  BAGL_LABELINE,  0x01,   0,   26,  128,   12,     0,      0,      0,         0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0   },
		"address",
		0, 0, 0, NULL, NULL, NULL
	},

	{
		// component       userid, x,   y,   width, height, stroke, radius, fill,      fg,       bg,       font,                                                          icon
		{  BAGL_LABELINE,  0x02,   0,   12,  128,   12,     0,      0,      0,         0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0   },
		(char *)global.getPublicKeyContext.indexStr,
		0, 0, 0, NULL, NULL, NULL
	},
	{
		// somehow this is magically an animated ticker. Note that for
		// animated components, "icon" is now "speed" and "stroke" is now
		// "pause" (the delay after reaching the end)

		// component       userid, x,   y,   width, height, pause,     radius, fill,   fg,       bg,       font,                                                            speed
		{  BAGL_LABELINE,  0x02,   23,  26,  82,    12,     0x80 | 10, 0,      0,      0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26   },
		(char *)global.getPublicKeyContext.addrStr,
		0, 0, 0, NULL, NULL, NULL
	},
};

const bagl_element_t* ui_prepro_getPublicKey(const bagl_element_t *element) {
	if (element->component.userid == 0)         return element; // this element is displayed on every step
	if (element->component.userid != ux_step+1) return 0;       // this element is not displayed on this step

	// set the redisplay interval and render this element
	switch (element->component.userid) {
	case 1:
		// display "Confirm address" for 2 seconds
		UX_CALLBACK_SET_INTERVAL(2000);
		break;
	case 2:
		// cycle back to "Confirm address" after scrolling through pubkey
		UX_CALLBACK_SET_INTERVAL(1000 + bagl_label_roundtrip_duration_ms(element, 7));
		break;
	}
	return element;
}

// it's doesn't look like this function is called anywhere, but UX_DISPLAY is
// a macro that calls arg##_button. So when we call it with ui_getPublicKey,
// it calls this function to do the button handling.
unsigned int ui_getPublicKey_button(unsigned int button_mask, unsigned int button_mask_counter) {
	uint16_t tx = 0;
	switch (button_mask) {
	case BUTTON_EVT_RELEASED | BUTTON_LEFT: // REJECT
		G_io_apdu_buffer[tx++] = 0x69;
		G_io_apdu_buffer[tx++] = 0x85;
		break;

	case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPROVE
		extractPubkeyBytes(G_io_apdu_buffer, &global.getPublicKeyContext.publicKey);
		tx += 32;
		os_memmove(G_io_apdu_buffer + tx, global.getPublicKeyContext.addrStr, 76);
		tx += 76;
		G_io_apdu_buffer[tx++] = 0x90;
		G_io_apdu_buffer[tx++] = 0x00;
		break;

	default:
		// no response
		return 0;
	}

	// Send back the response, do not restart the event loop
	io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
	ui_idle();
	return 0;
}

// handleGetPublicKey reads a key index, derives the corresponding public key,
// converts it to a Sia address, and stores the address in fullAddress.
void handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
	getPublicKeyContext_t *ctx = &global.getPublicKeyContext;

	// read key index
	uint32_t index = U4LE(dataBuffer, 0);
	os_memmove(ctx->indexStr, "Key #", 5);
	bin2dec(ctx->indexStr+5, index);

	// derive public key from seed and index
	deriveSiaKeypair(index, NULL, &ctx->publicKey);

	// convert key to Sia address
	pubkeyToSiaAddress(ctx->addrStr, &ctx->publicKey);

	ux_step = 0;
	ux_step_count = 2;
	UX_DISPLAY(ui_getPublicKey, ui_prepro_getPublicKey);

	*flags |= IO_ASYNCH_REPLY;
}

const bagl_element_t ui_signHash[] = {
	{
		{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},
		NULL,
		0, 0, 0, NULL, NULL, NULL
	},
	{
		{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS},
		NULL,
		0, 0, 0, NULL, NULL, NULL
	},
	{
		{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CHECK},
		NULL,
		0, 0, 0, NULL, NULL, NULL
	},

	{
		{  BAGL_LABELINE,  0x01,   0,   19,  128,   12,     0,      0,      0,         0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0   },
		"Sign this hash?",
		0, 0, 0, NULL, NULL, NULL
	},

	{
		{  BAGL_LABELINE,  0x02,   0,   12,  128,   12,     0,      0,      0,         0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0   },
		(char *)global.signHashContext.indexStr,
		0, 0, 0, NULL, NULL, NULL
	},
	{
		{BAGL_LABELINE, 0x02, 23, 26, 82, 12, 0x80 | 10, 0, 0, 0xFFFFFF, 0x000000, BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 26},
		(char *)global.signHashContext.hashStr,
		0, 0, 0, NULL, NULL, NULL
	},
};

const bagl_element_t* ui_prepro_signHash(const bagl_element_t *element) {
	if (element->component.userid == 0)         return element; // this element is displayed on every step
	if (element->component.userid != ux_step+1) return 0;       // this element is not displayed on this step

	// set the redisplay interval and render this element
	switch (element->component.userid) {
	case 1:
		// display "Sign this hash?" for 2 seconds
		UX_CALLBACK_SET_INTERVAL(2000);
		break;
	case 2:
		// cycle back to "Sign this hash?" after scrolling through hash
		UX_CALLBACK_SET_INTERVAL(1000 + bagl_label_roundtrip_duration_ms(element, 7));
		break;
	}
	return element;
}

// it's doesn't look like this function is called anywhere, but UX_DISPLAY is
// a macro that calls arg##_button. So when we call it with ui_signHash, it
// calls this function to do the button handling.
unsigned int ui_signHash_button(unsigned int button_mask, unsigned int button_mask_counter) {
	uint16_t tx = 0;
	switch (button_mask) {
	case BUTTON_EVT_RELEASED | BUTTON_LEFT: // REJECT
		G_io_apdu_buffer[tx++] = 0x69;
		G_io_apdu_buffer[tx++] = 0x85;
		break;

	case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPROVE
		deriveAndSign(global.signHashContext.keyIndex, global.signHashContext.hash, G_io_apdu_buffer);
		tx += 64;
		G_io_apdu_buffer[tx++] = 0x90;
		G_io_apdu_buffer[tx++] = 0x00;
		break;

	default:
		// no response
		return 0;
	}

	// Send back the response, do not restart the event loop
	io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
	ui_idle();
	return 0;
}

// handleSignHash reads a key index and a hash, signs the hash using the key
// derived from the index, and stores the hex-encoded signature in fullAddress.
void handleSignHash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
	signHashContext_t *ctx = &global.signHashContext;

	// read key index
	ctx->keyIndex = U4LE(dataBuffer, 0);
	os_memmove(ctx->indexStr, "Key #", 5);
	bin2dec(ctx->indexStr+5, ctx->keyIndex);

	// read hash to sign
	os_memmove(ctx->hash, dataBuffer+4, 32);

	// convert hash to hex so it can be displayed
	bin2hex(ctx->hashStr, ctx->hash, 32);

	ux_step = 0;
	ux_step_count = 2;
	UX_DISPLAY(ui_signHash, ui_prepro_signHash);

	*flags |= IO_ASYNCH_REPLY;
}

// The APDU protocol uses a single-byte instruction code (INS) to specify
// which command should be executed. We use this code to dispatch on a table
// of function pointers.

#define INS_GET_PUBLIC_KEY 0x01
#define INS_SIGN_HASH      0x02

typedef void handler_fn_t(uint8_t, uint8_t, uint8_t *, uint16_t , volatile unsigned int *, volatile unsigned int *);

handler_fn_t* lookupHandler(uint8_t ins) {
	switch (ins) {
	case INS_GET_PUBLIC_KEY: return handleGetPublicKey;
	case INS_SIGN_HASH:      return handleSignHash;
	}
	return NULL;
}

// Everything below this point is Ledger magic. Don't bother trying to
// understand it.

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
	switch (channel & ~(IO_FLAGS)) {
	case CHANNEL_KEYBOARD:
		break;
	// multiplexed io exchange over a SPI channel and TLV encapsulated protocol
	case CHANNEL_SPI:
		if (tx_len) {
			io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);
			if (channel & IO_RESET_AFTER_REPLIED) {
				reset();
			}
			return 0; // nothing received from the master so far (it's a tx transaction)
		} else {
			return io_seproxyhal_spi_recv(G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
		}
	default:
		THROW(INVALID_PARAMETER);
	}
	return 0;
}

#define CLA          0xE0
#define OFFSET_CLA   0x00
#define OFFSET_INS   0x01
#define OFFSET_P1    0x02
#define OFFSET_P2    0x03
#define OFFSET_LC    0x04
#define OFFSET_CDATA 0x05

void sia_main(void) {
	volatile unsigned int rx = 0;
	volatile unsigned int tx = 0;
	volatile unsigned int flags = 0;

	for (;;) {
		volatile unsigned short sw = 0;

		BEGIN_TRY {
			TRY {
				rx = tx;
				tx = 0; // ensure no race in catch_other if io_exchange throws an error
				rx = io_exchange(CHANNEL_APDU | flags, rx);
				flags = 0;

				// no apdu received; reset the session and reset the bootloader configuration
				if (rx == 0) {
					THROW(0x6982);
				}
				if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
					THROW(0x6E00);
				}
				// call handler function associated with this instruction
				handler_fn_t *handlerFn = lookupHandler(G_io_apdu_buffer[OFFSET_INS]);
				if (!handlerFn) {
					THROW(0x6D00);
				}
				handlerFn(G_io_apdu_buffer[OFFSET_P1], G_io_apdu_buffer[OFFSET_P2], G_io_apdu_buffer + OFFSET_CDATA, G_io_apdu_buffer[OFFSET_LC], &flags, &tx);
			}
			CATCH(EXCEPTION_IO_RESET) {
				THROW(EXCEPTION_IO_RESET);
			}
			CATCH_OTHER(e) {
				switch (e & 0xF000) {
				case 0x6000:
					// report the exception
					sw = e;
					break;
				case 0x9000:
					// All is well
					sw = e;
					break;
				default:
					// Internal error
					sw = 0x6800 | (e & 0x7FF);
					break;
				}
				// Unexpected exception => report
				G_io_apdu_buffer[tx] = sw >> 8;
				G_io_apdu_buffer[tx + 1] = sw;
				tx += 2;
			}
			FINALLY {
			}
		}
		END_TRY;
	}
}

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
	io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned char io_event(unsigned char channel) {
	// can't have more than one tag in the reply, not supported yet.
	switch (G_io_seproxyhal_spi_buffer[0]) {
	case SEPROXYHAL_TAG_FINGER_EVENT:
		UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
		break;

	case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
		UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
		break;

	case SEPROXYHAL_TAG_STATUS_EVENT:
		if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
			!(U4BE(G_io_seproxyhal_spi_buffer, 3) &
			  SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
			THROW(EXCEPTION_IO_RESET);
		}
		UX_DEFAULT_EVENT();
		break;

	case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
		UX_DISPLAYED_EVENT({});
		break;

	case SEPROXYHAL_TAG_TICKER_EVENT:
		UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
			if (UX_ALLOWED) {
				if (ux_step_count) {
					// prepare next screen
					ux_step = (ux_step + 1) % ux_step_count;
					// redisplay screen
					UX_REDISPLAY();
				}
			}
		});
		break;

	default:
		UX_DEFAULT_EVENT();
		break;
	}

	// close the event if not done previously (by a display or whatever)
	if (!io_seproxyhal_spi_is_status_sent()) {
		io_seproxyhal_general_status();
	}

	// command has been processed, DO NOT reset the current APDU transport
	return 1;
}

void app_exit(void) {
	BEGIN_TRY_L(exit) {
		TRY_L(exit) {
			os_sched_exit(-1);
		}
		FINALLY_L(exit) {
		}
	}
	END_TRY_L(exit);
}

__attribute__((section(".boot"))) int main(void) {
	// exit critical section
	__asm volatile("cpsie i");

	for (;;) {
		UX_INIT();

		// ensure exception will work as planned
		os_boot();

		BEGIN_TRY {
			TRY {
				io_seproxyhal_init();

				USB_power(0);
				USB_power(1);

				ui_idle();

				sia_main();
			}
			CATCH(EXCEPTION_IO_RESET) {
				// reset IO and UX before continuing
				continue;
			}
			CATCH_ALL {
				break;
			}
			FINALLY {
			}
		}
		END_TRY;
	}
	app_exit();

	return 0;
}
