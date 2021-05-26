// This file contains the implementation of the signHash command. The files
// for the other commands will have the same basic structure: A set of screens
// (comprising the screen elements, preprocessor, and button handler) followed
// by the command handler itself.
//
// A high-level description of signHash is as follows. The user initiates the
// command on their computer, specifying the hash they would like to sign and
// the key they would like to sign with. The command handler then displays the
// hash on the device and asks the user to compare it to the hash shown on the
// computer. The user can press the left and right buttons to scroll through
// the hash. When the user finishes comparing, they press both buttons to
// proceed to the next screen, which asks the user to approve or deny signing
// the hash. If the user presses the left button, the action is denied and a
// rejection code is sent to the computer. If they press the right button, the
// action is approved and the requested signature is computed and sent to the
// computer. In either case, the command ends by returning to the main screen.
//
// Keep this description in mind as you read through the implementation.

#include <string.h>
#include <os_io_seproxyhal.h>
#include "blake2b.h"
#include "sia.h"
#include "sia_ux.h"
#include <stdint.h>
#include <stdbool.h>

// Get a pointer to signHash's state variables. This is purely for
// convenience, so that we can refer to these variables concisely from any
// signHash-related function.
static signHashContext_t *ctx = &global.signHashContext;

static unsigned int io_seproxyhal_touch_hash_ok(void) {
    // Derive the secret key and sign the hash, storing the signature in
    // the APDU buffer. This is the first Sia-specific function we've
    // encountered; it is defined in sia.c.
    deriveAndSign(G_io_apdu_buffer, ctx->keyIndex, ctx->hash);
    io_exchange_with_code(SW_OK, 64);

    ui_idle();
    return 0;
}

UX_STEP_NOCB(
	ux_approve_hash_flow_1_step,
	bnnn_paging,
	{
		"Compare Input:",
		global.signHashContext.hexHash
	}
);

UX_STEP_VALID(
	ux_approve_hash_flow_2_step,
	pb,
	io_seproxyhal_touch_hash_ok(),
	{
		&C_icon_validate,
		"Approve"
	}
);

UX_STEP_VALID(
	ux_approve_hash_flow_3_step,
	pb,
	io_seproxyhal_cancel(),
	{
		&C_icon_crossmark,
		"Reject"
	}
);

// Flow for the signing hash menu:
// #1 screen: the hash repeated for confirmation
// #2 screen: approve
// #3 screen: reject
UX_FLOW(
	ux_approve_hash_flow,
	&ux_approve_hash_flow_1_step,
	&ux_approve_hash_flow_2_step,
	&ux_approve_hash_flow_3_step
);

void handleSignHash(uint8_t p1, uint8_t p2, uint8_t *buffer, uint16_t len,
                    /* out */ volatile unsigned int *flags,
                    /* out */ volatile unsigned int *tx) {
    // Read the index of the signing key. U4LE is a helper macro for
    // converting a 4-byte buffer to a uint32_t.
    ctx->keyIndex = U4LE(buffer, 0);
    // Read the hash.
    memmove(ctx->hash, buffer + 4, sizeof(ctx->hash));

    // Prepare to display the comparison screen by converting the hash to hex
    bin2hex(ctx->hexHash, ctx->hash, sizeof(ctx->hash));

    ux_flow_init(0, ux_approve_hash_flow, NULL);

    *flags |= IO_ASYNCH_REPLY;
}

// Now that we've seen the individual pieces, we can construct a full picture
// of what the signHash command looks like.
//
// The command begins when sia_main reads an APDU packet from the computer
// with INS == INS_SIGN_HASH. sia_main looks up the appropriate handler,
// handleSignHash, and calls it. handleSignHash reads the command data,
// prepares and displays the comparison screen, and sets the IO_ASYNC_REPLY
// flag. Control returns to sia_main, which blocks when it reaches the
// io_exchange call.
//
// UX_DISPLAY was called with the ui_prepro_signHash_compare preprocessor, so
// that preprocessor is now called each time the compare screen is rendered.
// Since we are initially displaying the beginning of the hash, the
// preprocessor hides the left arrow. The user presses and holds the right
// button, which triggers the button handler to advance the displayIndex every
// 100ms. Each advance requires redisplaying the screen via UX_REDISPLAY(),
// and thus rerunning the preprocessor. As soon as the right button is
// pressed, the preprocessor detects that text has scrolled off the left side
// of the screen, so it unhides the left arrow; when the end of the hash is
// reached, it hides the right arrow.
//
// When the user has finished comparing the hashes, they press both buttons
// together, triggering ui_signHash_compare_button to prepare the approval
// screen and call UX_DISPLAY on ui_signHash_approve. A NULL preprocessor is
// specified for this screen, since we don't need to filter out any of its
// elements. We'll assume that the user presses the 'approve' button, causing
// the button handler to place the hash in G_io_apdu_buffer and call
// io_exchange_with_code, which sends the response APDU to the computer with
// the IO_RETURN_AFTER_TX flag set. The button handler then calls ui_idle,
// thus returning to the main menu.
//
// This completes the signHash command. Back in sia_main, io_exchange is still
// blocked, waiting for the computer to send a new request APDU. For the next
// section of this walkthrough, we will assume that the next APDU requests the
// getPublicKey command, so proceed to getPublicKey.c.
