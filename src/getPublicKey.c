// This file contains the implementation of the getPublicKey command. It is
// broadly similar to the signHash command, but with a few new features. Since
// much of the code is the same, expect far fewer comments.
//
// A high-level description of getPublicKey is as follows. The user initiates
// the command on their computer by requesting the generation of a specific
// public key. The command handler then displays a screen asking the user to
// confirm the action. If the user presses the 'approve' button, the requested
// key is generated, sent to the computer, and displayed on the device. The
// user may then visually compare the key shown on the device to the key
// received by the computer. Augmenting this, the user may optionally request
// that an address be generated from the public key, in which case this
// address is displayed instead of the public key. A final two-button press
// returns the user to the main screen.
//
// Note that the order of the getPublicKey screens is the reverse of signHash:
// first approval, then comparison.
//
// Keep this description in mind as you read through the implementation.

#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>
#include <stdint.h>

#include "blake2b.h"
#include "sia.h"
#include "sia_ux.h"

// Get a pointer to getPublicKey's state variables.
static getPublicKeyContext_t *ctx = &global.getPublicKeyContext;

// Allows scrolling through the address/public key
UX_STEP_CB(
	ux_compare_pk_flow_1_step,
	bnnn_paging,
	ui_idle(),
	{
		"Compare",
		global.getPublicKeyContext.fullStr
	}
);

UX_FLOW(
	ux_compare_pk_flow,
	&ux_compare_pk_flow_1_step
);

unsigned int io_seproxyhal_touch_pk_ok(void) {
    cx_ecfp_public_key_t publicKey = {0};

    // The response APDU will contain multiple objects, which means we need to
    // remember our offset within G_io_apdu_buffer. By convention, the offset
    // variable is named 'tx'.
    uint8_t tx = 0;

    deriveSiaKeypair(ctx->keyIndex, NULL, &publicKey);
    extractPubkeyBytes(G_io_apdu_buffer + tx, &publicKey);
    tx += 32;
    pubkeyToSiaAddress(G_io_apdu_buffer + tx, &publicKey);
    tx += 76;

    // Flush the APDU buffer, sending the response.
    io_exchange_with_code(SW_OK, tx);

    // Prepare the comparison screen, filling in the header and body text.
    memmove(ctx->typeStr, "Compare:", 9);
    if (ctx->genAddr) {
        // The APDU buffer already contains the hex-encoded address, so
        // copy it directly.
        memmove(ctx->fullStr, G_io_apdu_buffer + 32, 76);
        ctx->fullStr[76] = '\0';
    } else {
        // The APDU buffer contains the raw bytes of the public key, so
        // first we need to convert to a human-readable form.
        bin2hex(ctx->fullStr, G_io_apdu_buffer, 32);
    }

    ux_flow_init(0, ux_compare_pk_flow, NULL);

    return 0;
}

UX_STEP_NOCB(
	ux_approve_pk_flow_1_step, bn,
     {
		global.getPublicKeyContext.typeStr,
		global.getPublicKeyContext.keyStr
	}
);

UX_STEP_VALID(
	ux_approve_pk_flow_2_step,
	pb,
	io_seproxyhal_touch_pk_ok(),
	{
		&C_icon_validate,
		"Approve"
	}
);

UX_STEP_VALID(
	ux_approve_pk_flow_3_step,
	pb,
	io_seproxyhal_cancel(),
	{
		&C_icon_crossmark,
		"Reject"
	}
);

// Flow for the public key/address menu:
// #1 screen: "generate address/public key from key #x?"
// #2 screen: approve
// #3 screen: reject
UX_FLOW(
	ux_approve_pk_flow,
	&ux_approve_pk_flow_1_step,
	&ux_approve_pk_flow_2_step,
	&ux_approve_pk_flow_3_step
);

// These are APDU parameters that control the behavior of the getPublicKey
// command.
#define P2_DISPLAY_ADDRESS 0x00
#define P2_DISPLAY_PUBKEY 0x01

void handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t* buffer, uint16_t len,
                        /* out */ volatile unsigned int* flags,
                        /* out */ volatile unsigned int* tx) {
    UNUSED(p1);
    UNUSED(len);
    UNUSED(tx);

    if ((p2 != P2_DISPLAY_ADDRESS) && (p2 != P2_DISPLAY_PUBKEY)) {
        // Although THROW is technically a general-purpose exception
        // mechanism, within a command handler it is basically just a
        // convenient way of bailing out early and sending an error code to
        // the computer. The exception will be caught by sia_main, which
        // appends the code to the response APDU and sends it, much like
        // io_exchange_with_code. THROW should not be called from
        // preprocessors or button handlers.
        THROW(SW_INVALID_PARAM);
    }

    // Read Key Index
    ctx->keyIndex = U4LE(buffer, 0);
    ctx->genAddr = (p2 == P2_DISPLAY_ADDRESS);

    if (ctx->genAddr) {
        memmove(ctx->typeStr, "Generate Address", 17);
        memmove(ctx->keyStr, "from Key #", 10);
        int n = bin2dec(ctx->keyStr + 10, ctx->keyIndex);
        memmove(ctx->keyStr + 10 + n, "?", 2);
    } else {
        memmove(ctx->typeStr, "Generate Public", 16);
        memmove(ctx->keyStr, "Key #", 5);
        int n = bin2dec(ctx->keyStr + 5, ctx->keyIndex);
        memmove(ctx->keyStr + 5 + n, "?", 2);
    }

    ux_flow_init(0, ux_approve_pk_flow, NULL);

    *flags |= IO_ASYNCH_REPLY;
}
