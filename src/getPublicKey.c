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
#include <io.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <buffer.h>

#include "blake2b.h"
#include "sia.h"
#include "sia_ux.h"

// These are APDU parameters that control the behavior of the getPublicKey
// command.
#define P2_DISPLAY_ADDRESS 0x00
#define P2_DISPLAY_PUBKEY  0x01

// Get a pointer to getPublicKey's state variables.
static getPublicKeyContext_t* ctx = &global.getPublicKeyContext;

static unsigned int send_pubkey(void);

#ifdef HAVE_BAGL
// Allows scrolling through the address/public key
UX_STEP_CB(ux_compare_pk_flow_1_step,
           bnnn_paging,
           ui_idle(),
           {"Compare", global.getPublicKeyContext.fullStr});

UX_FLOW(ux_compare_pk_flow, &ux_compare_pk_flow_1_step);

UX_STEP_NOCB(ux_approve_pk_flow_1_step,
             bn,
             {global.getPublicKeyContext.typeStr, global.getPublicKeyContext.keyStr});

UX_STEP_VALID(ux_approve_pk_flow_2_step, pb, send_pubkey(), {&C_icon_validate_14, "Approve"});

UX_STEP_VALID(ux_approve_pk_flow_3_step, pb, io_reject(), {&C_icon_crossmark, "Reject"});

// Flow for the public key/address menu:
// #1 screen: "generate address/public key from key #x?"
// #2 screen: approve
// #3 screen: reject
UX_FLOW(ux_approve_pk_flow,
        &ux_approve_pk_flow_1_step,
        &ux_approve_pk_flow_2_step,
        &ux_approve_pk_flow_3_step);
#else

static void cancel_status(void) {
    if (ctx->genAddr) {
        nbgl_useCaseStatus("Address Verification Cancelled", false, ui_idle);
    } else {
        nbgl_useCaseStatus("Pubkey Verification Cancelled", false, ui_idle);
    }
}

static void confirm_address_rejection(void) {
    // display a status page and go back to main
    io_send_sw(SW_USER_REJECTED);
    cancel_status();
}

static void review_choice(bool confirm) {
    if (confirm) {
        if (ctx->genAddr) {
            nbgl_useCaseStatus("ADDRESS VERIFIED", true, ui_idle);
        } else {
            nbgl_useCaseStatus("PUBKEY VERIFIED", true, ui_idle);
        }
    } else {
        cancel_status();
    }
}

static void continue_review(void) {
    send_pubkey();
    nbgl_useCaseAddressConfirmation(ctx->fullStr, review_choice);
}
#endif

static unsigned int send_pubkey(void) {
    uint8_t publicKey[65] = {0};

    deriveSiaPublicKey(ctx->keyIndex, publicKey);

    uint8_t pubkeyBytes[32] = {0};
    extractPubkeyBytes(pubkeyBytes, publicKey);
    uint8_t siaAddress[76 + 1] = {0};
    pubkeyToSiaAddress((char*) siaAddress, publicKey);

    // Flush the APDU buffer, sending the response.
    const buffer_t bufs[2] = {
        {.ptr = pubkeyBytes, .size = 32, .offset = 0},
        {.ptr = siaAddress, .size = 76, .offset = 0},
    };
    io_send_response_buffers(bufs, sizeof(bufs) / sizeof(bufs[0]), SW_OK);

    // Prepare the comparison screen, filling in the header and body text.
    memmove(ctx->typeStr, "Compare:", 9);
    if (ctx->genAddr) {
        // The APDU buffer already contains the hex-encoded address, so
        // copy it directly.
        memcpy(ctx->fullStr, siaAddress, sizeof(siaAddress));
    } else {
        // The APDU buffer contains the raw bytes of the public key, so
        // first we need to convert to a human-readable form.
        bin2hex(ctx->fullStr, pubkeyBytes, 32);
    }

#ifdef HAVE_BAGL
    ux_flow_init(0, ux_compare_pk_flow, NULL);
#endif

    return 0;
}

uint16_t handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t* buffer, uint16_t len) {
    UNUSED(p1);
    UNUSED(len);

    if ((p2 != P2_DISPLAY_ADDRESS) && (p2 != P2_DISPLAY_PUBKEY)) {
        return SW_INVALID_PARAM;
    }

    // Read Key Index
    explicit_bzero(ctx, sizeof(getPublicKeyContext_t));
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

#ifdef HAVE_BAGL
    ux_flow_init(0, ux_approve_pk_flow, NULL);
#else
    nbgl_useCaseReviewStart(&C_stax_app_sia,
                            ctx->typeStr,
                            ctx->keyStr,
                            "Cancel",
                            continue_review,
                            confirm_address_rejection);
#endif

    return 0;
}
