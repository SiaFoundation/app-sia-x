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

#include <os_io_seproxyhal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <io.h>

#include "blake2b.h"
#include "sia.h"
#include "sia_ux.h"

// Get a pointer to signHash's state variables. This is purely for
// convenience, so that we can refer to these variables concisely from any
// signHash-related function.
static signHashContext_t *ctx = &global.signHashContext;

static unsigned int io_seproxyhal_touch_hash_ok(void) {
    // Derive the secret key and sign the hash, storing the signature in
    // the APDU buffer. This is the first Sia-specific function we've
    // encountered; it is defined in sia.c.
    uint8_t signature[64] = {0};
    deriveAndSign(signature, ctx->keyIndex, ctx->hash);
    io_send_response_pointer(signature, sizeof(signature), SW_OK);

#ifdef HAVE_BAGL
    ui_idle();
#else
    nbgl_useCaseStatus("HASH SIGNED", true, ui_idle);
#endif

    return 0;
}

#ifdef HAVE_BAGL
UX_STEP_NOCB(ux_approve_hash_flow_1_step,
             bnnn_paging,
             {"Compare Input:", global.signHashContext.hexHash});

UX_STEP_VALID(ux_approve_hash_flow_2_step,
              pb,
              io_seproxyhal_touch_hash_ok(),
              {&C_icon_validate_14, "Approve"});

UX_STEP_VALID(ux_approve_hash_flow_3_step, pb, io_reject(), {&C_icon_crossmark, "Reject"});

// Flow for the signing hash menu:
// #1 screen: the hash repeated for confirmation
// #2 screen: approve
// #3 screen: reject
UX_FLOW(ux_approve_hash_flow,
        &ux_approve_hash_flow_1_step,
        &ux_approve_hash_flow_2_step,
        &ux_approve_hash_flow_3_step);
#else

static nbgl_layoutTagValue_t pair = {0};

static void cancel_review(void) {
    // display a status page and go back to main
    io_send_sw(SW_USER_REJECTED);
    nbgl_useCaseStatus("Signing Cancelled", false, ui_idle);
}

static void confirm_callback(bool confirm) {
    if (confirm) {
        io_seproxyhal_touch_hash_ok();
    } else {
        cancel_review();
    }
}

#endif

uint16_t handleSignHash(uint8_t p1 __attribute__((unused)),
                        uint8_t p2 __attribute__((unused)),
                        uint8_t *buffer,
                        uint16_t len) {
    if (len != sizeof(uint32_t) + SIA_HASH_SIZE) {
        return SW_INVALID_PARAM;
    } else if (!N_storage.blindSign) {
        return SW_USER_REJECTED;
    }

    // Read the index of the signing key. U4LE is a helper macro for
    // converting a 4-byte buffer to a uint32_t.
    explicit_bzero(ctx, sizeof(signHashContext_t));
    ctx->keyIndex = U4LE(buffer, 0);

    // Read the hash.
    memcpy(ctx->hash, buffer + sizeof(uint32_t), SIA_HASH_SIZE);

    // Prepare to display the comparison screen by converting the hash to hex
    bin2hex(ctx->hexHash, ctx->hash, SIA_HASH_SIZE);

#ifdef HAVE_BAGL
    ux_flow_init(0, ux_approve_hash_flow, NULL);
#else
    snprintf(ctx->typeStr, sizeof(ctx->typeStr), "Sign Hash with Key %d?", ctx->keyIndex);

    pair.item = "Hash";
    pair.value = ctx->hexHash;

    nbgl_layoutTagValueList_t tagValueList = {0};
    tagValueList.nbPairs = 1;
    tagValueList.pairs = &pair;

    nbgl_useCaseReview(TYPE_MESSAGE,
                       &tagValueList,
                       &C_stax_app_sia_big,
                       ctx->typeStr,
                       NULL,
                       "Sign hash",
                       confirm_callback);
#endif

    return 0;
}
