/*******************************************************************************
 *
 *  (c) 2016 Ledger
 *  (c) 2018 Nebulous
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

// This code also serves as a walkthrough for writing your own Ledger Nano S
// app. Begin by reading this file top-to-bottom, and proceed to the next file
// when directed. It is recommended that you install this app on your Nano S
// so that you can see how each section of code maps to real-world behavior.
// This also allows you to experiment by modifying the code and observing the
// effect on the app.
//
// I'll begin by describing the high-level architecture of the app. The entry
// point is this file, main.c, which initializes the app and runs the APDU
// request/response loop. The loop reads APDU packets from the computer, which
// instructs it to run various commands. The Sia app supports three commands,
// each defined in a separate file: getPublicKey, signHash, and calcTxnHash.
// These each make use of Sia-specific functions, which are defined in sia.c.
// Finally, some global variables and helper functions are declared in ux.h.
//
// Each command consists of a command handler and a set of screens. Each
// screen has an associated set of elements that can be rendered, a
// preprocessor that controls which elements are rendered, and a button
// handler that processes user input. The command handler is called whenever
// sia_main receives an APDU requesting that command, and is responsible for
// displaying the first screen of the command. Control flow then moves to the
// button handler for that screen, which selects the next screen to display
// based on which button was pressed. Button handlers are also responsible for
// sending APDU replies back to the computer.
//
// The control flow can be a little confusing to understand, because the
// button handler isn't really on the "main execution path" -- it's only
// called via interrupt, typically while execution is blocked on an
// io_exchange call. (In general, it is instructive to think of io_exchange as
// the *only* call that can block.) io_exchange exchanges APDU packets with
// the computer: first it sends a response packet, then it receives a request
// packet. This ordering may seem strange, but it makes sense when you
// consider that the Nano S has to do work in between receiving a command and
// replying to it. Thus, the packet sent by io_exchange is a *response* to the
// previous request, and the packet received is the next request.
//
// But there's a problem with this flow: in most cases, we can't respond to
// the command request until we've received some user input, e.g. approving a
// signature. If io_exchange is the only call that blocks, how can we tell it
// to wait for user input? The answer is a special flag, IO_ASYNC_REPLY. When
// io_exchange is called with this flag, it blocks, but it doesn't send a
// response; instead, it just waits for a new request. Later on, we make a
// separate call to io_exchange, this time with the IO_RETURN_AFTER_TX flag.
// This call sends the response, and then returns immediately without waiting
// for the next request. Visually, it is clear that these flags have opposite
// effects on io_exchange:
//
//                                      ----Time--->
//    io_exchange:        [---Send Response---|---Wait for Request---]
//    IO_ASYNC_REPLY:                           ^Only do this part^
//    IO_RETURN_AFTER_TX:  ^Only do this part^
//
// So a typical command flow looks something like this. We start in sia_main,
// which is an infinite loop that starts by calling io_exchange. It receives
// an APDU request from the computer and calls the associated command handler.
// The handler displays a screen, e.g. "Generate address?", and sets the
// IO_ASYNC_REPLY flag before returning. Control returns to sia_main, which
// loops around and calls io_exchange again; due to the flag, it now blocks.
// Everything is frozen until the user decides which button to press. When
// they eventually press the "Approve" button, the button handler jumps into
// action. It generates the address, constructs a response APDU containing
// that address, calls io_exchange with IO_RETURN_AFTER_TX, and redisplays the
// main menu. When a new command arrives, it will be received by the blocked
// io_exchange in sia_main.
//
// More complex commands may require multiple requests and responses. There
// are two approaches to handling this. One approach is to treat each command
// handler as a self-contained unit: that is, the main loop should only handle
// the *first* request for a given command. Subsequent requests are handled by
// additional io_exchange calls within the command handler. The other approach
// is to let the main loop handle all requests, and design the handlers so
// that they can "pick up where they left off." Both designs have tradeoffs.
// In the Sia app, the only handler that requires multiple requests is
// calcTxnHash, and it takes the latter approach.
//
// On the other end of the spectrum, there are simple commands that do not
// require any user input. Many Nano S apps have a "getVersion" command that
// replies to the computer with the app's version. In this case, it is
// sufficient for the command handler to prepare the response APDU and allow
// the main loop to send it immediately, without setting IO_ASYNC_REPLY.
//
// The important things to remember are:
// - io_exchange is the only blocking call
// - the main loop invokes command handlers, which display screens and set button handlers
// - button handlers switch between screens and reply to the computer

#include <glyphs.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>
#include <stdint.h>
#include <io.h>
#include <ux.h>
#include <parser.h>

#include "blake2b.h"
#include "sia.h"
#include "sia_ux.h"

// You may notice that this file includes blake2b.h despite doing no hashing.
// This is because the Sia app uses the Plan 9 convention for header files:
// header files may not #include other header files. This file needs ux.h, but
// ux.h depends on sia.h, which depends on blake2b.h; so all three must be
// included before we can include ux.h. Feel free to use the more conventional
// #ifndef guards in your own app.

// These are global variables declared in ux.h. They can't be defined there
// because multiple files include ux.h; they need to be defined in exactly one
// place. See ux.h for their descriptions.
commandContext global;

// Here we define the main menu, using the Ledger-provided menu API. This menu
// turns out to be fairly unimportant for Nano S apps, since commands are sent
// by the computer instead of being initiated by the user. It typically just
// contains an idle screen and a version screen.

void ui_idle(void);
void ui_menu_about(void);

#ifdef HAVE_BAGL
UX_STEP_NOCB(ux_menu_ready_step, nn, {"Awaiting", "commands"});
UX_STEP_CB(ux_menu_about_step, pn, ui_menu_about(), {&C_icon_certificate, "About"});
UX_STEP_VALID(ux_menu_exit_step, pn, os_sched_exit(0), {&C_icon_dashboard, "Quit"});

// flow for the main menu:
// #1 screen: ready
// #2 screen: about submenu
// #3 screen: quit
UX_FLOW(ux_menu_main_flow, &ux_menu_ready_step, &ux_menu_about_step, &ux_menu_exit_step, FLOW_LOOP);

UX_STEP_NOCB(ux_menu_version_step, bn, {"Version", APPVERSION});
UX_STEP_NOCB(ux_menu_developer_step, bn, {"Developer", APPDEVELOPER});
UX_STEP_CB(ux_menu_back_step, pb, ui_idle(), {&C_icon_back, "Back"});

// flow for the about submenu:
// #1 screen: app version
// #2 screen: back button
UX_FLOW(ux_menu_about_flow,
        &ux_menu_version_step,
        &ux_menu_developer_step,
        &ux_menu_back_step,
        FLOW_LOOP);

void ui_idle(void) {
    if (G_ux.stack_count == 0) {
        ux_stack_push();
    }

    ux_flow_init(0, ux_menu_main_flow, NULL);
}

void ui_menu_about(void) {
    ux_flow_init(0, ux_menu_about_flow, NULL);
}
#else
static const char *const INFO_TYPES[] = {"Version", "Developer"};
static const char *const INFO_CONTENTS[] = {APPVERSION, APPDEVELOPER};

static bool nav_callback(uint8_t page, nbgl_pageContent_t *content) {
    UNUSED(page);
    content->type = INFOS_LIST;
    content->infosList.nbInfos = 2;
    content->infosList.infoTypes = INFO_TYPES;
    content->infosList.infoContents = INFO_CONTENTS;
    return true;
}

void app_quit(void) {
    // exit app here
    os_sched_exit(-1);
}

void ui_idle(void) {
    nbgl_useCaseHome(APPNAME, &C_stax_app_sia, NULL, false, ui_menu_about, app_quit);
}

void ui_menu_about(void) {
    nbgl_useCaseSettings(APPNAME, 0, 1, false, ui_idle, nav_callback, NULL);
}

#endif

unsigned int io_reject(void) {
    io_send_sw(SW_USER_REJECTED);
    // Return to the main screen.
    ui_idle();
    return 0;
}

// The APDU protocol uses a single-byte instruction code (INS) to specify
// which command should be executed. We'll use this code to dispatch on a
// table of function pointers.
#define INS_GET_VERSION    0x01
#define INS_GET_PUBLIC_KEY 0x02
#define INS_SIGN_HASH      0x04
#define INS_GET_TXN_HASH   0x08

// This is the function signature for a command handler.
// Returns 0 on success.
typedef uint16_t handler_fn_t(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength);

handler_fn_t handleGetVersion;
handler_fn_t handleGetPublicKey;
handler_fn_t handleSignHash;
handler_fn_t handleCalcTxnHash;

static handler_fn_t *lookupHandler(uint8_t ins) {
    switch (ins) {
        case INS_GET_VERSION:
            return handleGetVersion;
        case INS_GET_PUBLIC_KEY:
            return handleGetPublicKey;
        case INS_SIGN_HASH:
            return handleSignHash;
        case INS_GET_TXN_HASH:
            return handleCalcTxnHash;
        default:
            return NULL;
    }
}

// These are the offsets of various parts of a request APDU packet. INS
// identifies the requested command (see above), and P1 and P2 are parameters
// to the command.
#define CLA          0xE0
#define OFFSET_CLA   0x00
#define OFFSET_INS   0x01
#define OFFSET_P1    0x02
#define OFFSET_P2    0x03
#define OFFSET_LC    0x04
#define OFFSET_CDATA 0x05

// Everything below this point is Ledger magic. And the magic isn't well-
// documented, so if you want to understand it, you'll need to read the
// source, which you can find in the nanos-secure-sdk repo. Fortunately, you
// don't need to understand any of this in order to write an app.
//
// Next, we'll look at how the various commands are implemented. We'll start
// with the simplest command, signHash.c.

void send_error_code(uint16_t e) {
    // Convert the exception to a response code. All error codes
    // start with 6, except for 0x9000, which is a special
    // "success" code. Every APDU payload should end with such a
    // code, even if no other data is sent. For example, when
    // calcTxnHash is processing packets of txn data, it replies
    // with just 0x9000 to indicate that it is ready to receive
    // more data.
    //
    // If the first byte is not a 6, mask it with 0x6800 to
    // convert it to a proper error code. I'm not totally sure why
    // this is done; perhaps to handle single-byte exception
    // codes?
    short sw = 0;
    switch (e & 0xF000) {
        case 0x6000:
        case 0x9000:
            sw = e;
            break;
        default:
            sw = 0x6800 | (e & 0x7FF);
            break;
    }
    io_send_sw(sw);
}

void app_main() {
    // Mark the transaction context as uninitialized.
    explicit_bzero(&global, sizeof(global));

    // Initialize io
    io_init();

    ui_idle();

    int input_len = 0;
    command_t cmd = {0};
    for (;;) {
        // Read command into G_io_apdu_buffer
        if ((input_len = io_recv_command()) < 0) {
            PRINTF("Failed to receive");
            io_send_sw(SW_INVALID_PARAM);
            continue;
        }

        // Parse command into CLA, INS, P1/P2, LC, and data
        if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
            PRINTF("Invalid command length");
            io_send_sw(SW_INVALID_PARAM);
            continue;
        }

        // Lookup and call the requested command handler.
        handler_fn_t *handlerFn = lookupHandler(cmd.ins);
        if (!handlerFn) {
            PRINTF("Instruction not supported");
            send_error_code(SW_INS_NOT_SUPPORTED);
            continue;
        }

// without calling this, pagination will always begin on the last page if a paginated menu has been
// scrolled through before during the session
#ifdef TARGET_NANOX
        ux_layout_bnnn_paging_reset();
#elif defined(HAVE_BAGL)
        ux_layout_paging_reset();
#endif

        const uint16_t e = handlerFn(cmd.p1, cmd.p2, cmd.data, cmd.lc);
        if (e != 0) {
            send_error_code(e);
            continue;
        }
    }
}
