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

// These are global variables declared in ux.h. They can't be defined there
// because multiple files include ux.h; they need to be defined in exactly one
// place. See ux.h for their descriptions.
commandContext global;
const internalStorage_t N_storage_real;

void ui_idle(void);
void ui_menu_about(void);

static void update_blind_sign_ui(void);

static void toggle_blind_sign(void) {
    const bool new_value = !N_storage.blindSign;
    nvm_write((void *) &N_storage.blindSign, (void *) &new_value, sizeof(bool));
    update_blind_sign_ui();
}

#ifdef HAVE_BAGL
static char BLIND_SIGNING_MESSAGE[22] = {0};

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
UX_STEP_CB(ux_menu_blind_sign_step,
           pn,
           toggle_blind_sign(),
           {&C_icon_certificate, BLIND_SIGNING_MESSAGE});
UX_STEP_CB(ux_menu_back_step, pb, ui_idle(), {&C_icon_back, "Back"});

// flow for the about submenu:
// #1 screen: app version
// #2 screen: blind sign setting
// #3 screen: back button
UX_FLOW(ux_menu_about_flow,
        &ux_menu_version_step,
        &ux_menu_developer_step,
        &ux_menu_blind_sign_step,
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

static void update_blind_sign_ui(void) {
    if (N_storage.blindSign) {
        memcpy(BLIND_SIGNING_MESSAGE, "Disable blind signing", sizeof(BLIND_SIGNING_MESSAGE));
    } else {
        memcpy(BLIND_SIGNING_MESSAGE, "Enable blind signing", sizeof(BLIND_SIGNING_MESSAGE));
    }
    ui_idle();
}

#else

static void controls_callback(int token, uint8_t index, int page);

#define SETTING_INFO_NB     2
static const char *const INFO_TYPES[SETTING_INFO_NB] = {"Version", "Developer"};
static const char *const INFO_CONTENTS[SETTING_INFO_NB] = {APPVERSION, APPDEVELOPER};

// settings switches definitions
enum { BLIND_SIGNING_TOKEN = FIRST_USER_TOKEN };
enum { BLIND_SIGNING_ID = 0, SETTINGS_SWITCHES_NB };

static nbgl_contentSwitch_t switches[SETTINGS_SWITCHES_NB] = {0};

static const nbgl_contentInfoList_t infoList = {
    .nbInfos = SETTING_INFO_NB,
    .infoTypes = INFO_TYPES,
    .infoContents = INFO_CONTENTS,
};

// settings menu definition
#define SETTING_CONTENTS_NB 1
static const nbgl_content_t contents[SETTING_CONTENTS_NB] = {
    {.type = SWITCHES_LIST,
     .content.switchesList.nbSwitches = SETTINGS_SWITCHES_NB,
     .content.switchesList.switches = switches,
     .contentActionCallback = controls_callback}};

static const nbgl_genericContents_t settingContents = {.callbackCallNeeded = false,
                                                       .contentsList = contents,
                                                       .nbContents = SETTING_CONTENTS_NB};

static void controls_callback(int token, uint8_t index, int page) {
    UNUSED(index);
    UNUSED(page);
    if (token == BLIND_SIGNING_TOKEN) {
        toggle_blind_sign();
    }
}

static void update_blind_sign_ui(void) {
    switches[BLIND_SIGNING_ID].initState = N_storage.blindSign ? ON_STATE : OFF_STATE;
}

void app_quit(void) {
    // exit app here
    os_sched_exit(-1);
}

void ui_idle(void) {
    switches[BLIND_SIGNING_ID].text = "Enable blind signing";
    switches[BLIND_SIGNING_ID].subText = "Recommend only for experienced users";
    switches[BLIND_SIGNING_ID].token = BLIND_SIGNING_TOKEN;
    switches[BLIND_SIGNING_ID].tuneId = TUNE_TAP_CASUAL;

    nbgl_useCaseHomeAndSettings(APPNAME,
                                &C_stax_app_sia_big,
                                NULL,
                                INIT_HOME_PAGE,
                                &settingContents,
                                &infoList,
                                NULL,
                                app_quit);
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

    if (!N_storage.initialized) {
        internalStorage_t storage = {0};
        storage.initialized = true;
        nvm_write((void *) &N_storage, (void *) &storage, sizeof(internalStorage_t));
    }
    update_blind_sign_ui();
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

        const uint16_t e = handlerFn(cmd.p1, cmd.p2, cmd.data, cmd.lc);
        if (e != 0) {
            send_error_code(e);
            continue;
        }
    }
}
