#include <ux.h>
#ifdef HAVE_NBGL
#include <nbgl_use_case.h>
#endif

#include "txn.h"

// Each command has some state associated with it that sticks around for the
// life of the command. A separate context_t struct should be defined for each
// command.

typedef struct {
	uint32_t keyIndex;
	bool genAddr;
	// NUL-terminated strings for display
	char typeStr[40]; // variable-length
	char keyStr[40]; // variable-length
	char fullStr[77]; // variable length
} getPublicKeyContext_t;

#define SIA_HASH_SIZE 32

typedef struct {
	uint32_t keyIndex;
	uint8_t hash[SIA_HASH_SIZE];
	char hexHash[SIA_HASH_SIZE * 2];
} signHashContext_t;

typedef struct {
	uint32_t keyIndex;
	bool sign;
	uint8_t elemPart; // screen index of elements
	txn_state_t txn;
	// NULL-terminated strings for display
	char labelStr[40]; // variable length
	char fullStr[128]; // variable length
	bool initialized; // protects against certain attacks
} calcTxnHashContext_t;

// To save memory, we store all the context types in a single global union,
// taking advantage of the fact that only one command is executed at a time.
typedef union {
	getPublicKeyContext_t getPublicKeyContext;
	signHashContext_t signHashContext;
	calcTxnHashContext_t calcTxnHashContext;
} commandContext;
extern commandContext global;

// These are helper macros for defining UI elements. There are four basic UI
// elements: the background, which is a black rectangle that fills the whole
// screen; icons on the left and right sides of the screen, typically used for
// navigation or approval; and text, which can be anywhere. The UI_TEXT macro
// uses Open Sans Regular 11px, which I've found to be adequate for all text
// elements; if other fonts are desired, I suggest defining a separate macro
// for each of them (e.g. UI_TEXT_BOLD).
//
// In the event that you want to define your own UI elements from scratch,
// you'll want to read include/bagl.h and include/os_io_seproxyhal.h in the
// nanos-secure-sdk repo to learn what each of the fields are used for.
#define UI_BACKGROUND() {{BAGL_RECTANGLE,0,0,0,128,32,0,0,BAGL_FILL,0,0xFFFFFF,0,0},NULL,0,0,0,NULL,NULL,NULL}
#define UI_ICON_LEFT(userid, glyph) {{BAGL_ICON,userid,3,12,7,7,0,0,0,0xFFFFFF,0,0,glyph},NULL,0,0,0,NULL,NULL,NULL}
#define UI_ICON_RIGHT(userid, glyph) {{BAGL_ICON,userid,117,13,8,6,0,0,0,0xFFFFFF,0,0,glyph},NULL,0,0,0,NULL,NULL,NULL}
#define UI_TEXT(userid, x, y, w, text) {{BAGL_LABELINE,userid,x,y,w,12,0,0,0,0xFFFFFF,0,BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER,0},(char *)text,0,0,0,NULL,NULL,NULL}

// ui_idle displays the main menu screen. Command handlers should call ui_idle
// when they finish.
void ui_idle(void);

// about submenu of the main screen
void ui_menu_about(void);

// io_exchange_with_code is a helper function for sending APDUs, primarily
// from button handlers. It appends code to G_io_apdu_buffer and calls
// io_exchange with the IO_RETURN_AFTER_TX flag. tx is the current offset
// within G_io_apdu_buffer (before the code is appended).
void io_exchange_with_code(uint16_t code, uint16_t tx);

// standard "reject" function so we don't repeat code
unsigned int io_seproxyhal_cancel(void);
