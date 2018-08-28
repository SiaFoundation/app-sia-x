typedef struct {
	uint32_t keyIndex;
	bool genAddr;
	uint8_t displayIndex;
	// NUL-terminated strings for display
	uint8_t typeStr[40]; // variable-length
	uint8_t keyStr[40]; // variable-length
	uint8_t fullStr[77]; // variable length
	uint8_t partialStr[13];
} getPublicKeyContext_t;

typedef struct {
	uint32_t keyIndex;
	uint8_t hash[32];
	uint8_t hexHash[64];
	uint8_t displayIndex;
	// NUL-terminated strings for display
	uint8_t indexStr[40]; // variable-length
	uint8_t partialHashStr[13];
} signHashContext_t;

typedef struct {
	uint32_t keyIndex;
	bool sign;
	uint8_t elemLen;
	uint8_t displayIndex;
	uint8_t elemPart; // screen index of elements
	txn_state_t txn;
	// NUL-terminated strings for display
	uint8_t labelStr[40]; // variable length
	uint8_t fullStr[128]; // variable length
	uint8_t partialStr[13];
} calcTxnHashContext_t;

// each command has some state associated with it that sticks around for the
// life of the command. We use a union to save memory, taking advantage of the
// fact that only one command is executed at a time.
typedef union {
	getPublicKeyContext_t getPublicKeyContext;
	signHashContext_t signHashContext;
	calcTxnHashContext_t calcTxnHashContext;
} commandContext;
extern commandContext global;

// magic global variable implicitly referenced by the UX_ macros
extern ux_state_t ux;

// helper macros for defining UI elements
#define UI_BACKGROUND() {{BAGL_RECTANGLE,0,0,0,128,32,0,0,BAGL_FILL,0,0xFFFFFF,0,0},NULL,0,0,0,NULL,NULL,NULL}
#define UI_ICON_LEFT(userid, glyph) {{BAGL_ICON,userid,3,12,7,7,0,0,0,0xFFFFFF,0,0,glyph},NULL,0,0,0,NULL,NULL,NULL}
#define UI_ICON_RIGHT(userid, glyph) {{BAGL_ICON,userid,117,13,8,6,0,0,0,0xFFFFFF,0,0,glyph},NULL,0,0,0,NULL,NULL,NULL}
#define UI_TEXT(userid, x, y, w, text) {{BAGL_LABELINE,userid,x,y,w,12,0,0,0,0xFFFFFF,0,BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER,0},(char *)text,0,0,0,NULL,NULL,NULL}

// ui_idle displays the main menu screen.
void ui_idle(void);

// io_exchange_with_code is a helper function for sending APDUs, primarily
// from button handlers. It appends code to G_io_apdu_buffer and calls
// io_exchange with the IO_RETURN_AFTER_TX flag.
void io_exchange_with_code(uint16_t code, uint16_t tx);