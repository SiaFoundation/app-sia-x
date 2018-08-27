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

void io_exchange_with_code(uint16_t code, uint16_t tx);

void ui_idle(void);

// helper macros for defining UI elements
#define UI_BACKGROUND() {{BAGL_RECTANGLE,0,0,0,128,32,0,0,BAGL_FILL,0,0xFFFFFF,0,0},NULL,0,0,0,NULL,NULL,NULL}
#define UI_ICON_LEFT(userid, glyph) {{BAGL_ICON,userid,3,12,7,7,0,0,0,0xFFFFFF,0,0,glyph},NULL,0,0,0,NULL,NULL,NULL}
#define UI_ICON_RIGHT(userid, glyph) {{BAGL_ICON,userid,117,13,8,6,0,0,0,0xFFFFFF,0,0,glyph},NULL,0,0,0,NULL,NULL,NULL}
#define UI_TEXT(userid, x, y, w, text) {{BAGL_LABELINE,userid,x,y,w,12,0,0,0,0xFFFFFF,0,BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER,0},(char *)text,0,0,0,NULL,NULL,NULL}
