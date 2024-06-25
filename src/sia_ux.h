#ifndef SIA_UX_H
#define SIA_UX_H

#include <ux.h>
#include "txn.h"

#ifdef HAVE_NBGL
#include <nbgl_use_case.h>
#endif

#define APPDEVELOPER "Sia Foundation"

// Each command has some state associated with it that sticks around for the
// life of the command. A separate context_t struct should be defined for each
// command.

typedef struct {
    uint32_t keyIndex;
    bool genAddr;
    // NUL-terminated strings for display
    char typeStr[40];  // variable-length
    char keyStr[40];   // variable-length
    char fullStr[77];  // variable length
} getPublicKeyContext_t;

#define SIA_HASH_SIZE 32

typedef struct {
    uint32_t keyIndex;
    uint8_t hash[SIA_HASH_SIZE];

    char typeStr[40];
    char hexHash[SIA_HASH_SIZE * 2];
} signHashContext_t;

typedef struct {
    uint32_t keyIndex;
    bool sign;
    uint8_t elemPart;  // screen index of elements

    uint16_t elementIndex;

    txn_state_t txn;
    // NULL-terminated strings for display
    char labelStr[40];     // variable length
    char fullStr[2][128];  // variable length
    bool initialized;      // protects against certain attacks
    bool finished;         // whether we have reached the end of the transaction
} calcTxnHashContext_t;

// To save memory, we store all the context types in a single global union,
// taking advantage of the fact that only one command is executed at a time.
typedef union {
    getPublicKeyContext_t getPublicKeyContext;
    signHashContext_t signHashContext;
    calcTxnHashContext_t calcTxnHashContext;
} commandContext;
extern commandContext global;

typedef struct internalStorage_t {
    bool blindSign;
    bool initialized;
} internalStorage_t;

extern const internalStorage_t N_storage_real;
#define N_storage (*(volatile internalStorage_t *) PIC(&N_storage_real))

// ui_idle displays the main menu screen. Command handlers should call ui_idle
// when they finish.
void ui_idle(void);

// about submenu of the main screen
void ui_menu_about(void);

// standard "reject" function so we don't repeat code
unsigned int io_reject(void);

#endif /* SIA_UX_H */