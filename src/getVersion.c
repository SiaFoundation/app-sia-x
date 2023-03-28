#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "blake2b.h"
#include "sia.h"
#include "sia_ux.h"

// handleGetVersion is the entry point for the getVersion command. It
// unconditionally sends the app version.
void handleGetVersion(uint8_t p1 __attribute__((unused)),
	uint8_t p2 __attribute__((unused)),
	uint8_t *dataBuffer __attribute__((unused)),
	uint16_t dataLength __attribute__((unused)),
	volatile unsigned int *flags __attribute__((unused)),
	volatile unsigned int *tx __attribute__((unused))) {
	G_io_apdu_buffer[0] = APPVERSION[0] - '0';
	G_io_apdu_buffer[1] = APPVERSION[2] - '0';
	G_io_apdu_buffer[2] = APPVERSION[4] - '0';
	io_exchange_with_code(SW_OK, 3);
}

