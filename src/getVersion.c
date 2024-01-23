#include <io.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>
#include <stdint.h>

#include "blake2b.h"
#include "sia.h"
#include "sia_ux.h"
#include <buffer.h>

// handleGetVersion is the entry point for the getVersion command. It
// unconditionally sends the app version.
void handleGetVersion(uint8_t p1 __attribute__((unused)),
                      uint8_t p2 __attribute__((unused)),
                      uint8_t *dataBuffer __attribute__((unused)),
                      uint16_t dataLength __attribute__((unused))) {
    static const uint8_t appVersion[3] = {APPVERSION[0] - '0',
                                          APPVERSION[2] - '0',
                                          APPVERSION[4] - '0'};

    buffer_t buffer = {0};
    buffer.ptr = appVersion;
    buffer.size = sizeof(appVersion);
    io_send_response_buffers(&buffer, 1, SW_OK);
}
