/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "hathor.h"
#include "ux.h"

// handleGetVersion is the entry point for the getVersion command. It
// unconditionally sends the app version.
void handleGetVersion(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
    // We return HTR before the app version, so our wallet can identify it's talking
    // to the Hathor app. Otherwise, we could be making this request for another app
    // and would also get a version from it.
	G_io_apdu_buffer[0] = 'H';
	G_io_apdu_buffer[1] = 'T';
	G_io_apdu_buffer[2] = 'R';
	G_io_apdu_buffer[3] = APPVERSION[0] - '0';
	G_io_apdu_buffer[4] = APPVERSION[2] - '0';
	G_io_apdu_buffer[5] = APPVERSION[4] - '0';
	io_exchange_with_code(SW_OK, 6);
}
