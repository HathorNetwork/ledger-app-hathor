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
#include <string.h>
#include "hathor.h"
#include "ux.h"

// Define the approval screen. This is where the user will confirm that they
// want to authorize access from the desktop wallet.
static const bagl_element_t ui_getXPub_approve[] = {
    UI_BACKGROUND(),

    // Rejection/approval icons, represented by a cross and a check mark,
    // respectively.
    UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),

    // The two lines of text, which together form a complete sentence:
    //
    //    Authorize
    //    access?
    //
    UI_TEXT(0x00, 0, 12, 128, "Authorize"),
    UI_TEXT(0x00, 0, 26, 128, "access?"),
};

// This is the button handler for the approval screen
static unsigned int ui_getXPub_approve_button(unsigned int button_mask, unsigned int button_mask_counter) {
    // tx is the offset within G_io_apdu_buffer
    uint16_t tx = 0;
    cx_ecfp_public_key_t public_key;
    cx_ecfp_private_key_t private_key;
    unsigned char chain_code[32];
    unsigned char hash_160[20];

    // bip32 path for 44'/280'/0'/0
    uint32_t path[4];
    memcpy(path, htr_bip44, 3*sizeof(uint32_t));
    path[3] = 0;

    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // REJECT
        // Send an error code to the computer. The application on the computer
        // should recognize this code and display a "user refused" message
        // instead of a generic error.
        io_exchange_with_code(SW_USER_REJECTED, 0);
        // Return to the main screen.
        ui_idle();
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPROVE
        derive_keypair(path, 4, &private_key, &public_key, chain_code);
        memcpy(G_io_apdu_buffer + tx, public_key.W, public_key.W_len);
        tx += public_key.W_len;
        memcpy(G_io_apdu_buffer + tx, chain_code, 32);
        tx += 32;

        // get parent fingerprint
        derive_keypair(path, 3, &private_key, &public_key, chain_code);
        compress_public_key(public_key.W);
        hash160(public_key.W, 33, hash_160);
        // fingerprint is only first 4 bytes of hash
        memcpy(G_io_apdu_buffer + tx, hash_160, 4);
        tx += 4;

        // erase sensitive data
        explicit_bzero(&private_key, sizeof(private_key));
        explicit_bzero(&public_key, sizeof(public_key));
        explicit_bzero(chain_code, 32);

        // Send user approved
        io_exchange_with_code(SW_OK, tx);

        // Return to the main screen.
        ui_idle();
        break;
    }
    return 0;
}

/**
 * handleGetXPub is the entry point for this screen. It returns all elements necessary
 * to create the xpub key: public key (uncompressed), chain code and parent fingerprint.
 */
void handleGetXPub(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
    UX_DISPLAY(ui_getXPub_approve, NULL);
    *flags |= IO_ASYNCH_REPLY;
}
