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

static getAddressContext_t *ctx = &global.getAddressContext;

// Define the comparison screen. This is where the user will compare the address on
// their device to the one shown on the computer. There are lef/right buttons on the
// screen to navigate the hash. Clicking both buttons goes back to main screen.
static const bagl_element_t ui_getAddress_compare[] = {
    UI_BACKGROUND(),

    // Left and right buttons for scrolling the text.
    UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
    UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),

    UI_TEXT(0x00, 0, 12, 128, "Compare addresses:"),
    UI_TEXT(0x00, 0, 26, 128, global.getAddressContext.partialAddress),
    //UI_TEXT(0x00, 0, 26, 128, "testete11"),
};

// Preprocessor for this screen. Hides left or right arrows depending on the
// scrolling position.
static const bagl_element_t* ui_prepro_getAddress_compare(const bagl_element_t *element) {
    switch (element->component.userid) {
    case 1:
        // 0x01 is the left icon so return NULL if we're displaying the beginning of the text.
        return (ctx->displayIndex == 0) ? NULL : element;
    case 2:
        // 0x02 is the right, so return NULL if we're displaying the end of the text.
        return (ctx->displayIndex == sizeof(ctx->b58_address)-12) ? NULL : element;
    default:
        // Always display all other elements.
        return element;
    }
}

// This is the button handler for the comparison screen.
static unsigned int ui_getAddress_compare_button(unsigned int button_mask, unsigned int button_mask_counter) {
    switch (button_mask) {
    // scroll left by either clicking or pressing the left button
    case BUTTON_LEFT:
    case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
        // Decrement the displayIndex when the left button is pressed (or held).
        if (ctx->displayIndex > 0) {
            ctx->displayIndex--;
        }
        os_memmove(ctx->partialAddress, ctx->b58_address+ctx->displayIndex, 12);
        UX_REDISPLAY();
        break;

    // scroll right by either clicking or pressing the right button
    case BUTTON_RIGHT:
    case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
        if (ctx->displayIndex < sizeof(ctx->b58_address)-12) {
            ctx->displayIndex++;
        }
        os_memmove(ctx->partialAddress, ctx->b58_address+ctx->displayIndex, 12);
        UX_REDISPLAY();
        break;

    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
        io_exchange_with_code(SW_OK, 0);
        // Return to the main screen.
        ui_idle();
        break;
    }
    return 0;
}

void handleGetAddress(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
    // Read the index of the signing key. U4BE is a helper macro for
    // converting a 4-byte buffer to a uint32_t.
    uint32_t key_index = U4BE(dataBuffer, 0);

    cx_ecfp_public_key_t public_key;
    cx_ecfp_private_key_t private_key;
    uint8_t bin_address[25];

    // bip32 path for 44'/280'/0'/0/key_index
    uint32_t path[5];
    memcpy(path, htr_bip44, 3*sizeof(uint32_t));
    path[3] = 0;
    path[4] = key_index;

    // Get address for the path
    derive_keypair(path, 5, &private_key, &public_key, NULL);
    pubkey_to_address(&public_key, bin_address);
    // erase sensitive data
    explicit_bzero(&private_key, sizeof(private_key));
    explicit_bzero(&public_key, sizeof(public_key));

    // convert to base58
    if (encode_base58(bin_address, sizeof(bin_address), ctx->b58_address, sizeof(ctx->b58_address)) == -1) {
        // there's been an error
        THROW(SW_DEVELOPER_ERR);
    }

    // move the first 12 characters into the partialAddress buffer.
    os_memmove(ctx->partialAddress, ctx->b58_address, 12);
    ctx->partialAddress[12] = '\0';
    ctx->displayIndex = 0;

    UX_DISPLAY(ui_getAddress_compare, ui_prepro_getAddress_compare);
    *flags |= IO_ASYNCH_REPLY;
}
