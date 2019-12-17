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
#include "util.h"
#include "ux.h"

static sign_tx_context_t *ctx = &global.sign_tx_context;

/*
 * Prepare the output information that will be displayed.
 */
static void prepare_display_output(uint8_t index) {
    tx_output_t output = ctx->transaction.outputs[index];
    unsigned char address[25];
    pubkey_hash_to_address(output.pubkey_hash, address);
    uint8_t len = encode_base58(address, 25, ctx->info, sizeof(ctx->info));
    os_memmove(ctx->info + len, " HTR ", 5);
    format_value(output.value, ctx->info+len+5);
}

/*
 * Returns the first output to be display. In general, that's output 0. This is only
 * not true if output 0 is the change output. In that case, the first output to be
 * displayed is 1.
 */
static uint8_t get_first_output() {
    return ((ctx->has_change_output && ctx->change_output_index == 0) ? 1 : 0);
}

/*
 * Returns the last output to be displayed. In general, the change output is the last
 * in a transaction, so the last to be displayed is the second to last.
 */
static uint8_t get_last_output() {
    return (ctx->has_change_output && ctx->change_output_index == (ctx->transaction.outputs_len - 1)
            ? ctx->transaction.outputs_len - 2 : ctx->transaction.outputs_len - 1);
}

/*
 * Gets the next output to be displayed, given an output index. Skips the change output.
 */
static uint8_t get_next_output(uint8_t index) {
    uint8_t next = index + 1;
    return (next == ctx->change_output_index ? next + 1 : next);
}

/*
 * Gets the previous output to be displayed, given an output index. Skips the change output.
 */
static uint8_t get_previous_output(uint8_t index) {
    uint8_t prev = index - 1;
    return (prev == ctx->change_output_index ? prev - 1 : prev);
}

static const bagl_element_t* ui_prepro_sign_tx_confirm(const bagl_element_t *element) {
    if (element->component.userid == 1 && ctx->state == USER_APPROVED) {
        // don't display arrows after user confirms (when processing signatures)
        return NULL;
    } else {
        return element;
    }
}

static const bagl_element_t ui_sign_tx_confirm[] = {
    UI_BACKGROUND(),

    // Left and right buttons for scrolling the text.
    UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x01, BAGL_GLYPH_ICON_CHECK),

    UI_TEXT(0x00, 0, 12, 128, global.sign_tx_context.line1),
    UI_TEXT(0x00, 0, 26, 128, global.sign_tx_context.line2),
};

// This is the button handler for the confirmation screen
static unsigned int ui_sign_tx_confirm_button(unsigned int button_mask, unsigned int button_mask_counter) {
    if (ctx->state == USER_APPROVED) {
        // button pressed after it's been already confirmed,
        // while processing signatures. Just ignore it.
        return 0;
    }

    //TODO maybe we want the user to hold either button instead of a simple click
    switch (button_mask) {
        case BUTTON_LEFT:
        case BUTTON_EVT_FAST | BUTTON_LEFT: // cancel
            io_exchange_with_code(SW_USER_REJECTED, 0);
            // Return to the main screen.
            ui_idle();
            break;

        case BUTTON_RIGHT:
        case BUTTON_EVT_FAST | BUTTON_RIGHT: // confirm
            ctx->state = USER_APPROVED;
            io_exchange_with_code(SW_OK, 0);
            os_memmove(ctx->line1, "Processing\0", 11);
            os_memmove(ctx->line2, "...\0", 4);
            UX_REDISPLAY();
            break;
    }
    return 0;
}

// Define the sign tx screen. User will be able to scroll through all outputs
// (address + value) with left/right buttons. When he's done, he will click both
// buttons and a final confirmation screen appears.
static const bagl_element_t ui_sign_tx_compare[] = {
    UI_BACKGROUND(),

    // Left and right buttons for scrolling the text.
    UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
    UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),

    UI_TEXT(0x00, 0, 12, 128, global.sign_tx_context.line1),
    UI_TEXT(0x00, 0, 26, 128, global.sign_tx_context.line2),
};

// Preprocessor for this screen. Hides left or right arrows depending on the
// scrolling position.
static const bagl_element_t* ui_prepro_sign_tx_compare(const bagl_element_t *element) {
    switch (element->component.userid) {
    case 1:
        // 0x01 is the left icon so return NULL if we're displaying the beginning of the first element.
        //return (ctx->displayIndex == 0) ? NULL : element;
        return ((ctx->current_output == get_first_output() && ctx->display_index == 0) ? NULL : element);
    case 2:
        // 0x02 is the right, so return NULL if we're displaying the end of the last element.
        //return (ctx->displayIndex == sizeof(ctx->b58_address)-12) ? NULL : element;
        return ((ctx->current_output == get_last_output()
                    && ctx->display_index == (strlen(ctx->info) - 12)) ? NULL : element);
    default:
        // Always display all other elements.
        return element;
    }
}

// This is the button handler for the outputs screen.
static unsigned int ui_sign_tx_compare_button(unsigned int button_mask, unsigned int button_mask_counter) {
    switch (button_mask) {
        // scroll left by either clicking or pressing the left button
        case BUTTON_LEFT:
        case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
            if (ctx->display_index == 0) {
                // we're at the beginning of an output
                if (ctx->current_output == get_first_output()) {
                    // do nothing
                    UX_REDISPLAY();
                    break;
                } else {
                    // go to previous output
                    ctx->current_output = get_previous_output(ctx->current_output);
                    prepare_display_output(ctx->current_output);
                    ctx->display_index = strlen(ctx->info) - 12;
                }
            } else {
                ctx->display_index--;
            }

            itoa(ctx->current_output, ctx->line1 + 8, 10);
            os_memmove(ctx->line2, ctx->info+ctx->display_index, 12);
            UX_REDISPLAY();
            break;

        // scroll right by either clicking or pressing the right button
        case BUTTON_RIGHT:
        case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
            if (ctx->display_index == strlen(ctx->info) - 12) {
                // we're at the end of one of the outputs
                if (ctx->current_output == get_last_output()) {
                    // if it's the last one, do nothing
                    UX_REDISPLAY();
                    break;
                } else {
                    // go to next output
                    ctx->current_output = get_next_output(ctx->current_output);
                    prepare_display_output(ctx->current_output);
                    ctx->display_index = 0;
                }
            } else {
                ctx->display_index++;
            }

            itoa(ctx->current_output, ctx->line1 + 8, 10);
            os_memmove(ctx->line2, ctx->info+ctx->display_index, 12);
            UX_REDISPLAY();
            break;

        case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
            // Go to confirmation screen
            os_memmove(ctx->line1, "Send\0", 5);
            os_memmove(ctx->line2, "transaction?\0", 13);
            UX_DISPLAY(ui_sign_tx_confirm, ui_prepro_sign_tx_confirm);
            break;
    }
    return 0;
}

void handle_sign_tx(uint8_t p1, uint8_t p2, uint8_t *data_buffer, uint16_t data_length, volatile unsigned int *flags, volatile unsigned int *tx) {
    cx_ecfp_public_key_t public_key;
    cx_ecfp_private_key_t private_key;
    // bip32 path for 44'/280'/0'/0/key_index
    uint32_t path[5];
    uint8_t hash[32];

    if (p1 == 2) {
        // all done, go back to main menu
        io_exchange_with_code(SW_OK, 0);
        ui_idle();
    }

    if (p1 == 1) {
        // asking for signature
        uint32_t key_index = U4BE(data_buffer, 0);

        // bip32 path for 44'/280'/0'/0/key_index
        memcpy(path, htr_bip44, 3*sizeof(uint32_t));
        path[3] = 0;
        path[4] = key_index;

        // Get key for path
        derive_keypair(path, 5, &private_key, &public_key, NULL);

        // sign message (sha256d of sighash_all data)
        unsigned int info;
        sha256d(ctx->buffer, ctx->buffer_len, hash);
        int sig_size = cx_ecdsa_sign(&private_key, CX_LAST | CX_RND_RFC6979, CX_SHA256, hash, 32, G_io_apdu_buffer, 256, &info);

        // erase sensitive data
        explicit_bzero(&private_key, sizeof(private_key));
        explicit_bzero(&public_key, sizeof(public_key));

        io_exchange_with_code(SW_OK, sig_size);
    }

    if (p1 == 0) {
        if (ctx->state == USER_APPROVED) {
            // can't receive more data after user's approval
            THROW(SW_INVALID_PARAM);
        }

        // we're receiving data
        if (ctx->state == UNINITIALIZED) {
            // starting new tx; not initialized yet
            ctx->state = RECEIVING_DATA;
            ctx->buffer_len = 0;
            ctx->has_change_output = false;
            ctx->change_output_index = 0;
            ctx->change_key_index = 0;
            ctx->current_output = 0;
            ctx->display_index = 0;
            init_tx(&ctx->transaction);
        }

        if (p2 >= 0) {
            //receiving data
            os_memcpy(ctx->buffer + ctx->buffer_len, data_buffer, data_length);
            ctx->buffer_len += data_length;
        }

        if (p2 == 0) {
            // end of data, parse it
            uint8_t *buf = ctx->buffer;
            assert_length(1, ctx->buffer_len);
            // check output change. If next byte is greater than 0, there's a change output
            ctx->has_change_output = (*buf > 0 ? true : false);
            buf++;
            if (ctx->has_change_output) {
                assert_length(5, ctx->buffer_len - 1);
                ctx->change_output_index = *buf;
                buf++;
                ctx->change_key_index = U4BE(buf, 0);
                buf += 4;
            }

            uint8_t *ret = parse_tx(buf, (ctx->buffer + ctx->buffer_len - buf), &ctx->transaction);

            if (ret - ctx->buffer != ctx->buffer_len) {
                // we finished parsing the tx but there's extra data on the buffer
                io_exchange_with_code(SW_DEVELOPER_ERR, 0);
                return;
            }

            // check if change output is within existing outputs
            if (ctx->change_output_index >= ctx->transaction.outputs_len) {
                io_exchange_with_code(SW_INVALID_PARAM, 0);
                return;
            }

            // check that change output has pubkey hash matching informed key index
            if (ctx->has_change_output) {
                // bip32 path for 44'/280'/0'/0/key_index
                memcpy(path, htr_bip44, 3*sizeof(uint32_t));
                path[3] = 0;
                path[4] = ctx->change_key_index;

                // Get pubkey hash for path
                derive_keypair(path, 5, &private_key, &public_key, NULL);
                compress_public_key(public_key.W);
                hash160(public_key.W, 33, hash);
                // erase sensitive data
                explicit_bzero(&private_key, sizeof(private_key));
                explicit_bzero(&public_key, sizeof(public_key));
                if (os_memcmp(hash, ctx->transaction.outputs[ctx->change_output_index].pubkey_hash, 20) != 0) {
                    // not the same
                    io_exchange_with_code(SW_INVALID_PARAM, 0);
                    return;
                }
            }

            // prepare the outputs
            ctx->current_output = get_first_output();
            prepare_display_output(ctx->current_output);
            os_memmove(ctx->line1, "Output #", 8);
            itoa(ctx->current_output, ctx->line1 + 8, 10);
            os_memmove(ctx->line2, ctx->info+ctx->display_index, 12);
            ctx->line2[12] = '\0';

            UX_DISPLAY(ui_sign_tx_compare, ui_prepro_sign_tx_compare);
            *flags |= IO_ASYNCH_REPLY;
            return;
        }
        io_exchange_with_code(SW_OK, 0);
    }
}
