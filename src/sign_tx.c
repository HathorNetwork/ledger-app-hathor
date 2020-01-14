/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * The sign tx command is a bit more complex than the others, mostly
 * due to the transaction parsing. It requires multiple iterations from
 * the wallet to complete and we use p1 values to track this communication.
 *
 * On the first packet received, it has the change output info, if one exists.
 * If there's no change output, it's just the byte 0x00. Otherwise, it expects
 * any non 0x00 value, followed by the change output index (1 byte) and the key
 * index (4 bytes) that the change is supposed to be sent to. This information
 * is used to confirmed that the change is indeed being sent to an address from
 * this wallet. Eg: 
 *      [0x01, 0x03, 0x00, 0x00, 0x00, 0x05]
 *
 *      . 0x01 - indicates there's a change output
 *      . 0x03 - change is output with index 3 (output index start at 0)
 *      . [0x00, 0x00, 0x00, 0x05] - change is sent to key with index 5 (44'/280'/0'/0/5)
 *
 * Immediately after the change output info, still in the first packet, we start
 * receiving the sighash_all data for the transaction. This is the data that will
 * be signed by Ledger so the inputs can be spent. This data may be very large
 * and it may take multiple packets to receive all the information, as the
 * communication protocol only allows 255 bytes to be passed at a time between
 * Ledger and the wallet. All these initial packets (change output info + sighash_all)
 * use p1 = 0.
 *
 * The code on sign_tx parses the sighash_all data to display information about
 * the transaction to the user. Currently, we only display output info, but we
 * will include token information in the future.
 *
 * The data is parsed iteratively until everything is received from the wallet.
 * This means that in the first packet we may only have data available for the
 * first 2 outputs and the data for the third one is truncated. We display and
 * confirm with the user these 2 outputs and proceed to request more data from
 * the wallet to display the remaining outputs.
 *
 * If there's a change output on this transaction, it is not shown to the user.
 * Usually, change outputs are calculated automatically by the wallet, so it
 * would be confusing to display them to the user. We do, however, verify that
 * the change output actually sends the value to an address belonging to this
 * wallet, so there's no harm in 'hiding' this output from the user.
 *
 * After we receive all data and the user confirms all outputs, a final screen
 * is displayed asking whether the user wants to sign the tx. If he agrees, we
 * send this info back to the wallet and expect to receive in the next packet(s)
 * the key index to sign the sighash_all data. Each packet from this point on
 * corresponds to a request to sign the data with the corresponding key and use
 * p1 = 1. We reply to each request with the signature for the given key. When
 * the wallet collects all signatures it needs, it sends a packet saying that
 * all is done (p1 = 2). Ledger will then go back to the main display.
 *
 * Summary:
 *
 * | p1 | Data
 * |----|------------------------------------
 * | 0  | Change output info and sighash_all, up to 255 bytes at a time
 * | 1  | Key index to sign the sighash data (4 bytes)
 * | 2  | None
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

typedef enum {
    ELEM_TOKEN_UID,
    ELEM_INPUT,
    ELEM_OUTPUT,
} tx_element_type_e;

// verifies an output sends its funds to a given key index. Used
// for confirming the change output. Returns false if not valid.
bool verify_change_output(tx_output_t output, uint8_t index) {
    // bip32 path for 44'/280'/0'/0/key_index
    uint8_t hash[20];
    cx_ecfp_public_key_t public_key;
    cx_ecfp_private_key_t private_key;

    // get key pair for path 44'/280'/0'/0/index
    derive_keypair(&private_key, &public_key, NULL, 2, 0, index);
    compress_public_key(public_key.W);
    hash160(public_key.W, 33, hash);
    // erase sensitive data
    explicit_bzero(&private_key, sizeof(private_key));
    explicit_bzero(&public_key, sizeof(public_key));
    if (os_memcmp(hash, output.pubkey_hash, 20) != 0) {
        // not the same
        return false;
    }
    return true;
}

// tries to decode an element from the context's buffer
void _decode_next_element() {
    if (ctx->remaining_tokens > 0) {
        // read one token uid
        if (ctx->buffer_len < 32) {
            THROW(TX_STATE_PARTIAL);
        }
        // for now, we ignore it
        ctx->remaining_tokens--;
        ctx->buffer_len -= 32;
        ctx->elem_type = ELEM_TOKEN_UID;
        os_memmove(ctx->buffer, ctx->buffer + 32, ctx->buffer_len);
    } else if (ctx->remaining_inputs > 0) {
        // read input
        if (ctx->buffer_len < 35) {     // tx_id (32 bytes) + index (1 byte) + data_len (2 bytes)
            THROW(TX_STATE_PARTIAL);
        }
        // we require the input data to be empty because we're signing the whole
        // bytes we get from the wallet (in sighash_all, inputs must have no data)
        if (U2BE(ctx->buffer, 33) > 0) {
            THROW(TX_STATE_ERR);
        }
        // we ignore it
        ctx->remaining_inputs--;
        ctx->buffer_len -= 35;
        ctx->elem_type = ELEM_INPUT;
        os_memmove(ctx->buffer, ctx->buffer + 35, ctx->buffer_len);
    } else if (ctx->current_output < ctx->outputs_len) {
        uint8_t *buf = parse_output(ctx->buffer, ctx->buffer_len, &ctx->decoded_output);
        ctx->decoded_output.index = ctx->current_output;
        ctx->elem_type = ELEM_OUTPUT;
        ctx->buffer_len -= (buf - ctx->buffer);
        os_memmove(ctx->buffer, buf, ctx->buffer_len);
        ctx->current_output++;
    } else {
        // end of data we should read. Is there something left on the buffer?
        if (ctx->buffer_len > 0) {
            THROW(TX_STATE_ERR);
        }
        THROW(TX_STATE_FINISHED);
    }

    switch (ctx->elem_type) {
        case ELEM_TOKEN_UID:
            // not displaying token uid now
            break;
        case ELEM_INPUT:
            // not displaying inputs
            break;
        case ELEM_OUTPUT:
            // check if this is the change output
            if (ctx->has_change_output && ctx->change_output_index == ctx->decoded_output.index) {
                if (!verify_change_output(ctx->decoded_output, ctx->change_key_index)) {
                    THROW(TX_STATE_ERR);
                }
            } else {
                // if it's not change output, raise TX_STATE_READY to display output on screen
                THROW(TX_STATE_READY);
            }
            break;
    }
}

tx_decoder_state_e decode_next_element() {
    volatile tx_decoder_state_e result;
    BEGIN_TRY {
        TRY {
            // read until we reach a displayable element or the end of the buffer
            for (;;) {
                _decode_next_element();
            }
        }
        CATCH_OTHER(e) {
            result = e;
        }
        FINALLY {
        }
    }
    END_TRY;
    return result;
}

/*
 * Parses the change output info and returns its size. The first byte indicates
 * whether there's change or not (no change output if byte=0x00). There are 2
 * possible return values:
 *   . 1: if there's no change output, it's only 1 byte;
 *   . 6: if there is, it's [change_exists (1 byte) + output_index (1 byte) + key_index (4 bytes)]
 */
static uint8_t parse_change_output_info(uint8_t *in, size_t inlen) {
    uint8_t *buf = in;
    assert_length(1, inlen);
    // check output change. If next byte is greater than 0, there's a change output
    ctx->has_change_output = (*buf > 0 ? true : false);
    buf++;
    if (ctx->has_change_output) {
        assert_length(5, inlen - 1);
        ctx->change_output_index = *buf;
        buf++;
        ctx->change_key_index = U4BE(buf, 0);
        buf += 4;
    }
    return buf - in;
}

/*
 * Prepare the output information that will be displayed. We use 2 lines:
 *   Output 1/3
 *   HHVnn9mr8yPReovgt7AoeJRgS5QoXMa5fo HTR 12.00
 *
 * The second line is always scrollable, as it doesn't fit Ledger's display.
 * First line shows the current output index and total outputs, not considering
 * the change output. Indexes start at 1.
 */
static void prepare_display_output(tx_output_t output) {
    // first prepare the address + value line
    unsigned char address[25];
    pubkey_hash_to_address(output.pubkey_hash, address);
    uint8_t len = encode_base58(address, 25, ctx->info, sizeof(ctx->info));
    os_memmove(ctx->info + len, " HTR ", 5);
    format_value(output.value, ctx->info + len + 5);

    // line1
    uint8_t total_outputs = ctx->outputs_len;
    // fake_output_index is used to display consecutive indexes to the user when there's
    // change output. Also, output indexes start at 0, so add 1 to start on 1
    uint8_t fake_output_index = ctx->decoded_output.index + 1;
    if (ctx->has_change_output) {
        // change output is not shown to user
        // if there's change output, subtract one
        total_outputs = ctx->outputs_len - 1;
        if (ctx->decoded_output.index > ctx->change_output_index) {
            // outputs after the change output don't need to add 1
            fake_output_index = ctx->decoded_output.index;
        }
    }
    os_memmove(ctx->line1, "Output ", 7);
    itoa(fake_output_index, ctx->line1 + 7, 10);
    len = strlen(ctx->line1);
    ctx->line1[len++] = '/';
    itoa(total_outputs, ctx->line1 + len, 10);

    // line2
    os_memmove(ctx->line2, ctx->info + ctx->display_index, 12);
    ctx->line2[12] = '\0';
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

// Define the sign tx screen. User will be able to scroll through an output.
// (address + value) with left/right buttons. When he's done, he will click both
// buttons and see next output. A final confirmation screen appears before 
// sending tokens.
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
        // 0x01 is the left icon so return NULL if we're displaying the beginning of the text.
        return (ctx->display_index == 0) ? NULL : element;
    case 2:
        // 0x02 is the right, so return NULL if we're displaying the end of the text.
        return ctx->display_index == (strlen((const char*)ctx->info) - 12) ? NULL : element;
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
            if (ctx->display_index != 0) {
                ctx->display_index--;
                os_memmove(ctx->line2, ctx->info + ctx->display_index, 12);
                UX_REDISPLAY();
            }

            break;

        // scroll right by either clicking or pressing the right button
        case BUTTON_RIGHT:
        case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
            if (ctx->display_index != strlen((const char*)ctx->info) - 12) {
                ctx->display_index++;
                os_memmove(ctx->line2, ctx->info + ctx->display_index, 12);
                UX_REDISPLAY();
            }

            break;

        case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED TO NEXT OUTPUT
            ctx->display_index = 0;
            switch(decode_next_element()) {
                case TX_STATE_ERR:
                    io_exchange_with_code(SW_INVALID_PARAM, 0);
                    ui_idle();
                    break;
                case TX_STATE_PARTIAL:
                    // We don't have enough data to decode the next element; send an
                    // OK code to request more.
                    io_exchange_with_code(SW_OK, 0);
                    break;
                case TX_STATE_READY:
                    //display element
                    if (ctx->elem_type == ELEM_OUTPUT) {
                        prepare_display_output(ctx->decoded_output);
                    } else {
                        THROW(SW_INVALID_PARAM);
                    }

                    UX_REDISPLAY();
                    break;
                case TX_STATE_FINISHED:
                    // Go to confirmation screen
                    os_memmove(ctx->line1, "Send\0", 5);
                    os_memmove(ctx->line2, "transaction?\0", 13);
                    UX_DISPLAY(ui_sign_tx_confirm, ui_prepro_sign_tx_confirm);
                    break;
            }
    }
    return 0;
}

void handle_sign_tx(uint8_t p1, uint8_t p2, uint8_t *data_buffer, uint16_t data_length, volatile unsigned int *flags, volatile unsigned int *tx) {
    cx_ecfp_public_key_t public_key;
    cx_ecfp_private_key_t private_key;

    if (p1 == 2) {
        // all done, go back to main menu
        io_exchange_with_code(SW_OK, 0);
        ui_idle();
    }

    if (p1 == 1) {
        if (ctx->state != USER_APPROVED) {
            io_exchange_with_code(SW_DEVELOPER_ERR, 0);
            ui_idle();
            return;
        }

        // asking for signature
        uint32_t key_index = U4BE(data_buffer, 0);

        // get key pair for path 44'/280'/0'/0/key_index
        derive_keypair(&private_key, &public_key, NULL, 2, 0, key_index);

        if (ctx->sighash_all[0] == '\0') {
            // finish the first hash of the data
            cx_hash(&ctx->sha256.header, CX_LAST, ctx->sighash_all, 0, ctx->sighash_all, 32);
            // now get second sha256 of data
            cx_sha256_init(&ctx->sha256);
            cx_hash(&ctx->sha256.header, CX_LAST, ctx->sighash_all, 32, ctx->sighash_all, 32);
        }
        // sign message (sha256d of sighash_all data)
        int sig_size = cx_ecdsa_sign(&private_key, CX_LAST | CX_RND_RFC6979, CX_SHA256, ctx->sighash_all, 32, G_io_apdu_buffer, 256, NULL);

        // erase sensitive data
        explicit_bzero(&private_key, sizeof(private_key));
        explicit_bzero(&public_key, sizeof(public_key));

        io_exchange_with_code(SW_OK, sig_size);
    }

    if (p1 == 0) {
        // we're receiving transaction data
        if (ctx->state == USER_APPROVED) {
            // can't receive more data after user's approval
            io_exchange_with_code(SW_INVALID_PARAM, 0);
            ui_idle();
            return;
        }

        if (ctx->state == UNINITIALIZED) {
            // starting new tx; not initialized yet
            ctx->state = RECEIVING_DATA;
            ctx->buffer_len = 0;
            ctx->has_change_output = false;
            ctx->change_output_index = 0;
            ctx->change_key_index = 0;
            ctx->current_output = 0;
            ctx->display_index = 0;
            ctx->sighash_all[0] = '\0';
            cx_sha256_init(&ctx->sha256);

            // the first chunk of data has the change output info
            uint8_t offset = parse_change_output_info(data_buffer, data_length);

            // copy all remaining bytes to hash
            cx_hash(&ctx->sha256.header, 0, data_buffer + offset, data_length - offset, NULL, 0);

            // also get length of tokens, inputs and outputs
            assert_length(5, data_length - offset);    // version + remaining_tokens + remaining_inputs + outputs_len
            //transaction->version = U2BE(data_buffer, offset);
            offset += 2;
            ctx->remaining_tokens = data_buffer[offset];
            offset++;
            ctx->remaining_inputs = data_buffer[offset];
            offset++;
            ctx->outputs_len = data_buffer[offset];
            offset++;

            // copy remaining bytes to decode buffer
            ctx->buffer_len = data_length - offset;
            os_memcpy(ctx->buffer, data_buffer + offset, ctx->buffer_len);
        } else {
            // add it to the hash
            cx_hash(&ctx->sha256.header, 0, data_buffer, data_length, NULL, 0);

            // copy to decode buffer
            os_memcpy(ctx->buffer + ctx->buffer_len, data_buffer, data_length);
            ctx->buffer_len += data_length;
        }

        // at this point, ctx->buffer has bytes to be decoded
        switch(decode_next_element()) {
            case TX_STATE_ERR:
                io_exchange_with_code(SW_INVALID_PARAM, 0);
                ui_idle();
                break;
            case TX_STATE_PARTIAL:
                // We don't have enough data to decode the next element; send an
                // OK code to request more.
                THROW(SW_OK);
            case TX_STATE_READY:
                //display element
                prepare_display_output(ctx->decoded_output);
                UX_DISPLAY(ui_sign_tx_compare, ui_prepro_sign_tx_compare);
                *flags |= IO_ASYNCH_REPLY;
                return;
            case TX_STATE_FINISHED:
                // Go to confirmation screen
                os_memmove(ctx->line1, "Send\0", 5);
                os_memmove(ctx->line2, "transaction?\0", 13);
                UX_DISPLAY(ui_sign_tx_confirm, ui_prepro_sign_tx_confirm);
                *flags |= IO_ASYNCH_REPLY;
                return;
        }
    }
}
