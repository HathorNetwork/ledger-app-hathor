/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

typedef struct {
    // public key index for the address
    uint32_t keyIndex;
    // base-58 address
    uint8_t b58_address[34];
    // the starting index to be shown
    uint8_t displayIndex;
    // NULL-terminated string for display
    uint8_t partialAddress[13];
} getAddressContext_t;

// TODO not useful using union now but it will be when we add signTx command
// To save memory, we store all the context types in a single global union,
// taking advantage of the fact that only one command is executed at a time.
typedef union {
    getAddressContext_t getAddressContext;
    //calcTxnHashContext_t calcTxnHashContext;
} commandContext;
extern commandContext global;

// ux is a magic global variable implicitly referenced by the UX_ macros. Apps
// should never need to reference it directly.
extern ux_state_t ux;

// These are helper macros for defining UI elements. There are four basic UI
// elements: the background, which is a black rectangle that fills the whole
// screen; icons on the left and right sides of the screen, typically used for
// navigation or approval; and text, which can be anywhere. The UI_TEXT macro
// uses Open Sans Regular 11px, which I've found to be adequate for all text
// elements; if other fonts are desired, I suggest defining a separate macro
// for each of them (e.g. UI_TEXT_BOLD).
//
// In the event that you want to define your own UI elements from scratch,
// you'll want to read include/bagl.h and include/os_io_seproxyhal.h in the
// nanos-secure-sdk repo to learn what each of the fields are used for.
#define UI_BACKGROUND() {{BAGL_RECTANGLE,0,0,0,128,32,0,0,BAGL_FILL,0,0xFFFFFF,0,0},NULL,0,0,0,NULL,NULL,NULL}
#define UI_ICON_LEFT(userid, glyph) {{BAGL_ICON,userid,3,12,7,7,0,0,0,0xFFFFFF,0,0,glyph},NULL,0,0,0,NULL,NULL,NULL}
#define UI_ICON_RIGHT(userid, glyph) {{BAGL_ICON,userid,117,13,8,6,0,0,0,0xFFFFFF,0,0,glyph},NULL,0,0,0,NULL,NULL,NULL}
#define UI_TEXT(userid, x, y, w, text) {{BAGL_LABELINE,userid,x,y,w,12,0,0,0,0xFFFFFF,0,BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER,0},(char *)text,0,0,0,NULL,NULL,NULL}

// ui_idle displays the main menu screen. Command handlers should call ui_idle
// when they finish.
void ui_idle(void);

// io_exchange_with_code is a helper function for sending APDUs, primarily
// from button handlers. It appends code to G_io_apdu_buffer and calls
// io_exchange with the IO_RETURN_AFTER_TX flag. tx is the current offset
// within G_io_apdu_buffer (before the code is appended).
void io_exchange_with_code(uint16_t code, uint16_t tx);
