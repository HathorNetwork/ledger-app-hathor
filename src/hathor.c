/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <os.h>
#include <cx.h>
#include "hathor.h"
#include "util.h"

// All keys that we derive start with path 44'/280'/0'
const uint32_t htr_bip44[] = { 44 | 0x80000000, 280 | 0x80000000, 0 | 0x80000000 };

void derive_keypair(
    uint32_t *path,
    unsigned int path_len,
    cx_ecfp_private_key_t *private_key,
    cx_ecfp_public_key_t *public_key,
    unsigned char *chain_code
) {
    unsigned char private_component[32];

    os_perso_derive_node_bip32(CX_CURVE_256K1, path, path_len, private_component, chain_code);
    cx_ecdsa_init_private_key(CX_CURVE_256K1, private_component, 32, private_key);
    cx_ecfp_generate_pair(CX_CURVE_256K1, public_key, private_key, 1);
}

void sha256d(unsigned char *in, size_t inlen, unsigned char *out) {
    cx_sha256_t hash;
    unsigned char buffer[32];

    cx_sha256_init(&hash);
    cx_hash(&hash.header, CX_LAST, in, inlen, buffer, 32);
    cx_sha256_init(&hash);
    cx_hash(&hash.header, CX_LAST, buffer, 32, out, 32);
}

void hash160(unsigned char *in, size_t inlen, unsigned char *out) {
    union {
        cx_sha256_t shasha;
        cx_ripemd160_t riprip;
    } u;
    unsigned char buffer[32];

    cx_sha256_init(&u.shasha);
    cx_hash(&u.shasha.header, CX_LAST, in, inlen, buffer, 32);
    cx_ripemd160_init(&u.riprip);
    cx_hash(&u.riprip.header, CX_LAST, buffer, 32, out, 20);
}

void compress_public_key(unsigned char *value) {
    value[0] = ((value[64] & 1) ? 0x03 : 0x02);
}

void pubkey_hash_to_address(uint8_t *hash, uint8_t *out) {
    unsigned char checksum_buffer[32];
    // prepend version
    out[0] = P2PKH_VERSION_BYTE;
    os_memmove(out+1, hash, 20);
    // sha256d of above and get first 4 bytes (checksum)
    sha256d(out, 21, checksum_buffer);
    os_memmove(out+21, checksum_buffer, 4);
}

void pubkey_to_address(cx_ecfp_public_key_t *public_key, uint8_t *out) {
    unsigned char hash_buffer[20];
    // get compressed pubkey
    compress_public_key(public_key->W);
    // get hash160
    hash160(public_key->W, 33, hash_buffer);
    pubkey_hash_to_address(hash_buffer, out);
}

void init_tx(transaction_t *tx) {
    tx->version = 0;
    tx->tokens_len = 0;
    tx->inputs_len = 0;
    tx->outputs_len = 0;
}

/*
void parse_input(uint8_t *buf, tx_input_t *input) {
    PRINTF("parse_input start buf %p\n", buf);
    os_memcpy(input->tx_id, buf, 32);
    (*buf) += 32;
    input->index = *buf;
    PRINTF("index: %u\n", *buf);
    (*buf)++;
    uint16_t data_len = U2BE(buf, 0);
    (*buf) += 2;
    // ignore input data
    (*buf) += data_len;
    PRINTF("parse_input end buf %p\n", buf);
}
*/

// return >0 if error, else return 0
uint8_t* parse_tx(uint8_t *in, size_t inlen, transaction_t *transaction) {
    // TODO always check for buffer overflow
    uint8_t *buf = in;
    transaction->version = U2BE(buf, 0);
    buf += 2;
    transaction->tokens_len = *buf;
    buf++;
    transaction->inputs_len = *buf;
    buf++;
    transaction->outputs_len = *buf;
    buf++;
    // TODO considering only hathors now, invalid with more tokens
    // skip reading tokens
    buf += 32*transaction->tokens_len;
    // read inputs
    for (int i = 0; i < transaction->inputs_len; i++) {
        //TODO refactor function
        //parse_input(buf, &(transaction->inputs[i]));
        os_memcpy(transaction->inputs[i].tx_id, buf, 32);
        buf += 32;
        transaction->inputs[i].index = *buf;
        buf++;
        uint16_t data_len = U2BE(buf, 0);
        buf += 2;
        // ignore input data
        buf += data_len;
    }

    for (int i = 0; i < transaction->outputs_len; i++) {
        //TODO refactor function
        transaction->outputs[i].value = U4BE(buf, 0);
        buf += 4;
        transaction->outputs[i].token_data = *buf;
        buf++;
        uint16_t script_len = U2BE(buf, 0);
        buf += 2;
        //TODO considering only p2pkh, without timelock
        os_memcpy(transaction->outputs[i].pubkey_hash, buf+3, 20);
        buf += script_len;
    }
    return buf;
}

void print_input(tx_input_t input, uint8_t index) {
    PRINTF("input %u: index %u\n", index, input.index);
}

void print_output(tx_output_t output, uint8_t index) {
    PRINTF("output %u: token_data %u, value %u\n", index, output.token_data, output.value);
}

void print_tx(transaction_t transaction) {
    PRINTF("\n\n-------- TRANSACTION --------\n");
    PRINTF("version: %u\n", transaction.version);
    PRINTF("tokens_len: %u\n", transaction.tokens_len);
    PRINTF("inputs_len: %u\n", transaction.inputs_len);
    PRINTF("outputs_len: %u\n", transaction.outputs_len);
    for (int i = 0; i < transaction.inputs_len; i++) {
        print_input(transaction.inputs[i], i);
    }
    for (int i = 0; i < transaction.outputs_len; i++) {
        print_output(transaction.outputs[i], i);
    }
    PRINTF("-----------------------------\n");
}

void format_value(int value, char *out) {
    // first deal with the part to the left of the decimal separator
    int tmp = value / 100;
    int c;
    char buf[20];
    char *p;

    itoa(tmp, buf, 10);
    c = 2 - strlen(buf) % 3;
    for (p = buf; *p != 0; p++) {
       *out++ = *p;
       if (c == 1) {
           *out++ = ',';
       }
       c = (c + 1) % 3;
    }
    *--out = 0;

    // now the part to the right
    tmp = value % 100;
    int len = strlen(out);
    out[len++] = '.';
    if (tmp < 10) {
        out[len++] = '0';
    }
    itoa(tmp, out + len, 10);
}
