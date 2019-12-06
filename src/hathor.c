/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdbool.h>
#include <stdint.h>
#include <os.h>
#include <cx.h>
#include "hathor.h"

#define B58_MAX_INPUT_SIZE 120

// All keys that we derive start with path 44'/280'/0'
const uint32_t htr_bip44[] = { 44 | 0x80000000, 280 | 0x80000000, 0 | 0x80000000 };

unsigned char const BASE58ALPHABET[] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
    'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

void bin2hex(uint8_t *dst, uint8_t *data, uint64_t inlen) {
    static uint8_t const hex[] = "0123456789abcdef";
    for (uint64_t i = 0; i < inlen; i++) {
        dst[2*i+0] = hex[(data[i]>>4) & 0x0F];
        dst[2*i+1] = hex[(data[i]>>0) & 0x0F];
    }
    dst[2*inlen] = '\0';
}

int bin2dec(uint8_t *dst, uint64_t n) {
    if (n == 0) {
        dst[0] = '0';
        dst[1] = '\0';
        return 1;
    }
    // determine final length
    int len = 0;
    for (uint64_t nn = n; nn != 0; nn /= 10) {
        len++;
    }
    // write digits in big-endian order
    for (int i = len-1; i >= 0; i--) {
        dst[i] = (n % 10) + '0';
        n /= 10;
    }
    dst[len] = '\0';
    return len;
}

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

int encode_base58(const unsigned char *in, size_t inlen, unsigned char *out, size_t outlen) {
    unsigned char buffer[B58_MAX_INPUT_SIZE * 138 / 100 + 1] = {0};
    size_t i = 0, j;
    size_t startAt, stopAt;
    size_t zeroCount = 0;
    size_t outputSize;

    if (inlen > B58_MAX_INPUT_SIZE) {
        return -1;
    }

    while ((zeroCount < inlen) && (in[zeroCount] == 0)) {
        ++zeroCount;
    }

    outputSize = (inlen - zeroCount) * 138 / 100 + 1;
    stopAt = outputSize - 1;
    for (startAt = zeroCount; startAt < inlen; startAt++) {
        int carry = in[startAt];
        for (j = outputSize - 1; (int)j >= 0; j--) {
            carry += 256 * buffer[j];
            buffer[j] = carry % 58;
            carry /= 58;

            if (j <= stopAt - 1 && carry == 0) {
                break;
            }
        }
        stopAt = j;
    }

    j = 0;
    while (j < outputSize && buffer[j] == 0) {
        j += 1;
    }

    if (outlen < zeroCount + outputSize - j) {
        return -1;
    }

    os_memset(out, BASE58ALPHABET[0], zeroCount);

    i = zeroCount;
    while (j < outputSize) {
        out[i++] = BASE58ALPHABET[buffer[j++]];
    }
    return i;
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
