/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <stdarg.h>
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
    cx_ecfp_private_key_t *private_key,
    cx_ecfp_public_key_t *public_key,
    unsigned char *chain_code,
    int n_args,
    ...
) {
    unsigned char private_component[32];
    va_list ap;
    int i;
    uint32_t path[3 + n_args];
    memcpy(path, htr_bip44, 3*sizeof(uint32_t));

    va_start(ap, n_args);
    for(i = 0; i < n_args; i++) {
        path[3 + i] = va_arg(ap, int);
    }
    va_end(ap);

    os_perso_derive_node_bip32(CX_CURVE_256K1, path, 3 + n_args, private_component, chain_code);
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

/**
 * Validates that a script has the format of P2PKH. Throws an exception if doesn't.
 * P2PKH scripts have the format:
 *   [OP_DUP, OP_HASH160, pubkey_hash_len, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
 * Considering that pubkey hashes have 20 bytes and the values of the opcodes:
 *   [0x76, 0xA9, 20, pubkey_hash, 0x88, 0xAC]
 */
void validate_p2pkh_script(uint8_t *in) {
    uint8_t p2pkh[] = {0x76, 0xA9, 20, 0x88, 0xAC};
    if (os_memcmp(p2pkh, in, 3) != 0 || os_memcmp(p2pkh + 3, in + 23, 2) !=0) {
        THROW(SW_INVALID_PARAM);
    }
}

/*
 * Parses the output as either a 4 or 8-byte unsigned integer.
 *
 * Returns the position in buffer after parsing the value.
 */
uint8_t* parse_output_value(uint8_t *in, size_t inlen, uint64_t *value) {
    uint8_t *buf = in;
    uint64_t tmp = 0;
    // if first bit is 1, it's 8 bytes long. Otherwise, it's 4
    bool flag = ((0x80 & in[0]) ? true : false);
    if (flag) {
        assert_length(11, inlen);    // value + token_data + script_len
        tmp = U8BE(in, 0);
        tmp = (-1)*tmp;
        buf += 8;
    } else {
        tmp = U4BE(in, 0);
        buf += 4;
    }
    os_memcpy(value, &tmp, 8);
    return buf;
}

/**
 * Parses a tx output from the input data. Returns a pointer to the end of parsed data.
 */
uint8_t* parse_output(uint8_t *in, size_t inlen, tx_output_t *output) {
    uint8_t *buf = in;
    assert_length(7, inlen);    // value + token_data + script_len
    buf = parse_output_value(buf, inlen, &output->value);
    output->token_data = *buf;
    buf++;
    uint16_t script_len = U2BE(buf, 0);
    buf += 2;
    assert_length(script_len, inlen - 7);
    //XXX considering only p2pkh, without timelock
    validate_p2pkh_script(buf);
    os_memcpy(output->pubkey_hash, buf+3, 20);
    buf += script_len;
    return buf;
}

void format_value(uint64_t value, unsigned char *out) {
    // first deal with the part to the left of the decimal separator
    uint64_t tmp = value / 100;
    int c;
    char buf[35];
    char *p;

    utoa(tmp, buf);
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
    c = strlen((const char*)out);
    out[c++] = '.';
    if (tmp < 10) {
        out[c++] = '0';
    }
    itoa(tmp, (char*)out + c, 10);
}

void assert_length(size_t smaller, size_t larger) {
    if (smaller > larger) {
        THROW(TX_STATE_PARTIAL);
    }
}
