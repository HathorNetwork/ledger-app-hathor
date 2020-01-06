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
// We make `| 0x80000000` for hardened keys
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

void pubkey_to_address(cx_ecfp_public_key_t *public_key, uint8_t *out) {
    unsigned char checksumBuffer[32];
    // get compressed pubkey
    compress_public_key(public_key->W);
    // get hash160
    hash160(public_key->W, 33, out+1);
    // prepend version
    out[0] = P2PKH_VERSION_BYTE;
    // sha256d of above and get first 4 bytes (checksum)
    sha256d(out, 21, checksumBuffer);
    os_memmove(out+21, checksumBuffer, 4);
}
