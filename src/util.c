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

#define B58_MAX_INPUT_SIZE 120

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

int encode_base58(const unsigned char *in, size_t inlen, char *out, size_t outlen) {
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

void strrev(char *str) {
    char *p1, *p2;

    if (! str || ! *str) return str;
    for (p1 = str, p2 = str + strlen(str) - 1; p2 > p1; ++p1, --p2) {
        *p1 ^= *p2;
        *p2 ^= *p1;
        *p1 ^= *p2;
    }
}

void itoa(int value, char* result, int base) {
    // check that the base if valid
    if (base < 2 || base > 36) { *result = '\0'; }

    char* ptr = result, *ptr1 = result, tmp_char;
    int tmp_value;

    do {
        tmp_value = value;
        value /= base;
        *ptr++ = "zyxwvutsrqponmlkjihgfedcba9876543210123456789abcdefghijklmnopqrstuvwxyz" [35 + (tmp_value - value * base)];
    } while ( value );

    // Apply negative sign
    if (tmp_value < 0) *ptr++ = '-';
    *ptr-- = '\0';
    while(ptr1 < ptr) {
        tmp_char = *ptr;
        *ptr--= *ptr1;
        *ptr1++ = tmp_char;
    }
}

void utoa(uint64_t value, char *s) {
    uint64_t tmp = value;
    uint8_t idx = 0;
    while (tmp > 0) {
        s[idx] = (tmp % 10) + '0';
        tmp = tmp / 10;
        idx++;
    }
    s[idx] = '\0';
    strrev(s);
}
