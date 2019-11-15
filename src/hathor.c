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

void hash160(unsigned char *in, unsigned short inlen, unsigned char *out) {
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
