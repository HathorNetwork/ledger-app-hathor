/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// macros for converting raw bytes to uint64_t
#define U8BE(buf, off) (((uint64_t)(U4BE(buf, off))     << 32) | ((uint64_t)(U4BE(buf, off + 4)) & 0xFFFFFFFF))
#define U8LE(buf, off) (((uint64_t)(U4LE(buf, off + 4)) << 32) | ((uint64_t)(U4LE(buf, off))     & 0xFFFFFFFF))

/**
 * Converts a binary to hexadecimal string and appends a final NULL byte.
 *
 * @param  [in] data
 *   The binary data.
 *
 * @param  [in] inlen
 *   Length of input data.
 *
 * @param [out] dst
 *   Array to store the string.
 *
 */
void bin2hex(uint8_t *dst, uint8_t *data, uint64_t inlen);

/**
 * Converts an unsigned integer to a decimal string and appends a final NULL
 * byte. It returns the length of the string.
 *
 * @param  [in] n
 *   Unsigned integer to be converted.
 *
 * @param [out] dst
 *   Array to store the string.
 *
 * @return length of destination string
 */
int bin2dec(uint8_t *dst, uint64_t n);

/**
 * Encodes in base58.
 *
 * @param  [in] in
 *   Input data to be encoded.
 *
 * @param  [in] inlen
 *   Length of input data.
 *
 * @param [out] out
 *   Base58 of input data
 *
 * @param [in] outlen
 *   Size of the output buffer. If it's not enough to hold the encoded
 *   data, will return error (-1).
 *
 * @return the length of the base58 encoded data or -1 if there's an error
 */
int encode_base58(const unsigned char *in, size_t inlen, unsigned char *out, size_t outlen);

/**
 * Returns the string representation of a integer.
 *
 * @param  [in] value
 *   Value to be converted.
 *
 * @param [out] result
 *   String representation of the value.
 *
 * @param  [in] base
 *   Base to use when converting.
 *
 */
void itoa(int value, char *result, int base);
