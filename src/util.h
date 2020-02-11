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
 * Inverts a NULL-terminated string in place.
 *
 * @param [in/out] str
 *   The string to be inverted.
 *
 */
void strrev(char *str);

/**
 * Returns the string representation of a signed integer.
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

/**
 * Returns the string representation of an unsigned integer, in base 10. It's
 * preferable to use itoa instead of this function, unless you absolutely
 * have to.
 *
 * @param  [in] value
 *   Value to be converted, up to 64 bits.
 *
 * @param [out] result
 *   String representation of the value.
 *
 */
void utoa(uint64_t value, char *result);
