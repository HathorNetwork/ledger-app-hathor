/**
 * Copyright (c) Hathor Labs and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// exception codes
#define SW_DEVELOPER_ERR 0x6B00
#define SW_INVALID_PARAM 0x6B01
#define SW_IMPROPER_INIT 0x6B02
#define SW_USER_REJECTED 0x6985
#define SW_OK            0x9000

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
 * Get the private/public keys and chain code for the desired path.
 *
 * @param  [in] path
 *   The BIP-32 path.
 *
 * @param  [in] path_len
 *   Length of the path.
 *
 * @param [out] private_key
 *   The private key for the given path.
 *
 * @param [out] public_key
 *   The public key for the given path.
 *
 * @param [out] chain_code
 *   Chain code for this path.
 *
 */
void derive_keypair(
    uint32_t *path,
    unsigned int path_len,
    cx_ecfp_private_key_t *private_key,
    cx_ecfp_public_key_t *public_key,
    unsigned char *chain_code);

/**
 * Performs the hash160 (sha256 + ripemd160) of the data
 *
 * @param  [in] in
 *   Input data to be hashed
 *
 * @param  [in] inlen
 *   Length of input data.
 *
 * @param [out] out
 *   Hash160 of input data. Should have at least 20 bytes.
 *
 */
void hash160(unsigned char *in, unsigned short inlen, unsigned char *out);

/**
 * Performs the hash160 (sha256 + ripemd160) of the data
 *
 * @param [in/out] value
 *   The 65-byte uncompressed public key. The compression only needs
 *   to update the first byte and will modify the input, so the compressed
 *   public key will be in the first 33 bytes of the input.
 *
 */
void compress_public_key(unsigned char *value);
