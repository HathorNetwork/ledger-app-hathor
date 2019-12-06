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
 * All keys that we derive start with path 44'/280'/0'.
 *
 * 280 is Hathor's BIP44 code: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
 */
extern const uint32_t htr_bip44[3];

typedef struct {
    uint8_t tx_id[32];
    uint8_t index;
} tx_input_t;

// TODO only p2pkh and HTR for now
// TODO add timelock
typedef struct {
    uint32_t value;     //TODO support 64-bit values
    // hash160 of public key
    uint8_t token_data;
    uint8_t pubkey_hash[20];
    //uint16_t script_len;
    //uint8_t script[100];
} tx_output_t;

typedef struct {
    uint16_t version;
    uint8_t tokens_len;
    //uint32_t tokens[5];
    uint8_t inputs_len;
    tx_input_t inputs[10];
    uint8_t outputs_len;
    tx_output_t outputs[10];
} transaction_t;

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
 * Performs the sha256d (double sha256) of the data.
 *
 * @param  [in] in
 *   Input data to be hashed.
 *
 * @param  [in] inlen
 *   Length of input data.
 *
 * @param [out] out
 *   sha256d of input data. Should have at least 32 bytes.
 *
 */
void sha256d(unsigned char *in, size_t inlen, unsigned char *out);

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
 *   hash160 of input data. Should have at least 20 bytes.
 *
 */
void hash160(unsigned char *in, size_t inlen, unsigned char *out);

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
 * Derives the address (as bytes, not base58) from a public key hash.
 *
 * @param  [in] public_key_hash
 *   The public key hash.
 *
 * @param [out] out
 *   Address for the given public key.
 *
 */
void pubkey_hash_to_address(uint8_t *public_key_hash, uint8_t *out);

/**
 * Derives the address (as bytes, not base58) from a public key.
 *
 * @param  [in] public_key
 *   The public key.
 *
 * @param [out] out
 *   Address for the given public key.
 *
 */
void pubkey_to_address(cx_ecfp_public_key_t *public_key, uint8_t *out);

//TODO docstrings
void init_tx(transaction_t *transaction);

uint8_t* parse_tx(uint8_t *in, size_t inlen, transaction_t *transaction);

void print_input(tx_input_t input, uint8_t index);

void print_tx(transaction_t transaction);
