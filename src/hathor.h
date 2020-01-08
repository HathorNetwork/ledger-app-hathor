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
    uint64_t value;
    // hash160 of public key
    uint8_t token_data;
    uint8_t pubkey_hash[20];
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

/**
 * Inititalizes a transaction struct, which basically sets some of its
 * values to 0.
 *
 * @param [out] transaction
 *   transaction struct to be initialized.
 *
 */
void init_tx(transaction_t *transaction);

/*
 * Assemble a transaction object from a sequence of bytes.
 *
 * @param  [in] in
 *   Input data.
 *
 * @param  [in] inlen
 *   Length of the input data.
 *
 * @param [out] transaction
 *   Transaction object with the information parsed from the data.
 *
 */
uint8_t* parse_tx(uint8_t *in, size_t inlen, transaction_t *transaction);

//TODO docstring
uint8_t* parse_output(uint8_t *in, size_t inlen, tx_output_t *output);

/**
 * Print basic information about a transaction. Used for debugging.
 *
 * @param  [in] transaction
 *   Transaction to be displayed.
 *
 */
void print_tx(transaction_t transaction);

/**
 * Returns the NULL-terminated string representation of an integer value,
 * with 2 decimal places and comma separator. Eg:
 *   1000 -> "10.00"
 *   5000000 -> "50,000.00"
 *
 * @param  [in] value
 *   Value to be converted.
 *
 * @param [out] out
 *   String representation of the value.
 *
 */
void format_value(uint64_t value, unsigned char *out);

/**
 * Raises an exception in case the expected size is not smaller
 * than the other.
 *
 * @param  [in] smaller
 *   Value supposed to be smaller.
 *
 * @param  [in] larger
 *   Value supposed to be larger.
 *
 */
void assert_length(size_t smaller, size_t larger);
