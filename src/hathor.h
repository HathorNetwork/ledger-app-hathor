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

// opcodes
#define OP_DUP          0x76
#define OP_EQUALVERIFY  0x88
#define OP_HASH160      0xA9
#define OP_CHECKSIG     0xAC


/**
 * All keys that we derive start with path 44'/280'/0'.
 *
 * 280 is Hathor's BIP44 code: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
 */
extern const uint32_t htr_bip44[3];

// TODO only p2pkh and HTR for now
// TODO add timelock
typedef struct {
    uint8_t index;      // the index of this output in the tx
    uint64_t value;
    // hash160 of public key
    uint8_t token_data;
    uint8_t pubkey_hash[20];
} tx_output_t;

// indicates a transaction decoder status
typedef enum {
    TX_STATE_ERR = 1,           // invalid transaction (NOTE: it's illegal to THROW(0))
    TX_STATE_PARTIAL = 2,       // no elements have been fully decoded yet
    TX_STATE_READY = 3,         // at least one element is fully decoded
    TX_STATE_FINISHED = 4,      // reached end of transaction
} tx_decoder_state_e;

/**
 * Get the private/public keys and chain code for the desired path. This
 * function accepts a variable number of arguments and always derives paths
 * starting on 44'/280'/0'. So if there are 2 variable arguments (0 and 5),
 * the derived path will be 44'/280'/0'/0/5
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
 * @param  [in] n_args
 *   Number of variable arguments.
 *
 * @param  [in] ...
 *   The indexes for deriving the keypair.
 *
 */
void derive_keypair(
    cx_ecfp_private_key_t *private_key,
    cx_ecfp_public_key_t *public_key,
    unsigned char *chain_code,
    int n_args,
    ...);

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
 * Parses an output from bytes.
 *
 * @param  [in] in
 *   Data to be parsed.
 *
 * @param  [in] inlen
 *   Size of data to be parsed.
 *
 * @param [out] output
 *   Holds the decoded output.
 *
 */
uint8_t* parse_output(uint8_t *in, size_t inlen, tx_output_t *output);

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
