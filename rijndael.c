/*
 * D23124670 / Pavan Kumar Murugan
 * This file implements functions declared in the header file for encrypting and decrypting a single block
 * of data using the AES algorithm. The block and key sizes are both 128 bits. The implementation is inspired
 * by the Python AES algorithm implementation available at:
 * https://github.com/boppreh/aes.git
 * 
 */

#include <stdlib.h>
#include <string.h>

#include "rijndael.h"


// lookup table for the s-box
const unsigned char s_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
};

// inverse s-box
const unsigned char inv_s_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E,
    0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32,
    0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49,
    0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
    0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05,
    0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41,
    0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
    0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
    0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
    0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0C, 0x7D,
};

// lookup table for the r-con
const unsigned char r_con[32] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
    0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97,
    0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
};

/*
 * my_free Function
 *
 * This function deallocates the memory block previously allocated by the malloc function.
 * It is a wrapper for the standard library function free.
 *
 * Parameters:
 *   - pointer: Pointer to the memory block to be deallocated.
 *
 */
void my_free(unsigned char *pointer) { free(pointer); }

/*
 * InvertSubBytes Function
 *
 * This function implements the inverse SubBytes transformation in the AES decryption algorithm.
 * It substitutes each byte in the input block with a corresponding value from the inverse S-box lookup table.
 *
 * Parameters:
 *   - block: Pointer to the 128-bit block of data (16 bytes) on which the inverse SubBytes operation will be applied.
 *
 */
void invert_sub_bytes(unsigned char *block) {
  // Iterate through each byte in the block
  unsigned char *ptr = block;
  unsigned char *end = block + BLOCK_SIZE;
  for (; ptr < end; ptr++) {
    // Apply inverse substitution to each byte using the inverse S-box
    *ptr = inv_s_box[*ptr];
  }
}

/*
 * SubBytes Function
 *
 * This function implements the SubBytes transformation in the AES encryption algorithm.
 * It substitutes each byte in the input block with a corresponding value from the S-box lookup table.
 *
 * Parameters:
 *   - block: Pointer to the 128-bit block of data (16 bytes) on which the SubBytes operation will be applied.
 *
 */
void sub_bytes(unsigned char *block) {
  // Initialize a pointer to the start of the block
    unsigned char *ptr = block;
    // Calculate the end pointer of the block
    unsigned char *end = block + BLOCK_SIZE;

    // Iterate over each byte in the block
    while (ptr < end) {
        // Substitute the byte using the S-box lookup table
        *ptr = s_box[*ptr];
        // Move to the next byte in the block
        ptr++;
    }
}

/*
 * Shift Rows Function
 *
 * This function implements the ShiftRows transformation in the AES encryption algorithm.
 * It cyclically shifts the bytes in each row of the input block to the left.
 * The first row remains unchanged, the second row is shifted by one position to the left,
 * the third row is shifted by two positions to the left, and the fourth row is shifted by three positions to the left.
 *
 * Parameters:
 *   - block: Pointer to the 128-bit block of data (16 bytes) on which the ShiftRows operation will be applied.
 *
 */
void shift_rows(unsigned char *block) {
  unsigned char temp;

    // Shift the second row
    temp = block[1];
    block[1] = block[5];
    block[5] = block[9];
    block[9] = block[13];
    block[13] = temp;

    // Shift the third row
    temp = block[2];
    block[2] = block[10];
    block[10] = temp;
    temp = block[6];
    block[6] = block[14];
    block[14] = temp;

    // Shift the fourth row
    temp = block[15];
    block[15] = block[11];
    block[11] = block[7];
    block[7] = block[3];
    block[3] = temp;
}

/*
 * Loop Function
 *
 * This function implements the loop operation used in AES encryption, which involves left-shifting a byte by one bit
 * and performing an XOR operation with the polynomial 0x1b if the most significant bit of the byte is set.
 *
 * Parameters:
 *   - x: The byte value to which the loop operation will be applied.
 *
 * Returns:
 *   - The result of the loop operation on the input byte 'x'.
 *
 */
unsigned char loop(unsigned char x) {
  // Left shift x by 1 bit
    unsigned char result = x << 1;

    // If the most significant bit of x is set (i.e., x & 0x80 is non-zero)
    if (x & 0x80) {
        // XOR the result with the polynomial 0x1b
        result ^= 0x1b;
    }

    // Return the result after left shifting and XOR operation
    return result;
}

/*
 * Mix Single Column Function
 *
 * This function applies the MixSingleColumn operation in AES encryption to a given 4-byte word.
 * It performs the mixing operation on each byte of the word based on specific XOR and looped multiplication operations.
 *
 * Parameters:
 *   - word: A pointer to the 4-byte word to which the MixSingleColumn operation will be applied.
 *
 */
void mix_single_column(unsigned char *word) {
  // Store the original values of the word
    unsigned char t0 = word[0], t1 = word[1], t2 = word[2], t3 = word[3];
    unsigned char temp;

    // Calculate the value of 'temp' by XORing all bytes of the word
    temp = t0 ^ t1 ^ t2 ^ t3;

    // Mix the first byte of the word
    word[0] = t0 ^ temp ^ loop(t0 ^ t1);

    // Mix the second byte of the word
    word[1] = t1 ^ temp ^ loop(t1 ^ t2);

    // Mix the third byte of the word
    word[2] = t2 ^ temp ^ loop(t2 ^ t3);

    // Mix the fourth byte of the word
    word[3] = t3 ^ temp ^ loop(t3 ^ t0);
}

/*
 * Mix Columns Function
 *
 * This function applies the MixColumns operation in AES encryption to a given block of data.
 * Unlike the traditional MixColumns operation, where columns are mixed, this function mixes
 * rows by treating each 4-byte row as a column and applying the mix_single_column function.
 *
 * Parameters:
 *   - block: A pointer to the block of data to which the MixColumns operation will be applied.
 *
 */
void mix_columns(unsigned char *block) {
  unsigned char (*m)[4][4] = (unsigned char(*)[4][4])block;

  for (int i = 0; i < 4; i++) {
    // instead of mixing a column, we mix a row
    mix_single_column((unsigned char *)m[0][i]);
  }
}

/*
 * Invert Shift Rows Function
 *
 * This function performs the inverse ShiftRows operation in AES decryption for a given block of data.
 * The operation is applied row-wise to each 4-byte row of the block, with different shifting patterns
 * for each row to revert the effect of the original ShiftRows operation.
 *
 * Parameters:
 *   - block: A pointer to the block of data to which the inverse ShiftRows operation will be applied.
 *
 */
void invert_shift_rows(unsigned char *block) {
 unsigned char temp;

    // For the second row, perform a right shift by one position
    temp = block[13];
    block[13] = block[9];
    block[9] = block[5];
    block[5] = block[1];
    block[1] = temp;

    // For the third row, perform a right shift by two positions
    temp = block[2];
    block[2] = block[10];
    block[10] = temp;
    temp = block[6];
    block[6] = block[14];
    block[14] = temp;

    // For the fourth row, perform a right shift by three positions
    temp = block[3];
    block[3] = block[7];
    block[7] = block[11];
    block[11] = block[15];
    block[15] = temp;
}

/*
 * Invert Mix Columns Function
 *
 * This function performs the inverse MixColumns operation in AES decryption for a given block of data.
 * The operation is applied column-wise to each 4-byte column of the block, and the transformation
 * is done using pre-calculated values u and v.
 *
 * Parameters:
 *   - block: A pointer to the block of data to which the inverse MixColumns operation will be applied.
 *
 */
void invert_mix_columns(unsigned char *block) {
  unsigned char u, v;

  // Column 0
  // Calculate u and v values for the first column
  u = loop(loop(block[0] ^ block[2]));
  v = loop(loop(block[1] ^ block[3]));

  // Apply the mix column transformation to the first column
  block[0] ^= u;
  block[1] ^= v;
  block[2] ^= u;
  block[3] ^= v;

  // Column 1
  // Calculate u and v values for the second column
  u = loop(loop(block[4] ^ block[6]));
  v = loop(loop(block[5] ^ block[7]));

  // Apply the mix column transformation to the second column
  block[4] ^= u;
  block[5] ^= v;
  block[6] ^= u;
  block[7] ^= v;

  // Column 2
  // Calculate u and v values for the third column
  u = loop(loop(block[8] ^ block[10]));
  v = loop(loop(block[9] ^ block[11]));

  // Apply the mix column transformation to the third column
  block[8] ^= u;
  block[9] ^= v;
  block[10] ^= u;
  block[11] ^= v;

  // Column 3
  // Calculate u and v values for the fourth column
  u = loop(loop(block[12] ^ block[14]));
  v = loop(loop(block[13] ^ block[15]));

  // Apply the mix column transformation to the fourth column
  block[12] ^= u;
  block[13] ^= v;
  block[14] ^= u;
  block[15] ^= v;

  // After applying the mix column transformation to all columns,
  // perform the mix_columns operation on the entire block
  mix_columns(block);
}

/*
 * Add Round Key Function
 *
 * This function performs the AddRoundKey operation in AES encryption by XORing each byte in the block
 * with the corresponding byte in the round key.
 *
 * Parameters:
 *   - block: A pointer to the block of data to which the round key will be added.
 *   - round_key: A pointer to the round key data.
 *
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  // Iterate over each byte in the block and perform XOR operation with the corresponding byte in the round key
    for (int i = 0; i < 16; i++) {
        block[i] ^= round_key[i]; // XOR operation between the byte in the block and the byte in the round key
    }
}

/*
 * Key Expansion Function
 *
 * This function expands the given cipher key to generate the round keys used in AES encryption.
 * It allocates memory for the expanded key, copies the original cipher key to the first block,
 * and iterates over each round to generate subsequent round keys. For each round, it performs
 * key schedule operations, including rotation, byte substitution, XOR operations with the previous
 * round key, and XOR with round constants.
 *
 * Parameters:
 *   - cipher_key: A pointer to the original cipher key.
 *
 * Returns:
 *   - A pointer to the expanded key if memory allocation is successful, or NULL if memory allocation fails.
 *
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  // Allocate memory for the expanded key
    unsigned char *output = (unsigned char *)malloc(BLOCK_SIZE * (ROUNDS + 1));
    if (output == NULL) {
        return NULL; // Return NULL if memory allocation fails
    }

    // Copy the original cipher key to the first block of the output
    memcpy(output, cipher_key, BLOCK_SIZE);

    // Iterate over each round to generate round keys
    for (int round = 1; round < ROUNDS + 1; round++) {
        // Calculate pointers to the new key and the last key
        unsigned char *new_key = &output[round * BLOCK_SIZE];
        unsigned char *last_key = &output[(round - 1) * BLOCK_SIZE];

        memcpy(new_key, &last_key[BLOCK_SIZE - WORD_SIZE], WORD_SIZE);

        // Rotate the last word of the previous round key
        unsigned char temp = new_key[0];
        new_key[0] = new_key[1];
        new_key[1] = new_key[2];
        new_key[2] = new_key[3];
        new_key[3] = temp;

        // Substitute bytes of the new key using the S-box
        for (int i = 0; i < WORD_SIZE; i++) {
            new_key[i] = s_box[new_key[i]];
        }

        // XOR the first word of the new key with the last word of the previous round key
        for (int i = 0; i < WORD_SIZE; i++) {
            new_key[i] ^= last_key[i];
        }

        // XOR the first byte of the new key with the round constant
        new_key[0] ^= r_con[round];

        // Generate the rest of the words of the new key using XOR operations
        for (int j = 1; j < 4; j++) {
            for (int k = 0; k < WORD_SIZE; k++) {
                new_key[j * WORD_SIZE + k] = new_key[(j - 1) * WORD_SIZE + k] ^ last_key[j * WORD_SIZE + k];
            }
        }
    }

    return output; // Return the expanded key
}

/*
 * AES Encryption Function
 *
 * This function encrypts a single block of data using the AES algorithm with a 128-bit block size and a 128-bit key.
 * It performs the encryption process, including key expansion, round operations, and finalization, to produce the ciphertext block.
 *
 * Parameters:
 *   - plaintext: A pointer to the plaintext block to be encrypted.
 *   - key: A pointer to the encryption key.
 *
 * Returns:
 *   - A pointer to the encrypted ciphertext block if successful, or NULL if the block size or number of rounds is incorrect,
 *     or if memory allocation fails for round keys or the output block.
 *
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
    // Check if the block size is 128 bits and the number of rounds is 10
    if (BLOCK_SIZE != 16 || ROUNDS != 10) {
        return NULL; // Return NULL if the block size or the number of rounds is incorrect
    }

    // Expand the key to generate the round keys
    unsigned char *roundkeys = expand_key(key);
    if (roundkeys == NULL) {
        return NULL; // Return NULL if memory allocation for round keys fails
    }

    // Allocate memory for the output block
    unsigned char *output = (unsigned char *)malloc(BLOCK_SIZE);
    if (output == NULL) {
        free(roundkeys);
        return NULL; // Return NULL if memory allocation for output block fails
    }

    // Copy the plaintext block to the output
    memcpy(output, plaintext, BLOCK_SIZE);

    // Initial round: Add round key
    add_round_key(output, roundkeys);

    // Main rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey
    for (int round = 1; round < ROUNDS; round++) {
        sub_bytes(output); // Substitute bytes using S-box
        shift_rows(output); // Shift rows operation
        mix_columns(output); // Mix columns operation
        add_round_key(output, &roundkeys[round * BLOCK_SIZE]); // Add round key
    }

    // Final round: SubBytes, ShiftRows, AddRoundKey
    sub_bytes(output); // Substitute bytes using S-box
    shift_rows(output); // Shift rows operation
    add_round_key(output, &roundkeys[ROUNDS * BLOCK_SIZE]); // Add the last round key

    // Free the memory allocated for the expanded key
    free(roundkeys);

    // Return the encrypted block
    return output;
}

/*
 * AES Decryption Function
 *
 * This function decrypts a single block of data using the AES algorithm with a 128-bit block size and a 128-bit key.
 * It reverses the steps performed during encryption to obtain the original plaintext block from the given ciphertext block.
 *
 * Parameters:
 *   - ciphertext: A pointer to the ciphertext block to be decrypted.
 *   - key: A pointer to the encryption key.
 *
 * Returns:
 *   - A pointer to the decrypted plaintext block if successful, or NULL if the block size or number of rounds is incorrect.
 *
 */
unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  // Check if the block size is 128 bits and the number of rounds is 10
  if (BLOCK_SIZE != 16 || ROUNDS != 10) {
    return NULL; // Return NULL if the block size or the number of rounds is incorrect
  }

  // Expand the key to generate the round keys
  unsigned char *roundkeys = expand_key(key);

  // Allocate memory for the output block
  unsigned char *output = (unsigned char *)malloc(BLOCK_SIZE);

  // Copy the ciphertext block to the output
  memcpy(output, ciphertext, BLOCK_SIZE);

  // Final round: Add round key, InvertShiftRows, InvertSubBytes
  add_round_key(output, &roundkeys[ROUNDS * BLOCK_SIZE]); // Add the last round key
  invert_shift_rows(output); // Reverse the shift rows operation
  invert_sub_bytes(output); // Reverse the sub bytes operation

  // Main rounds in reverse order: InvertMixColumns, InvertShiftRows, InvertSubBytes, AddRoundKey
  for (int round = 9; round > 0; round--) {
    add_round_key(output, roundkeys + (BLOCK_SIZE * round)); // Add the round key
    invert_mix_columns(output); // Reverse the mix columns operation
    invert_shift_rows(output); // Reverse the shift rows operation
    invert_sub_bytes(output); // Reverse the sub bytes operation
  }

  // Initial round: Add round key
  add_round_key(output, roundkeys); // Add the first round key

  // Free the memory allocated for the expanded key
  free(roundkeys);

  // Return the decrypted block
  return output;
}