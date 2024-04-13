/*
 * D23124670 / Pavan Kumar Murugan
 *
 * This file declares the function prototypes for the primary encryption
 * and decryption operations. Additionally, it defines macros to enhance
 * code readability and eliminate magic numbers.
 *
 */
#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16
#define WORD_SIZE 4
#define ROUNDS 10

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif
