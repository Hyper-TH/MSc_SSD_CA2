/*
 * C20361521 - Twila Habab
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rijndael.h"
#include "substitution.h"

size_t block_size_to_bytes(aes_block_size_t block_size) {
  switch (block_size) {
  case AES_BLOCK_128:
    return 16;
  case AES_BLOCK_256:
    return 32;
  case AES_BLOCK_512:
    return 64;
  default:
    fprintf(stderr, "Invalid block size %d\n", block_size);
    exit(1);
  }
}

unsigned char block_access(unsigned char *block, size_t row, size_t col, aes_block_size_t block_size) {
  int row_len;
  switch (block_size) {
    case AES_BLOCK_128:
      row_len = 4;
      break;
    case AES_BLOCK_256:
      row_len = 8;
      break;
    case AES_BLOCK_512:
      row_len = 16;
      break;
    default:
      fprintf(stderr, "Invalid block size for block_access: %d\n", block_size);
      exit(1);
  }

  return block[(row * row_len) + col];
}

char *message(char n) {
  char *output = (char *)malloc(7);
  strcpy(output, "hello");
  output[5] = n;
  output[6] = 0;
  return output;
}

/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {

      // GEMINI RESPONSE
      // Need to calculate the 1D index for the 4x4 grid
      int index = (i * 4) + j

      block[index] = s_box[block[index]]
    }
  }
}

void shift_rows(unsigned char *block, aes_block_size_t block_size) {
    for (i = 0; i < 4; i++) {
      for (j = 0; j < 4; j++) {
        int index = (i * 4) + j
        block[index] = inv_s_box[block[index]]
      }
  }
}

// xtime in C
unsigned char xtime(unsigned char a) {
  return (a & 0x80) ? ((a << 1) ^ 0x1B) : (a << 1);
}

void mix_columns(unsigned char *block, aes_block_size_t block_size) {
  unsigned char t = block[0] ^ block[1] ^ block[2] ^ block[3];
  unsigned char u = a[0];

  block[0] ^= t ^ xtime(block[0] ^ a[1]);
  block[1] ^= t ^ xtime(block[1] ^ a[2]);
  block[2] ^= t ^ xtime(block[2] ^ a[3]);
  block[3] ^= t ^ xtime(block[3] ^ u);
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  // TODO: Implement me!
    for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {

      int index = (i * 4) + j

      block[index] = inv_s_box[block[index]]
    }
  }
}

void invert_shift_rows(unsigned char *block, aes_block_size_t block_size) {
  // TODO: Implement me!
}

void invert_mix_columns(unsigned char *block, aes_block_size_t block_size) {
  // TODO: Implement me!
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, 
                   unsigned char *round_key,
                   aes_block_size_t block_size) {
  // TODO: Implement me!
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key, aes_block_size_t block_size) {
  // TODO: Implement me!
  return 0;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * block_size_to_bytes(block_size));
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * block_size_to_bytes(block_size));
  return output;
}
