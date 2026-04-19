/*
 * C20361521 - Twila Habab
 * This file implements the core AES-128 (Rijndael) block cipher operations,
 * including key expansion, encryption, and decryption for 128-bit blocks.
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

// STEP 1 - SUB-BYTES
/*
* Sub bytes uses S-BOX for substitution table
* The position of the byte in the current state is used
* as the index from the S-BOX to get the new value of the byte
*/ 
void sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      block[i + (j * 4)] = s_box[block[i + (j * 4)]]; // LLM-Assisted for calcuation of the index
      // block[i + (j * 4)] = s_box[block[i + (j * 3)]]; // for testing purposes
    }
  }
}

// STEP 2 - SHIFT ROWS
// Each row (bar the first [0]) is shifted/rotated to the left
// by a certain number of bytes (1 for row 1, 2 for row 2, 3 for row 3)
void shift_rows(unsigned char *block, aes_block_size_t block_size) {
  unsigned char temp;
  /*
  * [0] [4] [8] [12] 
  * [1] [5] [9] [13]
  * [2] [6] [10] [14]
  * [3] [7] [11] [15]
  */

  // Row 0: No shift

  // Row 1: Shift left by 1 (Indices: 1, 5, 9, 13)
  temp = block[1];
  block[1]  = block[5];
  block[5]  = block[9];
  block[9]  = block[13];
  block[13] = temp;

  // Row 2: Shift left by 2 (Indices: 2, 6, 10, 14)
  temp = block[2];
  block[2]  = block[10];
  block[10] = temp;
  temp = block[6];
  block[6]  = block[14];
  block[14] = temp;

  // Row 3: Shift left by 3 (Indices: 3, 7, 11, 15)
  temp = block[15];
  block[15] = block[11]; 
  // block[15] = block[7]; // for testing purposes
  block[11] = block[7];
  block[7]  = block[3];
  block[3]  = temp;
}

/*
 * xtime: Multiplication by {02} in the Galois Field GF(2^8).
 * This is implemented as a left shift followed by a conditional XOR with 0x1B 
 * if the most significant bit was set (to keep the result within the field).
 */
// LLM-ASSISTED IMPLEMENTATION
unsigned char xtime(unsigned char a) {
  return (a & 0x80) ? ((a << 1) ^ 0x1B) : (a << 1);
}

// STEP 3 - MIX COLUMNS
/*
* Each column is treated as a polynomial and multiplied by a fixed polynomial.
*/
// LLM-ASSISTED IMPLEMENTATION
void mix_columns(unsigned char *block, aes_block_size_t block_size) {
  for (int i = 0; i < 4; i++) {
    unsigned char *column = block + (i * 4);
    unsigned char t = column[0] ^ column[1] ^ column[2] ^ column[3];
    unsigned char u = column[0];

    column[0] ^= t ^ xtime(column[0] ^ column[1]);
    // column[0] ^= t ^ xtime(column[0] ^ column[2]); // for testing purposes
    column[1] ^= t ^ xtime(column[1] ^ column[2]);
    column[2] ^= t ^ xtime(column[2] ^ column[3]);
    column[3] ^= t ^ xtime(column[3] ^ u);
  }
}


// OPERATION FOR DECRYPTIONS
/*
 * invert_sub_bytes: Undoes the S-box substitution using the inverse S-box.
 */
void invert_sub_bytes(unsigned char *block, aes_block_size_t block_size) {
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        block[i + (j * 4)] = inv_s_box[block[i + (j * 4)]];
        // block[i + (j * 4)] = inv_s_box[block[i + (j * 3)]]; // for testing purposes
    }
  }
}

/*
 * invert_shift_rows: Undoes the shift rows operation.
 */
void invert_shift_rows(unsigned char *block, aes_block_size_t block_size) {
  unsigned char temp;
  /*
  * [0] [4] [8] [12] 
  * [1] [5] [9] [13]
  * [2] [6] [10] [14]
  * [3] [7] [11] [15]
  */

  // Row 1: Shift right by 1
  temp = block[13];
  block[13] = block[9];
  block[9]  = block[5];
  block[5]  = block[1];
  block[1]  = temp;

  // Row 2: Shift right by 2
  temp = block[2];
  block[2]  = block[10];
  block[10] = temp;
  temp = block[6];
  block[6]  = block[14];
  block[14] = temp;

  // Row 3: Shift right by 3 (same as shift left by 1)
  temp = block[3];
  block[3]  = block[7];
  block[7]  = block[11];
  block[11] = block[15];
  block[15] = temp;
}

/*
 * invert_mix_columns: Undoes the mix columns operation.
 */
// LLM-ASSISTED IMPLEMENTATION
void invert_mix_columns(unsigned char *block, aes_block_size_t block_size) {
  for (int i = 0; i < 4; i++) {
    unsigned char *column = block + (i * 4);
    unsigned char u = xtime(xtime(column[0] ^ column[2]));
    unsigned char v = xtime(xtime(column[1] ^ column[3]));
    column[0] ^= u; column[1] ^= v; column[2] ^= u; column[3] ^= v;

    // column[0] ^= u; column[1] ^= v; column[2] ^= u; column[2] ^= v; // for testing purposes
  }
  mix_columns(block, block_size);
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, 
                   unsigned char *round_key,
                   aes_block_size_t block_size) {
  for (int i = 0; i < block_size_to_bytes(block_size); i++) {
    block[i] ^= round_key[i];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key, aes_block_size_t block_size) {
  unsigned char *expanded_key = (unsigned char *)malloc(176);
  memcpy(expanded_key, cipher_key, 16);   // First round key is the cipher key

  int bytes_generated = 16;
  int rcon_iteration = 1;
  unsigned char temp[4];

  while (bytes_generated < 176) {
    // Read the last 4 bytes of current key into temp
    memcpy(temp, expanded_key + bytes_generated - 4, 4);

    // If this is the start of a new round key
    if (bytes_generated % 16 == 0) {
      // ROTWORD: Rotate each byte to the left
      unsigned char t = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      // temp[2] = temp[1]; // for testing purposes
      temp[3] = t;

      // SUBWORD: Apply the S-Box
      temp[0] = s_box[temp[0]];
      temp[1] = s_box[temp[1]];
      temp[2] = s_box[temp[2]];
      temp[3] = s_box[temp[3]];

      // RCON: XOR the first byte with the round constant
      temp[0] ^= r_con[rcon_iteration];
      rcon_iteration++;
    }

    // Generate the next 4 bytes by XORing temp with the word 16 bytes back
    for (int i = 0; i < 4; i++) {
      expanded_key[bytes_generated] = expanded_key[bytes_generated - 16] ^ temp[i];
      bytes_generated++;
    }
  }
  return expanded_key;
}


/*
 * The implementations of the functions declared in the
 * header file should go here
 */
// GLUE CODE
unsigned char *aes_encrypt_block(unsigned char *plaintext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
  size_t size = block_size_to_bytes(block_size);
  unsigned char *output = (unsigned char *)malloc(size);
  memcpy(output, plaintext, size);

  // 1. Get Round Keys
  unsigned char *round_keys = expand_key(key, block_size);
  
  // 2. Initial AddRoundKey
  add_round_key(output, round_keys, block_size);

  // 3. The 9 rounds of Substitution and Permutations
  for (int round = 1; round <= 9; round++) {
    sub_bytes(output, block_size);
    shift_rows(output, block_size);
    mix_columns(output, block_size);
    add_round_key(output, round_keys + (round * 16), block_size);
  }
  
  // 4. Final Round (No MixColumns Operation)
  sub_bytes(output, block_size);
  shift_rows(output, block_size);
  add_round_key(output, round_keys + (10 * 16), block_size);

  // Free the buffer
  free(round_keys);

  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
  size_t size = block_size_to_bytes(block_size);
  unsigned char *output = (unsigned char *)malloc(size);
  memcpy(output, ciphertext, size);

  unsigned char *round_keys = expand_key(key, block_size);

  // 1. Initial AddRoundKey (K10)
  add_round_key(output, round_keys + 160, block_size);

  // 2. The 9 rounds of Inverse Substitution and Permutations
  for (int round = 9; round >= 1; round--) {
    invert_shift_rows(output, block_size);
    invert_sub_bytes(output, block_size);
    add_round_key(output, round_keys + (round * 16), block_size);
    invert_mix_columns(output, block_size);
  }

  // 3. Final Round (No InvertMixColumns Operation)
  invert_shift_rows(output, block_size);
  invert_sub_bytes(output, block_size);

  // 4. Add the first round key
  add_round_key(output, round_keys, block_size);

  free(round_keys);
  return output;
}
