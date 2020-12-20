///////////////////////////////////
// This implementation was been  //
// placed in the public domain by//
//                               //
// Petter Solnoer - 31/03/2020   //
///////////////////////////////////

#ifndef AES_CFB
#define AES_CFB

#include "tables.h"

#if __ARM_NEON
#include <arm_neon.h>
#endif

// define modes
// for encryption
// and decryption
#define ENCRYPT 0
#define DECRYPT 1

#define AES_BLOCKSIZE 16

// Struct containing the shift register of previous ciphertexts
// and the round keys of the cipher
struct aes_state{
	// Registers to hold previous ciphertext	
	uint32_t reg1;
	uint32_t reg2;
	uint32_t reg3;
	uint32_t reg4;

	// Registers to hold round keys
	uint32_t rk[44];
};

// The interface consist of
// cipher initialization
// and process packet.
void aes_cfb_initialize(aes_state *cs, uint8_t key[16], uint8_t iv[16]);
void aes_cfb_process_packet(aes_state *cs, uint8_t *out, uint8_t *in, int size, int mode);

// the encryption mode of the cipher 
// and the key expansion can be accessed
// directly in order to verify the
// implementation with official
// test vectors.
void aes_encrypt(aes_state *cs, uint32_t keystream[]);
void aes_key_expansion(uint8_t key[], uint32_t key_schedule[]);

inline void initial_round(uint32_t *a, uint32_t *b,  uint32_t *c, uint32_t *d, uint32_t *round_key)
{
	// The initial round of AES only consist
	// of round key addition
	*a = (*a) ^ (*round_key); round_key++;
	*b = (*b) ^ (*round_key); round_key++;
	*c = (*c) ^ (*round_key); round_key++;
	*d = (*d) ^ (*round_key); round_key++;
}

inline void round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, uint32_t *round_key)
{
	// Copies needed to hold variables
	// during operations
	uint32_t tmp_a = *a;
	uint32_t tmp_b = *b;
	uint32_t tmp_c = *c;
	uint32_t tmp_d = *d;

	uint8_t tmp;
	// Each table T yields 32 bits output
	tmp = (uint8_t) tmp_a;
	*a = T0[tmp];
	tmp = (uint8_t) (tmp_b >> 8);
	*a = (*a) ^ T1[tmp];
	tmp = (uint8_t) (tmp_c >> 16);
	*a = (*a) ^ T2[tmp];
	tmp = (uint8_t) (tmp_d >> 24);
	*a = (*a) ^ T3[tmp];
	*a = (*a) ^ (*round_key); round_key++;

	// The second output word of 32 bits
	tmp = (uint8_t) tmp_b;
	*b = T0[tmp];
	tmp = (uint8_t) (tmp_c >> 8);
	*b = (*b) ^ T1[tmp];
	tmp = (uint8_t) (tmp_d >> 16);
	*b = (*b) ^ T2[tmp];
	tmp = (uint8_t) (tmp_a >> 24);
	*b = (*b) ^ T3[tmp];
	*b = (*b) ^ (*round_key); round_key++;

	// The third output word of 32 bits
	tmp = (uint8_t) tmp_c;
	*c = T0[tmp];
	tmp = (uint8_t) (tmp_d >> 8);
	*c = (*c) ^ T1[tmp];
	tmp = (uint8_t) (tmp_a >> 16);
	*c = (*c) ^ T2[tmp];
	tmp = (uint8_t) (tmp_b >> 24);
	*c = (*c) ^ T3[tmp];
	*c = (*c) ^ (*round_key); round_key++;

	// The fourth word of 32 bits
	tmp = (uint8_t) tmp_d;
	*d = T0[tmp];
	tmp = (uint8_t) (tmp_a >> 8);
	*d = (*d) ^ T1[tmp];
	tmp = (uint8_t) (tmp_b >> 16);
	*d = (*d) ^ T2[tmp];
	tmp = (uint8_t) (tmp_c >> 24);
	*d = (*d) ^ T3[tmp];
	*d = (*d) ^ (*round_key);

}

inline void final_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d, uint32_t *round_key)
{
	// Create copies of input
	uint32_t tmp_a = *a;
	uint32_t tmp_b = *b;
	uint32_t tmp_c = *c;
	uint32_t tmp_d = *d;

	// Need to operate on bytes
	uint8_t tmp;

	// First output word
	// Access Sbox directly, no mix column step.
	tmp = (uint8_t) tmp_a;
	(*a) = (uint32_t) (Sbox[tmp]);
	tmp = (uint8_t) (tmp_b >> 8);
	(*a) = (*a) ^ ( (uint32_t) (Sbox[tmp] << 8) );
	tmp = (uint8_t) (tmp_c >> 16);
	(*a) = (*a) ^ ( (uint32_t) (Sbox[tmp] << 16) );
	tmp = (uint8_t) (tmp_d >> 24);
	(*a) = (*a) ^ ( (uint32_t) (Sbox[tmp] << 24) );
	(*a) = (*a) ^ (*round_key); round_key++;
	
	// Second output word
	tmp = (uint8_t) tmp_b;
	(*b) = (uint32_t) (Sbox[tmp]);
	tmp = (uint8_t) (tmp_c >> 8);
	(*b) = (*b) ^ ( (uint32_t) (Sbox[tmp] << 8) );
	tmp = (uint8_t) (tmp_d >> 16);
	(*b) = (*b) ^ ( (uint32_t) (Sbox[tmp] << 16) );
	tmp = (uint8_t) (tmp_a >> 24);
	(*b) = (*b) ^ ( (uint32_t) (Sbox[tmp] << 24) );
	(*b) = (*b) ^ (*round_key); round_key++;

	// Third output word
	tmp = (uint8_t) tmp_c;
	(*c) = (uint32_t) (Sbox[tmp]);
	tmp = (uint8_t) (tmp_d >> 8);
	(*c) = (*c) ^ ( (uint32_t) (Sbox[tmp] << 8) );
	tmp = (uint8_t) (tmp_a >> 16);
	(*c) = (*c) ^ ( (uint32_t) (Sbox[tmp] << 16) );
	tmp = (uint8_t) (tmp_b >> 24);
	(*c) = (*c) ^ ( (uint32_t) (Sbox[tmp] << 24) );
	(*c) = (*c) ^ (*round_key); round_key++;

	// Fourth output word
	tmp = (uint8_t) tmp_d;
	(*d) = (uint32_t) (Sbox[tmp]);
	tmp = (uint8_t) (tmp_a >> 8);
	(*d) = (*d) ^ ( (uint32_t) (Sbox[tmp] << 8) );
	tmp = (uint8_t) (tmp_b >> 16);
	(*d) = (*d) ^ ( (uint32_t) (Sbox[tmp] << 16) );
	tmp = (uint8_t) (tmp_c >> 24);
	(*d) = (*d) ^ ( (uint32_t) (Sbox[tmp] << 24) );
	(*d) = (*d) ^ (*round_key);

}
#endif
