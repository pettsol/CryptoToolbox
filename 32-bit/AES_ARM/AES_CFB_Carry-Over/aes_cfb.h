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
struct cipher_state{
	// Registers to hold previous ciphertext	
	u32 reg1;
	u32 reg2;
	u32 reg3;
	u32 reg4;

	// Registers to hold round keys
	u32 rk[44];
};

// The interface consist of
// cipher initialization
// and process packet.
void cfb_initialize_cipher(cipher_state *cs, u8 key[], u32 *iv);
void cfb_process_packet(cipher_state *cs, u8 *out, u8 *in, int size, int mode);

// the encryption mode of the cipher 
// and the key expansion can be accessed
// directly in order to verify the
// implementation with official
// test vectors.
void aes_encrypt(cipher_state *cs, u32 keystream[]);
void KeyExpansion(u8 key[], u32 key_schedule[]);

inline void initial_round(u32 *a, u32 *b,  u32 *c, u32 *d, u32 *round_key)
{
	// The initial round of AES only consist
	// of round key addition
	*a = (*a) ^ (*round_key); round_key++;
	*b = (*b) ^ (*round_key); round_key++;
	*c = (*c) ^ (*round_key); round_key++;
	*d = (*d) ^ (*round_key); round_key++;
}

inline void round(u32 *a, u32 *b, u32 *c, u32 *d, u32 *round_key)
{
	// Copies needed to hold variables
	// during operations
	u32 tmp_a = *a;
	u32 tmp_b = *b;
	u32 tmp_c = *c;
	u32 tmp_d = *d;

	u8 tmp;
	// Each table T yields 32 bits output
	tmp = (u8) tmp_a;
	*a = T0[tmp];
	tmp = (u8) (tmp_b >> 8);
	*a = (*a) ^ T1[tmp];
	tmp = (u8) (tmp_c >> 16);
	*a = (*a) ^ T2[tmp];
	tmp = (u8) (tmp_d >> 24);
	*a = (*a) ^ T3[tmp];
	*a = (*a) ^ (*round_key); round_key++;

	// The second output word of 32 bits
	tmp = (u8) tmp_b;
	*b = T0[tmp];
	tmp = (u8) (tmp_c >> 8);
	*b = (*b) ^ T1[tmp];
	tmp = (u8) (tmp_d >> 16);
	*b = (*b) ^ T2[tmp];
	tmp = (u8) (tmp_a >> 24);
	*b = (*b) ^ T3[tmp];
	*b = (*b) ^ (*round_key); round_key++;

	// The third output word of 32 bits
	tmp = (u8) tmp_c;
	*c = T0[tmp];
	tmp = (u8) (tmp_d >> 8);
	*c = (*c) ^ T1[tmp];
	tmp = (u8) (tmp_a >> 16);
	*c = (*c) ^ T2[tmp];
	tmp = (u8) (tmp_b >> 24);
	*c = (*c) ^ T3[tmp];
	*c = (*c) ^ (*round_key); round_key++;

	// The fourth word of 32 bits
	tmp = (u8) tmp_d;
	*d = T0[tmp];
	tmp = (u8) (tmp_a >> 8);
	*d = (*d) ^ T1[tmp];
	tmp = (u8) (tmp_b >> 16);
	*d = (*d) ^ T2[tmp];
	tmp = (u8) (tmp_c >> 24);
	*d = (*d) ^ T3[tmp];
	*d = (*d) ^ (*round_key);

}

inline void final_round(u32 *a, u32 *b, u32 *c, u32 *d, u32 *round_key)
{
	// Create copies of input
	u32 tmp_a = *a;
	u32 tmp_b = *b;
	u32 tmp_c = *c;
	u32 tmp_d = *d;

	// Need to operate on bytes
	u8 tmp;

	// First output word
	// Access Sbox directly, no mix column step.
	tmp = (u8) tmp_a;
	(*a) = (u32) (Sbox[tmp]);
	tmp = (u8) (tmp_b >> 8);
	(*a) = (*a) ^ ( (u32) (Sbox[tmp] << 8) );
	tmp = (u8) (tmp_c >> 16);
	(*a) = (*a) ^ ( (u32) (Sbox[tmp] << 16) );
	tmp = (u8) (tmp_d >> 24);
	(*a) = (*a) ^ ( (u32) (Sbox[tmp] << 24) );
	(*a) = (*a) ^ (*round_key); round_key++;
	
	// Second output word
	tmp = (u8) tmp_b;
	(*b) = (u32) (Sbox[tmp]);
	tmp = (u8) (tmp_c >> 8);
	(*b) = (*b) ^ ( (u32) (Sbox[tmp] << 8) );
	tmp = (u8) (tmp_d >> 16);
	(*b) = (*b) ^ ( (u32) (Sbox[tmp] << 16) );
	tmp = (u8) (tmp_a >> 24);
	(*b) = (*b) ^ ( (u32) (Sbox[tmp] << 24) );
	(*b) = (*b) ^ (*round_key); round_key++;

	// Third output word
	tmp = (u8) tmp_c;
	(*c) = (u32) (Sbox[tmp]);
	tmp = (u8) (tmp_d >> 8);
	(*c) = (*c) ^ ( (u32) (Sbox[tmp] << 8) );
	tmp = (u8) (tmp_a >> 16);
	(*c) = (*c) ^ ( (u32) (Sbox[tmp] << 16) );
	tmp = (u8) (tmp_b >> 24);
	(*c) = (*c) ^ ( (u32) (Sbox[tmp] << 24) );
	(*c) = (*c) ^ (*round_key); round_key++;

	// Fourth output word
	tmp = (u8) tmp_d;
	(*d) = (u32) (Sbox[tmp]);
	tmp = (u8) (tmp_a >> 8);
	(*d) = (*d) ^ ( (u32) (Sbox[tmp] << 8) );
	tmp = (u8) (tmp_b >> 16);
	(*d) = (*d) ^ ( (u32) (Sbox[tmp] << 16) );
	tmp = (u8) (tmp_c >> 24);
	(*d) = (*d) ^ ( (u32) (Sbox[tmp] << 24) );
	(*d) = (*d) ^ (*round_key);

}
#endif
