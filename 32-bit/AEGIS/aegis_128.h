///////////////////////////////////
// This implementation was been  //
// placed in the public domain by//
//                               //
// Petter Solnoer - 24/08/2020   //
///////////////////////////////////

#ifndef AEGIS_128
#define AEGIS_128

#include "tables.h"

#include <cstring>

// Magic constants
#define AEGIS_BLOCKSIZE 16
#define IV_SIZE 16

// AEGIS state consist of 80 bytes, held in 16-byte (128 bit)
// sequences. There is also a 16-byte temp variable w.
struct aegis_state{
	u32 key[4];

	u32 s0[4];
	u32 s1[4];
	u32 s2[4];
	u32 s3[4];
	u32 s4[4];
	u32 w[4];
};

void aegis_load_key(aegis_state *cs, u32 *key);
void aegis_encrypt_packet(aegis_state *cs, u8 *ct, u8* tag, u8 *pt, u8 *ad, u32 *iv, u64 adlen, u64 msglen);
int aegis_decrypt_packet(aegis_state *cs, u8 *pt, u8 *ct, u8 *ad, u32 *iv, u32 *tag, u64 adlen, u64 msglen);

// The AES round function is used five times in AEGIS-128
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

// State update function
inline void aegis_state_update(aegis_state *cs, u32 *message_block)
{

	u32 tmp[4];
	u32 tmp_key[4];
	u32 tmp_state[4];


	// UPDATE FIRST REGISTER //
	// Store s0 as tmp var.
	std::memcpy(tmp_state, cs->s0, 16);
	// XOR msg and old s0 as tmp key.
	tmp_key[0] = tmp_state[0] ^ *message_block++;
	tmp_key[1] = tmp_state[1] ^ *message_block++;
	tmp_key[2] = tmp_state[2] ^ *message_block++;
	tmp_key[3] = tmp_state[3] ^ *message_block++;
	// Copy s4 into s0 as state.
	std::memcpy(cs->s0, cs->s4, 16);
	// Iterate round
	round(cs->s0, cs->s0+1, cs->s0+2, cs->s0+3, tmp_key);

	// UPDATE SECOND REGISTER //
	// Store s1 as round key
	std::memcpy(tmp_key, cs->s1, 16);
	// Copy old s0 into s1 state.
	std::memcpy(cs->s1, tmp_state, 16);
	// Iterate round
	round(cs->s1, cs->s1+1, cs->s1+2, cs->s1+3, tmp_key);
	// Copy old s1 into tmp state
	std::memcpy(tmp_state, tmp_key, 16);

	// UPDATE THIRD REGISTER //
	// Store s2 as round key
	std::memcpy(tmp_key, cs->s2, 16);
	// Copy old s1 into s2 state.
	std::memcpy(cs->s2, tmp_state, 16);
	// Iterate round
	round(cs->s2, cs->s2+1, cs->s2+2, cs->s2+3, tmp_key);
	// Copy old s2 into tmp state
	std::memcpy(tmp_state, tmp_key, 16);

	// UPDATE THIRD REGISTER //
	// Store s3 as round key
	std::memcpy(tmp_key, cs->s3, 16);
	// Copy old s2 into s3 state.
	std::memcpy(cs->s3, tmp_state, 16);
	// Iterate round
	round(cs->s3, cs->s3+1, cs->s3+2, cs->s3+3, tmp_key);
	// Copy old s3 into tmp state
	std::memcpy(tmp_state, tmp_key, 16);

	// UPDATE FOURTH REGISTER //
	// Store s4 as round key
	std::memcpy(tmp_key, cs->s4, 16);
	// Copy old s3 into s4 state.
	std::memcpy(cs->s4, tmp_state, 16);
	// Iterate round
	round(cs->s4, cs->s4+1, cs->s4+2, cs->s4+3, tmp_key);
}
#endif
