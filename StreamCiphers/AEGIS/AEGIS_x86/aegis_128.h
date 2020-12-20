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

#ifdef x86_INTRINSICS
#include <x86intrin.h>
/* Advanced SSE3 / AES intrinsics for x86 now available  */
#endif

// Magic constants
#define AEGIS_BLOCKSIZE 16
#define IV_SIZE 16

// AEGIS state consist of 80 bytes, held in 16-byte (128 bit)
// sequences. There is also a 16-byte temp variable w.
struct aegis_state{
	uint32_t key[4];

	uint32_t s0[4];
	uint32_t s1[4];
	uint32_t s2[4];
	uint32_t s3[4];
	uint32_t s4[4];
	uint32_t w[4];
};

void aegis_load_key(aegis_state *cs, uint8_t key[16]);
void aegis_encrypt_packet(aegis_state *cs, uint8_t *ct, uint8_t tag[16], uint8_t *pt, uint8_t *ad, uint8_t iv[16], uint64_t adlen, uint64_t msglen);
int aegis_decrypt_packet(aegis_state *cs, uint8_t *pt, uint8_t *ct, uint8_t *ad, uint8_t iv[16], uint8_t tag[16], uint64_t adlen, uint64_t msglen);

// The AES round function is used five times in AEGIS-128
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

// State update function
inline void aegis_state_update(aegis_state *cs, uint32_t *message_block)
{

#ifdef x86_INTRINSICS
	__m128i B_TMP;
	__m128i B_MSG;
	__m128i B_KEY;
	__m128i B_S0;
	__m128i B_S1;
	__m128i B_S2;
	__m128i B_S3;
	__m128i B_S4;
#else
	uint32_t tmp[4];
	uint32_t tmp_key[4];
	uint32_t tmp_state[4];
#endif

#ifdef x86_INTRINSICS
	// UPDATE FIRST REGISTER //
	// Store s0 as tmp var.
	B_TMP = _mm_loadu_si128((__m128i*)cs->s0);
	B_MSG = _mm_loadu_si128((__m128i*)message_block);
	B_KEY = _mm_xor_si128(B_TMP, B_MSG);
	B_S0 = _mm_loadu_si128((__m128i*)cs->s4);
#else
	std::memcpy(tmp_state, cs->s0, 16);
	// XOR msg and old s0 as tmp key.
	tmp_key[0] = tmp_state[0] ^ *message_block++;
	tmp_key[1] = tmp_state[1] ^ *message_block++;
	tmp_key[2] = tmp_state[2] ^ *message_block++;
	tmp_key[3] = tmp_state[3] ^ *message_block++;
	// Copy s4 into s0 as state.
	std::memcpy(cs->s0, cs->s4, 16);
#endif
	// Iterate round
#ifdef x86_INTRINSICS
	B_S0 = _mm_aesenc_si128 (B_S0, B_KEY);	
	_mm_storeu_si128 ((__m128i*)cs->s0, B_S0);
#else	
	round(cs->s0, cs->s0+1, cs->s0+2, cs->s0+3, tmp_key);
#endif
	
	//round(cs->s0, cs->s0+1, cs->s0+2, cs->s0+3, tmp_key);

	// UPDATE SECOND REGISTER //
	// Store s1 as round key
#ifdef x86_INTRINSICS
	B_KEY = _mm_loadu_si128((__m128i*)cs->s1);
	B_S1 = B_TMP;
#else
	std::memcpy(tmp_key, cs->s1, 16);
	// Copy old s0 into s1 state.
	std::memcpy(cs->s1, tmp_state, 16);
#endif
#ifdef x86_INTRINSICS
	B_S1 = _mm_aesenc_si128 (B_S1, B_KEY);	
	B_TMP = B_KEY;
	_mm_storeu_si128 ((__m128i*)cs->s1, B_S1);
#else	
	round(cs->s1, cs->s1+1, cs->s1+2, cs->s1+3, tmp_key);
	// Iterate round
	//round(cs->s1, cs->s1+1, cs->s1+2, cs->s1+3, tmp_key);
	// Copy old s1 into tmp state
	std::memcpy(tmp_state, tmp_key, 16);
#endif
	// UPDATE THIRD REGISTER //
	// Store s2 as round key
#ifdef x86_INTRINSICS
	B_KEY = _mm_loadu_si128((__m128i*)cs->s2);
	B_S2 = B_TMP;
#else
	std::memcpy(tmp_key, cs->s2, 16);
	// Copy old s1 into s2 state.
	std::memcpy(cs->s2, tmp_state, 16);
#endif
	// Iterate round
#ifdef x86_INTRINSICS
	B_S2 = _mm_aesenc_si128(B_S2, B_KEY);
	B_TMP = B_KEY;
	_mm_storeu_si128 ((__m128i*)cs->s2, B_S2);
#else	
	round(cs->s2, cs->s2+1, cs->s2+2, cs->s2+3, tmp_key);
	// Copy old s2 into temp state
	std::memcpy(tmp_state, tmp_key, 16);
#endif
	// UPDATE FOURTH REGISTER //
	// Store s3 as round key
#ifdef x86_INTRINSICS
	B_KEY = _mm_loadu_si128 ((__m128i*)cs->s3);
	B_S3 = B_TMP;
#else
	std::memcpy(tmp_key, cs->s3, 16);
	// Copy old s2 into s3 state.
	std::memcpy(cs->s3, tmp_state, 16);
#endif
	// Iterate round
#ifdef x86_INTRINSICS
	B_S3 = _mm_aesenc_si128 (B_S3, B_KEY);
	B_TMP = B_KEY;
	_mm_storeu_si128 ((__m128i*)cs->s3, B_S3);
#else	
	// Regular table driven
	round(cs->s3, cs->s3+1, cs->s3+2, cs->s3+3, tmp_key);
	// Copy old s3 into tmp state
	std::memcpy(tmp_state, tmp_key, 16);
#endif

	//round(cs->s3, cs->s3+1, cs->s3+2, cs->s3+3, tmp_key);

	// UPDATE FIFTH REGISTER //
	// Store s4 as round key
#ifdef x86_INTRINSICS
	B_KEY = _mm_loadu_si128((__m128i*)cs->s4);
	B_S4 = B_TMP;
#else
	std::memcpy(tmp_key, cs->s4, 16);
	// Copy old s3 into s4 state.
	std::memcpy(cs->s4, tmp_state, 16);
#endif
	// Iterate round
#ifdef x86_INTRINSICS
	B_S4 = _mm_aesenc_si128(B_S4, B_KEY);
	_mm_storeu_si128((__m128i*)cs->s4, B_S4);
#else	
	round(cs->s4, cs->s4+1, cs->s4+2, cs->s4+3, tmp_key);
#endif

	//round(cs->s4, cs->s4+1, cs->s4+2, cs->s4+3, tmp_key);
}
#endif
