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

#if __ARM_NEON
#include <arm_acle.h>
#include <arm_neon.h>
/* Advanced SIMD intrinsics are now available */
#endif

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

#ifdef ARM_INTRINSICS
	uint8x16_t B_TMP;
	uint8x16_t B_MSG;
	uint8x16_t B_KEY;
	uint8x16_t B_S0;
	uint8x16_t B_S1;
	uint8x16_t B_S2;
	uint8x16_t B_S3;
	uint8x16_t B_S4;
#else
	u32 tmp[4];
	u32 tmp_key[4];
	u32 tmp_state[4];
#endif

#ifdef ARM_INTRINSICS
	// UPDATE FIRST REGISTER //
	// Store s0 as tmp var.
	B_TMP = vld1q_u8((u8*)cs->s0);
	B_MSG = vld1q_u8((u8*)message_block);
	B_KEY = veorq_u8(B_TMP, B_MSG);
	B_S0 = vld1q_u8((u8*)cs->s4);
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
#ifdef ARM_INTRINSICS
	// ARM INSTRINSICS
	
	B_S0 = veorq_u8(B_S0, B_KEY);
	//vst1q_u8((u8*)cs->s2, B);
	//B = vaeseq_u8(B, Key);
	B_S0 = vaesmcq_u8(vaeseq_u8(B_S0, B_KEY));
	B_S0 = veorq_u8(B_S0, B_KEY);
	vst1q_u8((u8*)cs->s0, B_S0);
#else	
	round(cs->s0, cs->s0+1, cs->s0+2, cs->s0+3, tmp_key);
#endif
	
	//round(cs->s0, cs->s0+1, cs->s0+2, cs->s0+3, tmp_key);

	// UPDATE SECOND REGISTER //
	// Store s1 as round key
#ifdef ARM_INTRINSICS
	B_KEY = vld1q_u8((u8*)cs->s1);
	B_S1 = B_TMP;
#else
	std::memcpy(tmp_key, cs->s1, 16);
	// Copy old s0 into s1 state.
	std::memcpy(cs->s1, tmp_state, 16);
#endif
#ifdef ARM_INTRINSICS
	// ARM INSTRINSICS
	
	B_S1 = veorq_u8(B_S1, B_KEY);
	//vst1q_u8((u8*)cs->s2, B);
	//B = vaeseq_u8(B, Key);
	B_S1 = vaesmcq_u8(vaeseq_u8(B_S1, B_KEY));
	B_S1 = veorq_u8(B_S1, B_KEY);
	B_TMP = B_KEY;
	vst1q_u8((u8*)cs->s1, B_S1);
#else	
	round(cs->s1, cs->s1+1, cs->s1+2, cs->s1+3, tmp_key);
	// Iterate round
	//round(cs->s1, cs->s1+1, cs->s1+2, cs->s1+3, tmp_key);
	// Copy old s1 into tmp state
	std::memcpy(tmp_state, tmp_key, 16);
#endif
	// UPDATE THIRD REGISTER //
	// Store s2 as round key
#ifdef ARM_INTRINSICS
	B_KEY = vld1q_u8((u8*)cs->s2);
	B_S2 = B_TMP;
#else
	std::memcpy(tmp_key, cs->s2, 16);
	// Copy old s1 into s2 state.
	std::memcpy(cs->s2, tmp_state, 16);
#endif
	// Iterate round
#ifdef ARM_INTRINSICS
	// ARM INSTRINSICS
	B_S2 = veorq_u8(B_S2, B_KEY);
	//vst1q_u8((u8*)cs->s2, B);
	//B = vaeseq_u8(B, Key);
	B_S2 = vaesmcq_u8(vaeseq_u8(B_S2, B_KEY));
	B_S2 = veorq_u8(B_S2, B_KEY);
	B_TMP = B_KEY;
	vst1q_u8((u8*)cs->s2, B_S2);
#else	
	round(cs->s2, cs->s2+1, cs->s2+2, cs->s2+3, tmp_key);
	// Copy old s2 into temp state
	std::memcpy(tmp_state, tmp_key, 16);
#endif
	// UPDATE FOURTH REGISTER //
	// Store s3 as round key
#ifdef ARM_INTRINSICS
	B_KEY = vld1q_u8((u8*)cs->s3);
	B_S3 = B_TMP;
#else
	std::memcpy(tmp_key, cs->s3, 16);
	// Copy old s2 into s3 state.
	std::memcpy(cs->s3, tmp_state, 16);
#endif
	// Iterate round
#ifdef ARM_INTRINSICS
	// ARM INSTRINSICS	
	B_S3 = veorq_u8(B_S3, B_KEY);
	//vst1q_u8((u8*)cs->s2, B);
	//B = vaeseq_u8(B, Key);
	B_S3 = vaesmcq_u8(vaeseq_u8(B_S3, B_KEY));
	B_S3 = veorq_u8(B_S3, B_KEY);
	B_TMP = B_KEY;
	vst1q_u8((u8*)cs->s3, B_S3);
#else	
	// Regular table driven
	round(cs->s3, cs->s3+1, cs->s3+2, cs->s3+3, tmp_key);
	// Copy old s3 into tmp state
	std::memcpy(tmp_state, tmp_key, 16);
#endif

	//round(cs->s3, cs->s3+1, cs->s3+2, cs->s3+3, tmp_key);

	// UPDATE FIFTH REGISTER //
	// Store s4 as round key
#ifdef ARM_INTRINSICS
	B_KEY = vld1q_u8((u8*)cs->s4);
	B_S4 = B_TMP;
#else
	std::memcpy(tmp_key, cs->s4, 16);
	// Copy old s3 into s4 state.
	std::memcpy(cs->s4, tmp_state, 16);
#endif
	// Iterate round
#ifdef ARM_INTRINSICS
	// ARM INTRINSICS
	B_S4 = veorq_u8(B_S4, B_KEY);
	//vst1q_u8((u8*)cs->s2, B);
	//B = vaeseq_u8(B, Key);
	B_S4 = vaesmcq_u8(vaeseq_u8(B_S4, B_KEY));
	B_S4 = veorq_u8(B_S4, B_KEY);
	vst1q_u8((u8*)cs->s4, B_S4);
#else	
	round(cs->s4, cs->s4+1, cs->s4+2, cs->s4+3, tmp_key);
#endif

	//round(cs->s4, cs->s4+1, cs->s4+2, cs->s4+3, tmp_key);
}
#endif
