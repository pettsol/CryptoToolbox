///////////////////////////////////
// This implementation was been  //
// placed in the public domain by//
//                               //
// Petter Solnoer - 07/09/2020   //
///////////////////////////////////

#include <cstring>
#include <iostream>
#include <fstream>
#include "aes_ctr.h"
#include <string>

#if __ARM_NEON
#include <arm_acle.h>
#include <arm_neon.h>
/* Advanced SIMD intrinsics are now available  */
#endif

#ifdef DEBUG
#include "../../../../Encoders/Hex/encoder.h"
#endif


u32 RotByte(u32 word)
{
	u32 ret = ((word << 24) | (word >> 8));
	return ret;
}

u32 SubByte(u32 word)
{
	u32 ret;
	ret = Sbox[(u8)word];
	ret = ret ^ (Sbox[(u8)(word >> 8)] << 8);
	ret = ret ^ (Sbox[(u8)(word >> 16)] << 16);
	ret = ret ^ (Sbox[(u8)(word >> 24)] << 24);
	return ret;
}

void aes_key_expansion(u8 key[], u32 key_schedule[])
{
	u32 temp;
	int i = 0;

	
	while (i < 4)
	{
		key_schedule[i] = (u32) ( ((u32)key[4*i]) | (((u32)key[4*i+1]) << 8) |
				(((u32)key[4*i+2]) << 16) | (((u32)key[4*i+3]) << 24) );
		i++;
	}
	
	while ( i < 44 )
	{
		temp = key_schedule[i-1];
		if ( (i % 4) == 0)
		{
			temp = SubByte(RotByte(temp)) ^ Rcon[i/4];
		}
		key_schedule[i] = key_schedule[i-4] ^ temp;
		i++;
	}
}

void aes_load_iv(aes_state *cs, u8 iv[12])
{
	u32 *w_ptr = (u32*)iv;
	// Load IV - 96 bits
	cs->reg1 = *w_ptr; w_ptr++;
	cs->reg2 = *w_ptr; w_ptr++;
	cs->reg3 = *w_ptr; w_ptr++;
	// Set CTR to 1
	u8 ctr[4] = {0x00, 0x00, 0x00, 0x01};
	std::memcpy(&cs->reg4, ctr, 4);
}

void aes_load_key(aes_state *cs, u8 key[16])
{
	aes_key_expansion(key, cs->rk);
}
/*
void aes_ctr_initialize(aes_state *cs, u8 key[16], u8 iv[12])
{
	aes_key_expansion(key, cs->rk);
	aes_load_iv(cs, (u32*)iv);
}
*/

void aes_encrypt(aes_state *cs, u32 keystream[])
{
#ifdef ARM_INTRINSICS
        uint8x16_t B_S = vld1q_u8((u8*)&cs->reg1);
        uint8x16_t B_K0 = vld1q_u8((u8*)cs->rk);
        uint8x16_t B_K1 = vld1q_u8((u8*)&cs->rk[4]);
        uint8x16_t B_K2 = vld1q_u8((u8*)&cs->rk[8]);
        uint8x16_t B_K3 = vld1q_u8((u8*)&cs->rk[12]);
        uint8x16_t B_K4 = vld1q_u8((u8*)&cs->rk[16]);
        uint8x16_t B_K5 = vld1q_u8((u8*)&cs->rk[20]);
        uint8x16_t B_K6 = vld1q_u8((u8*)&cs->rk[24]);
        uint8x16_t B_K7 = vld1q_u8((u8*)&cs->rk[28]);
        uint8x16_t B_K8 = vld1q_u8((u8*)&cs->rk[32]);
        uint8x16_t B_K9 = vld1q_u8((u8*)&cs->rk[36]);
        uint8x16_t B_K10 = vld1q_u8((u8*)&cs->rk[40]);

        B_S = vaesmcq_u8(vaeseq_u8(B_S, B_K0));
        B_S = vaesmcq_u8(vaeseq_u8(B_S, B_K1));
        B_S = vaesmcq_u8(vaeseq_u8(B_S, B_K2));
        B_S = vaesmcq_u8(vaeseq_u8(B_S, B_K3));
        B_S = vaesmcq_u8(vaeseq_u8(B_S, B_K4));
        B_S = vaesmcq_u8(vaeseq_u8(B_S, B_K5));
        B_S = vaesmcq_u8(vaeseq_u8(B_S, B_K6));
        B_S = vaesmcq_u8(vaeseq_u8(B_S, B_K7));
        B_S = vaesmcq_u8(vaeseq_u8(B_S, B_K8));
        B_S = vaeseq_u8(B_S, B_K9);
        B_S = veorq_u8(B_S, B_K10);

        vst1q_u8((u8*)keystream, B_S);
#else

	// Save the state
	u32 state[4];
	std::memcpy(state, &cs->reg1, 16);

	initial_round(&(cs->reg1), &(cs->reg2), &(cs->reg3), &(cs->reg4), &(cs->rk[0]));
	#ifndef ROUND_REDUCED
	round(&(cs->reg1), &(cs->reg2), &(cs->reg3), &(cs->reg4), &(cs->rk[4]));
	round(&(cs->reg1), &(cs->reg2), &(cs->reg3), &(cs->reg4), &(cs->rk[8]));
	round(&(cs->reg1), &(cs->reg2), &(cs->reg3), &(cs->reg4), &(cs->rk[12]));
	round(&(cs->reg1), &(cs->reg2), &(cs->reg3), &(cs->reg4), &(cs->rk[16]));
	#endif
	round(&(cs->reg1), &(cs->reg2), &(cs->reg3), &(cs->reg4), &(cs->rk[20]));
	round(&(cs->reg1), &(cs->reg2), &(cs->reg3), &(cs->reg4), &(cs->rk[24]));
	round(&(cs->reg1), &(cs->reg2), &(cs->reg3), &(cs->reg4), &(cs->rk[28]));
	round(&(cs->reg1), &(cs->reg2), &(cs->reg3), &(cs->reg4), &(cs->rk[32]));
	round(&(cs->reg1), &(cs->reg2), &(cs->reg3), &(cs->reg4), &(cs->rk[36]));
	final_round(&(cs->reg1), &(cs->reg2), &(cs->reg3), &(cs->reg4), &(cs->rk[40]));
	keystream[0] = cs->reg1; keystream[1] = cs->reg2;
	keystream[2] = cs->reg3; keystream[3] = cs->reg4;

	// Set state
	std::memcpy(&(cs->reg1), state, 16);
#endif
}

void state_update(aes_state *cs)
{
	// Increment the counter. Note that the CTR is defined in
	// big endian convention.
	u32 tmp = (((cs->reg4) >> 24) & 0x000000ff) |
		  (((cs->reg4) >> 8) & 0x0000ff00) |
		  (((cs->reg4) << 8) & 0x00ff0000) |
		  (((cs->reg4) << 24) & 0xff000000);

	tmp++;

	cs->reg4 = (((tmp) >> 24) & 0x000000ff) |
		   (((tmp) >> 8) & 0x0000ff00) |
		   (((tmp) << 8) & 0x00ff0000) |
		   (((tmp) << 24) & 0xff000000);
}

void aes_ctr_process_packet(aes_state *cs, u8 *out, u8 *in, int size)
{
	u32 *w_ptr_in = (u32*)in;;
	u32 *w_ptr_out = (u32*)out;
	u32 *w_state_ptr;
	u32 keystream[4] = {0,0,0,0};
	
	while (size > 0)
	{
		aes_encrypt(cs, keystream);

#ifdef DEBUG
		// Print the generated keystream
		char hex_ks[33];
		string2hexString(hex_ks, (u8*)keystream, 16);
		std::string print_ks(hex_ks, 33);
		std::cout << "Keystream: " << print_ks << std::endl;
#endif

		if(size >= 16)
		{
			// Encrypt using a full block
			// Cast to operate on words
			// Encrypt and update the state register
			// with cipher feedback
			
			*w_ptr_out = (*w_ptr_in) ^ keystream[0]; w_ptr_in++; w_ptr_out++;
			*w_ptr_out = (*w_ptr_in) ^ keystream[1]; w_ptr_in++; w_ptr_out++;
			*w_ptr_out = (*w_ptr_in) ^ keystream[2]; w_ptr_in++; w_ptr_out++;
			*w_ptr_out = (*w_ptr_in) ^ keystream[3]; w_ptr_in++; w_ptr_out++;
			
			size -= 16;
			state_update(cs); 
		}
		else
		{
			// Process individual bytes at this point
			u8 *tmp_ptr = (u8*) w_state_ptr;
			int prev_size = size;
			//int t = 3;
			int k = 0;
			while (size >= 4)
			{
				*w_ptr_out = (*w_ptr_in) ^ keystream[k++]; w_ptr_in++; w_ptr_out++;
				size -= 4;
			}

			if (size >0)
			{
				int l = 0;
				u8 *byte_ptr_out = (u8*) w_ptr_out;
				u8 *byte_ptr_in = (u8*) w_ptr_in;
				while (size > 0)
				{
					*byte_ptr_out = (*byte_ptr_in) ^ ( (u8)(keystream[k] >> (24 - (8*(l--)))));
					byte_ptr_out++; byte_ptr_in++;
					size -= 1;
				}
			}

			state_update(cs); 

		}
	}
}

