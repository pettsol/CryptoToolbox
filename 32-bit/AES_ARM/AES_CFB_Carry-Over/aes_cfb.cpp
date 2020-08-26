///////////////////////////////////
// This implementation was been  //
// placed in the public domain by//
//                               //
// Petter Solnoer - 26/08/2020   //
///////////////////////////////////

#include <iostream>
#include <fstream>
#include "aes_cfb.h"
#include <string>

#if __ARM_NEON
#include <arm_acle.h>
#include <arm_neon.h>
/* Advanced SIMD intrinsics are now available */
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

void KeyExpansion(u8 key[], u32 key_schedule[])
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

void aes_load_iv(cipher_state *cs, u32 *iv)
{
	cs->reg1 = *iv; iv++;
	cs->reg2 = *iv; iv++;
	cs->reg3 = *iv; iv++;
	cs->reg4 = *iv; iv++;
}

void cfb_initialize_cipher(cipher_state *cs, u8 key[], u32 *iv)
{
	KeyExpansion(key, cs->rk);
	aes_load_iv(cs, iv);
}

void aes_encrypt(cipher_state *cs, u32 keystream[])
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
	vst1q_u8((u8*)&cs->reg1, B_S);
#else
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
#endif
}

void full_state_update(cipher_state *cs, u32 *ctxt)
{
	cs->reg1 = (*ctxt); ctxt++;
	cs->reg2 = (*ctxt); ctxt++;
	cs->reg3 = (*ctxt); ctxt++;
	cs->reg4 = (*ctxt); ctxt++;
}

void partial_state_update(cipher_state *cs, u8 *ctxt, int size)
{
	if (size % 4 == 0)
	{
		if (size == 4)
		{
			cs->reg1 = cs->reg2;
			cs->reg2 = cs->reg3;
			cs->reg3 = cs->reg4;
			cs->reg4 = (*((u32*)ctxt));
		}
		else if (size == 8)
		{
			cs->reg1 = cs->reg3;
			cs->reg2 = cs->reg4;
			cs->reg3 = (*((u32*)ctxt)); ctxt++;
			cs->reg4 = (*((u32*)ctxt));
		}
		else
		{
			cs->reg1 = cs->reg4;
			cs->reg2 = (*((u32*)ctxt)); ctxt++;
			cs->reg3 = (*((u32*)ctxt)); ctxt++;
			cs->reg4 = (*((u32*)ctxt));
		}
	}
	else if (size % 4 == 1)
	{
		if (size == 1)
		{
			cs->reg1 = ((cs->reg1 << 8) ^ (cs->reg2 >> 24));
			cs->reg2 = ((cs->reg2 << 8) ^ (cs->reg3 >> 24));
			cs->reg3 = ((cs->reg3 << 8) ^ (cs->reg4 >> 24));
			cs->reg4 = ((cs->reg4 << 8) ^ (*ctxt));
			size = 0;

		}
		if (size == 5)
		{
			cs->reg1 = ((cs->reg2 << 8) ^ (cs->reg3 >> 24));
			cs->reg2 = ((cs->reg3 << 8) ^ (cs->reg4 >> 24));
			cs->reg3 = ((cs->reg4 << 8) ^ (*ctxt)); ctxt++;
			cs->reg4 = (*((u32*)ctxt));
			size = 0;
		}
		if (size == 9)
		{
			cs->reg1 = ((cs->reg3 << 8) ^ (cs->reg4 >> 24));
			cs->reg2 = ((cs->reg4 << 8) ^ (*ctxt)); ctxt++;
			cs->reg3 = (*((u32*)ctxt)); ctxt += 4;
			cs->reg4 = (*((u32*)ctxt));
			size = 0;
		}
		if (size == 13)
		{
			cs->reg1 = ((cs->reg4 << 8) ^ (*ctxt)); ctxt++;
			cs->reg2 = (*((u32*)ctxt)); ctxt += 4;
			cs->reg3 = (*((u32*)ctxt)); ctxt += 4;
			cs->reg4 = (*((u32*)ctxt));
			size = 0;

		}
	}
	else if (size % 4 == 2)
	{
		if (size == 2)
		{
			cs->reg1 = ((cs->reg1 << 16) ^ (cs->reg2 >> 16));
			cs->reg2 = ((cs->reg2 << 16) ^ (cs->reg3 >> 16));
			cs->reg3 = ((cs->reg3 << 16) ^ (cs->reg4 >> 16));
			cs->reg4 = ((cs->reg4 << 16) ^ ((*ctxt) << 8)); ctxt++;
			cs->reg4 = (cs->reg4 ^ (*ctxt));

		}
		if (size == 6)
		{
			cs->reg1 = ((cs->reg2 << 16) ^ (cs->reg3 >> 16));
			cs->reg2 = ((cs->reg3 << 16) ^ (cs->reg4 >> 16));
			cs->reg3 = ((cs->reg4 << 16) ^ ((*ctxt) << 8)); ctxt++;
			cs->reg3 = ((cs->reg3) ^ (*ctxt)); ctxt++;
			cs->reg4 = (*((u32*)ctxt));
			size = 0;
		}
		if (size == 10)
		{
			cs->reg1 = ((cs->reg3 << 16) ^ (cs->reg4 >> 16));
			cs->reg2 = ((cs->reg4 << 16) ^ ((*ctxt) << 8)); ctxt++;
			cs->reg2 = ((cs->reg2) ^ (*ctxt)); ctxt++;
			cs->reg3 = (*((u32*)ctxt)); ctxt += 4;
			cs->reg4 = (*((u32*)ctxt));
			size = 0;
		}
		if (size == 14)
		{
			cs->reg1 = ((cs->reg4 << 16) ^ ((*ctxt) << 8)); ctxt++;
			cs->reg1 = ((cs->reg1) ^ (*ctxt)); ctxt++;
			cs->reg2 = (*((u32*)ctxt)); ctxt += 4;
			cs->reg3 = (*((u32*)ctxt)); ctxt += 4;
			cs->reg4 = (*((u32*)ctxt));
			size = 0;

		}
	}
	else
	{
		if (size == 3)
		{
			cs->reg1 = ((cs->reg1 << 24) ^ (cs->reg2 >> 8));
			cs->reg2 = ((cs->reg2 << 24) ^ (cs->reg3 >> 8));
			cs->reg3 = ((cs->reg3 << 24) ^ (cs->reg4 >> 8));
			cs->reg4 = ((cs->reg4 << 24) ^ ((*ctxt) << 16)); ctxt++;
			cs->reg4 = (cs->reg4 ^ ((*ctxt) << 8)); ctxt++;
			cs->reg4 = (cs->reg4 ^ (*ctxt));
		}
		if (size == 7)
		{
			cs->reg1 = ((cs->reg2 << 24) ^ (cs->reg3 >> 8));
			cs->reg2 = ((cs->reg3 << 24) ^ (cs->reg4 >> 8));
			cs->reg3 = ((cs->reg3 << 24) ^ ((*ctxt) << 16)); ctxt++;
			cs->reg3 = ((cs->reg3) ^ ((*ctxt) << 8)); ctxt++;
			cs->reg3 = ((cs->reg3) ^ (*ctxt)); ctxt++;
			cs->reg4 = (*((u32*)ctxt));
			size = 0;
		}
		if (size == 11)
		{
			cs->reg1 = ((cs->reg3 << 24) ^ (cs->reg4 >> 8));
			cs->reg2 = ((cs->reg4 << 24) ^ ((*ctxt) << 16)); ctxt++;
			cs->reg2 = ((cs->reg2) ^ ((*ctxt) << 8)); ctxt++;
			cs->reg2 = ((cs->reg2) ^ (*ctxt)); ctxt++;
			cs->reg3 = (*((u32*)ctxt)); ctxt += 4;
			cs->reg4 = (*((u32*)ctxt));
			size = 0;
		}
		if (size == 15)
		{
			cs->reg1 = ((cs->reg4 << 24) ^ ((*ctxt) << 16)); ctxt++;
			cs->reg1 = ((cs->reg1) ^ ((*ctxt) << 8)); ctxt++;
			cs->reg1 = ((cs->reg1) ^ (*ctxt)); ctxt++;
			cs->reg2 = (*((u32*)ctxt)); ctxt += 4;
			cs->reg3 = (*((u32*)ctxt)); ctxt += 4;
			cs->reg4 = (*((u32*)ctxt));
			size = 0;

		}
	}

}

void cfb_process_packet(cipher_state *cs, u8 *out, u8 *in, int size, int mode)
{
	
	u32 *w_ptr_in = (u32*)in;;
	u32 *w_ptr_out = (u32*)out;
	u32 *w_state_ptr;
	u32 keystream[4] = {0,0,0,0};
	
	while (size > 0)
	{
		// Generate key bits
		if( mode )
		{
			// Decryption mode
			// Current ciphertext
			// enters next state
			w_state_ptr = w_ptr_in;
		}
		else
		{
			// Encryption mode
			// New ciphertext
			// enters next state
			w_state_ptr = w_ptr_out;
		}
		
		aes_encrypt(cs, keystream);
		
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
			full_state_update(cs, w_state_ptr); 
		}
		else
		{
			// Process individual bytes at this point
			u8 *tmp_ptr = (u8*) w_state_ptr;
			int prev_size = size;
			int k = 3;
			while (size >= 4)
			{
				*w_ptr_out = (*w_ptr_in) ^ keystream[k--]; w_ptr_in++; w_ptr_out++;
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

			partial_state_update(cs, tmp_ptr, prev_size); 

		}
	}
}

