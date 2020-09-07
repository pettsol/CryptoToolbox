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

#ifdef x86_INTRINSICS
#include <x86intrin.h>
/* Advanced SSE3 / AES intrinsics for x86 now available  */
#endif

#ifdef DEBUG
#include "../../HexEncoder/encoder.h"
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

#ifdef x86_INTRINSICS
inline __m128i AES_128_ASSIST (__m128i temp1, __m128i temp2)
{ 
	__m128i temp3;
   	temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
   	temp3 = _mm_slli_si128 (temp1, 0x4);
   	temp1 = _mm_xor_si128 (temp1, temp3);
   	temp3 = _mm_slli_si128 (temp3, 0x4);
   	temp1 = _mm_xor_si128 (temp1, temp3);
   	temp3 = _mm_slli_si128 (temp3, 0x4);
   	temp1 = _mm_xor_si128 (temp1, temp3); 
  	temp1 = _mm_xor_si128 (temp1, temp2); 
    	return temp1;     
}

void AES_128_Key_Expansion (const unsigned char *userkey,
			    unsigned char *key)
{
       __m128i temp1, temp2;
       __m128i *Key_Schedule = (__m128i*)key;
       temp1 = _mm_loadu_si128((__m128i*)userkey);
       Key_Schedule[0] = temp1;
       temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
       temp1 = AES_128_ASSIST(temp1, temp2);
       Key_Schedule[1] = temp1;
       temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
       temp1 = AES_128_ASSIST(temp1, temp2);
       Key_Schedule[2] = temp1;
       temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
       temp1 = AES_128_ASSIST(temp1, temp2);
       Key_Schedule[3] = temp1;
       temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
       temp1 = AES_128_ASSIST(temp1, temp2);
       Key_Schedule[4] = temp1;
       temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
       temp1 = AES_128_ASSIST(temp1, temp2);
       Key_Schedule[5] = temp1; 
       temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
       temp1 = AES_128_ASSIST(temp1, temp2);
       Key_Schedule[6] = temp1;
       temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
       temp1 = AES_128_ASSIST(temp1, temp2);
       Key_Schedule[7] = temp1;
       temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
       temp1 = AES_128_ASSIST(temp1, temp2);
       Key_Schedule[8] = temp1;
       temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
       temp1 = AES_128_ASSIST(temp1, temp2);
       Key_Schedule[9] = temp1;
       temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
       temp1 = AES_128_ASSIST(temp1, temp2);
       Key_Schedule[10] = temp1;
}
#else

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
#endif

void aes_load_iv(cipher_state *cs, u32 *iv)
{
	// Load IV - 96 bits
	cs->reg1 = *iv; iv++;
	cs->reg2 = *iv; iv++;
	cs->reg3 = *iv; iv++;
	// Set CTR to 1
	u8 ctr[4] = {0x00, 0x00, 0x00, 0x01};
	std::memcpy(&cs->reg4, ctr, 4);
}

void ctr_initialize_cipher(cipher_state *cs, u8 key[], u32 *iv)
{
#ifdef x86_INTRINSICS
	AES_128_Key_Expansion(key, (u8*)cs->rk);
#else
	KeyExpansion(key, cs->rk);
#endif
	aes_load_iv(cs, iv);
}

void aes_encrypt(cipher_state *cs, u32 keystream[])
{
#ifdef x86_INTRINSICS
	__m128i B_S = _mm_loadu_si128 ((__m128i*)&cs->reg1);
        __m128i B_K0 = _mm_loadu_si128 ((__m128i*)&cs->rk);
        __m128i B_K1 = _mm_loadu_si128 ((__m128i*)&cs->rk[4]);
        __m128i B_K2 = _mm_loadu_si128 ((__m128i*)&cs->rk[8]);
        __m128i B_K3 = _mm_loadu_si128 ((__m128i*)&cs->rk[12]);
        __m128i B_K4 = _mm_loadu_si128 ((__m128i*)&cs->rk[16]);
        __m128i B_K5 = _mm_loadu_si128 ((__m128i*)&cs->rk[20]);
        __m128i B_K6 = _mm_loadu_si128 ((__m128i*)&cs->rk[24]);
        __m128i B_K7 = _mm_loadu_si128 ((__m128i*)&cs->rk[28]);
        __m128i B_K8 = _mm_loadu_si128 ((__m128i*)&cs->rk[32]);
        __m128i B_K9 = _mm_loadu_si128 ((__m128i*)&cs->rk[36]);
        __m128i B_K10 = _mm_loadu_si128 ((__m128i*)&cs->rk[40]);

        B_S = _mm_xor_si128 (B_S, B_K0);
        B_S = _mm_aesenc_si128 (B_S, B_K1);
        B_S = _mm_aesenc_si128 (B_S, B_K2);
        B_S = _mm_aesenc_si128 (B_S, B_K3);
        B_S = _mm_aesenc_si128 (B_S, B_K4);
        B_S = _mm_aesenc_si128 (B_S, B_K5);
        B_S = _mm_aesenc_si128 (B_S, B_K6);
        B_S = _mm_aesenc_si128 (B_S, B_K7);
        B_S = _mm_aesenc_si128 (B_S, B_K8);
        B_S = _mm_aesenc_si128 (B_S, B_K9);
        B_S = _mm_aesenclast_si128 (B_S, B_K10);

        _mm_storeu_si128 ((__m128i*)keystream, B_S);
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

void state_update(cipher_state *cs)
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

void ctr_process_packet(cipher_state *cs, u8 *out, u8 *in, int size, int mode)
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

