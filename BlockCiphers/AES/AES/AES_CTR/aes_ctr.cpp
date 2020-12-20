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

#ifdef DEBUG
#include "../../../../Encoders/Hex/encoder.h"
#endif


uint32_t RotByte(uint32_t word)
{
	uint32_t ret = ((word << 24) | (word >> 8));
	return ret;
}

uint32_t SubByte(uint32_t word)
{
	uint32_t ret;
	ret = Sbox[(uint8_t)word];
	ret = ret ^ (Sbox[(uint8_t)(word >> 8)] << 8);
	ret = ret ^ (Sbox[(uint8_t)(word >> 16)] << 16);
	ret = ret ^ (Sbox[(uint8_t)(word >> 24)] << 24);
	return ret;
}

void aes_key_expansion(uint8_t key[], uint32_t key_schedule[])
{
	uint32_t temp;
	int i = 0;

	
	while (i < 4)
	{
		key_schedule[i] = (uint32_t) ( ((uint32_t)key[4*i]) | (((uint32_t)key[4*i+1]) << 8) |
				(((uint32_t)key[4*i+2]) << 16) | (((uint32_t)key[4*i+3]) << 24) );
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

void aes_load_iv(aes_state *cs, uint8_t nonce[12])
{
	uint32_t *w_ptr = (uint32_t*)nonce;
	// Load IV - 96 bits
	cs->reg1 = *w_ptr; w_ptr++;
	cs->reg2 = *w_ptr; w_ptr++;
	cs->reg3 = *w_ptr; w_ptr++;
	// Set CTR to 1
	uint8_t ctr[4] = {0x00, 0x00, 0x00, 0x01};
	std::memcpy(&cs->reg4, ctr, 4);
}

void aes_load_key(aes_state *cs, uint8_t key[16])
{
	aes_key_expansion(key, cs->rk);
}
/*
void aes_ctr_initialize(aes_state *cs, uint8_t key[16], uint8_t iv[12])
{
	aes_key_expansion(key, cs->rk);
	aes_load_iv(cs, (uint32_t*)iv);
}
*/

void aes_encrypt(aes_state *cs, uint32_t keystream[])
{
	// Save the state
	uint32_t state[4];
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
}

void state_update(aes_state *cs)
{
	// Increment the counter. Note that the CTR is defined in
	// big endian convention.
	uint32_t tmp = (((cs->reg4) >> 24) & 0x000000ff) |
		  (((cs->reg4) >> 8) & 0x0000ff00) |
		  (((cs->reg4) << 8) & 0x00ff0000) |
		  (((cs->reg4) << 24) & 0xff000000);

	tmp++;

	cs->reg4 = (((tmp) >> 24) & 0x000000ff) |
		   (((tmp) >> 8) & 0x0000ff00) |
		   (((tmp) << 8) & 0x00ff0000) |
		   (((tmp) << 24) & 0xff000000);
}

void aes_ctr_process_packet(aes_state *cs, uint8_t *out, uint8_t *in, int size)
{

	uint32_t *w_ptr_in = (uint32_t*)in;;
	uint32_t *w_ptr_out = (uint32_t*)out;
	uint32_t *w_state_ptr;
	uint32_t keystream[4] = {0,0,0,0};
	
	while (size > 0)
	{
		aes_encrypt(cs, keystream);

#ifdef DEBUG
		// Print the generated keystream
		char hex_ks[33];
		string2hexString(hex_ks, (uint8_t*)keystream, 16);
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
			uint8_t *tmp_ptr = (uint8_t*) w_state_ptr;
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
				uint8_t *byte_ptr_out = (uint8_t*) w_ptr_out;
				uint8_t *byte_ptr_in = (uint8_t*) w_ptr_in;
				while (size > 0)
				{
					*byte_ptr_out = (*byte_ptr_in) ^ ( (uint8_t)(keystream[k] >> (24 - (8*(l--)))));
					byte_ptr_out++; byte_ptr_in++;
					size -= 1;
				}
			}

			state_update(cs); 

		}
	}
}

