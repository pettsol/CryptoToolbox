///////////////////////////////////////
// This implementation of HC-128     //
// was placed in the public domain   //
// by:                               //
//                                   // 
// Petter Solnoer - 16/04/2020       //
///////////////////////////////////////

#include "hc128.h"

#include <iostream>
#include <cstring>

void hc128_initialize(hc128_state *cs, uint8_t key[16], uint8_t iv[16])
{
	// The initialization of HC128 maps the key and IV to an initial state
	// held in the P and Q tables.
	uint32_t W[1280];

	// Stage 1: Expand key and IV into array W
	std::memcpy(W, key, 16); std::memcpy(&(W[4]), key, 16);
	std::memcpy(&(W[8]), iv, 16); std::memcpy(&(W[12]), iv, 16);

//	char hexKey[33];
//	string2hexString(hexKey, (uint8_t*)key, 16);
//	std::string printKey(hexKey, 32);

	for (int i = 16; i < 1280; i++)
	{
		W[i] = f2(W[i-2]) + W[i-7] + f1(W[i-15]) + W[i-16] + i;
	}
	
	/////////////////////////////////////////////
	// Stage 2: Extract P and Q from W
	for (int i = 0; i < 512; i++)
	{
		cs->P[i] = W[i+256];
		cs->Q[i] = W[i+768];
	}
	/////////////////////////////////////////////
	// Stage 3: Iterate cipher 1024 steps, and update P, Q with output
	//
	// We must perform operations modulo 512. This corresponds to performing
	// the operation, and extracting the bits with a bitmask 
	// 0001 1111 1111 = 0x1FF
	for (int i = 0; i < 512; i++)
	{
		cs->P[i] = ( cs->P[i] + g1(cs->P[(i-3)&0x1FF],
					cs->P[(i-10)&0x1FF],
					cs->P[(i-511)&0x1FF]) ) ^
			h1(cs, cs->P[(i-12)&0x1FF]);
	}

	for (int i = 0; i < 512; i++)
	{
		cs->Q[i] = ( cs->Q[i] + g2(cs->Q[(i-3)&0x1FF],
					cs->Q[(i-10)&0x1FF],
					cs->Q[(i-511)&0x1FF]) ) ^
			h2(cs, cs->Q[(i-12)&0x1FF]);
	}

}

void hc128_generate_keystream(hc128_state *cs, uint32_t *keystream, uint64_t size)
{
	// Generate keystream
	for (int i = 0; i <= (size-1)/4; i++)
	{
		int j = (i&0x1FF);
		if ( (i&0x3FF) < 512 )
		{
			// Operate on P
			cs->P[j] = cs->P[j] + g1(cs->P[(j-3)&0x1FF],
					cs->P[(j-10)&0x1FF],
					cs->P[(j-511)&0x1FF]);
			*keystream = h1(cs, cs->P[(j-12)&0x1FF]) ^ (cs->P[j]);
			keystream++;	
		} else {
			// Operate on Q
			cs->Q[j] = cs->Q[j] + g2(cs->Q[(j-3)&0x1FF],
					cs->Q[(j-10)&0x1FF],
					cs->Q[(j-511)&0x1FF]);
			*keystream = h2(cs, cs->Q[(j-12)&0x1FF]) ^ (cs->Q[j]);
			keystream++;
		}
	}
}

void hc128_process_packet(hc128_state *cs, uint8_t *output, uint8_t *input, uint64_t size)
{
	// Assert that message size is strictly greater than zero
	if ( size < 1 ) return;
		

	uint32_t keystream[(size-1)/4 +1];

	// Generate enough keystream
	hc128_generate_keystream(cs, keystream, size);

	int counter = 0;
	// Process a full word
	while ( size > 3 )
	{
		// Mix keystream and input to get output
		*((uint32_t*)output) = *((uint32_t*)input) ^ keystream[counter++];
		size -= 4; output += 4; input += 4; 
	}
	// Process the final < 4 bytes
	uint8_t *byteptr = (uint8_t*)&keystream[counter];
	for ( ; size > 0; size-- )
	{
		// Mix keystream to the final bytes
		*output = *input ^ *byteptr; byteptr++; output++; input++;
	}	
}
