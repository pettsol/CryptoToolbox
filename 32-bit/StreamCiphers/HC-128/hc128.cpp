///////////////////////////////////////
// This implementation of HC-128     //
// was placed in the public domain   //
// by:                               //
//                                   // 
// Petter Solnoer - 16/04/2020       //
///////////////////////////////////////

#include "hc128.h"
#include "../../HexEncoder/encoder.h"

#include <iostream>
#include <cstring>

void hc128_initialize(hc128_state *cs, u32 key[4], u32 iv[4])
{
	// The initialization of HC128 maps the key and IV to an initial state
	// held in the P and Q tables.
	u32 W[1280];

	// Stage 1: Expand key and IV into array W
	std::memcpy(W, key, 16); std::memcpy(&(W[4]), key, 16);
	std::memcpy(&(W[8]), iv, 16); std::memcpy(&(W[12]), iv, 16);

	char hexKey[33];
	string2hexString(hexKey, (u8*)key, 16);
	std::string printKey(hexKey, 32);
	std::cout << "Key: " << printKey << std::endl;

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

void hc128_generate_keystream(hc128_state *cs, u32 *keystream, u64 size)
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

void hc128_process_packet(hc128_state *cs, u8 *output, u8 *input, u64 size)
{
	u32 keystream[(size-1)/4 +1];

	// Generate enough keystream
	hc128_generate_keystream(cs, keystream, size);

	int counter = 0;
	// Process a full word
	while ( size > 3 )
	{
		// Mix keystream and input to get output
		*((u32*)output) = *((u32*)input) ^ keystream[counter++];
		size -= 4; output += 4; input += 4; 
	}
	// Process the final < 4 bytes
	u8 *byteptr = (u8*)&keystream[counter];
	for ( ; size > 0; size-- )
	{
		// Mix keystream to the final bytes
		*output = *input ^ *byteptr; byteptr++; output++; input++;
	}	
}
