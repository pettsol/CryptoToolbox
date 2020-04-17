///////////////////////////////////////////
// This implementation of SHA-256 was    //
// placed in the public domain by:       //
//                                       //
// Petter Solnoer - 15/04/2020           //
///////////////////////////////////////////

#include "../../../HexEncoder/encoder.h"
#include "sha-256.h"
#include "sha-256-tables.h"

#include <cstring>
#include <iostream>

// Each message must be padded to be a multiple of 512 bits
void pad_message(u8 *message, u64 size)
{
	message += size;

	u8 one = 1;

	// Append a 1 bit followed by zeros.
	// Because we operate on BYTES, a 1
	// bit corresponds for a hex-8 followed
	// by a hex-0. I.e. 1000 0000
	*message = 0x80; message++;

	int k = 0;

	while ( ((size + 1 + k) % 64) != 56 )
	{
		*message = 0; message++; k++;
	}
	// Append the size in bitlength. Note that again
	// we must transform to little-endian format!
	u64 bit_length = 8*size;
	u8 *tmp = (u8*) message;
	*tmp = (u8)(bit_length >> 56); tmp++;
	*tmp = (u8)(bit_length >> 48); tmp++;
	*tmp = (u8)(bit_length >> 40); tmp++;
	*tmp = (u8)(bit_length >> 32); tmp++;
	*tmp = (u8)(bit_length >> 24); tmp++;
	*tmp = (u8)(bit_length >> 16); tmp++;
	*tmp = (u8)(bit_length >> 8); tmp++;
	*tmp = (u8)(bit_length);
}

void process_message(u32 *digest, u32 *message, u64 size)
{
	int n = 0;
	// Declare message to hold padded text
	if ( (size + 1)%64 > 56 )
	{
		n = (size/64)*64 + 128;
	} else {
		n = (size/64)*64 + 64;
	}
	u32 msg[n/4];

	// Compute the number of 512 bit blocks
	int N = n / 64;

	std::memcpy(msg, message, size);
	// Pad message to full 512 bit blocks
	
	pad_message( (u8*)msg, size );

	// State to hold message schedule
	// and working variables
	sha_256_state ss;

	// Set the initial hash value
	// from predefined table
	for (int i = 0; i < 8; i++) {
		ss.digest[i] = H0[i];
	}

	// Temporary variables T1, T2
	u32 T1, T2;

	u8* byte_ptr = (u8*)msg;
	// Iterate through each 512-bit block
	for ( int i = 1; i <= N; i++ )
	{
		// Prepare the message schedule
		for ( int t = 0; t < 64; t++ )
		{
			if (t < 16) {
				// SHA-256 specification is big-endian.
				ss.W[t] = (byte_ptr[64*(i-1) + 4*t] << 24) |
					(byte_ptr[64*(i-1) + 4*t+1] << 16) |
					(byte_ptr[64*(i-1) + 4*t+2] << 8) |
					(byte_ptr[64*(i-1) + 4*t+3]);
			} else {
				ss.W[t] = sigma_1(ss.W[t-2]) +
							ss.W[t-7] +
							sigma_0(ss.W[t-15]) +
							ss.W[t-16];
			}
		}
		// Initialize the eight working variables
		// Easily done by memcpy (size = 8 * 4 = 32 bytes)
		std::memcpy(ss.working_variables, ss.digest, 32);
		//
		for ( int t = 0; t < 64; t++ )
		{
			T1 = ss.working_variables[7] + SIGMA_1(ss.working_variables[4]) +
				ch(ss.working_variables[4], ss.working_variables[5], ss.working_variables[6]) +
				K[t] + ss.W[t];

			T2 = SIGMA_0(ss.working_variables[0]) +
				maj(ss.working_variables[0],
				ss.working_variables[1],
				ss.working_variables[2]);

			ss.working_variables[7] = ss.working_variables[6];
			ss.working_variables[6] = ss.working_variables[5];
			ss.working_variables[5] = ss.working_variables[4];
			ss.working_variables[4] = ss.working_variables[3] + T1;
			ss.working_variables[3] = ss.working_variables[2];
			ss.working_variables[2] = ss.working_variables[1];
			ss.working_variables[1] = ss.working_variables[0];
			ss.working_variables[0] = T1 + T2;
		}
		
		// Compute the i'th intermediate hash value
		ss.digest[0] = ss.working_variables[0] + ss.digest[0];
		ss.digest[1] = ss.working_variables[1] + ss.digest[1];
		ss.digest[2] = ss.working_variables[2] + ss.digest[2];
		ss.digest[3] = ss.working_variables[3] + ss.digest[3];
		ss.digest[4] = ss.working_variables[4] + ss.digest[4];
		ss.digest[5] = ss.working_variables[5] + ss.digest[5];
		ss.digest[6] = ss.working_variables[6] + ss.digest[6];
		ss.digest[7] = ss.working_variables[7] + ss.digest[7];
	}
	// Make sure output is little-endian
	for (int i = 0; i < 8; i++)
	{
		*digest = ((ss.digest[i] << 24) & 0xff000000) |
		       	((ss.digest[i] << 8) & 0x00ff0000) |
		       	((ss.digest[i] >> 8) & 0x0000ff00) |
		       	((ss.digest[i] >> 24) & 0x000000ff); digest++;
	}
	//std::memcpy(digest, ss.digest, 32);
}
