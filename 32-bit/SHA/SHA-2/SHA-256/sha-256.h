///////////////////////////////////////////
// This implementation of SHA-256 was    //
// placed in the public domain by:       //
//                                       //
// Petter Solnoer - 15/04/2020           //
///////////////////////////////////////////

#ifndef SHA_256_H
#define SHA_256_H

#include "sha-256-tables.h"

void pad_message(u8 *message, u64 size);
void process_message(u32 *digest, u32 *message, u64 size);

struct sha_256_state
{
	// Message schedule
	u32 W[64];

	// Working variables
	// a = 0; b = 1; ... ; h = 7;.
	u32 working_variables[8];

	// Holding the state of the hash
	u32 digest[8];
};

inline u32 ch(u32 x, u32 y, u32 z)
{
	return ( ((x) & (y)) ^ (~(x) & (z)) );
}

inline u32 maj(u32 x, u32 y, u32 z)
{
	return ( ( (x) & (y) ) ^ ( (x) & (z) ) ^ ( (y) & (z) ) );
}

inline u32 SIGMA_0(u32 x)
{
	return ( ROTR_32(x,2) ^ ROTR_32(x,13)  ^ ROTR_32(x,22) );
}

inline u32 SIGMA_1(u32 x)
{
	return ( ROTR_32(x,6) ^ ROTR_32(x,11) ^ ROTR_32(x,25) );
}

inline u32 sigma_0(u32 x)
{
	return ( ROTR_32(x,7) ^ ROTR_32(x,18) ^ SHR(x,3) ); 
}

inline u32 sigma_1(u32 x)
{
	return ( ROTR_32(x,17) ^ ROTR_32(x,19) ^ SHR(x,10) );
}

#endif
