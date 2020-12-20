///////////////////////////////////////////
// This implementation of SHA-256 was    //
// placed in the public domain by:       //
//                                       //
// Petter Solnoer - 15/04/2020           //
///////////////////////////////////////////

#ifndef SHA_256_H
#define SHA_256_H

#include "sha-256-tables.h"

void pad_message(uint8_t *message, uint64_t size);
void sha256_process_message(uint8_t *digest, uint8_t *message, uint64_t size);

struct sha_256_state
{
	// Message schedule
	uint32_t W[64];

	// Working variables
	// a = 0; b = 1; ... ; h = 7;.
	uint32_t working_variables[8];

	// Holding the state of the hash
	uint32_t digest[8];
};

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
	return ( ((x) & (y)) ^ (~(x) & (z)) );
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
	return ( ( (x) & (y) ) ^ ( (x) & (z) ) ^ ( (y) & (z) ) );
}

inline uint32_t SIGMA_0(uint32_t x)
{
	return ( ROTR_32(x,2) ^ ROTR_32(x,13)  ^ ROTR_32(x,22) );
}

inline uint32_t SIGMA_1(uint32_t x)
{
	return ( ROTR_32(x,6) ^ ROTR_32(x,11) ^ ROTR_32(x,25) );
}

inline uint32_t sigma_0(uint32_t x)
{
	return ( ROTR_32(x,7) ^ ROTR_32(x,18) ^ SHR(x,3) ); 
}

inline uint32_t sigma_1(uint32_t x)
{
	return ( ROTR_32(x,17) ^ ROTR_32(x,19) ^ SHR(x,10) );
}

#endif
