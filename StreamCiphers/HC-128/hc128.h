///////////////////////////////////////
// This implementation of HC-128     //
// was placed in the public domain   //
// by:                               //
//                                   // 
// Petter Solnoer - 16/04/2020       //
///////////////////////////////////////


#ifndef HC_128_H
#define HC_128_H

#include <stdint.h>
#include <fstream>

// Force inline on compilers
#ifdef _MSC_VER
	#define forceinline __forceinline
#elif defined(__GNUC__)
	#define forceinline inline __attribute__((__always_inline__))
#elif defined(__CLANG__)
	#if __has_attribute(__always_inline__)
		#define forceinline inline __attribute__((__always_inline__))
	#else
		#define forceinline inline
	#endif
#else
	#define forceinline inline
#endif

#define ROTR_32(x,n) ( (x >> (n))  | (x << (32-(n)) ) )
#define ROTL_32(x,n) ROTR_32(x, (32-(n)))

#define HC128_KEYLENGTH 16
#define HC128_IV_SIZE 16

struct hc128_state{
	uint32_t P[512];
	uint32_t Q[512];
};

void hc128_initialize(hc128_state *cs, uint8_t key[16], uint8_t iv[16]);
void hc128_generate_keystream(hc128_state, uint32_t *keystream, uint64_t size);
void hc128_process_packet(hc128_state *cs, uint8_t *output, uint8_t *input, uint64_t size);

inline uint32_t f1(uint32_t x)
{
	return ( ROTR_32(x,7) ^ ROTR_32(x,18) ^ (x >> 3) );
}

inline uint32_t f2(uint32_t x)
{
	return ( ROTR_32(x,17) ^ ROTR_32(x,19) ^ (x >> 10) );
}

inline uint32_t g1(uint32_t x, uint32_t y, uint32_t z)
{
	return ( ( ROTR_32(x,10) ^ ROTR_32(z,23) ) + ROTR_32(y,8) );
}

inline uint32_t g2(uint32_t x, uint32_t y, uint32_t z)
{
	return ( ( ROTL_32(x,10) ^ ROTL_32(z,23) ) + ROTL_32(y,8) );
}

inline uint32_t h1(hc128_state *cs, uint32_t x)
{
	// Do something with Q
	return ( cs->Q[(uint8_t)x] + cs->Q[(256 + ((uint8_t)(x >> 16) ))]  );
}

inline uint32_t h2(hc128_state *cs, uint32_t x)
{
	// Do something with P
	return ( cs->P[(uint8_t)x] + cs->P[(256 + ((uint8_t)(x >> 16) ))]  );
}

#endif
