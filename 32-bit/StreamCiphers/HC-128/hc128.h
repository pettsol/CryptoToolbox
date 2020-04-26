///////////////////////////////////////
// This implementation of HC-128     //
// was placed in the public domain   //
// by:                               //
//                                   // 
// Petter Solnoer - 16/04/2020       //
///////////////////////////////////////


#ifndef HC_128_H
#define HC_128_H

#include <climits>
#include <fstream>

// Verify that the data types are as expected

#if (UCHAR_MAX != 0xFFU)
#error UCHAR IS NOT 8 BITS
#endif

#if (USHRT_MAX != 0xFFFFU)
#error USHORT IS NOT 16 BITS
#endif

#if (UINT_MAX != 0xFFFFFFFFU)
#error UINT IS NOT 32 BITS
#endif

#if (ULLONG_MAX != 0xFFFFFFFFFFFFFFFFU)
#error ULONGLONG IS NOT 64 BITS
#endif

// Define sizes

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

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
	u32 P[512];
	u32 Q[512];
};

void hc128_initialize(hc128_state *cs, u32 key[4], u32 iv[4]);
void hc128_generate_keystream(hc128_state, u32 *keystream, u64 size);
void hc128_process_packet(hc128_state *cs, u8 *output, u8 *input, u64 size);

inline u32 f1(u32 x)
{
	return ( ROTR_32(x,7) ^ ROTR_32(x,18) ^ (x >> 3) );
}

inline u32 f2(u32 x)
{
	return ( ROTR_32(x,17) ^ ROTR_32(x,19) ^ (x >> 10) );
}

inline u32 g1(u32 x, u32 y, u32 z)
{
	return ( ( ROTR_32(x,10) ^ ROTR_32(z,23) ) + ROTR_32(y,8) );
}

inline u32 g2(u32 x, u32 y, u32 z)
{
	return ( ( ROTL_32(x,10) ^ ROTL_32(z,23) ) + ROTL_32(y,8) );
}

inline u32 h1(hc128_state *cs, u32 x)
{
	// Do something with Q
	return ( cs->Q[(u8)x] + cs->Q[(256 + ((u8)(x >> 16) ))]  );
}

inline u32 h2(hc128_state *cs, u32 x)
{
	// Do something with P
	return ( cs->P[(u8)x] + cs->P[(256 + ((u8)(x >> 16) ))]  );
}

#endif
