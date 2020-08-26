///////////////////////////////////////
// This implementation of Poly1305   //
// was placed in the public domain   //
// by:                               //
//                                   // 
// Petter Solnoer - 25/08/2020       //
///////////////////////////////////////

#ifndef Poly1305_H
#define Poly1305_H

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

#define Poly1305_KEYLENGTH 64

void poly1305_mac(u8 *tag, u8 *msg, u8 *key);

inline void le_bytes_to_num(u8 *out_buf, u8 *in_buf)
{
	for (int i = 0; i<16; i++)
	{
		*out_buf[i] = *in_buf[15-i];
	}
}

inline void clamp(u8 r[16])
{
     r[3] &= 15;
     r[7] &= 15;
     r[11] &= 15;
     r[15] &= 15;
     r[4] &= 252;
     r[8] &= 252;
     r[12] &= 252;
}

#endif

