#ifndef MD5_H
#define MD5_H

/* MD5.H - header file for MD5C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.




Rivest                                                          [Page 8]

 
RFC 1321              MD5 Message-Digest Algorithm            April 1992


These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* LOCAL CHANGES MADE BY PETTER SOLNOER */

#include <climits>
#include <fstream>

// Check that the size of
// data types are as 
// expected

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

// The following is required to force inline on compilers

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

// We can now typedef variables of fixed sizes

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;




/* MD5 context. */
typedef struct {
  u32 state[4];                                   /* state (ABCD) */
  u32 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  u8 buffer[64];                         /* input buffer */
} MD5_CTX;

void MD5Init(MD5_CTX *);
void MD5Update(MD5_CTX *, u8 *, u32);
void MD5Final(u8 [16], MD5_CTX *);

void MD5_process_packet(MD5_CTX *cs, u8 digest[16], u8 *input, u32 size);


#endif
