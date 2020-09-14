///////////////////////////////////////
// This implementation of HMAC with  //
// SHA-256 was placed in the public  //
// domain by:                        //
//                                   // 
// Petter Solnoer - 15/04/2020       //
///////////////////////////////////////

#ifndef HMAC_H
#define HMAC_H

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

#define HMAC_KEYLENGTH 64

struct hmac_state{
	u8 key[HMAC_KEYLENGTH];

	u8 inner_key[HMAC_KEYLENGTH];
	u8 outer_key[HMAC_KEYLENGTH];
};

static const u8 ipad = 0x36;
static const u8 opad = 0x5c;

void hmac_load_key(hmac_state *ctx, u8* key, int B);
void tag_generation(hmac_state *ctx, u8* tag, u8 *message, u64 dataLength, int tagSize);
int tag_validation(hmac_state *ctx, u8 *tag, u8 *message, u64 dataLength, int tagSize);

#endif
