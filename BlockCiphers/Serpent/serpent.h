#ifndef SERPENT_H
#define SERPENT_H

#include <iostream>
#include <climits>
#include <fstream>

#define SOSEMANUK_H

#ifdef SOSEMANUK_H
	#define N_ROUNDS 25
#else
	#define N_ROUNDS 33
#endif

#define ROTL_32(x, n) ( ((x) << (n)) | ((x) >> (32-n)) )

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

struct serpent_state{
	u32 RK[4*N_ROUNDS];
};

void serpent_key_schedule(serpent_state *ctx, u8 *key, int size);
void serpent_process_packet(serpent_state *ctx, u32 *out, u32 *in, u64 size);
#ifdef SOSEMANUK_H
void serpent1(u32 *r0, u32 *r1, u32 *r2, u32 *r3);
#endif
inline void S0(u32 *r0, u32 *r1, u32 *r2, u32 *r3, u32 *r4)
{
	*r3 ^= *r0; *r4 = *r1;
        *r1 &= *r3; *r4 ^= *r2;
        *r1 ^= *r0; *r0 |= *r3;
	*r0 ^= *r4; *r4 ^= *r3;
	*r3 ^= *r2; *r2 |= *r1;
	*r2 ^= *r4; *r4 = ~(*r4);
	*r4 |= *r1; *r1 ^= *r3;
	*r1 ^= *r4; *r3 |= *r0;
	*r1 ^= *r3; *r4 ^= *r3;

	// Output should be r1 || r4 || r2 || r0
}

inline void S1(u32 *r0, u32 *r1, u32 *r2, u32 *r3, u32 *r4)
{
        *r0 = ~(*r0); *r2 = ~(*r2);
        *r4 = *r0; *r0 &= *r1;
        *r2 ^= *r0; *r0 |= *r3;
        *r3 ^= *r2; *r1 ^= *r0;
        *r0 ^= *r4; *r4 |= *r1;
        *r1 ^= *r3; *r2 |= *r0;
        *r2 &= *r4; *r0 ^= *r1;
        *r1 &= *r2; *r1 ^= *r0;
        *r0 &= *r2; *r0 ^= *r4;

        // Output should be r2 || r0 || r3 || r1

}

inline void S2(u32 *r0, u32 *r1, u32 *r2, u32 *r3, u32 *r4)
{
        *r4 = *r0; *r0 &= *r2;
        *r0 ^= *r3; *r2 ^= *r1;
        *r2 ^= *r0; *r3 |= *r4;
        *r3 ^= *r1; *r4 ^= *r2;
        *r1 = *r3; *r3 |= *r4;
        *r3 ^= *r0; *r0 &= *r1;
        *r4 ^= *r0; *r1 ^= *r3;
        *r1 ^= *r4; *r4 = ~(*r4);

        // Output should be r2 || r3 || r1 || r4

}

inline void S3(u32 *r0, u32 *r1, u32 *r2, u32 *r3, u32 *r4)
{
        *r4 = *r0; *r0 |= *r3;
        *r3 ^= *r1; *r1 &= *r4;
        *r4 ^= *r2; *r2 ^= *r3;
        *r3 &= *r0; *r4 |= *r1;
        *r3 ^= *r4; *r0 ^= *r1;
        *r4 &= *r0; *r1 ^= *r3;
        *r4 ^= *r2; *r1 |= *r0;
        *r1 ^= *r2; *r0 ^= *r3;
        *r2 = *r1; *r1 |= *r3;
	*r1 ^= *r0;

	// r1 || r2 || r3 || r4

}

inline void S4(u32 *r0, u32 *r1, u32 *r2, u32 *r3, u32 *r4)
{
        *r1 ^= *r3; *r3 = ~(*r3);
        *r2 ^= *r3; *r3 ^= *r0;
        *r4 = *r1; *r1 &= *r3;
        *r1 ^= *r2; *r4 ^= *r3;
        *r0 ^= *r4; *r2 &= *r4;
        *r2 ^= *r0; *r0 &= *r1;
        *r3 ^= *r0; *r4 |= *r1;
        *r4 ^= *r0; *r0 |= *r3;
        *r0 ^= *r2; *r2 &= *r3;
	*r0 = ~(*r0); *r4 ^= *r2;

}

inline void S5(u32 *r0, u32 *r1, u32 *r2, u32 *r3, u32 *r4)
{
	*r0 ^= *r1; *r1 ^= *r3;
	*r3 = ~(*r3); *r4 = *r1;
	*r1 &= *r0; *r2 ^= *r3;
	*r1 ^= *r2; *r2 |= *r4;
	*r4 ^= *r3; *r3 &= *r1;
	*r3 ^= *r0; *r4 ^= *r1;
	*r4 ^= *r2; *r2 ^= *r0;
	*r0 &= *r3; *r2 = ~(*r2);
	*r0 ^= *r4; *r4 |= *r3;
	*r2 ^= *r4;

	// r1 || r3 || r0 || r2

}

inline void S6(u32 *r0, u32 *r1, u32 *r2, u32 *r3, u32 *r4)
{
	*r2 = ~(*r2); *r4 = *r3;
	*r3 &= *r0; *r0 ^= *r4;
	*r3 ^= *r2; *r2 |= *r4;
	*r1 ^= *r3; *r2 ^= *r0;
	*r0 |= *r1; *r2 ^= *r1;
	*r4 ^= *r0; *r0 |= *r3;
	*r0 ^= *r2; *r4 ^= *r3;
	*r4 ^= *r0; *r3 = ~(*r3);
	*r2 &= *r4; *r2 ^= *r3;
}

inline void S7(u32 *r0, u32 *r1, u32 *r2, u32 *r3, u32 *r4)
{
	*r4 = *r1; *r1 |= *r2;
	*r1 ^= *r3; *r4 ^= *r2;
	*r2 ^= *r1; *r3 |= *r4;
	*r3 &= *r0; *r4 ^= *r2;
	*r3 ^= *r1; *r1 |= *r4;
	*r1 ^= *r0; *r0 |= *r4;
	*r0 ^= *r2; *r1 ^= *r4;
	*r2 ^= *r1; *r1 &= *r0;
	*r1 ^= *r4; *r2 = ~(*r2);
	*r2 |= *r0; *r4 ^= *r2;
}

inline void LT(u32 *r0, u32 *r1, u32 *r2, u32 *r3)
{
	*r0 = ROTL_32(*r0, 13);
	*r2 = ROTL_32(*r2, 3);
	*r1 = (*r1) ^ (*r0) ^ (*r2);
	*r3 = (*r3) ^ (*r2) ^ ((*r0) << 3);
	*r1 = ROTL_32(*r1, 1);
	*r3 = ROTL_32(*r3, 7);
	*r0 = (*r0) ^ (*r1) ^ (*r3);
	*r2 = (*r2) ^ (*r3) ^ ((*r1) << 7);
	*r0 = ROTL_32(*r0, 5);
	*r2 = ROTL_32(*r2, 22);
}

inline void ARK(serpent_state *ctx, u32 *r0, u32 *r1, u32 *r2, u32 *r3, int N)
{
	// RK's are held in a one dimensional array.
	*r0 = (*r0) ^ (ctx->RK[4*N]);
	*r1 = (*r1) ^ (ctx->RK[4*N + 1]);
	*r2 = (*r2) ^ (ctx->RK[4*N + 2]);
	*r3 = (*r3) ^ (ctx->RK[4*N + 3]);
}

#endif
