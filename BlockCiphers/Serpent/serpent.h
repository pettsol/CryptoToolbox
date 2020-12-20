#ifndef SERPENT_H
#define SERPENT_H

#include <stdint.h>
#include <iostream>
#include <fstream>

#define SOSEMANUK_H

#ifdef SOSEMANUK_H
	#define N_ROUNDS 25
#else
	#define N_ROUNDS 33
#endif

#define ROTL_32(x, n) ( ((x) << (n)) | ((x) >> (32-n)) )

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

struct serpent_state{
	uint32_t RK[4*N_ROUNDS];
};

void serpent_key_schedule(serpent_state *ctx, uint8_t *key, int size);
void serpent_process_packet(serpent_state *ctx, uint32_t *out, uint32_t *in, uint64_t size);
#ifdef SOSEMANUK_H
void serpent1(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3);
#endif
inline void S0(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3, uint32_t *r4)
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

inline void S1(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3, uint32_t *r4)
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

inline void S2(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3, uint32_t *r4)
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

inline void S3(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3, uint32_t *r4)
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

inline void S4(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3, uint32_t *r4)
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

inline void S5(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3, uint32_t *r4)
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

inline void S6(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3, uint32_t *r4)
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

inline void S7(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3, uint32_t *r4)
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

inline void LT(uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3)
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

inline void ARK(serpent_state *ctx, uint32_t *r0, uint32_t *r1, uint32_t *r2, uint32_t *r3, int N)
{
	// RK's are held in a one dimensional array.
	*r0 = (*r0) ^ (ctx->RK[4*N]);
	*r1 = (*r1) ^ (ctx->RK[4*N + 1]);
	*r2 = (*r2) ^ (ctx->RK[4*N + 2]);
	*r3 = (*r3) ^ (ctx->RK[4*N + 3]);
}

#endif
