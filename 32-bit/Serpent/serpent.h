#ifndef SERPENT_H
#define SERPENT_H

#include "tables.h"

#define N_ROUNDS 32


#define ROTL_32(x, n) ( ((x) << (n)) | ((x) >> (32-n)) )

struct cipher_state{
	u32 RK[4*N_ROUNDS];
};

void key_schedule(cipher_state *ctx, u8 *key, int size);
void process_packet(cipher_state *ctx, u32 *out, u32 *in, u64 size);

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

inline void ARK(cipher_state *ctx, u32 *r0, u32 *r1, u32 *r2, u32 *r3, int N)
{
	// RK's are held in a one dimensional array.
	*r0 = (*r0) ^ (ctx->RK[4*N]);
	*r1 = (*r1) ^ (ctx->RK[4*N + 1]);
	*r2 = (*r2) ^ (ctx->RK[4*N + 2]);
	*r3 = (*r3) ^ (ctx->RK[4*N + 3]);
}

inline void rounds(cipher_state *ctx, u32 *r0, u32 *r1, u32 *r2, u32 *r3)
{
	// A fifth working register is needed
	u32 *r4 = new u32;;

	// Rounds
	/* 0 */ ARK(ctx, r0, r1, r2, r3, 0); S0(r0, r1, r2, r3, r4); LT(r1, r4, r2, r0);
	/* 1 */ ARK(ctx, r1, r4, r2, r0, 1); S1(r1, r4, r2, r0, r3); LT(r2, r1, r0, r4);
	/* 2 */ ARK(ctx, r2, r1, r0, r4, 2); S2(r2, r1, r0, r4, r3); LT(r0, r4, r1, r3);
	/* 3 */ ARK(ctx, r0, r4, r1, r3, 3); S3(r0, r4, r1, r3, r2); LT(r4, r1, r3, r2);
	/* 4 */ ARK(ctx, r4, r1, r3, r2, 4); S4(r4, r1, r3, r2, r0); LT(r1, r0, r4, r2);
	/* 5 */ ARK(ctx, r1, r0, r4, r2, 5); S5(r1, r0, r4, r2, r3); LT(r0, r2, r1, r4);
	/* 6 */ ARK(ctx, r0, r2, r1, r4, 6); S6(r0, r2, r1, r4, r3); LT(r0, r2, r3, r1);
	/* 7 */ ARK(ctx, r0, r2, r3, r1, 7); S7(r0, r2, r3, r1, r4); LT(r4, r1, r2, r0);

	/* 8 */ ARK(ctx, r4, r1, r2, r0, 8); S0(r4, r1, r2, r0, r3); LT(r1, r3, r2, r4);
	/* 9 */ ARK(ctx, r1, r3, r2, r4, 9); S1(r1, r3, r2, r4, r0); LT(r2, r1, r4, r3);
	/* 10 */ ARK(ctx, r2, r1, r4, r3, 10); S2(r2, r1, r4, r3, r0); LT(r4, r3, r1, r0);
	/* 11 */ ARK(ctx, r4, r3, r1, r0, 11); S3(r4, r3, r1, r0, r2); LT(r3, r1, r0, r2);
	/* 12 */ ARK(ctx, r3, r1, r0, r2, 12); S4(r3, r1, r0, r2, r4); LT(r1, r4, r3, r2);
	/* 13 */ ARK(ctx, r1, r4, r3, r2, 13); S5(r1, r4, r3, r2, r0); LT(r4, r2, r1, r3);
	/* 14 */ ARK(ctx, r4, r2, r1, r3, 14); S6(r4, r2, r1, r3, r0); LT(r4, r2, r0, r1);
	/* 15 */ ARK(ctx, r4, r2, r0, r1, 15); S7(r4, r2, r0, r1, r3); LT(r3, r1, r2, r4);
	
	/* 16 */ ARK(ctx, r3, r1, r2, r4, 16); S0(r3, r1, r2, r4, r0); LT(r1, r0, r2, r3);
	/* 17 */ ARK(ctx, r1, r0, r2, r3, 17); S1(r1, r0, r2, r3, r4); LT(r2, r1, r3, r0);
	/* 18 */ ARK(ctx, r2, r1, r3, r0, 18); S2(r2, r1, r3, r0, r4); LT(r3, r0, r1, r4);
	/* 19 */ ARK(ctx, r3, r0, r1, r4, 19); S3(r3, r0, r1, r4, r2); LT(r0, r1, r4, r2);
	/* 20 */ ARK(ctx, r0, r1, r4, r2, 20); S4(r0, r1, r4, r2, r3); LT(r1, r3, r0, r2);
	/* 21 */ ARK(ctx, r1, r3, r0, r2, 21); S5(r1, r3, r0, r2, r4); LT(r3, r2, r1, r0);
	/* 22 */ ARK(ctx, r3, r2, r1, r0, 22); S6(r3, r2, r1, r0, r4); LT(r3, r2, r4, r1);
	/* 23 */ ARK(ctx, r3, r2, r4, r1, 23); S7(r3, r2, r4, r1, r0); LT(r0, r1, r2, r3);
	
	/* 24 */ ARK(ctx, r0, r1, r2, r3, 24); S0(r0, r1, r2, r3, r4); LT(r1, r4, r2, r0);
	/* 25 */ ARK(ctx, r1, r4, r2, r0, 25); S1(r1, r4, r2, r0, r3); LT(r2, r1, r0, r4);
	/* 26 */ ARK(ctx, r2, r1, r0, r4, 26); S2(r2, r1, r0, r4, r3); LT(r0, r4, r1, r3);
	/* 27 */ ARK(ctx, r0, r4, r1, r3, 27); S3(r0, r4, r1, r3, r2); LT(r4, r1, r3, r2);
	/* 28 */ ARK(ctx, r4, r1, r3, r2, 28); S4(r4, r1, r3, r2, r0); LT(r1, r0, r4, r2);
	/* 29 */ ARK(ctx, r1, r0, r4, r2, 29); S5(r1, r0, r4, r2, r3); LT(r0, r2, r1, r4);
	/* 30 */ ARK(ctx, r0, r2, r1, r4, 30); S6(r0, r2, r1, r4, r3); LT(r0, r2, r3, r1);
	// In the last round, the LT is replaced with a final key addition
	/* 31 */ ARK(ctx, r0, r2, r3, r1, 31); S7(r0, r2, r3, r1, r4); ARK(ctx, r4, r1, r2, r0, 32);

	// Output the correct order. R1, R2 holds the correct values already.
	*r3 = *r0;
	*r0 = *r4;

	// Clean up
	delete r4;
}


#endif
