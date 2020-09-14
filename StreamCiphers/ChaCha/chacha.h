#ifndef CHACHA_H
#define CHACHA_H

#include <climits>

// Check the sizes
#if (UCHAR_MAX != 0xFFU)
#error UCHAR IS NOT 8 BITS
#endif

#if (USHRT_MAX != 0xFFFFU)
#error USHRT IS NOT 16 BITS
#endif

#if (UINT_MAX != 0xFFFFFFFFU)
#error UINT IS NOT 32 BITS
#endif

#if (ULLONG_MAX != 0xFFFFFFFFFFFFFFFFU)
#error ULONGLONG IS NOT 64 BITS
#endif

// define sizes
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

// Force inline
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

#define ROTR_32(x,n) ( (x >> (n)) | (x << (32-(n)) ) )
#define ROTL_32(x,n) ROTR_32(x,(32-(n)))

struct chacha_state{
	u32 state[16];
};

void chacha20_initialize(chacha_state *cs, u32 key[8], u32 nonce[3]);
void chacha20_block(chacha_state *cs, u32 counter, u32 *keystream);
void chacha20_process_packet(chacha_state *cs, u8 *output, u8 *input, u64 size);
void test_q(u32 *input, u32 *output);
void byte_swap(u8 *output, u8 *input, int size);

inline void q_round(chacha_state *cs, int a, int b, int c, int d){
	
	cs->state[a] += cs->state[b];
	cs->state[d] ^= cs->state[a];
	cs->state[d] = ROTL_32((cs->state[d]), 16);

	cs->state[c] += cs->state[d];
	cs->state[b] ^= cs->state[c];
	cs->state[b] = ROTL_32((cs->state[b]), 12);

	cs->state[a] += cs->state[b];
	cs->state[d] ^= cs->state[a];
	cs->state[d] = ROTL_32((cs->state[d]), 8);

	cs->state[c] += cs->state[d];
	cs->state[b] ^= cs->state[c];
	cs->state[b] = ROTL_32((cs->state[b]), 7);
}

inline void inner_block(chacha_state *cs)
{
	q_round(cs, 0, 4, 8, 12);
	q_round(cs, 1, 5, 9, 13);
	q_round(cs, 2, 6, 10, 14);
	q_round(cs, 3, 7, 11, 15);
	q_round(cs, 0, 5, 10, 15);
	q_round(cs, 1, 6, 11, 12);
	q_round(cs, 2, 7, 8, 13);
	q_round(cs, 3, 4, 9, 14);
}





#endif
