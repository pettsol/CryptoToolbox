#ifndef CHACHA_H
#define CHACHA_H

#include <stdint.h>

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
	uint32_t state[16];
};

void chacha_initialize(chacha_state *cs, uint8_t key[32], uint8_t nonce[12]);
void chacha_block(chacha_state *cs, uint32_t counter, uint32_t *keystream);
void chacha_process_packet(chacha_state *cs, uint8_t *output, uint8_t *input, uint64_t size);
void test_q(uint32_t *input, uint32_t *output);
void byte_swap(uint8_t *output, uint8_t *input, int size);

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
