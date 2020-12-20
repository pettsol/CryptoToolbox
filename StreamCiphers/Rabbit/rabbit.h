#ifndef RABBIT_H
#define RABBIT_H

#include <stdint.h>
#include <iostream>

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

#define WORDSIZE 0x100000000

static const uint32_t A[8] = {
	0x4d34d34d, 0xd34d34d3, 0x34d34d34, 0x4d34d34d,
	0xd34d34d3, 0x34d34d34, 0x4d34d34d, 0xd34d34d3
};

struct rabbit_state{
	uint32_t MASTER_X[8];
	uint32_t MASTER_C[8];
	uint32_t X[8];
	uint32_t C[8];
	uint8_t carry;
};

inline uint32_t g(uint32_t u, uint32_t v)
{
	uint64_t hold = ((u+v) % WORDSIZE) * ((u+v) % WORDSIZE);
	uint32_t LSW = hold & 0xffffffff;
	uint32_t MSW = (hold >> 32) & 0xffffffff;
	return (LSW ^ MSW);
}

void rabbit_load_key(rabbit_state *cs, uint8_t key[16]);
void rabbit_load_iv(rabbit_state *cs, uint8_t iv[8]);
void rabbit_extract_keystream(rabbit_state *cs, uint32_t *keystream);
void rabbit_process_packet(rabbit_state *cs, uint8_t *output, uint8_t *input, uint64_t size);
#ifdef DEBUG
void byte_swap(uint8_t *out, uint8_t *in, int size);
void print_key(uint32_t key[4]);
void print_inner_state(rabbit_state *cs);
#endif

inline void rabbit_counter(rabbit_state *cs)
{
	uint64_t temp;
	for (int j = 0; j < 8; j++)
	{
		temp = (uint64_t)cs->C[j] + (uint64_t)A[j] + (uint64_t)cs->carry;
		cs->carry = temp > WORDSIZE;
#ifdef DEBUG
		std::cout << "Wordsize: " << WORDSIZE << std::endl;

		std::cout << "Temp = " << temp << " | carry = " << (uint32_t)cs->carry << std::endl;
#endif
		cs->C[j] = (temp % WORDSIZE);
	}
}

inline void rabbit_next_state(rabbit_state *cs)
{
	uint32_t G[8];
	
	for (int j = 0; j < 8; j++)
	{
		G[j] = g(cs->X[j], cs->C[j]);
	}
	cs->X[0] = (G[0] + ROTL_32(G[7],16) + ROTL_32(G[6],16)) % WORDSIZE;
	cs->X[1] = (G[1] + ROTL_32(G[0],8) + G[7]) % WORDSIZE;
	cs->X[2] = (G[2] + ROTL_32(G[1],16) + ROTL_32(G[0],16)) % WORDSIZE;
	cs->X[3] = (G[3] + ROTL_32(G[2],8) + G[1]) % WORDSIZE;
	cs->X[4] = (G[4] + ROTL_32(G[3],16) + ROTL_32(G[2],16)) % WORDSIZE;
	cs->X[5] = (G[5] + ROTL_32(G[4],8) + G[3]) % WORDSIZE;
	cs->X[6] = (G[6] + ROTL_32(G[5],16) + ROTL_32(G[4],16)) % WORDSIZE;
	cs->X[7] = (G[7] + ROTL_32(G[6],8) + G[5]) % WORDSIZE;
}


#endif
