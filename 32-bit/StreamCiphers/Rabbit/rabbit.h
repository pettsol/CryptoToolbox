#ifndef RABBIT_H
#define RABBIT_H

#include <climits>
#include <iostream>


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

#define WORDSIZE 0x100000000

static const u32 A[8] = {
	0x4d34d34d, 0xd34d34d3, 0x34d34d34, 0x4d34d34d,
	0xd34d34d3, 0x34d34d34, 0x4d34d34d, 0xd34d34d3
};

struct rabbit_state{
	u32 X[8];
	u32 C[8];
	u8 carry;
};

inline u32 g(u32 u, u32 v)
{
	u64 hold = ((u+v) % WORDSIZE) * ((u+v) % WORDSIZE);
	u32 LSW = hold & 0xffffffff;
	u32 MSW = (hold >> 32) & 0xffffffff;
	return (LSW ^ MSW);
}

void rabbit_key_setup(rabbit_state *cs, u32 key[8]);
void rabbit_iv_setup(rabbit_state *cs, u32 iv[2]);
void rabbit_extract_keystream(rabbit_state *cs, u32 *keystream);
void rabbit_process_packet(rabbit_state *cs, u8 *output, u8 *input, u64);
#ifdef DEBUG
void byte_swap(u8 *out, u8 *in, int size);
void print_key(u32 key[4]);
void print_inner_state(rabbit_state *cs);
#endif

inline void rabbit_counter(rabbit_state *cs)
{
	u64 temp;
	for (int j = 0; j < 8; j++)
	{
		temp = (u64)cs->C[j] + (u64)A[j] + (u64)cs->carry;
		cs->carry = temp > WORDSIZE;
#ifdef DEBUG
		std::cout << "Wordsize: " << WORDSIZE << std::endl;

		std::cout << "Temp = " << temp << " | carry = " << (u32)cs->carry << std::endl;
#endif
		cs->C[j] = (temp % WORDSIZE);
	}
}

inline void rabbit_next_state(rabbit_state *cs)
{
	u32 G[8];
	
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
