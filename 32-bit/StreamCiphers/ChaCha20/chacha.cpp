#include "chacha.h"

#include <iostream>
#include <cstring>
#include <cmath>

void test_q(u32 *input, u32 *output)
{
	chacha_state ctx;

	std::memcpy(ctx.state, input, 64);

	q_round(&ctx, 2, 7, 8, 13);

	std::memcpy(output, ctx.state, 64);
}

void byte_swap(u8 *output, u8 *input, int size)
{
	for (int i = 0; i < size/4; i++)
	{
		u32 num = ((u32*)input)[i];
		u32 swapped = ((num >> 24)&0xff) | ((num << 8)&0xff0000) |
			((num >> 8)&0xff00) | ((num << 24)&0xff000000);
		((u32*)input)[i] = swapped;
	}
}

void chacha20_initialize(chacha_state *cs, u32 key[8],  u32 nonce[3])
{
	// Load constants into words 0-3
	cs->state[0] = 0x61707865;
	cs->state[1] = 0x3320646e;
	cs->state[2] = 0x79622d32;
	cs->state[3] = 0x6b206574;

	// Copy the key into words 4-11 = 4*8 = 32 bytes
	std::memcpy(&(cs->state[4]), key, 32);

	// Copy the IV into words 12-15, IV = BLOCK_CTR || NONCE || NONCE || NONCE
	// Note: The counter is always initialized to 1.
	cs->state[12] = 1;
	std::memcpy(&(cs->state[13]), nonce, 12);
}

void chacha20_block(chacha_state *ctx, u32 counter, u32 *keystream)
{

	ctx->state[12] = counter;

	chacha_state ctx_work;

	std::memcpy(ctx_work.state, ctx->state, 64);

	for (int i = 0; i < 10; i++)
	{
		inner_block(&ctx_work);
	}
	for (int i = 0; i < 16; i++)
	{
		ctx_work.state[i] += ctx->state[i];
		//ctx->state[i] += ctx_work.state[i];
	}
	std::memcpy(keystream, ctx_work.state, 64);
	//std::memcpy(keystream, ctx->state, 64); 
		
}

void chacha20_process_packet(chacha_state *cs, u8 *output, u8 *input, u64 size)
{
	// Generate sufficient keystream;
	int n_words = std::ceil(double(size)/4);

	int n_iterations = std::ceil(double(n_words)/16);

	u32 *keystream = new u32[n_iterations*16];

	u32 counter = 1;

	for (int i = 0; i < n_iterations; i++)
	{
		chacha20_block(cs, counter, &(keystream[16*i]));
		counter++;
	}

	int n_bytes = size;
	u32 *w_ptr_in = (u32*) input;
	u32 *w_ptr_out = (u32*) output;
	int ks_index = 0;
	while (n_bytes > 3)
	{
		*w_ptr_out = *w_ptr_in ^ keystream[ks_index];
		w_ptr_in++; w_ptr_out++; ks_index++;
		n_bytes -= 4;
	}
	input = (u8*) w_ptr_in;
	output = (u8*) w_ptr_out;
	u8 *byte_ks = (u8*)&keystream[ks_index]; 
	for (int i = 0; i < n_bytes; i++)
	{
		*output = *input ^ *byte_ks; byte_ks++;
		//*output = *input ^ ((keystream[ks_index] >> (24-8*i))&0xff);
		output++; input++;
	}
	delete[] keystream;
}
