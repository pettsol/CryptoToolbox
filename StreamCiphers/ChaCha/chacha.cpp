#include "chacha.h"

#include <iostream>
#include <cstring>
#include <cmath>

void test_q(uint32_t *input, uint32_t *output)
{
	chacha_state ctx;

	std::memcpy(ctx.state, input, 64);

	q_round(&ctx, 2, 7, 8, 13);

	std::memcpy(output, ctx.state, 64);
}

void byte_swap(uint8_t *output, uint8_t *input, int size)
{
	for (int i = 0; i < size/4; i++)
	{
		uint32_t num = ((uint32_t*)input)[i];
		uint32_t swapped = ((num >> 24)&0xff) | ((num << 8)&0xff0000) |
			((num >> 8)&0xff00) | ((num << 24)&0xff000000);
		((uint32_t*)input)[i] = swapped;
	}
}

void chacha_initialize(chacha_state *cs, uint8_t key[32],  uint8_t nonce[12])
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

void chacha_block(chacha_state *cs, uint32_t counter, uint32_t *keystream)
{

	cs->state[12] = counter;

	chacha_state cs_work;

	std::memcpy(cs_work.state, cs->state, 64);

#ifdef TWELVE_ROUNDS
	int NROUNDS = 12;
#elif EIGHT_ROUNDS
	int NROUNDS = 8;
#else
	int NROUNDS = 20;
#endif

	for (int i = 0; i < (NROUNDS/2); i++)
	{
		inner_block(&cs_work);
	}
	for (int i = 0; i < 16; i++)
	{
		cs_work.state[i] += cs->state[i];
		//ctx->state[i] += ctx_work.state[i];
	}
	std::memcpy(keystream, cs_work.state, 64);
	//std::memcpy(keystream, ctx->state, 64); 
		
}

void chacha_process_packet(chacha_state *cs, uint8_t *output, uint8_t *input, uint64_t size)
{
	// Generate sufficient keystream;
	int n_words = std::ceil(double(size)/4);

	int n_iterations = std::ceil(double(n_words)/16);

	uint32_t *keystream = new uint32_t[n_iterations*16];

	uint32_t counter = 1;

	for (int i = 0; i < n_iterations; i++)
	{
		chacha_block(cs, counter, &(keystream[16*i]));
		counter++;
	}

	int n_bytes = size;
	uint32_t *w_ptr_in = (uint32_t*) input;
	uint32_t *w_ptr_out = (uint32_t*) output;
	int ks_index = 0;
	while (n_bytes > 3)
	{
		*w_ptr_out = *w_ptr_in ^ keystream[ks_index];
		w_ptr_in++; w_ptr_out++; ks_index++;
		n_bytes -= 4;
	}
	input = (uint8_t*) w_ptr_in;
	output = (uint8_t*) w_ptr_out;
	uint8_t *byte_ks = (uint8_t*)&keystream[ks_index]; 
	for (int i = 0; i < n_bytes; i++)
	{
		*output = *input ^ *byte_ks; byte_ks++;
		//*output = *input ^ ((keystream[ks_index] >> (24-8*i))&0xff);
		output++; input++;
	}
	delete[] keystream;
}
