#include "sosemanuk.h"
#include <iostream>


void sosemanuk_load_key(sosemanuk_state *ctx, u8 *key, u64 size)
{
	// Find the 25 round keys that will be used
	// in the IV injection.
	serpent_key_schedule(&(ctx->serpent_cs), key, size);
}

void sosemanuk_load_iv(sosemanuk_state *ctx, u32 *iv)
{
	// Let the IV serve as input to the serpent cipher
	// and store the output from the 12th, 18th and 24th
	// round as the initial state of Sosemanuk.
	u32 initial_state[12];
	serpent_process_packet(&(ctx->serpent_cs), initial_state, iv, 16);

	ctx->s[9] = initial_state[0];
	ctx->s[8] = initial_state[1];
	ctx->s[7] = initial_state[2];
	ctx->s[6] = initial_state[3];
	
	ctx->R1 = initial_state[4];
	ctx->R2 = initial_state[6];

	ctx->s[5] = initial_state[7];
	ctx->s[4] = initial_state[5];

	ctx->s[3] = initial_state[8];
	ctx->s[2] = initial_state[9];
	ctx->s[1] = initial_state[10];
	ctx->s[0] = initial_state[11];
	
}

void sosemanuk_process_packet(sosemanuk_state *ctx, u8 *out, u8 *in, u64 size)
{
	// Get word ptrs
	u32 *w_ptr_out = (u32*)out; u32 *w_ptr_in = (u32*)in;

	// We need buffers to work with
	u32 f_buf[4];
	u32 s_buf[4];
	while (size >= 16)
	{
		// Perform full encryption

		// Four steps of:
		// - Update FSM
		// - Update LFSR
		sosemanuk_fsm_update(ctx, &f_buf[0]);
		sosemanuk_lfsr_update(ctx, &s_buf[0]);

		sosemanuk_fsm_update(ctx, &f_buf[1]);
		sosemanuk_lfsr_update(ctx, &s_buf[1]);

		sosemanuk_fsm_update(ctx, &f_buf[2]);
		sosemanuk_lfsr_update(ctx, &s_buf[2]);

		sosemanuk_fsm_update(ctx, &f_buf[3]);
		sosemanuk_lfsr_update(ctx, &s_buf[3]);

		// Then feed them all into Serpent1
		serpent1(&f_buf[0], &f_buf[1], &f_buf[2], &f_buf[3]);

		// Then xor with s_buf to get key stream
		s_buf[0] = s_buf[0] ^ f_buf[0]; s_buf[1] = s_buf[1] ^ f_buf[1];
		s_buf[2] = s_buf[2] ^ f_buf[2]; s_buf[3] = s_buf[3] ^ f_buf[3];

		// Then mix keystream with the input to get the output
		*w_ptr_out = *w_ptr_in ^ s_buf[0]; w_ptr_out++; w_ptr_in++;	
		*w_ptr_out = *w_ptr_in ^ s_buf[1]; w_ptr_out++; w_ptr_in++;
		*w_ptr_out = *w_ptr_in ^ s_buf[2]; w_ptr_out++; w_ptr_in++;
		*w_ptr_out = *w_ptr_in ^ s_buf[3]; w_ptr_out++; w_ptr_in++;

		size -= 16;
	}

	sosemanuk_fsm_update(ctx, &f_buf[0]);
	sosemanuk_lfsr_update(ctx, &s_buf[0]);
	
	sosemanuk_fsm_update(ctx, &f_buf[1]);
	sosemanuk_lfsr_update(ctx, &s_buf[1]);

	sosemanuk_fsm_update(ctx, &f_buf[2]);
	sosemanuk_lfsr_update(ctx, &s_buf[2]);

	sosemanuk_fsm_update(ctx, &f_buf[3]);
	sosemanuk_lfsr_update(ctx, &s_buf[3]);

	// Then feed them all into Serpent1
	serpent1(&f_buf[0], &f_buf[1], &f_buf[2], &f_buf[3]);

	// Then xor with s_buf to get key stream
	s_buf[0] = s_buf[0] ^ f_buf[0]; s_buf[1] = s_buf[1] ^ f_buf[1];
	s_buf[2] = s_buf[2] ^ f_buf[2]; s_buf[3] = s_buf[3] ^ f_buf[3];

	int i = 0;
	while (size >= 4)
	{
		// Process each full word
		*w_ptr_out = *w_ptr_in ^ s_buf[i++];
		w_ptr_out++; w_ptr_in++;
		size -= 4;
	}
	out = (u8*) w_ptr_out;
	in = (u8*) w_ptr_in;

	for (int j = 0; j < size; j++)
	{
		// Get the final bytes
		*out = *in ^ ((u8)(s_buf[i] >> (8*j)));
		out++; in++;
	}
}
