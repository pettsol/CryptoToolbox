#include "sosemanuk.h"
#include <iostream>


void sosemanuk_load_key(sosemanuk_state *cs, uint8_t *key, int keysize)
{
	// Find the 25 round keys that will be used
	// in the IV injection.
	serpent_key_schedule(&(cs->serpent_cs), key, keysize);
}

void sosemanuk_load_iv(sosemanuk_state *cs, uint8_t iv[16])
{
	// Let the IV serve as input to the serpent cipher
	// and store the output from the 12th, 18th and 24th
	// round as the initial state of Sosemanuk.
	uint32_t initial_state[12];
	serpent_process_packet(&(cs->serpent_cs), initial_state, (uint32_t*)iv, 16);

	cs->s[9] = initial_state[0];
	cs->s[8] = initial_state[1];
	cs->s[7] = initial_state[2];
	cs->s[6] = initial_state[3];
	
	cs->R1 = initial_state[4];
	cs->R2 = initial_state[6];

	cs->s[5] = initial_state[7];
	cs->s[4] = initial_state[5];

	cs->s[3] = initial_state[8];
	cs->s[2] = initial_state[9];
	cs->s[1] = initial_state[10];
	cs->s[0] = initial_state[11];
	
}

void sosemanuk_process_packet(sosemanuk_state *cs, uint8_t *out, uint8_t *in, uint64_t size)
{
	// Get word ptrs
	uint32_t *w_ptr_out = (uint32_t*)out; uint32_t *w_ptr_in = (uint32_t*)in;

	// We need buffers to work with
	uint32_t f_buf[4];
	uint32_t s_buf[4];
	while (size >= 16)
	{
		// Perform full encryption

		// Four steps of:
		// - Update FSM
		// - Update LFSR
		sosemanuk_fsm_update(cs, &f_buf[0]);
		sosemanuk_lfsr_update(cs, &s_buf[0]);

		sosemanuk_fsm_update(cs, &f_buf[1]);
		sosemanuk_lfsr_update(cs, &s_buf[1]);

		sosemanuk_fsm_update(cs, &f_buf[2]);
		sosemanuk_lfsr_update(cs, &s_buf[2]);

		sosemanuk_fsm_update(cs, &f_buf[3]);
		sosemanuk_lfsr_update(cs, &s_buf[3]);

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

	sosemanuk_fsm_update(cs, &f_buf[0]);
	sosemanuk_lfsr_update(cs, &s_buf[0]);
	
	sosemanuk_fsm_update(cs, &f_buf[1]);
	sosemanuk_lfsr_update(cs, &s_buf[1]);

	sosemanuk_fsm_update(cs, &f_buf[2]);
	sosemanuk_lfsr_update(cs, &s_buf[2]);

	sosemanuk_fsm_update(cs, &f_buf[3]);
	sosemanuk_lfsr_update(cs, &s_buf[3]);

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
	out = (uint8_t*) w_ptr_out;
	in = (uint8_t*) w_ptr_in;

	for (int j = 0; j < size; j++)
	{
		// Get the final bytes
		*out = *in ^ ((uint8_t)(s_buf[i] >> (8*j)));
		out++; in++;
	}
}
