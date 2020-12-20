#ifndef SOSEMANUK_H
#define SOSEMANUK_H

#include "serpent.h"
#include "sosemanuk_tables.h"

#define M 0x54655307

#define SOSEMANUK_KEYLENGTH 16

struct sosemanuk_state{
	// Keep stuff here
	// A serpent cipher is needed
	// for IV handling
	serpent_state serpent_cs;
	uint32_t s[10];
	uint32_t R1;
	uint32_t R2;
};

// The key schedule extracts the first 25 keys
// from the Serpent key schedule
void sosemanuk_load_key(sosemanuk_state *cs, uint8_t *key, int keysize);

// The IV injection extracts the result
// from the 12th, 18th and 24th round
// of Serpent.
void sosemanuk_load_iv(sosemanuk_state *cs, uint8_t iv[16]);

// Process packet consists of a state update
// and an output function, as most stream
// ciphers.
void sosemanuk_process_packet(sosemanuk_state *cs, uint8_t *out, uint8_t *in, uint64_t size);

// 

inline uint32_t mux(uint32_t R1, uint32_t arg1, uint32_t arg2)
{
	// This can be implemented efficiently using the always-
	// hated ternary operator and the bitmask
	// 0x1 = 0001 :-)
	return ( (R1 & 0x1) ? arg2 : arg1 );	
}

inline uint32_t Trans(uint32_t R1)
{
	R1 = (M * R1);
	return (ROTL_32(R1, 7));
}

inline void sosemanuk_fsm_update(sosemanuk_state *cs, uint32_t *f_buf)
{
	// Update fsm
	cs->R1 = cs->R2 + mux(cs->R1, cs->s[1], (cs->s[8] ^ cs->s[9]));
	cs->R2 = Trans(cs->R1);
	*f_buf = (cs->s[9] + cs->R1) ^ cs->R2;
	
}

inline void sosemanuk_lfsr_update(sosemanuk_state *cs, uint32_t *s_buf)
{
	// Compute next LFSR input

	uint32_t tmp = ( ((cs->s[3] >> 8) ^ inv_alpha[((uint8_t)(cs->s[3]))]) 
		^ ((cs->s[0] << 8) ^ alpha[(uint8_t)(cs->s[0] >> 24)]) ) ^ cs->s[9];	
	
	// Store the s[0] value in the buffer
	*s_buf = cs->s[0];

	// Shift the LFSR
	cs->s[0] = cs->s[1]; cs->s[1] = cs->s[2]; cs->s[2] = cs->s[3];
	cs->s[3] = cs->s[4]; cs->s[4] = cs->s[5]; cs->s[5] = cs->s[6];
	cs->s[6] = cs->s[7]; cs->s[7] = cs->s[8]; cs->s[8] = cs->s[9];

	// Input the new LFSR input
	cs->s[9] = tmp;
}

#endif
