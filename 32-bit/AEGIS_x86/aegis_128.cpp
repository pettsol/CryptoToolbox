///////////////////////////////////
// This implementation was been  //
// placed in the public domain by//
//                               //
// Petter Solnoer - 24/08/2020   //
///////////////////////////////////

#include <string>
#include <cmath>

#include "aegis_128.h"
#include "../HexEncoder/encoder.h"

void always_memset(void *dest, int ch, size_t count)
{
	memset(dest, ch, count);
	asm volatile("" : : : "memory");
}

void aegis_load_key(aegis_state *cs, u32 *key)
{
	std::memcpy(cs->key, key, 16);
}

void aegis_initialize(aegis_state *cs, u32 *iv)
{
	u32 message[40];

	// Key XOR IV
	u32 tmp[4];
	tmp[0] = (*(cs->key)) ^ (*iv);
	tmp[1] = (*(cs->key+1)) ^ (*(iv+1));
	tmp[2] = (*(cs->key+2)) ^ (*(iv+2));
	tmp[3] = (*(cs->key+3)) ^ (*(iv+3));
	
	// pointer to constant
	u32 *const_ptr = (u32*)&constant;

	// Load initial values to state registers
	std::memcpy(cs->s0, tmp, 16);
	std::memcpy(cs->s1, &constant[16], 16);
	std::memcpy(cs->s2, &constant[0], 16);

	cs->s3[0] = (*(cs->key)) ^ (*const_ptr);
	cs->s3[1] = (*(cs->key+1)) ^ (*(const_ptr+1));
	cs->s3[2] = (*(cs->key+2)) ^ (*(const_ptr+2));
	cs->s3[3] = (*(cs->key+3)) ^ (*(const_ptr+3));

	cs->s4[0] = (*(cs->key)) ^ (*(const_ptr+4));
	cs->s4[1] = (*(cs->key+1)) ^ (*(const_ptr+5));
	cs->s4[2] = (*(cs->key+2)) ^ (*(const_ptr+6));
	cs->s4[3] = (*(cs->key+3)) ^ (*(const_ptr+7));

	// Load the message content
	for (int i = 0; i < 5; i++)
	{
		message[8*i] = *(cs->key);
		message[8*i+1] = *(cs->key+1);
		message[8*i+2] = *(cs->key+2);
		message[8*i+3] = *(cs->key+3);

		message[8*i+4] = tmp[0];
		message[8*i+5] = tmp[1];
		message[8*i+6] = tmp[2];
		message[8*i+7] = tmp[3];
	}
	// Iterate state update 10 times
	aegis_state_update(cs, (message));
	aegis_state_update(cs, (message+4));
	aegis_state_update(cs, (message+8));
	aegis_state_update(cs, (message+12));
	aegis_state_update(cs, (message+16));
	aegis_state_update(cs, (message+20));
	aegis_state_update(cs, (message+24));
	aegis_state_update(cs, (message+28));
	aegis_state_update(cs, (message+32));
	aegis_state_update(cs, (message+36));
}

void aegis_process_ad(aegis_state *cs, u8 *ad, u64 adlen)
{
	if (!adlen) return;

	u32 *w_ptr;

	if (adlen % 16)
	{
		// PAD
		int pad_length = 16 - (adlen % 16);
		u8 *padded_ad;

		// Allocate memory for padded ad, initialized to zero.
		padded_ad = new u8 [adlen+pad_length]();
		std::memcpy(padded_ad, ad, adlen);

		w_ptr = (u32*)padded_ad;
		// Update state
		for (int i = 0; i < std::ceil(double(adlen)/16); i++)
		{
			aegis_state_update(cs, (w_ptr+4*i));
		}
		delete[] padded_ad;
		return;
	}
	w_ptr = (u32*)ad;
	for (int i = 0; i < std::ceil(double(adlen)/16); i++)
	{
		aegis_state_update(cs, (w_ptr+4*i));
	}
	return;
}

void aegis_encrypt(aegis_state *cs, u8 *ct, u8 *pt, u64 msglen)
{
	if (!msglen) return;

	u32 *ct_w_ptr = (u32*)ct;
	u32 *pt_w_ptr = (u32*)pt;

	u64 tmp = 0;

	// Encrypt full blocks
	for (tmp; tmp < (msglen-15); tmp = tmp+16)
	{
		// Encrypt using state
		*ct_w_ptr++ = *pt_w_ptr++ ^ cs->s1[0] ^ cs->s4[0] ^ (cs->s2[0] & cs->s3[0]);
		*ct_w_ptr++ = *pt_w_ptr++ ^ cs->s1[1] ^ cs->s4[1] ^ (cs->s2[1] & cs->s3[1]);
		*ct_w_ptr++ = *pt_w_ptr++ ^ cs->s1[2] ^ cs->s4[2] ^ (cs->s2[2] & cs->s3[2]);
		*ct_w_ptr++ = *pt_w_ptr++ ^ cs->s1[3] ^ cs->s4[3] ^ (cs->s2[3] & cs->s3[3]);

		// Update the state
		aegis_state_update(cs, (pt_w_ptr-4));

	}

	if (tmp == msglen) return;

	u32 padded_block[4] = {0};

	std::memcpy(padded_block, pt_w_ptr, msglen-tmp);

	int i = 0;

	// Encrypt individual words if applicable
	for (tmp; tmp < (msglen-3); tmp = tmp+4)
	{
		*ct_w_ptr++ = *pt_w_ptr++ ^ cs->s1[i] ^ cs->s4[i] ^ (cs->s2[i] & cs->s3[i]);
		i++;
	}

	// Encrypt individual bytes if applicable
	ct = (u8*) ct_w_ptr;
	pt = (u8*) pt_w_ptr;

	int j = 0;

	while (tmp < msglen)
	{
		*ct++ = *pt++ ^ (u8)((cs->s1[i] ^ cs->s4[i] ^ (cs->s2[i] & cs->s3[i])) >> 8*j++);
		tmp++;
	}
	aegis_state_update(cs, padded_block);
	return;
}

void aegis_decrypt(aegis_state *cs, u8 *pt, u8 *ct, u64 msglen)
{
	if (!msglen) return;
	u32 *pt_w_ptr = (u32*)pt;
	u32 *ct_w_ptr = (u32*)ct;
	
	u64 tmp = 0;
	for (tmp; tmp < msglen-15; tmp += 16)
	{
		// Decrypt using state
		*pt_w_ptr++ = *ct_w_ptr++ ^ cs->s1[0] ^ cs->s4[0] ^ (cs->s2[0] & cs->s3[0]);
		*pt_w_ptr++ = *ct_w_ptr++ ^ cs->s1[1] ^ cs->s4[1] ^ (cs->s2[1] & cs->s3[1]);
		*pt_w_ptr++ = *ct_w_ptr++ ^ cs->s1[2] ^ cs->s4[2] ^ (cs->s2[2] & cs->s3[2]);
		*pt_w_ptr++ = *ct_w_ptr++ ^ cs->s1[3] ^ cs->s4[3] ^ (cs->s2[3] & cs->s3[3]);

		aegis_state_update(cs, (pt_w_ptr-4));
	}

	if (tmp == msglen) return;

	int overshoot = msglen-tmp;

	// Decrypt individual words if applicable
	u32 padded_block[4] = {0};
	u32 *tmp_ptr = pt_w_ptr;
	//std::memcpy(padded_block, pt_w_ptr, msglen-tmp);

	int i = 0;

	for (tmp; tmp < (msglen-3); tmp = tmp+4)
	{
		*pt_w_ptr++ = *ct_w_ptr++ ^ cs->s1[i] ^ cs->s4[i] ^ (cs->s2[i] & cs->s3[i]);
		i++;
	}

	// Decrypt individual bytes if applicable
	ct = (u8*) ct_w_ptr;
	pt = (u8*) pt_w_ptr;

	int j = 0;
	while (tmp < msglen)
	{
		*pt++ = *ct++ ^ (u8)((cs->s1[i] ^ cs->s4[i] ^ (cs->s2[i] & cs->s3[i])) >> 8*j++);
		tmp++;
	}

	std::memcpy(padded_block, tmp_ptr, overshoot);
		
	aegis_state_update(cs, padded_block);
}

void aegis_finalize(aegis_state *cs, u32 *tag, u64 adlen, u64 msglen)
{
	u32 tmp[4] = {0};

	// Cipher specifices bit-length, rather than
	// byte length.
	u64 bit_adlen = adlen * 8;
	u64 bit_msglen = msglen * 8;

	std::memcpy(tmp, &bit_adlen, 8);
	std::memcpy(tmp+2, &bit_msglen, 8);

	tmp[0] = tmp[0] ^ cs->s3[0];
	tmp[1] = tmp[1] ^ cs->s3[1];
	tmp[2] = tmp[2] ^ cs->s3[2];
	tmp[3] = tmp[3] ^ cs->s3[3];

	// Iterate update function 7 times
	aegis_state_update(cs, tmp);
	aegis_state_update(cs, tmp);
	aegis_state_update(cs, tmp);
	aegis_state_update(cs, tmp);
	aegis_state_update(cs, tmp);
	aegis_state_update(cs, tmp);
	aegis_state_update(cs, tmp);

	// Extract 16 byte tag from the final state
	tag[0] = cs->s0[0] ^ cs->s1[0] ^ cs->s2[0] ^ cs->s3[0] ^ cs->s4[0];
	tag[1] = cs->s0[1] ^ cs->s1[1] ^ cs->s2[1] ^ cs->s3[1] ^ cs->s4[1];
	tag[2] = cs->s0[2] ^ cs->s1[2] ^ cs->s2[2] ^ cs->s3[2] ^ cs->s4[2];
	tag[3] = cs->s0[3] ^ cs->s1[3] ^ cs->s2[3] ^ cs->s3[3] ^ cs->s4[3];
}

void aegis_encrypt_packet(aegis_state *cs, u8 *ct, u8* tag, u8 *pt, u8 *ad, u32 *iv, u64 adlen, u64 msglen)
{
	aegis_initialize(cs, iv);

	aegis_process_ad(cs, ad, adlen);

	aegis_encrypt(cs, ct, pt, msglen);

	aegis_finalize(cs, (u32*)tag, adlen, msglen);
}

int aegis_decrypt_packet(aegis_state *cs, u8 *pt, u8 *ct, u8 *ad, u32 *iv, u32 *tag, u64 adlen, u64 msglen)
{
	int flag = 0;
	u32 re_tag[4];

	aegis_initialize(cs, iv);

	aegis_process_ad(cs, ad, adlen);

	aegis_decrypt(cs, pt, ct, msglen);

	aegis_finalize(cs, re_tag, adlen, msglen);

	// Check whether recomputed tag is similar to prev. tag.
	// If they are not the same, remove all purge the pt and return false.

	
	for (int i = 0; i < 4; i++)
	{
		if (re_tag[i] != tag[i]) flag = 1;
	}
	if (flag)
	{
		// Tags do not match
		always_memset(pt, 0, msglen);
		always_memset(tag, 0, 16);
		return 0;
	}
	return 1;
}

