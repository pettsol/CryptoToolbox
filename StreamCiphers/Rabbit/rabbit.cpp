#include "rabbit.h"

#ifdef DEBUG
#include "../../Encoders/Hex/encoder.h"
#endif

#include <iostream>
#include <cstring>

#ifdef DEBUG
void byte_swap(uint8_t *output, uint8_t *input, int size)
{
	for (int i = 0; i < size/4; i++)
	{
		uint32_t num = ((uint32_t*)input)[i];
		uint32_t swapped = ((num >> 24) & 0xff) | ((num << 8) & 0xff0000) |
			((num >> 8) & 0xff00) | ((num << 24) & 0xff000000);
		((uint32_t*)input)[i] = swapped;
	}
}
#endif

void rabbit_load_key(rabbit_state *cs, uint8_t key[16])
{
	cs->carry = 0;

//	byte_swap((uint8_t*)key, (uint8_t*)key, 16);
	
	uint16_t *key_ptr = (uint16_t*)key;

	for (int j = 0; j < 8; j++)
	{
		if (j%2)
		{
#ifdef DEBUG
			int tmp = (j+5) & 0x7;
			std::cout << "j = " << j << " | j + 5 mod 8 = " << tmp << std::endl;
#endif
			// Odd
			cs->X[j] = (uint32_t)( (uint32_t)key_ptr[(j+5) & 0x7] << 16 | (uint32_t)key_ptr[(j+4) & 0x7] );
                        cs->C[j] = (uint32_t)( (uint32_t)key_ptr[j] << 16 | (uint32_t)key_ptr[(j+1) & 0x7] );

		} else
		{
#ifdef DEBUG
			std::cout << "j = " << j << std::endl;
			char first_c[5];
			char second_c[5];

			hex_encode(first_c, (uint8_t*)&key_ptr[(j+1) & 0x7], 2);
			hex_encode(second_c, (uint8_t*)&key_ptr[j], 2);

			std::string first_s(first_c);
			std::string second_s(second_c);
			std::cout << "First: " << first_s << " | Second: " << second_s << std::endl;
#endif
			// Even
			cs->X[j] = (uint32_t)( (uint32_t)key_ptr[(j+1) & 0x7] << 16 | (uint32_t)key_ptr[j] );
#ifdef DEBUG
			char print_c[9];
			hex_encode(print_c, (uint8_t*)&cs->X[j], 4);
			std::string print_s(print_c);
			std::cout << "X[" << j << "] = " << print_s << std::endl;
#endif
			cs->C[j] = (uint32_t)( (uint32_t)key_ptr[(j+4) & 0x7] << 16 | (uint32_t)key_ptr[(j+5) & 0x7] );
		}
	}

#ifdef DEBUG
	print_inner_state(cs);
#endif

	// Iterate system four times? Counter update and next-state function
	for (int i = 0; i < 4; i++)
	{
		rabbit_counter(cs);
		rabbit_next_state(cs);
#ifdef DEBUG
		std::cout << "\n\n\n***** ROUND " << i+1 << " *****\n" << std::endl;
		print_inner_state(cs);
#endif	
	}
	//
	// After the iterations, the counter variables are reinitialized
	for (int j = 0; j < 8; j++)
	{
		cs->C[j] = cs->C[j] ^ cs->X[(j+4) & 0x7];
	}
	// Master state has been derived. Save for future state updates
	for (int j = 0; j < 8; j++)
	{
		cs->MASTER_C[j] = cs->C[j];
		cs->MASTER_X[j] = cs->X[j];
	}
#ifdef DEBUG
	std::cout << "\n\n\nAfter final XOR\n" << std::endl;
	print_inner_state(cs);
#endif
}

// NOTE: The key derived from the key_setup is perceived as a
// MASTER STATE. Thus, BEFORE calling rabbit_iv_setup, the
// master state must be enacted. This can be achieved by storing the original
// state from the key setup.
void rabbit_load_iv(rabbit_state *cs, uint8_t iv[8])
{

	// Set X variable to master state
	cs->X[0] = cs->MASTER_X[0]; 
	cs->X[1] = cs->MASTER_X[1];
	cs->X[2] = cs->MASTER_X[2];
	cs->X[3] = cs->MASTER_X[3];
	cs->X[4] = cs->MASTER_X[4];
	cs->X[5] = cs->MASTER_X[5];
	cs->X[6] = cs->MASTER_X[6];
	cs->X[7] = cs->MASTER_X[7];

	uint16_t *iv_u16 = (uint16_t*)iv; 
	uint32_t *iv_u32 = (uint32_t*)iv;
	cs->C[0] = cs->MASTER_C[0] ^ iv_u32[0];
	cs->C[1] = cs->MASTER_C[1] ^ ( (iv_u16[3] << 16) | iv_u16[1] );
	cs->C[2] = cs->MASTER_C[2] ^ iv_u32[1];
	cs->C[3] = cs->MASTER_C[3] ^ ( (iv_u16[2] << 16) | iv_u16[0] );
	cs->C[4] = cs->MASTER_C[4] ^ iv_u32[0];
	cs->C[5] = cs->MASTER_C[5] ^ ( (iv_u16[3] << 16) | iv_u16[1] );
	cs->C[6] = cs->MASTER_C[6] ^ iv_u32[1];
	cs->C[7] = cs->MASTER_C[7] ^ ( (iv_u16[2] << 16) | iv_u16[0] );

	for (int i = 0; i < 4; i++)
	{
		rabbit_counter(cs);
		rabbit_next_state(cs);
	}
}

void rabbit_extract_keystream(rabbit_state *cs, uint32_t *keystream)
{
	// First update counter, then update state. Then extract 128 keystream bits.
	rabbit_counter(cs);
	rabbit_next_state(cs);

	uint16_t *ks_ptr = (uint16_t*)keystream;

	ks_ptr[0] = (cs->X[0]&0xffff) ^ ( (cs->X[5] >> 16) & 0xffff);
	ks_ptr[1] = ( (cs->X[0] >> 16) & 0xffff) ^ (cs->X[3] & 0xffff);
	ks_ptr[2] = (cs->X[2]&0xffff) ^ ( (cs->X[7] >> 16) & 0xffff);
	ks_ptr[3] = ( (cs->X[2] >> 16) & 0xffff) ^ (cs->X[5] & 0xffff);
	ks_ptr[4] = (cs->X[4]&0xffff) ^ ( (cs->X[1] >> 16) & 0xffff);
	ks_ptr[5] = ( (cs->X[4] >> 16) & 0xffff) ^ (cs->X[7] & 0xffff);
	ks_ptr[6] = (cs->X[6]&0xffff) ^ ( (cs->X[3] >> 16) & 0xffff);
	ks_ptr[7] = ( (cs->X[6] >> 16) & 0xffff) ^ (cs->X[1] & 0xffff);

}

void rabbit_process_packet(rabbit_state *cs, uint8_t *output, uint8_t *input, uint64_t size)
{
	uint64_t size_left = size;
	uint32_t keystream[4];
	uint32_t *w_ptr_out = (uint32_t*)output;
	uint32_t *w_ptr_in = (uint32_t*)input;
	while (size_left > 15)
	{
		// Process 4 words
		rabbit_extract_keystream(cs, keystream);
		
		*w_ptr_out = *w_ptr_in ^ keystream[0];
		w_ptr_out++; w_ptr_in++;

		*w_ptr_out = *w_ptr_in ^ keystream[1];
		w_ptr_out++; w_ptr_in++;

		*w_ptr_out = *w_ptr_in ^ keystream[2];
		w_ptr_out++; w_ptr_in++;

		*w_ptr_out = *w_ptr_in ^ keystream[3];
		w_ptr_out++; w_ptr_in++;
		//
		size_left -= 16;
	}
	if (size_left > 0)
	{

		output = (uint8_t*)w_ptr_out;
		input = (uint8_t*)w_ptr_in;
		uint8_t *keystream_byte = (uint8_t*)keystream;

		rabbit_extract_keystream(cs, keystream);
		while (size_left > 0)
		{
			*output = *input ^ *keystream_byte;
			output++; input++; keystream_byte++;
			size_left--;
		}
	}

}
#ifdef DEBUG
void print_key(uint32_t key[4])
{
	uint16_t *key_ptr = (uint16_t*)key;

	for (int i = 0; i < 8; i++)
	{
		char key_s[5];

		hex_encode(key_s, (uint8_t*)(key_ptr+i), 2);

		std::string key_string(key_s);

		std::cout << "Key " << i << " = " << key_string << std::endl;

	}
}

void print_inner_state(rabbit_state *cs)
{

	std::cout << "b = " << (int)cs->carry << std::endl;

	for (int i = 0; i < 8; i++)
	{
		// Print X
		uint8_t tmp[4];
		std::memcpy(tmp, &(cs->X[i]), 4);
		
		// Byte swap to big endian
		byte_swap(tmp, tmp, 4);
		
		// Convert to hex
		char tmp_c[9];
		hex_encode(tmp_c, tmp, 4);

		// Print
		std::string tmp_s(tmp_c);

		std::cout << "X" << i << " = " << tmp_s << std::endl;
	}
	for (int i = 0; i < 8; i++)
	{
		// Print C
		uint8_t tmp[4];
		std::memcpy(tmp, &(cs->C[i]), 4);

		// Byte swap to big endian
		byte_swap(tmp, tmp, 4);

		// Convert to hex
		char tmp_c[9];
		hex_encode(tmp_c, tmp, 4);

		// Print
		std::string tmp_s(tmp_c);

		std::cout << "C" << i << " = " << tmp_s << std::endl;
	}
}
#endif

