#include "rabbit.h"

#ifdef DEBUG
#include "../../Encoders/Hex/encoder.h"
#endif

#include <iostream>
#include <cstring>

#ifdef DEBUG
void byte_swap(u8 *output, u8 *input, int size)
{
	for (int i = 0; i < size/4; i++)
	{
		u32 num = ((u32*)input)[i];
		u32 swapped = ((num >> 24) & 0xff) | ((num << 8) & 0xff0000) |
			((num >> 8) & 0xff00) | ((num << 24) & 0xff000000);
		((u32*)input)[i] = swapped;
	}
}
#endif

void rabbit_key_setup(rabbit_state *cs, u32 key[4])
{
	cs->carry = 0;

//	byte_swap((u8*)key, (u8*)key, 16);
	
	u16 *key_ptr = (u16*)key;

	for (int j = 0; j < 8; j++)
	{
		if (j%2)
		{
#ifdef DEBUG
			int tmp = (j+5) & 0x7;
			std::cout << "j = " << j << " | j + 5 mod 8 = " << tmp << std::endl;
#endif
			// Odd
			cs->X[j] = (u32)( (u32)key_ptr[(j+5) & 0x7] << 16 | (u32)key_ptr[(j+4) & 0x7] );
                        cs->C[j] = (u32)( (u32)key_ptr[j] << 16 | (u32)key_ptr[(j+1) & 0x7] );

		} else
		{
#ifdef DEBUG
			std::cout << "j = " << j << std::endl;
			char first_c[5];
			char second_c[5];

			hex_encode(first_c, (u8*)&key_ptr[(j+1) & 0x7], 2);
			hex_encode(second_c, (u8*)&key_ptr[j], 2);

			std::string first_s(first_c);
			std::string second_s(second_c);
			std::cout << "First: " << first_s << " | Second: " << second_s << std::endl;
#endif
			// Even
			cs->X[j] = (u32)( (u32)key_ptr[(j+1) & 0x7] << 16 | (u32)key_ptr[j] );
#ifdef DEBUG
			char print_c[9];
			hex_encode(print_c, (u8*)&cs->X[j], 4);
			std::string print_s(print_c);
			std::cout << "X[" << j << "] = " << print_s << std::endl;
#endif
			cs->C[j] = (u32)( (u32)key_ptr[(j+4) & 0x7] << 16 | (u32)key_ptr[(j+5) & 0x7] );
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
void rabbit_iv_setup(rabbit_state *cs, u32 iv[2])
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

	u16 *iv_shrt = (u16*)iv; 
	cs->C[0] = cs->MASTER_C[0] ^ iv[0];
	cs->C[1] = cs->MASTER_C[1] ^ ( (iv_shrt[3] << 16) | iv_shrt[1] );
	cs->C[2] = cs->MASTER_C[2] ^ iv[1];
	cs->C[3] = cs->MASTER_C[3] ^ ( (iv_shrt[2] << 16) | iv_shrt[0] );
	cs->C[4] = cs->MASTER_C[4] ^ iv[0];
	cs->C[5] = cs->MASTER_C[5] ^ ( (iv_shrt[3] << 16) | iv_shrt[1] );
	cs->C[6] = cs->MASTER_C[6] ^ iv[1];
	cs->C[7] = cs->MASTER_C[7] ^ ( (iv_shrt[2] << 16) | iv_shrt[0] );

	for (int i = 0; i < 4; i++)
	{
		rabbit_counter(cs);
		rabbit_next_state(cs);
	}
}

void rabbit_extract_keystream(rabbit_state *cs, u32 *keystream)
{
	// First update counter, then update state. Then extract 128 keystream bits.
	rabbit_counter(cs);
	rabbit_next_state(cs);

	u16 *ks_ptr = (u16*)keystream;

	ks_ptr[0] = (cs->X[0]&0xffff) ^ ( (cs->X[5] >> 16) & 0xffff);
	ks_ptr[1] = ( (cs->X[0] >> 16) & 0xffff) ^ (cs->X[3] & 0xffff);
	ks_ptr[2] = (cs->X[2]&0xffff) ^ ( (cs->X[7] >> 16) & 0xffff);
	ks_ptr[3] = ( (cs->X[2] >> 16) & 0xffff) ^ (cs->X[5] & 0xffff);
	ks_ptr[4] = (cs->X[4]&0xffff) ^ ( (cs->X[1] >> 16) & 0xffff);
	ks_ptr[5] = ( (cs->X[4] >> 16) & 0xffff) ^ (cs->X[7] & 0xffff);
	ks_ptr[6] = (cs->X[6]&0xffff) ^ ( (cs->X[3] >> 16) & 0xffff);
	ks_ptr[7] = ( (cs->X[6] >> 16) & 0xffff) ^ (cs->X[1] & 0xffff);

}

void rabbit_process_packet(rabbit_state *cs, u8 *output, u8 *input, u64 size)
{
	u64 size_left = size;
	u32 keystream[4];
	u32 *w_ptr_out = (u32*)output;
	u32 *w_ptr_in = (u32*)input;
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

		output = (u8*)w_ptr_out;
		input = (u8*)w_ptr_in;
		u8 *keystream_byte = (u8*)keystream;

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
void print_key(u32 key[4])
{
	u16 *key_ptr = (u16*)key;

	for (int i = 0; i < 8; i++)
	{
		char key_s[5];

		hex_encode(key_s, (u8*)(key_ptr+i), 2);

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
		u8 tmp[4];
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
		u8 tmp[4];
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

