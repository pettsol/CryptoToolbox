#include "chacha.h"
#include "../../Encoders/Hex/encoder.h"

#include <iostream>
#include <cstring>

int main()
{
	std::string test_state = "617078653320646E79622D326B20657403020100070605040B0A09080F0E0D0C13121110171615141B1A19181F1E1D1C00000001090000004A00000000000000";

	uint8_t test_state_bytes[test_state.size()/2];

	// Convert to uint8_t bytes
	hex_decode(test_state_bytes, test_state.data(), test_state.size());

	// Swap to little endian byte order
	byte_swap(test_state_bytes, test_state_bytes, test_state.size()/2);

	// Instantiate a cipher state and copy
	chacha_state cs;
	std::memcpy(cs.state, test_state_bytes, test_state.size()/2);

	// Iterate a block
	uint8_t keystream[64];
	uint32_t counter = 1;
	chacha_block(&cs, counter, (uint32_t*)keystream);

	// Swap back
	byte_swap(keystream, keystream, 64);

	// Convert to hex
	char hex_keystream[test_state.size()+1];
	hex_encode(hex_keystream, keystream, 64);

	// Print
	std::string print_hex(hex_keystream);
	std::cout << "Output: " << print_hex << std::endl;
	

}
