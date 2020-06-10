#include "chacha.h"
#include "../../HexEncoder/encoder.h"

#include <iostream>
#include <cstring>

int main()
{
	std::string test_state = "617078653320646E79622D326B20657403020100070605040B0A09080F0E0D0C13121110171615141B1A19181F1E1D1C00000001090000004A00000000000000";

	u8 test_state_bytes[test_state.size()/2];

	// Convert to u8 bytes
	hex2stringString(test_state_bytes, test_state.data(), test_state.size());

	// Swap to little endian byte order
	byte_swap(test_state_bytes, test_state_bytes, test_state.size()/2);

	// Instantiate a cipher state and copy
	chacha_state cs;
	std::memcpy(cs.state, test_state_bytes, test_state.size()/2);

	// Iterate a block
	u8 keystream[64];
	u32 counter = 1;
	chacha20_block(&cs, counter, (u32*)keystream);

	// Swap back
	byte_swap(keystream, keystream, 64);

	// Convert to hex
	char hex_keystream[test_state.size()+1];
	string2hexString(hex_keystream, keystream, 64);

	// Print
	std::string print_hex(hex_keystream);
	std::cout << "Output: " << print_hex << std::endl;
	

}
