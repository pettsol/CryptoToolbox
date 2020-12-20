#include "chacha.h"
#include "../../Encoders/Hex/encoder.h"

#include <iostream>
#include <cstring>

int main()
{

	// ROTATION TEST
	uint32_t test = 0x7998bfda;
	test = ROTL_32(test, 7);
	std::cout << test << std::endl;
	// STRING
	//std::string HexIn = "7998BFDA";
	std::string HexIn = "DABF9879";
	//std::string HexIn = "BFDA7998";
	uint8_t in[4];
       	hex_decode(in, HexIn.data(), 8);

	uint32_t w_in[2];
	std::memcpy(w_in, in, 4);

	uint32_t in_rot = ROTL_32(w_in[0], 7);

	char HexOut[9];
	hex_encode(HexOut, (uint8_t*)&in_rot, 4);

	std::string printString(HexOut);
	std::cout << "Rot: " << printString << std::endl;



	// QUARTER TEST

	std::string hexInput = "879531E0C5ECF37D516461B1C9A62F8A44C20EF33390AF7FD9FC690B2A5F714C53372767B00A5631974C541A359E99635C9710613D6316892098D9D691DBD320";
	std::cout << "Input: " << hexInput << std::endl;
	std::cout << "Size of input: " << hexInput.size() << std::endl;

	uint8_t input[hexInput.size()/2];
	uint8_t output[hexInput.size()/2];
	hex_decode(input, hexInput.data(), hexInput.size());
	// Swap byte order of input
	byte_swap(input, input, hexInput.size()/2);
	
	// Pass to test q
	test_q((uint32_t*)input, (uint32_t*)output);

	// Swap byte order of output
	byte_swap(output, output, hexInput.size()/2);
	
	//
	char hexOutput[hexInput.size()+1];
	hex_encode(hexOutput, output, hexInput.size()/2);
	std::string print(hexOutput);

	std::cout << "Output: " << print << std::endl;

	// Quarter test 2
	//
	

}
