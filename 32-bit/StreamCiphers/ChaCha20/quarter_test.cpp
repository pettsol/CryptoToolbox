#include "chacha.h"
#include "../../HexEncoder/encoder.h"

#include <iostream>
#include <cstring>

int main()
{

	// ROTATION TEST
	u32 test = 0x7998bfda;
	test = ROTL_32(test, 7);
	std::cout << test << std::endl;
	// STRING
	//std::string HexIn = "7998BFDA";
	std::string HexIn = "DABF9879";
	//std::string HexIn = "BFDA7998";
	u8 in[4];
       	hex2stringString(in, HexIn.data(), 8);

	u32 w_in[2];
	std::memcpy(w_in, in, 4);

	u32 in_rot = ROTL_32(w_in[0], 7);

	char HexOut[9];
	string2hexString(HexOut, (u8*)&in_rot, 4);

	std::string printString(HexOut);
	std::cout << "Rot: " << printString << std::endl;



	// QUARTER TEST

	std::string hexInput = "879531E0C5ECF37D516461B1C9A62F8A44C20EF33390AF7FD9FC690B2A5F714C53372767B00A5631974C541A359E99635C9710613D6316892098D9D691DBD320";
	std::cout << "Input: " << hexInput << std::endl;
	std::cout << "Size of input: " << hexInput.size() << std::endl;

	u8 input[hexInput.size()/2];
	u8 output[hexInput.size()/2];
	hex2stringString(input, hexInput.data(), hexInput.size());
	// Swap byte order of input
	byte_swap(input, input, hexInput.size()/2);
	
	// Pass to test q
	test_q((u32*)input, (u32*)output);

	// Swap byte order of output
	byte_swap(output, output, hexInput.size()/2);
	
	//
	char hexOutput[hexInput.size()+1];
	string2hexString(hexOutput, output, hexInput.size()/2);
	std::string print(hexOutput);

	std::cout << "Output: " << print << std::endl;

	// Quarter test 2
	//
	

}
