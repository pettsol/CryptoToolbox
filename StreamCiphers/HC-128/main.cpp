///////////////////////////////////////
// This implementation of HC-128     //
// was placed in the public domain   //
// by:                               //
//                                   // 
// Petter Solnoer - 16/04/2020       //
///////////////////////////////////////

#include "hc128.h"
#include "../../Encoders/Hex/encoder.h"

#include <iostream>

int main()
{
	std::cout << "Hello World!\n";


	std::string pt = "Hello World! This is an example of the HC-128 stream cipher.\
 stream cipher. HC-128 is a symmetric, synchronous stream cipher that accept a 128-bit\
 key and a 128-bit initialization vector.";

	std::cout << "Plaintext: " << pt << std::endl;

	u8 ciphertext[pt.size()];
	u8 recovered[pt.size()];

	std::string hexkey = "0F62B5085BAE0154A7FA4DA0F34699EC";
	std::string hexIv = "288FF65DC42B92F960C72E95FC63CA31";

	u32 key[4];
	hex_decode((u8*)key, hexkey.data(), 32);

	u32 iv[4];
	hex_decode((u8*)iv, hexIv.data(), 32);

	// This segment performs the encryption	
	hc128_state e_cs;

	hc128_initialize(&e_cs, key, iv);

	hc128_process_packet(&e_cs, ciphertext, (u8*)pt.data(), pt.size());

	// This segment performs the decryption
	hc128_state d_cs;

	hc128_initialize(&d_cs, key, iv);

	hc128_process_packet(&d_cs, recovered, ciphertext, pt.size());

	// Print the recovered text:
	std::string print_recovered((char*)recovered, pt.size());
	std::cout << "Recovered: " << print_recovered << std::endl;
/*
	char hexCt[1025];
	string2hexString(ciphertext, hexCt, 512);
	std::string hexPrint(hexCt, 1024);

	for (int i = 0; i < 8; i++)
	{
		std::cout << "Stream [" << 64*i << "..." << 64*(i+1)-1 << "] = " <<
			hexPrint.substr(128*i, 128*(i+1)) << std::endl;
	}*/
}
