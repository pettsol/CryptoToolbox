#include "serpent.h"
#include "../../Encoders/Hex/encoder.h"

#include <iostream>
#include <cstring>

int main()
{

	// Hex test vector keystring
	std::string keyString = "0101010101010101010101010101010101010101010101010101010101010101";

	std::cout << "Key length: " << keyString.size() << std::endl;
	
	u8 key[32];
	hex_decode(key, keyString.data(), keyString.size());

	// Hex test vector plaintext
	std::string plainString = "11010101010101010101010101010101";
	
	u8 plain[16];
	hex_decode(plain, plainString.data(), plainString.size());

	serpent_state e_cs; std::memset(&e_cs, 0, sizeof(e_cs));

	serpent_key_schedule(&e_cs, key, 32);
#ifdef SOSEMANUK_H
	u8 cipher[48];
#else
	u8 cipher[16];
#endif
	serpent_process_packet(&e_cs, (u32*)cipher, (u32*)plain, 16);

#ifdef SOSEMANUK_H
	char hexCt[97];
	hex_encode(hexCt, cipher, 48);
	std::string hexCtString(hexCt, 96);
#else
	char hexCt[33];
	hex_encode(hexCt, cipher, 16);
	std::string hexCtString(hexCt, 32);
#endif
	std::cout << "Ciphertext: " << hexCtString << std::endl;
	
	std::cout << "Hello World!\n";
}
