#include "serpent.h"
#include "../HexEncoder/encoder.h"

#include <iostream>

int main()
{
	std::string keyString = "0000000000000000000000000000000000000000000000000000000000000000";
//	std::string keyString = "15FC0D48D7F8199CBE3991834D96F32710000000000000000000000000000000";

	std::cout << "Key length: " << keyString.size() << std::endl;
	
	u8 key[32];
	hex2stringString(key, keyString.data(), keyString.size());

	std::string plainString = "00000000000000000000000000000000";
	
	u8 plain[16];
	hex2stringString(plain, plainString.data(), plainString.size());

	cipher_state e_cs;
	key_schedule(&e_cs, key, 32);

	u8 cipher[16];
	process_packet(&e_cs, (u32*)cipher, (u32*)plain, 16);

	char hexCt[33];
	string2hexString(hexCt, cipher, 16);
	std::string hexCtString(hexCt, 32);

	// Print the round keys
	for (int i = 0; i < 33; i++)
	{
		char hexRK0[9];
		char hexRK1[9];
		char hexRK2[9];
		char hexRK3[9];
		string2hexString(hexRK0, (u8*)&e_cs.RK[4*i], 4);
		string2hexString(hexRK1, (u8*)&e_cs.RK[4*i+1], 4);
		string2hexString(hexRK2, (u8*)&e_cs.RK[4*i+2], 4);
		string2hexString(hexRK3, (u8*)&e_cs.RK[4*i+3], 4);

		std::string hexRK0String(hexRK0, 8);
		std::string hexRK1String(hexRK1, 8);
		std::string hexRK2String(hexRK2, 8);
		std::string hexRK3String(hexRK3, 8);

		std::cout << "Round key " << i << ": " << hexRK0String 
			<< " " << hexRK1String << " " << hexRK2String << " " << hexRK3String << std::endl;
	}
	//

	std::cout << "Ciphertext: " << hexCtString << std::endl;

	std::cout << "Hello World!\n";
}
