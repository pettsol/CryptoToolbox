#include "encoder.h"
#include "aes_cfb.h"
#include <iostream>

int main()
{
	std::string hex_key = "2B7E151628AED2A6ABF7158809CF4F3C";
	unsigned char key[16];

	hex2stringString(hex_key.data(), key, 32);
	//std::string key_string(key, 16);

//	std::cout << key_string << std::endl;

	cipher_state cs;

	KeyExpansion((u8*)key, cs.rk);

	//std::cout << (cs.rk[0] ^ cs.rk[4]) << std::endl;

	// TEST STRING2HEX:
	/*std::string TEST = "28AED2A6";
	std::cout << "ORIGINAL STRING: " << TEST << std::endl;

	char TEST_CHAR[2*TEST.size()+1];
	hex2stringString(TEST.data(), TEST_CHAR, 4);
	std::string TESTSTRING(TEST_CHAR, 4);
	//std::cout << TESTSTRING << std::endl;
	char RECOVERED_CHAR[9];
	string2hexString(TESTSTRING.data(), RECOVERED_CHAR, 4);
	std::string RECOVERED_STRING(RECOVERED_CHAR, 2*TEST.size()+1);
	std::cout << "RECOVERED STRING: " << RECOVERED_STRING << std::endl;
	*////////
	for (int i = 0; i < 11; i++)
	{
		char hex_key1[9];
		string2hexString((const u8* )&cs.rk[4*i], hex_key1, 4);

		char hex_key2[9];
		string2hexString((const u8* )&cs.rk[4*i+1], hex_key2, 4);
		
		char hex_key3[9];
		string2hexString((const u8* )&cs.rk[4*i+2], hex_key3, 4);

		char hex_key4[9];
		string2hexString((const u8* )&cs.rk[4*i+3], hex_key4, 4);

		std::cout << hex_key1 << " | "
		      << hex_key2 << " | "
		      << hex_key3 << " | "
		      << hex_key4 << std::endl;
	}
}
