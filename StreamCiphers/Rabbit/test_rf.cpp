#include "rabbit.h"
#include "../../Encoders/Hex/encoder.h"

#include <iostream>


int main()
{
	// C3 AC DC 51 | 62 F1 2E FC | 62 FE 91 3D | 13 29 91 28 //
//	std::string key_string = "C3ACDC5162F12EFC62FE913D13299128"; 
	// DC 51 C3 AC | 3B FC 62 F1 | 2E 3D 36 FE | 91 28 13 29 //
//	std::string key_string = "DC51C3AC3BFC62F12E3D36FE91281329";
	std::string key_string = "ACC351DCF162FC3BFE363D2E29132891";
//	std::string key_string = "912813292E3D36FE3BFC62F1DC51C3AC";
	std::string iv_string = "0000000000000000";

	uint8_t key[key_string.size()/2];
	uint8_t iv[iv_string.size()/2];

	hex_decode(key, key_string.data(), key_string.size());

	print_key((uint32_t*)key);

	std::cout << " Hello " << std::endl;
	// Swap bytes
//	byte_swap(key, key, key_string.size()/2);

	hex_decode(iv, iv_string.data(), iv_string.size());

	rabbit_state cs;

	rabbit_load_key(&cs, key);
//	rabbit_load_iv(&cs, iv);
//
//	uint8_t keystream[16];
//
//	rabbit_extract_keystream(&cs, (uint32_t*)keystream);
//
//	char keystream_hex[33];
//
//	string2hexString(keystream_hex, keystream, 16);
//
//	std::string keystream_string(keystream_hex);
//
//	std::cout << "Keystream: " << keystream_string << std::endl;
}
