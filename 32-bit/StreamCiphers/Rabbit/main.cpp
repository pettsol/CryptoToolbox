#include "rabbit.h"
#include "../../HexEncoder/encoder.h"

#include <iostream>


int main()
{
//	std::string key_string = "ACC351DCF162FC3BFE363D2E29132891";
	std::string key_string = "00000000000000000000000000000000";
	//std::string iv_string = "0000000000000000";

	std::string iv_string = "597E26C175F573C3";

	u8 key[key_string.size()/2];
	u8 iv[iv_string.size()/2];

	hex2stringString(key, key_string.data(), key_string.size());
	hex2stringString(iv, iv_string.data(), iv_string.size());

	rabbit_state cs;

	rabbit_key_setup(&cs, (u32*)key);
	rabbit_iv_setup(&cs, (u32*)iv);

	std::string plaintext = "Hello World! This is the Rabbit cipher designed by Cryptico A/S. It was submitted to the eSTREAM portfolio, and was a successful entrant. This implementation was written by Petter Solnoer and has been verified by official test vectors....";

	u8 ct[plaintext.size()];

	rabbit_process_packet(&cs, ct, (u8*)plaintext.data(), plaintext.size());

	// Encrypt more shit that won't be decipered.
	
	std::string mumbo = "..2.2.2.2.2.2.2.2.222..2.2.2.2.2.2.2.2.2..2.2.2.2.222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";

	u8 ct_throw[mumbo.size()];

	rabbit_process_packet(&cs, ct_throw, (u8*)mumbo.data(), mumbo.size());

	rabbit_iv_setup(&cs, (u32*)iv);

	std::string second_pt = "Does this decrypt successfully?";

	u8 second_ct[second_pt.size()];

	rabbit_process_packet(&cs, second_ct, (u8*)second_pt.data(), second_pt.size());

	char ct_hex[2*plaintext.size()+1];

	string2hexString(ct_hex, ct, plaintext.size());

	std::string ct_s(ct_hex);

	std::cout << "Plaintext: " << plaintext << std::endl;
	std::cout << "Ciphertext: " << ct_s << std::endl;
	
	rabbit_state d_cs;
	rabbit_key_setup(&d_cs, (u32*)key);
	rabbit_iv_setup(&d_cs, (u32*)iv);

	u8 recv[plaintext.size()];

	rabbit_process_packet(&d_cs, recv, ct, plaintext.size());

	std::string recovered((char*)recv, plaintext.size());

	std::cout << "Recovered: " << recovered << std::endl;

	rabbit_iv_setup(&d_cs, (u32*)iv);

	u8 recv2[second_pt.size()];

	rabbit_process_packet(&d_cs, recv2, second_ct, second_pt.size());

	std::string recovered_2((char*)recv2, second_pt.size());

	std::cout << "Recovered 2: " << recovered_2 << std::endl;

//	u8 keystream[16];

//	rabbit_extract_keystream(&cs, (u32*)keystream);

//	char keystream_hex[33];

//	string2hexString(keystream_hex, keystream, 16);

//	std::string keystream_string(keystream_hex);

//	std::cout << "Keystream: " << keystream_string << std::endl;
}
