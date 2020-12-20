#include "rabbit.h"
#include "../../Encoders/Hex/encoder.h"

#include <iostream>


int main()
{
//	std::string key_string = "ACC351DCF162FC3BFE363D2E29132891";
	std::string key_string = "00000000000000000000000000000000";
	//std::string iv_string = "0000000000000000";

	std::string iv_string = "597E26C175F573C3";

	uint8_t key[key_string.size()/2];
	uint8_t iv[iv_string.size()/2];

	hex_decode(key, key_string.data(), key_string.size());
	hex_decode(iv, iv_string.data(), iv_string.size());

	rabbit_state cs;

	rabbit_load_key(&cs, key);
	rabbit_load_iv(&cs, iv);

	std::string plaintext = "Hello World! This is the Rabbit cipher designed by Cryptico A/S. It was submitted to the eSTREAM portfolio, and was a successful entrant. This implementation was written by Petter Solnoer and has been verified by official test vectors....";

	uint8_t ct[plaintext.size()];

	rabbit_process_packet(&cs, ct, (uint8_t*)plaintext.data(), plaintext.size());

	// Encrypt more shit that won't be decipered.
	
	std::string mumbo = "..2.2.2.2.2.2.2.2.222..2.2.2.2.2.2.2.2.2..2.2.2.2.222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222";

	uint8_t ct_throw[mumbo.size()];

	rabbit_process_packet(&cs, ct_throw, (uint8_t*)mumbo.data(), mumbo.size());

	rabbit_load_iv(&cs, iv);

	std::string second_pt = "Does this decrypt successfully?";

	uint8_t second_ct[second_pt.size()];

	rabbit_process_packet(&cs, second_ct, (uint8_t*)second_pt.data(), second_pt.size());

	char ct_hex[2*plaintext.size()+1];

	hex_encode(ct_hex, ct, plaintext.size());

	std::string ct_s(ct_hex);

	std::cout << "Plaintext: " << plaintext << std::endl;
	std::cout << "Ciphertext: " << ct_s << std::endl;
	
	rabbit_state d_cs;
	rabbit_load_key(&d_cs, key);
	rabbit_load_iv(&d_cs, iv);

	uint8_t recv[plaintext.size()];

	rabbit_process_packet(&d_cs, recv, ct, plaintext.size());

	std::string recovered((char*)recv, plaintext.size());

	std::cout << "Recovered: " << recovered << std::endl;

	rabbit_load_iv(&d_cs, iv);

	uint8_t recv2[second_pt.size()];

	rabbit_process_packet(&d_cs, recv2, second_ct, second_pt.size());

	std::string recovered_2((char*)recv2, second_pt.size());

	std::cout << "Recovered 2: " << recovered_2 << std::endl;

//	uint8_t keystream[16];

//	rabbit_extract_keystream(&cs, (uint32_t*)keystream);

//	char keystream_hex[33];

//	string2hexString(keystream_hex, keystream, 16);

//	std::string keystream_string(keystream_hex);

//	std::cout << "Keystream: " << keystream_string << std::endl;
}
