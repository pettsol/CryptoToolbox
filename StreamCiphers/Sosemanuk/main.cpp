#include "sosemanuk.h"

#include "../../Encoders/Hex/encoder.h"

#include <iostream>

int main()
{
	// Hex test vector keystring
	std::string keyString = "0DA416FE03E36529FB9BEA70872F0B5D";

	std::cout << "Key length: " << keyString.size() << std::endl;
	
	u8 key[keyString.size()/2];
	hex_decode(key, keyString.data(), keyString.size());

	// Hex IV string
	std::string ivString = "D404755728FC17C659EC49D577A746E2";

	std::cout << "IV length: " << ivString.size() << std::endl;

	u8 iv[ivString.size()/2];
	hex_decode(iv, ivString.data(), ivString.size());

	// Hex test vector plaintext
	//std::string plainString = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
	
	std::string plain = "Sosemanuk stream cipher test";
	std::cout << "Plaintext: " << plain << std::endl;
	//u8 plain[plainString.size()/2];
	//hex2stringString(plain, plainString.data(), plainString.size());

	std::cout << "Initializing cipher\n";
	// Initialize cipher
	sosemanuk_state e_cs;

	std::cout << "Loading key\n";
	// Load key
	sosemanuk_load_key(&e_cs, key, keyString.size()/2);

	std::cout << "Loading iv\n";
	// Load iv
	sosemanuk_load_iv(&e_cs, iv);

	u8 cipher[plain.size()];

	std::cout << "Processing packet\n";
	sosemanuk_process_packet( &e_cs, cipher, (u8*)plain.data(), plain.size() );

	char hexCt[2*plain.size()+1];
	hex_encode(hexCt, cipher, plain.size());
	std::string hexCtString(hexCt, 2*plain.size());
	std::cout << "Ciphertext: " << hexCtString << std::endl;

	////////////////////
	// Decryption
	sosemanuk_state d_cs;
	sosemanuk_load_key(&d_cs, key, keyString.size()/2);
	sosemanuk_load_iv(&d_cs, iv);

	u8 recovered[plain.size()];

	sosemanuk_process_packet( &d_cs, recovered, cipher, plain.size() );

	std::string recov_string((char*)recovered, plain.size());
	std::cout << "Recovered: " << recov_string << std::endl;



	std::cout << "Sosemanuk says hello\n";
	std::cout << "Size: " << plain.size() << std::endl;
}
