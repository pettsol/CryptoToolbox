#include "chacha.h"
#include "../../Encoders/Hex/encoder.h"

#include <iostream>
#include <cstring>

int main()
{
	// NB! This is in the correct order in the specification. No need to swap.
	std::string key_string = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
	std::string nonce_string = "000000000000004A00000000";

	uint8_t key[32];
	uint8_t nonce[12];

	// Convert to uint8_t keys and nonces
	hex_decode(key, key_string.data(), key_string.size());
	hex_decode(nonce, nonce_string.data(), nonce_string.size());

	// Initialize the cipher
	chacha_state cs;
	chacha_initialize(&cs, key, nonce);

	// Declare plaintext
	std::string plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

	// Declare array to hold ciphertext
	uint8_t ciphertext[plaintext.size()];

	// Encrypt
	chacha_process_packet(&cs, ciphertext, (uint8_t*)plaintext.data(), plaintext.size());

	// Convert ciphertext to hex
	char ciphertext_hex[2*plaintext.size()+1];
	hex_encode(ciphertext_hex, ciphertext, plaintext.size());

	// Print ciphertext
	std::string ciphertext_string(ciphertext_hex);

	std::string first_part = ciphertext_string.substr(0,128);
	std::string second_part = ciphertext_string.substr(128);

	std::cout << "Ciphertext part 1: " << first_part << std::endl;
	std::cout << "Ciphertext part 2: " << second_part << std::endl;


}
