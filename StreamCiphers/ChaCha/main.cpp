#include "chacha.h"
#include "../../Encoders/Hex/encoder.h"

#include <iostream>

int main()
{
	// *****Encryption section***** //
	//
	// Declare the plaintext
	std::string message = "Hello World! This illustrates the use of the ChaCha20 stream cipher designed by Dr. Daniel Bernstein. This stream cipher accepts a 256-bit key and a 96-bit nonce.\n";

	std::cout << "Plaintext: " << message << std::endl;
	// Key and nonce in byte array order.
	std::string key_string = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
	std::string nonce_string = "000000000000004A00000000";

	uint8_t key[32];
	uint8_t nonce[12];

	// Convert hex key and nonce to uint8_t
	hex_decode(key, key_string.data(), key_string.size());
	hex_decode(nonce, nonce_string.data(), nonce_string.size());

	// Initialize the cipher to encrypt
	chacha_state e_cs;
	chacha_initialize(&e_cs, key, nonce);

	// Declare array to hold ciphertext
	uint8_t ciphertext[message.size()];

	// Encrypt
	chacha_process_packet(&e_cs, ciphertext, (uint8_t*)message.data(), message.size());

	// Print the hex encoding of the ciphertext
	char hex_ciphertext[2*message.size()+1];
	hex_encode(hex_ciphertext, ciphertext, message.size());
	std::string print_ciphertext(hex_ciphertext);
	std::cout << "Ciphertext: " << print_ciphertext << std::endl;

	// *****Decryption section***** //
	//
	// Initialize the cipher to decrypt
	chacha_state d_cs;
	chacha_initialize(&d_cs, key, nonce);

	// Declare array to hold recovered message
	uint8_t recovered[message.size()];

	// Decrypt
	chacha_process_packet(&d_cs, recovered, ciphertext, message.size());

	// Translate to string
	std::string recov_string((const char*)recovered, message.size());

	// Print recovered
	std::cout << "\nRecovered: " << recov_string << std::endl;
}
