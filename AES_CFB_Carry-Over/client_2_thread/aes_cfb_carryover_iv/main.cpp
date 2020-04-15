///////////////////////////////////
// This implementation was been  //
// placed in the public domain by//
//                               //
// Petter Solnoer - 31/03/2020   //
///////////////////////////////////

#include "aes_cfb.h"

#include <iostream>
// This is intended as a minimal
// working example, illustrating
// how the implementation is to
// be used.

// AES uses a blocksize of 16
// This implementation only
// supports 16 byte keys.
#define BLOCKSIZE 16 

int main()
{
	// 16 byte = 128 bit keys.
	u8 key[BLOCKSIZE] = {0};

	// This implementation
	// operates on 4 byte
	// words.
	u32 iv[BLOCKSIZE/4] = {0};
	
	// *ENCRYPTION* //

	// The struct cipher_state
	// holds the state of the
	// cipher (i.e. the IV
	// or previous ciphertext).
	cipher_state e_cs;

	// In order to initialize
	// the cipher, one must pass
	// a reference to the cipher
	// state along with the key
	// and iv. The IV is then
	// loaded into the registers
	// and the key schedule is
	// computed and stored in the
	// cipher state.
	cfb_initialize_cipher(&e_cs, key, iv);

	// The following string will
	// be encrypted.
	std::string plaintext = "Hello world! This program demonstrates how \
the implementation is to be used.";

	std::cout << "Plaintext: " << plaintext << std::endl;
	// Declare a variable that
	// will hold the ciphertext
	u8 ciphertext[plaintext.size()];

	// The plaintext is then
	// encrypted. Pass a reference
	// to the cipher state, a
	// pointer to the plaintext
	// and the ciphertext. The size
	// of the plaintext is also required.
	// State that the input is to
	// be encrypted.
	cfb_process_packet(&e_cs, (u8*)plaintext.data(), ciphertext, plaintext.size(), encrypt);

	// Print the corresponding
	// ciphertext:
	std::string ciphertext_string((char*)ciphertext, plaintext.size());
	std::cout << "Ciphertext: " << ciphertext_string << std::endl;

	// *DECRYPTION* //
	
	// Declare a new cipher
	// struct to decrypt
	cipher_state d_cs;

	// Initialize
	cfb_initialize_cipher(&d_cs, key, iv);

	// Declare a variable to
	// hold the recovered text.
	u8 recovered[ciphertext_string.size()];

	// Decrypt
	cfb_process_packet(&d_cs, (u8*)ciphertext_string.data(), recovered, ciphertext_string.size(), decrypt);

	// Print the recovered text
	std::string recovered_string((char*)recovered, ciphertext_string.size());
	std::cout << "Recovered: " << recovered_string << std::endl;

	// END OF EXAMPLE //

}
