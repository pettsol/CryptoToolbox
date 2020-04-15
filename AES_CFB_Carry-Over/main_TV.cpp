#include "aes_cfb.h"
#include "encoder.h"
#include <iostream>

int main()
{
	// NOTE: Hex encoding required 2 symbols per byte.
	// ENCRYPTION
	cipher_state e_cs;
	
	// Test vectors, keys and IVs encoded in HEX format	
	std::string hex_key = "2B7E151628AED2A6ABF7158809CF4F3C";
	unsigned char key[hex_key.size()/2+1];
	hex2stringString(hex_key.data(), key, hex_key.size());
	
	std::string hex_iv = "000102030405060708090A0B0C0D0E0F";
	unsigned char iv[hex_iv.size()/2+1];
	hex2stringString(hex_iv.data(), iv, hex_iv.size());
	
	// Initialize the keystream generator with key and IV
	cfb_initialize_cipher(&e_cs, (u8*)key, (u32*)iv); 

	// The test vector plaintext encoded in HEX
	std::string hex_pt = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";
	std::cout << "Length of hex_pt: " << hex_pt.size() << std::endl;
	unsigned char pt_array[hex_pt.size()/2+1];
	hex2stringString(hex_pt.data(), pt_array, hex_pt.size());

	// Try to recover the pt:
/*	
	char pt_recov[hex_pt.size()+1];
	string2hexString(pt_array, pt_recov, hex_pt.size()/2);
	std::string recov_string(pt_recov, hex_pt.size());
	std::cout << "Transmitt pt: " << hex_pt << std::endl;
	std::cout << "Recovered pt: " << recov_string << std::endl;
*/
	////

	// Print the plaintext
	std::cout << "Plaintext: " << hex_pt << std::endl;

	// Encrypt the message.
	unsigned char ct_array[hex_pt.size()/2+1];
	cfb_process_packet(&e_cs, (u8*)pt_array, (u8*)ct_array, hex_pt.size()/2, encrypt);
	//std::string ciphertext(ct_array, hex_pt.size()/2);

	// Encode the ciphertext, and print to verify
	char hex_ct[hex_pt.size()+1];
	string2hexString(ct_array, hex_ct, hex_pt.size()/2);
	std::string hex_ct_string(hex_ct, hex_pt.size());
	std::cout << "Ciphertext: " << hex_ct_string << std::endl;
	
	// DECRYPTION

	// Initialize a new cipher
	// with the same IV and key
	cipher_state d_cs;
	cfb_initialize_cipher(&d_cs, key, (u32*)iv);

	// The recovered plaintext is half the
	// size of the original hex encoded text
	unsigned char pt_recovered_array[hex_pt.size()/2+1];

	// Decrypt the packet
	cfb_process_packet(&d_cs, (u8*)ct_array, (u8*)pt_recovered_array, hex_pt.size()/2, decrypt);

	// Encode the recovered plaintext
	// in order to print it
	char hex_recovered_pt[hex_pt.size()+1];
	string2hexString(pt_recovered_array, hex_recovered_pt, hex_pt.size()/2);

	std::cout << "Recovered: " << hex_recovered_pt << std::endl;
}
