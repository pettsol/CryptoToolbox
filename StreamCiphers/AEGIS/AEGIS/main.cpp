#include "aegis_128.h"
#include "../../../Encoders/Hex/encoder.h"

#include <iostream>

int main()
{

	//uint64_t pt_length = 39;

	uint8_t key[16] = {0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
               	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	uint8_t iv[16] = {0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	/*uint8_t pt[pt_length] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26};

	uint8_t ad[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
	*/

	std::string plaintext = "Hello world! This is the sample program for AEGIS";


	int pt_length = plaintext.size();

	uint8_t ct[pt_length] = {0};
	uint8_t tag[16] = {0};

	aegis_state cs;


	
	aegis_load_key(&cs, key);
	aegis_encrypt_packet(&cs, ct, tag, (uint8_t*)plaintext.data(), iv, iv, IV_SIZE, pt_length);

	std::cout << "Successfully Encrypted\n";
	
	uint8_t recv[pt_length] = {0};

	if (!aegis_decrypt_packet(&cs, recv, ct, iv, iv, tag, IV_SIZE, pt_length))
	{
		std::cout << "Invalid tag!\n";
		exit(1);
	}

	std::cout << "Successfully Decrypted\n";

	/*char PT[2*pt_length+1];
	string2hexString(PT, (uint8_t*)plaintext.data(), pt_length);
	std::string hexPT(PT, 2*pt_length+1);
	std::cout << "Hex PT: " << hexPT << std::endl;
*/
	char hexCT[2*pt_length+1];
	hex_encode(hexCT, ct, pt_length);
	std::string hexString(hexCT, 2*pt_length+1);
	std::cout << "Hex CT: " << hexString << std::endl;

	/*char hexTAG[33];
	string2hexString(hexTAG, tag, 16);
	std::string hexTagString(hexTAG, 33);
	std::cout << "Hex TAG: " << hexTagString << std::endl;
*
	char recvPT[2*pt_length+1];
	string2hexString(recvPT, recv, pt_length+1);
	std::string hexRECV(recvPT, 2*pt_length+1);
	std::cout << "Hex RECV: " << recvPT << std::endl;
*/
	std::string recv_string((char*)recv, plaintext.size());
	std::cout << "Plaintext: " << plaintext << std::endl;
	std::cout << "Recovered: " << recv_string << std::endl;
}
