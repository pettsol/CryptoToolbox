#include "aegis_128.h"
#include "../HexEncoder/encoder.h"

#include <iostream>

int main()
{
	std::cout << "Size of long long: " << sizeof(long long) << std::endl;
	u8 key[16] = {0};
	u8 iv[16] = {0};

	u8 pt[16] = {0};
	u8 ad[4] = {0x00, 0x01, 0x02, 0x03};
//	u8 ad[16] = {0};
	
	u8 ct[16] = {0};
	u8 tag[16] = {0};

	aegis_state cs;
	
	aegis_load_key(&cs, (u32*)key);
	std::cout << "Load key\n";
	aegis_encrypt_packet(&cs, ct, tag, pt, ad, (u32*)iv, 4, 16);
	std::cout << "Encrypt packet\n";

	u8 recv[16] = {0};

	if (!aegis_decrypt_packet(&cs, recv, ct, ad, (u32*)iv, (u32*)tag, 4, 16))
	{
		std::cout << "Invalid tag!\n";
		exit(1);
	}

	std::cout << "Valid tag\n";

	char PT[33];
	string2hexString(PT, pt, 16);
	std::string hexPT(PT, 33);
	std::cout << "Hex PT: " << hexPT << std::endl;

	char hexCT[33];
	string2hexString(hexCT, ct, 16);
	std::string hexString(hexCT, 33);
	std::cout << "Hex CT: " << hexString << std::endl;

	char hexTAG[33];
	string2hexString(hexTAG, tag, 16);
	std::string hexTagString(hexTAG, 33);
	std::cout << "Hex TAG: " << hexTagString << std::endl;

	char recvPT[33];
	string2hexString(recvPT, recv, 16);
	std::string hexRECV(recvPT, 33);
	std::cout << "Hex RECV: " << recvPT << std::endl;
}
