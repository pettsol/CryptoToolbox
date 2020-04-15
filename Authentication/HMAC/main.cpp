#include "hmac.h"
#include "../../HexEncoder/encoder.h"

#include <iostream>

int main()
{
	hmac_state hs;

	std::string keystring = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263";

	std::string msg = "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E"; 

	u8 message[msg.size()/2];
	hex2stringString(msg.data(), message, msg.size());

	u8 key[keystring.size()/2];
	hex2stringString(keystring.data(), key, keystring.size());

	hmac_initialization(&hs, key, keystring.size()/2);

	u8 tag[16];

	//tag_generation(&hs, (u8*)message.data(), tag, message.size());
	tag_generation(&hs, message, tag, msg.size()/2, 16);

	char hex_tag[33];
	string2hexString(tag, hex_tag, 16);
	std::string hex_string(hex_tag, 32);
	std::cout << "Hex tag: " << hex_string << std::endl;

	if ( tag_validation(&hs, message, tag, msg.size()/2, 16)) { std::cout << "Tag confirmed\n"; }
	else {  std::cout << "Tag mismatch\n"; }
}
