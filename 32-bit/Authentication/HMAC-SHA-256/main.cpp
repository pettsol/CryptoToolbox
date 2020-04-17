///////////////////////////////////////
// This implementation of HMAC with  //
// SHA-256 was placed in the public  //
// domain by:                        //
//                                   // 
// Petter Solnoer - 15/04/2020       //
///////////////////////////////////////




#include "hmac.h"
#include "../../HexEncoder/encoder.h"

#include <iostream>

int main()
{
	hmac_state hs;

	std::string keystring = "000102030405060708090A0B0C0\
D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2\
B2C2D2E2F303132333435363738393A3B3C3D3E3F4041424344454647484\
94A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263";

	std::string msg = "53616D706C65206D65737361676520666\
F72206B65796C656E3D626C6F636B6C656E"; 

	u8 message[msg.size()/2];
	hex2stringString(message, msg.data(), msg.size());

	u8 key[keystring.size()/2];
	hex2stringString(key, keystring.data(), keystring.size());

	hmac_initialization(&hs, key, keystring.size()/2);

	u8 tag[16];

	//tag_generation(&hs, (u8*)message.data(), tag, message.size());
	tag_generation(&hs, tag, message, msg.size()/2, 16);

	char hex_tag[33];
	string2hexString(hex_tag, tag, 16);
	std::string hex_string(hex_tag, 32);
	std::cout << "Hex tag: " << hex_string << std::endl;

	if ( tag_validation(&hs, tag, message, msg.size()/2, 16))
	{ 
		std::cout << "Tag confirmed\n";
	} else {
		std::cout << "Tag mismatch\n";
	}
}
