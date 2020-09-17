///////////////////////////////////////
// This implementation of HMAC with  //
// SHA-256 was placed in the public  //
// domain by:                        //
//                                   // 
// Petter Solnoer - 15/04/2020       //
///////////////////////////////////////




#include "hmac.h"
#include "../../Encoders/Hex/encoder.h"

#include <iostream>

int main()
{

	std::cout << "Test vector for HMAC-SHA-256 with 100-byte key and 16-byte tag.\n";


	std::string ExpectedTag = "BDCCB6C72DDEADB500AE768386CB38CC";

	std::cout << "Expected tag: " << ExpectedTag << std::endl;

	hmac_state hs;

	std::string keystring = "000102030405060708090A0B0C0\
D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2\
B2C2D2E2F303132333435363738393A3B3C3D3E3F4041424344454647484\
94A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263";

	std::string msg = "53616D706C65206D65737361676520666\
F72206B65796C656E3D626C6F636B6C656E"; 

	u8 message[msg.size()/2];
	hex_decode(message, msg.data(), msg.size());

	u8 key[keystring.size()/2];
	hex_decode(key, keystring.data(), keystring.size());

	hmac_load_key(&hs, key, keystring.size()/2);

	u8 tag[16];

	//tag_generation(&hs, (u8*)message.data(), tag, message.size());
	hmac_tag_generation(&hs, tag, message, msg.size()/2, 16);

	char hex_tag[33];
	hex_encode(hex_tag, tag, 16);
	std::string hex_string(hex_tag, 32);
	std::cout << "Hex tag: " << hex_string << std::endl;

	u8 expected_tag[16];
	hex_decode(expected_tag, ExpectedTag.data(), 32);

	if ( hmac_tag_validation(&hs, tag, message, msg.size()/2, 16))
	{ 
		std::cout << "Validation Tag confirmed\n";
	} else {
		std::cout << "Validation Tag mismatch\n";
	}
	int status = 0;
	for (int i = 0; i < 16; i++)
	{
		if (tag[i] != expected_tag[i])
		{
			status = 1;
		}
	}
	if (status) { std::cout << "FAILURE\n";}
	else {std::cout << "SUCCESS!\n";}
}
