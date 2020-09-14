///////////////////////////////////////////
// This implementation of SHA-256 was    //
// placed in the public domain by:       //
//                                       //
// Petter Solnoer - 15/04/2020           //
///////////////////////////////////////////






#include "sha-256.h"
#include "../../../../Encoders/Hex/encoder.h"

#include <iostream>

int main()
{
	std::cout << "This examples computes the SHA-256-digest of a\
 message containing 1 000 000 ''a'' characters\n";

	std::string msg = "";

	for (int i = 0; i < 1000000; i++)
	{
		msg += "a";
	}

	u32 digest[32] = {0};

	process_message(digest, (u32*)msg.data(), (u64)msg.size());

	std::string dig((char*)digest, 32);

	char hex_representation[64];
	string2hexString(hex_representation, (const u8*)digest, 32);

	std::string hex_rep(hex_representation, 64);

	std::cout << "Digest: " << dig << std::endl;

	std::cout << "Digest in Hex: " << hex_rep << std::endl;
}
