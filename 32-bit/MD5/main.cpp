#include "md5.h"
#include "../HexEncoder/encoder.h"

#include <iostream>


int main()
{
	std::string test_string = "message digest";

	u8 digest[16];

	MD5_CTX cs;

	MD5Init(&cs);

	MD5Update(&cs, (u8*)test_string.data(), (u32)test_string.size());

	MD5Final(digest, &cs);

	char hex_digest[33];

	string2hexString(hex_digest, digest, 16);

	std::string hex_string(hex_digest);

	std::cout << "Digest: " << hex_digest << std::endl;

}
