#include "des.h"
#include "../../Encoders/Hex/encoder.h"
#include <iostream>

int main()
{
	std::string key_string = "0000000000000000";

	u8 key[8];

	hex2stringString(key, key_string.data(), 16);

	des_state e_cs;

	des_key_schedule_encrypt(&e_cs, key);

	std::string message = "STARFALLSTARFALL";

	std::cout << "Message size: " << message.size() << std::endl;

	u8 ct[16];

	des_process_packet_ecb(&e_cs, (u32*)ct, (u32*)message.data(), 16);

	char hex_ct[33];

	string2hexString(hex_ct, ct, 16);

	std::string hex_ct_string(hex_ct);

	std::cout << "Hex CT: " << hex_ct_string << std::endl;
}
