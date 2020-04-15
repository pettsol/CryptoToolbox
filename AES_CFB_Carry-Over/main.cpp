#include <iostream>

#include "aes_cfb.h"

#define BLOCKSIZE

int main()
{
	cipher_state e_cs;
	cipher_state d_cs;

	u8 key[BLOCKSIZE] = {0};
	u32 iv_encryption[BLOCKSIZE] = {0};
	u32 iv_decryption[BLOCKSIZE] = {1};

	cfb_initialize_cipher(&e_cs, key, iv_encryption);
	cfb_initialize_cipher(&d_cs, key, iv_decryption);

	std::string pt = "Hello world, this is the greatest attempt at encryption ever! Lets see what this cipher can do. Because it is self-synchronizing, it should automatically resynchronize even if the initialization vector is different between the transmitter and the receiver. Isn't that amazing?";

	std::cout << "Length of plaintext: " << pt.size() << std::endl;

	u8 ct[pt.size()];

	cfb_process_packet(&e_cs, (u8*)pt.data(), ct, pt.size(), encrypt);

	char recovered[pt.size()];
	
	cfb_process_packet(&d_cs, ct, (u8*)recovered, pt.size(), decrypt);

	std::string recovered_string(recovered, pt.size());

	std::cout << "Plaintext: " << pt << std::endl;
	std::cout << "Recovered: " << recovered_string << std::endl;

	std::cout << "Length of recovered: " << recovered_string.size() << std::endl;
}
