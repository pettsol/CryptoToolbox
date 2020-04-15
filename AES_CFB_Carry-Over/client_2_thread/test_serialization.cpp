#include "serialization.h"
#include "structs.h"
#include "aes_cfb.h"

#include <iostream>

#define DATA_SIZE sizeof(data_struct)

int main()
{
	data_struct data;
	data.is_broken = 1;
	data.data = 2;

	u8 pt[DATA_SIZE];
	serialize(&data, pt);

	cipher_state cs;

	u8 ck[16] = {0};
	u32 iv[4] = {0};

	cfb_initialize_cipher(&cs, ck, iv);

	u8 ct[DATA_SIZE];
	cfb_process_packet(&cs, pt, ct, DATA_SIZE, encrypt);

	cipher_state d_cs;

	std::string intermediate((char*)ct, DATA_SIZE);
	u8 *ct_test = (u8*)&intermediate[0];

	cfb_initialize_cipher(&cs, ck, iv);

	u8 recovered[DATA_SIZE];
	cfb_process_packet(&cs, ct_test, recovered, DATA_SIZE, decrypt);



	data_struct data_recovered;

	deserialize(recovered, &data_recovered);

	std::cout << data_recovered.is_broken << std::endl;
	std::cout << data_recovered.data << std::endl;

	cfb_process_packet(&cs, pt, ct, DATA_SIZE, encrypt);
	std::string intermediate((char*)ct, DATA_SIZE);
	u8 *ct_test = (u8*)&intermediate[0];
	cfb_process_packet(&cs, ct_test, recovered, DATA_SIZE, decrypt);

	deserialize(recovered, &data_recovered);

	std::cout << data_recovered.is_broken << std::endl;
	std::cout << data_recovered.data << std::endl;



}
