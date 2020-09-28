/////////////////////////////////////
// This implementation of AES      //
// in CFB mode with carry-over IV  //
// was placed in the public domain //
// by:                             //
//                                 //
// Petter Solnoer - 07/09/2020     //
/////////////////////////////////////

#include "aes_ctr.h"
#include "../../../../Encoders/Hex/encoder.h"

#include <cstring>
#include <iostream>
// This is intended as a minimal
// working example, illustrating
// how the implementation is to
// be used.

// AES uses a blocksize of 16
// This implementation only
// supports 16 byte keys.
#define BLOCKSIZE 16 

/*
u32 swap(u32 in)
{
	((num>>24)&0xff) | // move byte 3 to byte 0
       	((num<<8)&0xff0000) | // move byte 1 to byte 2
        ((num>>8)&0xff00) | // move byte 2 to byte 1
        ((num<<24)&0xff000000); // byte 0 to byte 3
}
*/
int main()
{
	// 16 byte = 128 bit keys.
	u8 key_1[BLOCKSIZE] = {0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC, 
			       0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E};

	u8 key_2[BLOCKSIZE] = {0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7,
	       		       0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63};

	u8 key_3[BLOCKSIZE] = {0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8,
	       	               0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC};

	// This implementation
	// operates on 4 byte
	// words.
	u8 nonce_1[12] = {0x00, 0x00, 0x00, 0x30, 0x00, 0x00,
             	       0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	u8 nonce_2[12] = {0x00, 0x6C, 0xB6, 0xDB, 0xC0, 0x54,
	       	       0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B};

	u8 nonce_3[12] = {0x00, 0xE0, 0x01, 0x7B, 0x27, 0x77,
		       0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0};
	
	u8 test_vector_1[16] = {0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
	       			0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67};

	// REVERSE
	//u8 r_key_1[16] = {0xF8, 0x52, 0x68, 0xAE, 0xCC, 0x67, 0x10, 0x12,
         //                 0x76, 0xA5, 0xF7, 0x4B, 0x9E, 0xF3, 0x77, 0x55};

//	u8 r_test_vector_1[16] = {0x67, 0x6E, 0x69, 0x53, 0x62, 0x20, 0x65, 0x6C,
//				  0x6B, 0x63, 0x6F, 0x6C, 0x67, 0x73, 0x6D, 0x20};
	//

	u8 ct_1[16] = {0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79,
	               0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8};

	u8 test_vector_2[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		 	      	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
       				0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

	u8 ct_2[32] = {0x51, 0x04, 0xA1, 0x06, 0x16, 0x8A, 0x72, 0xD9,
	               0x79, 0x0D, 0x41, 0xEE, 0x8E, 0xDA, 0xD3, 0x88,
	   	       0xEB, 0x2E, 0x1E, 0xFC, 0x46, 0xDA, 0x57, 0xC8,
	       	       0xFC, 0xE6, 0x30, 0xDF, 0x91, 0x41, 0xBE, 0x28};

	u8 test_vector_3[36] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		 	      	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
       				0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
				0x20, 0x21, 0x22, 0x23};

	u8 ct_3[36] = {0xC1, 0xCF, 0x48, 0xA8, 0x9F, 0x2F, 0xFD, 0xD9,
	               0xCF, 0x46, 0x52, 0xE9, 0xEF, 0xDB, 0x72, 0xD7,
		       0x45, 0x40, 0xA4, 0x2B, 0xDE, 0x6D, 0x78, 0x36,
		       0xD5, 0x9A, 0x5C, 0xEA, 0xAE, 0xF3, 0x10, 0x53,
		       0x25, 0xB2, 0x07, 0x2F};

	int n_total = 3;
	int n_wrong = 0;

	aes_state e_cs;

	// *TEST VECTOR 1* //
	//
	std::cout << "\n\n ***** TEST VECTOR 1 ***** \n";

	u8 tmp_1[16];
	//aes_ctr_initialize(&e_cs, key_1, iv_1);
	aes_load_key(&e_cs, key_1);
	aes_load_iv(&e_cs, nonce_1);
	aes_ctr_process_packet(&e_cs, tmp_1, test_vector_1, 16);
	char hex_tmp_1[33];
	hex_encode(hex_tmp_1, tmp_1, 16);
	std::string print_tmp_1(hex_tmp_1, 33);
	std::cout << "Output 1: " << print_tmp_1 << std::endl;

	for (int i = 0; i < 16; i++)
	{
		if (tmp_1[i] != ct_1[i])
		{
			n_wrong++;
			break;
		}
	}

	// *TEST VECTOR 2* //
	std::cout << "\n\n ***** TEST VECTOR 2 ***** \n";

	u8 tmp_2[32];
	//aes_ctr_initialize(&e_cs, key_2, iv_2);
	aes_load_key(&e_cs, key_2);
	aes_load_iv(&e_cs, nonce_2);
	aes_ctr_process_packet(&e_cs, tmp_2, test_vector_2, 32);
	char hex_tmp_2[65];
	hex_encode(hex_tmp_2, tmp_2, 32);
	std::string print_tmp_2(hex_tmp_2, 65);
	std::cout << "Output 2: " << print_tmp_2 << std::endl;

	for (int i = 0; i < 32; i++)
	{
		if (tmp_2[i] != ct_2[i])
		{
			n_wrong++;
			break;
		}
	}

	std::cout << "\n\n ***** TEST VECTOR 3 *****\n";

	u8 tmp_3[36];
	//aes_ctr_initialize(&e_cs, key_3, iv_3);
	aes_load_key(&e_cs, key_3);
	aes_load_iv(&e_cs, nonce_3);
	aes_ctr_process_packet(&e_cs, tmp_3, test_vector_3, 36);
	char hex_tmp_3[73];
	hex_encode(hex_tmp_3, tmp_3, 36);
	std::string print_tmp_3(hex_tmp_3, 73);
	std::cout << "Output 3: " << print_tmp_3 << std::endl;

	for (int i = 0; i < 36; i++)
	{
		if (tmp_3[i] != ct_3[i])
		{
			n_wrong++;
			break;
		}
	}

	std::cout << "\n\n\n TOTAL: " << n_total - n_wrong << " OF " << n_total << " CORRECT." << std::endl;

}
