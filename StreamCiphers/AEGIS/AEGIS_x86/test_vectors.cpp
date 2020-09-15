#include "aegis_128.h"
#include "../../../Encoders/Hex/encoder.h"

#include <iostream>


int main()
{

	int n_tests = 4;
	int successful = 0;

	/* TEST VECTOR 1 */

	int test_1 = 1;

	std::cout << "\n\n************* TEST VECTOR 1 ************\n\n";

	u8 key_1[16] = {0};
	u8 iv_1[16] = {0};
	u8 pt_1[16] = {0};
	u8 ct_1[16] = {0};
	u8 tag_1[16];
	u8 recv_1[16];

	std::string expected_ct_1 = "951B050FA72B1A2FC16D2E1F01B07D7E";
	std::string expected_tag_1 = "A7D2A99773249542F422217EE888D5F1";

	aegis_state cs_1;

	aegis_load_key(&cs_1, (u32*)key_1);

	aegis_encrypt_packet(&cs_1, ct_1, tag_1, pt_1, 0, (u32*)iv_1, 0, 16);

	if (!aegis_decrypt_packet(&cs_1, recv_1, ct_1, 0, (u32*)iv_1, (u32*)tag_1, 0, 16))
	{
		std::cout << "Invalid tag!\n";
		exit(1);
	}

	std::cout << "Valid tag\n";

	char PT_1[33];
	hex_encode(PT_1, pt_1, 16);
	std::string hexPT_1(PT_1, 33);
	std::cout << "PT: " << hexPT_1 << std::endl;

	char hexCT_1[33];
	hex_encode(hexCT_1, ct_1, 16);
	std::string hexString_1(hexCT_1, 33);
	std::cout << "Expected CT: " << expected_ct_1 << std::endl;
	std::cout << "Computed CT: " << hexString_1 << std::endl;

	char hexTAG_1[33];
	hex_encode(hexTAG_1, tag_1, 16);
	std::string hexTagString_1(hexTAG_1, 33);
	std::cout << "Expected TAG: " << expected_tag_1 << std::endl;
	std::cout << "Computed TAG: " << hexTagString_1 << std::endl;

	char recvPT_1[33];
	hex_encode(recvPT_1, recv_1, 16);
	std::string hexRECV_1(recvPT_1, 33);
	std::cout << "RECOVERED PT: " << recvPT_1 << std::endl;

	for (int i = 0; i < 32; i++)
	{
		if (expected_ct_1[i] != hexString_1[i])
		{
			test_1 = 0;
		}		
	}
	for (int i = 0; i < 32; i++)
	{
		if (expected_tag_1[i] != hexTAG_1[i])
		{
			test_1 = 0;
		}
	}
	if (test_1) 
	{
		successful++;
	}

	/* TEST VECTOR 2 */

	int test_2 = 1;
	
	std::cout << "\n\n************* TEST VECTOR 2 ************\n\n";
	
	u8 key_2[16] = {0};
	u8 iv_2[16] = {0};
	u8 pt_2[16] = {0};
	u8 ad_2[16] = {0};
	u8 ct_2[16] = {0};
	u8 tag_2[16];
	u8 recv_2[16];

	std::string expected_ct_2 = "10B0DEE65A97D751205C128A992473A1";
	std::string expected_tag_2 = "46DCB9EE93C46CF13731D41B9646C131";

	aegis_state cs_2;

	aegis_load_key(&cs_2, (u32*)key_2);

	aegis_encrypt_packet(&cs_2, ct_2, tag_2, pt_2, ad_2, (u32*)iv_2, 16, 16);

	if (!aegis_decrypt_packet(&cs_2, recv_2, ct_2, ad_2, (u32*)iv_2, (u32*)tag_2, 16, 16))
	{
		std::cout << "Invalid tag!\n";
		exit(1);
	}

	std::cout << "Valid tag\n";

	char PT_2[33];
	hex_encode(PT_2, pt_2, 16);
	std::string hexPT_2(PT_2, 33);
	std::cout << "PT: " << hexPT_2 << std::endl;

	char hexCT_2[33];
	hex_encode(hexCT_2, ct_2, 16);
	std::string hexString_2(hexCT_2, 33);
	std::cout << "Expected CT: " << expected_ct_2 << std::endl;
	std::cout << "Computed CT: " << hexString_2 << std::endl;

	char hexTAG_2[33];
	hex_encode(hexTAG_2, tag_2, 16);
	std::string hexTagString_2(hexTAG_2, 33);
	std::cout << "Expected TAG: " << expected_tag_2 << std::endl;
	std::cout << "Computed TAG: " << hexTagString_2 << std::endl;

	char recvPT_2[33];
	hex_encode(recvPT_2, recv_2, 16);
	std::string hexRECV_2(recvPT_2, 33);
	std::cout << "RECOVERED PT: " << recvPT_2 << std::endl;

	for (int i = 0; i < 32; i++)
	{
		if (expected_ct_2[i] != hexString_2[i])
		{
			test_2 = 0;
		}		
	}
	for (int i = 0; i < 32; i++)
	{
		if (expected_tag_2[i] != hexTAG_2[i])
		{
			test_2 = 0;
		}
	}
	if (test_2) 
	{
		successful++;
	}

	/* TEST VECTOR 3 */

	int test_3 = 1;
	
	std::cout << "\n\n************* TEST VECTOR 3 ************\n\n";
	
	u8 key_3[16] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	u8 iv_3[16] = {0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	u8 pt_3[16] = {0};
	u8 ad_3[4] = {0x00, 0x01, 0x02, 0x03};
	u8 ct_3[16] = {0};
	u8 tag_3[16];
	u8 recv_3[16];

	std::string expected_ct_3 = "2B78F5C1618DA39AFBB2920F5DAE02B0";
	std::string expected_tag_3 = "74759CD0E19314650D6C635B563D80FD";

	aegis_state cs_3;

	aegis_load_key(&cs_3, (u32*)key_3);

	aegis_encrypt_packet(&cs_3, ct_3, tag_3, pt_3, ad_3, (u32*)iv_3, 4, 16);

	if (!aegis_decrypt_packet(&cs_3, recv_3, ct_3, ad_3, (u32*)iv_3, (u32*)tag_3, 4, 16))
	{
		std::cout << "Invalid tag!\n";
		exit(1);
	}

	std::cout << "Valid tag\n";
	
	char PT_3[33];
	hex_encode(PT_3, pt_3, 16);
	std::string hexPT_3(PT_3, 33);
	std::cout << "PT: " << hexPT_3 << std::endl;

	char hexCT_3[33];
	hex_encode(hexCT_3, ct_3, 16);
	std::string hexString_3(hexCT_3, 33);
	std::cout << "Expected CT: " << expected_ct_3 << std::endl;
	std::cout << "Computed CT: " << hexString_3 << std::endl;

	char hexTAG_3[33];
	hex_encode(hexTAG_3, tag_3, 16);
	std::string hexTagString_3(hexTAG_3, 33);
	std::cout << "Expected TAG: " << expected_tag_3 << std::endl;
	std::cout << "Computed TAG: " << hexTagString_3 << std::endl;

	char recvPT_3[33];
	hex_encode(recvPT_3, recv_3, 16);
	std::string hexRECV_3(recvPT_3, 33);
	std::cout << "RECOVERED PT: " << recvPT_3 << std::endl;

	for (int i = 0; i < 32; i++)
	{
		if (expected_ct_3[i] != hexString_3[i])
		{
			test_3 = 0;
		}		
	}
	for (int i = 0; i < 32; i++)
	{
		if (expected_tag_3[i] != hexTAG_3[i])
		{
			test_3 = 0;
		}
	}
	if (test_3) 
	{
		successful++;
	}

	/* TEST VECTOR 4 */

	int test_4 = 1;

	std::cout << "\n\n************* TEST VECTOR 4 ************\n\n";

	u8 key_4[16] = {0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	u8 iv_4[16] = {0x10, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 
		     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	u8 pt_4[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	             0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
	
	u8 ad_4[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

	std::string expected_ct_4 = "E08EC10685D63C7364ECA78FF6E1A1DDFDFC15D5311A7F2988A0471A13973FD7";
	std::string expected_tag_4 = "27E84B6C4CC46CB6ECE8F1F3E4AA0E78";

	//u8 ad[16] = {0};
	
	u8 ct_4[32] = {0};
	u8 tag_4[16] = {0};

	aegis_state cs_4;
	
	aegis_load_key(&cs_4, (u32*)key_4);
	aegis_encrypt_packet(&cs_4, ct_4, tag_4, pt_4, ad_4, (u32*)iv_4, 8, 32);

	u8 recv_4[32] = {0};

	if (!aegis_decrypt_packet(&cs_4, recv_4, ct_4, ad_4, (u32*)iv_4, (u32*)tag_4, 8, 32))
	{
		std::cout << "Invalid tag!\n";
		exit(1);
	}

	std::cout << "Valid tag\n";

	char PT_4[65];
	hex_encode(PT_4, pt_4, 32);
	std::string hexPT_4(PT_4, 65);
	std::cout << "PT: " << hexPT_4 << std::endl;

	char hexCT_4[65];
	hex_encode(hexCT_4, ct_4, 32);
	std::string hexString_4(hexCT_4, 65);
	std::cout << "Expected CT: " << expected_ct_4 << std::endl;
	std::cout << "Computed CT: " << hexString_4 << std::endl;

	char hexTAG_4[33];
	hex_encode(hexTAG_4, tag_4, 16);
	std::string hexTagString_4(hexTAG_4, 33);
	std::cout << "Expected TAG: " << expected_tag_4 << std::endl;
	std::cout << "Computed TAG: " << hexTagString_4 << std::endl;

	char recvPT_4[65];
	hex_encode(recvPT_4, recv_4, 32);
	std::string hexRECV_4(recvPT_4, 65);
	std::cout << "RECOVERED PT: " << recvPT_4 << std::endl;

	for (int i = 0; i < 64; i++)
	{
		if (expected_ct_4[i] != hexString_4[i])
		{
			test_4 = 0;
		}		
	}
	for (int i = 0; i < 32; i++)
	{
		if (expected_tag_4[i] != hexTAG_4[i])
		{
			test_4 = 0;
		}
	}
	if (test_4) 
	{
		successful++;
	}

	// END OF TESTS //
	std::cout << "\n\nEND OF TESTS. NUMBER OF SUCCESSFUL TESTS: " << successful << " / " <<
		 n_tests << std::endl;
	if (successful == n_tests) std::cout << "************** SUCCESS! ****************" << std::endl;
	else std::cout << "**************** FAILURE! ******************" << std::endl;
}
