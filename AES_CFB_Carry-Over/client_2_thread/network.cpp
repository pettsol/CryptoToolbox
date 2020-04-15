/* NETWORK MODULE FOR ENCRYPTION LABORATORY */

#include <iostream>
#include <thread>
#include <string>
#include <cstring>
#include <mutex>
#include <queue>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include "cryptopp/filters.h"
#include "cryptopp/integer.h"
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include "cryptopp/hex.h"
#include "cryptopp/hkdf.h"

#include "structs.h"
#include "network.h"
#include "serialization.h"
#include "aes_cfb.h"

#define MAX_BUFFER 65536
#define DATA_SIZE sizeof(data_struct)

#define ENCRYPT 0
#define DECRYPT 1
#define BLOCKSIZE 16
#define PACKETSIZE DATA_SIZE+CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE

void tx_thread(std::string address, int server_port)
{
	// Set up IO
	float count = 0;

	// Set up network functions
	const char * c_address = address.c_str();
	sockaddr_in si_other;
	int sockfd;
	socklen_t slen = sizeof(si_other);

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) perror ("Udp send socket fd");

	memset((char *) &si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(server_port);

	std::cout << "Address: " << c_address << std::endl;
	std::cout << "Data size: " << DATA_SIZE << std::endl;

	int res = inet_aton(c_address, &si_other.sin_addr);

	// Set up crypto functions
	
	// Create cipher struct
	cipher_state cs;
	
	// Derive a key and IV first!
	CryptoPP::SecByteBlock key(BLOCKSIZE);
	CryptoPP::SecByteBlock akey(BLOCKSIZE);
	std::string password("default"), apassword("integrity");

	CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
	hkdf.DeriveKey(key, key.size(), (const CryptoPP::byte *)password.data(), password.size(),
			0, 0, NULL, 0);
	hkdf.DeriveKey(akey, akey.size(), (const CryptoPP::byte *)apassword.data(), apassword.size(),
			0, 0, NULL, 0);
	//Key and IV has been derived using a key derivation function
	//Now the encryption class must be instantiated and initialized
	u8 ck[BLOCKSIZE] = {0};
	//memcpy(ck, &key, BLOCKSIZE); // Key is 16 bytes
	u32 iv[BLOCKSIZE/4] = {0}; // Set IV to all zeros

	// Initialize cipher
	cfb_initialize_cipher(&cs, ck, iv);

	// Instatiate and initialize the HMAC
	CryptoPP::HMAC<CryptoPP::SHA256> hmac;
	hmac.SetKey(akey, akey.size() );
	// Get time stamp
	auto timestamp = std::chrono::system_clock::now();

	#ifdef DEBUG
	cipher_state d_cs;
	cfb_initialize_cipher(&d_cs, ck, iv);
	#endif
	
	// Enter loop
	std::string ciphertext;
	while(1)
	{

		// Verify that sufficient time has passed since the previous packet
		auto current_time = std::chrono::system_clock::now();
		auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - timestamp);
		if (diff.count() < 20) continue;

		timestamp = current_time;

		// Generate a new struct;
		data_struct item;
		item.is_broken = 0;
		item.data = count++;
		item.time_stamp = current_time;

		// Serialize the new struct
		u8 pt[DATA_SIZE];
		#ifdef DEBUG
		std::string print_pt((char*)pt, DATA_SIZE);
		std::cout << "Tx pt: " << print_pt << std::endl;
		#endif
		serialize(&item, pt);
		//std::string test2(packet, DATA_SIZE);

		// Perform the encryption
		u8 ct[DATA_SIZE];
		cfb_process_packet(&cs, pt, ct, DATA_SIZE, encrypt);
		std::string tmp((char*)ct, DATA_SIZE);

		// Compute MAC and append
		#ifdef MAC
		std::string tmp2;
		CryptoPP::StringSource s2(tmp, true,
				new CryptoPP::HashFilter( hmac,
				new CryptoPP::StringSink(tmp2), true));

		ciphertext = tmp2;
		#else
		ciphertext = tmp;
		#endif

		#ifdef DEBUG
		std::cout << "Tx ct: " << ciphertext << std::endl;

		// Attempt to deserialize the ct and decrypt it
		u8 recovered[DATA_SIZE];
		cfb_process_packet(&d_cs, (u8*)ciphertext.data(), recovered, DATA_SIZE, decrypt);
		std::string recovered_string((char*)recovered, DATA_SIZE);

		data_struct recovered_data;
		deserialize(recovered, &recovered_data);
		std::cout << recovered_data.is_broken << std::endl;
		std::cout << recovered_data.data << std::endl;

		std::cout << "Data size: " << DATA_SIZE << std::endl;
		std::cout << "ciphertext.size(): " << ciphertext.size() << std::endl;
		//std::cout << "Recovered: " << recovered_string << std::endl;
		#endif

		// Transmit the packet
		res = sendto(sockfd, ciphertext.data(), ciphertext.size(), 
				0, (sockaddr *) &si_other, slen);
		if (res == -1){
			perror("Send failed!");
			exit(EXIT_FAILURE);
		}
	}
}

void rx_thread(int client_port)
{
	// Set up network functions
	char buffer[MAX_BUFFER];
	sockaddr_in si_me, si_other;
	int sockfd;
	socklen_t slen = sizeof(si_other);

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == 1) perror ("udp receive socket fd");

	memset((char*) &si_me, 0, sizeof(si_me));
	memset(&si_other, 0, sizeof(si_other));

	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(client_port);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);

	int optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	const char *opt;
	opt = "eth1";
	setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, &opt, sizeof(opt));

	int res = bind(sockfd, (const sockaddr *)&si_me, sizeof(si_me));
	if (res == -1) perror("Bind failed!");
	
	int n;

	// Set up crypto
	cipher_state cs;
	
	// Derive key and IV
	CryptoPP::SecByteBlock key(BLOCKSIZE);
	CryptoPP::SecByteBlock akey(BLOCKSIZE);
	std::string password("default"), apassword("integrity");

	CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
	hkdf.DeriveKey(key, key.size(), (const CryptoPP::byte *)password.data(), password.size(),
			0, 0, NULL, 0);
	hkdf.DeriveKey(akey, akey.size(), (const CryptoPP::byte *)apassword.data(), apassword.size(),
			0, 0, NULL, 0);

	u8 ck[BLOCKSIZE] = {0};
	//memcpy(&ck, &key, BLOCKSIZE); // Key is 16 bytes
	//ck.reg1 = 0;
	//ck.reg2 = 0;
	//ck.reg3 = 0;
	//ck.reg4 = 0;
	u32 iv[BLOCKSIZE/4] = {0}; // Set IV to all zeros
	//iv.reg1 = 0;
	//iv.reg2 = 0;
	//iv.reg3 = 0;
	//iv.reg4 = 0;

	// Initialize cipher
	cfb_initialize_cipher(&cs, ck, iv);

	// Instantiate and initialize the HMAC
	CryptoPP::HMAC<CryptoPP::SHA256> hmac;
	hmac.SetKey(akey, akey.size() );

	// Open a file for logging
	std::ofstream log("cfb_carry_over.txt");

	data_struct data;	
	// Enter loop
	while(1)
	{
		// Receive packet
		n = recvfrom(sockfd, (char *)buffer, MAX_BUFFER, 0, (sockaddr *) &si_other, &slen);
		if ( n <= 0 ) perror ("Recvfrom error");
		#ifdef MAC
		std::string msg(buffer, PACKETSIZE);
		#endif
		#ifndef MAC
		std::string msg(buffer, DATA_SIZE);
		#endif
		// Verify the MAC
		#ifdef MAC
		CryptoPP::StringSource s1 (msg, true,
				new CryptoPP::HashVerificationFilter(hmac, NULL,
				CryptoPP::HashVerificationFilter::HASH_AT_END |
				CryptoPP::HashVerificationFilter::THROW_EXCEPTION) );
		
		std::string ciphertext = msg.substr(0, msg.size() -
				CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE);
		#else
		std::string ciphertext = msg;
		#endif
		#ifdef DEBUG	
		std::cout << "Received ct: " << ciphertext << std::endl;
		#endif
		u8 *ct = (u8*)&ciphertext[0];
		u8 pt[DATA_SIZE];
		cfb_process_packet(&cs, ct, pt, DATA_SIZE, decrypt);
		//std::string plaintext;

		// Deserialize!
		//const char* c_plaintext = plaintext.data();
		deserialize(pt, &data);

		// Log
		// Sanity check on received data
		#ifdef DEBUG
		std::cout << "is_broken: " << data.is_broken << std::endl;
		#endif
		if (data.is_broken) continue;

		//Subtract time stamp from current time to find time of flight in ms
		auto end = std::chrono::system_clock::now();

		auto duration = end - data.time_stamp;

		auto diff = 
			std::chrono::duration_cast<std::chrono::microseconds>(end - data.time_stamp);

		//std::cout << "Logged data: " << item.data << std::endl;
				
		log << diff.count() << std::endl;
		if (data.data > 10500) exit(0);
	}
}
