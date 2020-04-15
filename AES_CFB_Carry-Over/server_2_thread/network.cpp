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

#include "cryptopp/sha.h"
#include "cryptopp/hmac.h"
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

void tx_thread(std::string address, int server_port, data_queue &Q)
{
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
	//memcpy(&ck, &key, BLOCKSIZE); // Key is 16 bytes
	u32 iv[BLOCKSIZE/4] = {0}; // Set IV to all zeros

	// Initialize the cipher
	cfb_initialize_cipher(&cs, ck, iv);

	// Instatiate and initialize the HMAC
	CryptoPP::HMAC<CryptoPP::SHA256> hmac;
	hmac.SetKey(akey, akey.size() );
	
	// Enter loop
	std::string ciphertext;
	while(1)
	{
		if ( Q.lock.try_lock() ) {
			if ( Q.queue.size() == 0 ) {
				Q.lock.unlock();
				Q.cond_var.notify_one();
				continue;
			} else {
				// Take struct out of queue and serialize
				u8 pt[DATA_SIZE];
				data_struct item = Q.queue.front();
				Q.queue.pop();
				Q.lock.unlock();
		
				serialize(&item, pt);
				//std::string test2(plaintext, DATA_SIZE);

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
				std::cout << "Transmitting ct: "  << ciphertext << std::endl;
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
	}
}

void rx_thread(int client_port, data_queue &Q)
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
	u32 iv[BLOCKSIZE/4] = {0}; // Set IV to all zeros

	// Initialize cipher
	cfb_initialize_cipher(&cs, ck, iv);

	// Instantiate and initialize the HMAC
	CryptoPP::HMAC<CryptoPP::SHA256> hmac;
	hmac.SetKey(akey, akey.size() );

	data_struct data;

	int carry = 0;	
	// Enter loop
	while(1)
	{	
		if (carry) {
			if ( Q.lock.try_lock() ) {
				if ( Q.queue.size() < QUEUE_SIZE ) {
					Q.queue.push(data);
					Q.lock.unlock();
					carry = 0;
				} else {
					Q.lock.unlock();
					Q.cond_var.notify_one();
					continue;
				}
			} else {
				continue;
			}
		}
		// Receive packet
		n = recvfrom(sockfd, (char *)buffer, MAX_BUFFER, 0, (sockaddr *) &si_other, &slen);
		if ( n <= 0 ) perror ("Recvfrom error");

		#ifdef MAC
		std::string msg(buffer, PACKET_SIZE);
		#endif
		#ifndef MAC
		std::string msg(buffer, DATA_SIZE);
		#endif
		#ifdef DEBUG
		std::cout << "Rx ct: " << msg << std::endl;
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
		//u8 *ct = (u8*)ciphertext.data();
		u8 pt[DATA_SIZE];
		cfb_process_packet(&cs, (u8*)ciphertext.data(), pt, DATA_SIZE, decrypt);
		//std::string plaintext(packet, DATA_SIZE);
		#ifdef DEBUG
		std::string print_pt((char*)pt, DATA_SIZE);
		std::cout << "Rx pt: " << print_pt << std::endl;
		#endif
		
		// Deserialize!
		deserialize(pt, &data);

		#ifdef DEBUG
		std::cout << "is_broken: " << data.is_broken << std::endl;
		#endif
		
		carry = 1;
	}
}
