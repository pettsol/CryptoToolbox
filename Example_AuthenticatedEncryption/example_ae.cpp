// Include authentication algorithm: HMAC with SHA-256
#include "../Authentication/HMAC-SHA-256/hmac.h"

// Include the desired encryption algorithm
#include "../BlockCiphers/AES/AES/AES_CFB_Carry-Over/aes_cfb.h"
//#include "../StreamCiphers/Sosemanuk/sosemanuk.h"
#include "../StreamCiphers/HC-128/hc128.h"

// Include hex encoder if intermediate results are to
// be printed
#include "../Encoders/Hex/encoder.h"

#include <iostream>
#include <cstring>

// We will use the standard 128-bit HMAC-tag.
#define TAGSIZE 16

int main()
{
	// Create encryption and authentication keys.
	// They SHOULD be random, but for the purpose
	// of an example, it is not important.
	u8 a_key[HMAC_KEYLENGTH] = {0};
	u8 e_key[AES_BLOCKSIZE] = {0};

	// Instantiate and initialize a HMAC struct
	hmac_state a_cs;
	hmac_load_key(&a_cs, a_key, HMAC_KEYLENGTH);

	// Instantiate and initialize a AES_CFB struct
	aes_state e_cs;

	// Load an all-zero IV to initialize the feedback register
	u32 iv[AES_BLOCKSIZE/4] = {0};
	aes_cfb_initialize(&e_cs, e_key, iv);

	
	//////////////////////////////////////////////////////////
	// This section illustrates an authenticated encryption //
	// scheme known as Encrypt-then-MAC as described by     //
	// Bellare and Namprempre.                              //
	//////////////////////////////////////////////////////////


	// The first example will be with a self-synchronizing
	// cipher, where an IV is unneccesary.

	std::cout << "SECTION 1 - AUTHENTICATED ENCRYPTION WITH A SELF-SYNCHRONIZING CIPHER\n\n";

	// Declare a plaintext that is to be encrypted. This could
	// be anything.
	std::string plaintext = "Hello world! This is an example of AE with a self-synchronizing cipher.";

	std::cout << "Plaintext: " << plaintext << std::endl;
	// Declare a msg buffer that is to hold the ciphertext,
	// and tag. For ciphers that are NOT self-synchronizing,
	// this buffer must also hold an IV.
	//
	// AES in CFB-mode with IV carry-over is self-synchronizing.
	u8 msg[plaintext.size() + TAGSIZE];

	// The message will look like: ciphertext || tag
	aes_cfb_process_packet(&e_cs, msg, (u8*)plaintext.data(), plaintext.size(), ENCRYPT);

	// Compute the HMAC tag over the ciphertext and append:
	hmac_tag_generation(&a_cs, &msg[plaintext.size()], msg, plaintext.size(), TAGSIZE);

	// Print the entire message:
	char hexMsgChar[2*(plaintext.size() + TAGSIZE)+1];
	hex_encode(hexMsgChar, msg, plaintext.size()+TAGSIZE);
	std::string hexMsg(hexMsgChar, 2*(plaintext.size()+TAGSIZE));
	std::cout << "Msg: " << hexMsg << std::endl;

	///////////////////////////////////////////////////////////
	// In this section, the message will be validated, and ONLY
	// if the ( ciphertext || tag )-pair is valid will the
	// message be decrypted.
	
	// Declare a new AES_CFB struct to decrypt.
	aes_state d_cs;
	aes_cfb_initialize(&d_cs, e_key, iv);

	// Validate the tag:
	if ( !(hmac_tag_validation(&a_cs, &msg[plaintext.size()], msg, plaintext.size(), TAGSIZE)) ) {
		std::cout << "Invalid tag!\n";
		exit(1);
	}
	// Else tag is valid, proceed to decrypt.
	std::cout << "Valid tag\n";

	u8 recovered[plaintext.size()];
	aes_cfb_process_packet(&d_cs, recovered, msg, plaintext.size(), DECRYPT);

	std::string recov((const char*)recovered, plaintext.size());
	std::cout << "Recovered: " << recov << std::endl;

	// The second example will be with a synchronous cipher, where explicit synchronization
	// through IV is required.
	
	std::cout << "\n\nSECTION 2 - AUTHENTICATED ENCRYPTION WITH SYNCHRONOUS CIPHER\n\n";

	// Declare plaintext:
	std::string plaintext2 = "Hello world! This is an example of AE with a synchronous cipher.";

	std::cout << "Plaintext 2: " << plaintext2 << std::endl;

	// Declare a cipher struct for encryption. We will use HC-128.
	hc128_state e_cs2;
	hc128_initialize(&e_cs2, (u32*)e_key, iv);

	// Declare a msg2 buffer to hold IV || Ciphertext || Tag
	u8 msg2[HC128_IV_SIZE + plaintext2.size() + TAGSIZE];

	// Load the IV
	std::memcpy(msg2, iv, HC128_IV_SIZE);

	// Encrypt
	hc128_process_packet(&e_cs2, &msg2[HC128_IV_SIZE], (u8*)plaintext2.data(), plaintext2.size());

	// Compute the tag and append. NB! Tag is computed over IV || Ciphertext!
	hmac_tag_generation(&a_cs, &msg2[HC128_IV_SIZE+plaintext2.size()], msg2, HC128_IV_SIZE+plaintext2.size(), TAGSIZE);
	// Print contents of msg2:
	
	char hexMsg2Char[2*(HC128_IV_SIZE+plaintext2.size()+TAGSIZE)+1];
	hex_encode(hexMsg2Char, msg2, HC128_IV_SIZE+plaintext2.size()+TAGSIZE);
	std::string hexMsg2(hexMsg2Char, 2*(HC128_IV_SIZE+plaintext2.size()+TAGSIZE));
	std::cout << "Msg2: " << hexMsg2 << std::endl;

	// Validate the tag over the IV and the ciphertext. If the(IV || Ciphertext, Tag)-pair is
	// not valid, the ciphertext is NOT decrypted.
	if ( !(hmac_tag_validation(&a_cs, &msg2[HC128_IV_SIZE+plaintext2.size()], msg2, HC128_IV_SIZE+plaintext2.size(), TAGSIZE)) ) {
		std::cout << "Invalid tag!\n";
	}
	// Else, tag is valid. Proceed to initialize the cipher and decrypt.
	std::cout << "Valid tag!\n";

	// Create decryption object
	hc128_state d_cs2;
	
	// Initialize cipher with new IV. The IV sits at the front of the msg2.
	hc128_initialize(&d_cs2, (u32*)e_key, (u32*)msg2);

	// Decrypt. The ciphertext sits after the IV in msg2.
	u8 recovered2[plaintext2.size()];
	hc128_process_packet(&d_cs2, recovered2, &msg2[HC128_IV_SIZE], plaintext2.size());

	// Print the recovered plaintext2:
	std::string recov2((const char*)recovered2, plaintext2.size());
	std::cout << "Recovered 2: " << recov2 << std::endl;
}

