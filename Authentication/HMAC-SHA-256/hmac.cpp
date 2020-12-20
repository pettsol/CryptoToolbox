///////////////////////////////////////
// This implementation of HMAC with  //
// SHA-256 was placed in the public  //
// domain by:                        //
//                                   // 
// Petter Solnoer - 15/04/2020       //
///////////////////////////////////////




#include "hmac.h"
#include "sha-256.h"
#include <cstring>
#include <iostream>

#define KEYLENGTH 64
#define DIGESTSIZE 32
#define TAGSIZE 16

// The HMAC may be initialized by pre-XOR'ing the key with
// ipad / opad, saving time when packets are processed in
// a later stage.
void hmac_load_key(hmac_state *cs, uint8_t *key, int keysize)
{
	// If the key input is larger than desired, the
	// key must be hashed to the correct size by using
	// the associated hash-function.
	
	// Create a local copy of the key
	uint8_t localKey[HMAC_KEYLENGTH];

	if (keysize > HMAC_KEYLENGTH) {
		uint8_t hashedKey[DIGESTSIZE];
		sha256_process_message(hashedKey, key, keysize);
		std::memcpy(localKey, hashedKey, DIGESTSIZE);
		keysize = DIGESTSIZE;
	} else {
		std::memcpy(localKey, key, keysize);
	}

	// Pad the key with zeroes if the size is too small
	for (int i = keysize; i < HMAC_KEYLENGTH; i++) {
		localKey[i] = 0;
	}

	// Pad the key with the ipad and opad respectively
	for (int i = 0; i < HMAC_KEYLENGTH; i++)
	{
		// Generate inner and outer padded key
		cs->inner_key[i] = ipad ^ localKey[i];
		cs->outer_key[i] = opad ^ localKey[i];
	}
}

void hmac_tag_generation(hmac_state *cs, uint8_t *tag, uint8_t *message, uint64_t dataLength, int tagLength)
{
	// Assert that datalength is strictly positive
	if ( dataLength < 1 ) return;

	// The inner key is used in the first computation along with the message
	uint8_t *inner_computation = new uint8_t[dataLength+HMAC_KEYLENGTH];
	std::memcpy(inner_computation, cs->inner_key, HMAC_KEYLENGTH);
	std::memcpy(&(inner_computation[HMAC_KEYLENGTH]), message, dataLength);

	// Compute the hash of the message and the inner key
	uint8_t inner_hash[DIGESTSIZE];
	sha256_process_message(inner_hash, inner_computation, dataLength+HMAC_KEYLENGTH);
	
	// The outer key is appended to the inner hash.
	uint8_t outer_computation[DIGESTSIZE+HMAC_KEYLENGTH] = {0};
	std::memcpy(outer_computation, cs->outer_key, HMAC_KEYLENGTH);
	std::memcpy(&(outer_computation[HMAC_KEYLENGTH]), inner_hash, DIGESTSIZE);

	// Computer the final hash
	uint8_t outer_hash[DIGESTSIZE];
	sha256_process_message(outer_hash, outer_computation, DIGESTSIZE+HMAC_KEYLENGTH);
	
	// The final message authentication code is then found by
	// taking the leftmost t bytes.
	std::memcpy(tag, outer_hash, tagLength);

	// Clean up
	delete[] inner_computation;
}

int hmac_tag_validation(hmac_state *cs, uint8_t *tag, uint8_t *message, uint64_t dataLength, int tagLength)
{
	// Generate a tag from the received message
	uint8_t newTag[tagLength];
	hmac_tag_generation(cs, newTag, message, dataLength, tagLength);

	// Compare the newly generated tag with the
	// recevied tag.
	for (int i = 0; i < tagLength; i++)
	{
		if ( tag[i] != newTag[i] ) return 0;
	}

	return 1;
}
