#include "hmac.h"
#include "../../SHA/SHA-2/SHA-256/sha-256.h"
#include "../../HexEncoder/encoder.h"
#include <cstring>
#include <iostream>

#define KEYLENGTH 64
#define DIGESTSIZE 32
#define TAGSIZE 16

// The HMAC may be initialized by pre-XOR'ing the key with
// ipad / opad, saving time when packets are processed in
// a later stage.
void hmac_initialization(hmac_state *ctx, u8* key, int B)
{
	// If the key input is larger than desired, the
	// key must be hashed to the correct size by using
	// the associated hash-function.
	
	// Create a local copy of the key
	u8 localKey[KEYLENGTH];

	if (B > KEYLENGTH) {
		u8 hashedKey[DIGESTSIZE];
		process_message((u32*)key, (u32*)hashedKey, B);
		std::memcpy(localKey, hashedKey, DIGESTSIZE);
		B = DIGESTSIZE;
	} else {
		std::memcpy(localKey, key, B);
	}

	// Pad the key with zeroes if the size is too small
	for (int i = B; i < KEYLENGTH; i++) {
		localKey[i] = 0;
	}

	// Pad the key with the ipad and opad respectively
	for (int i = 0; i < KEYLENGTH; i++)
	{
		// Generate inner and outer padded key
		ctx->inner_key[i] = ipad ^ localKey[i];
		ctx->outer_key[i] = opad ^ localKey[i];
	}
}

void tag_generation(hmac_state *ctx, u8 *message, u8* tag, u64 dataLength, int tagLength)
{
	// The inner key is used in the first computation along with the message
	u8 inner_computation[dataLength+KEYLENGTH];
	std::memcpy(inner_computation, ctx->inner_key, KEYLENGTH);
	std::memcpy(&(inner_computation[KEYLENGTH]), message, dataLength);

	// Compute the hash of the message and the inner key
	u8 inner_hash[DIGESTSIZE];
	process_message((u32*)inner_computation, (u32*)inner_hash, dataLength+KEYLENGTH);
	
	// The outer key is appended to the inner hash.
	u8 outer_computation[DIGESTSIZE+KEYLENGTH] = {0};
	std::memcpy(outer_computation, ctx->outer_key, KEYLENGTH);
	std::memcpy(&(outer_computation[KEYLENGTH]), inner_hash, DIGESTSIZE);

	// Computer the final hash
	u8 outer_hash[DIGESTSIZE];
	process_message((u32*)outer_computation, (u32*)outer_hash, DIGESTSIZE+KEYLENGTH);
	
	// The final message authentication code is then found by
	// taking the leftmost t bytes.
	std::memcpy(tag, outer_hash, tagLength);
}

int tag_validation(hmac_state *ctx, u8 *message, u8* tag, u64 dataLength, int tagLength)
{
	// Generate a tag from the received message
	u8 newTag[tagLength];
	tag_generation(ctx, message, newTag, dataLength, tagLength);

	// Compare the newly generated tag with the
	// recevied tag.
	for (int i = 0; i < tagLength; i++)
	{
		if ( tag[i] != newTag[i] ) return 0;
	}

	return 1;
}
