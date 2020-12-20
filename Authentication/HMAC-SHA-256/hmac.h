///////////////////////////////////////
// This implementation of HMAC with  //
// SHA-256 was placed in the public  //
// domain by:                        //
//                                   // 
// Petter Solnoer - 15/04/2020       //
///////////////////////////////////////

#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>
#include <fstream>

// Force inline on compilers
#ifdef _MSC_VER
	#define forceinline __forceinline
#elif defined(__GNUC__)
	#define forceinline inline __attribute__((__always_inline__))
#elif defined(__CLANG__)
	#if __has_attribute(__always_inline__)
		#define forceinline inline __attribute__((__always_inline__))
	#else
		#define forceinline inline
	#endif
#else
	#define forceinline inline
#endif

#define HMAC_KEYLENGTH 64

struct hmac_state{
	uint8_t key[HMAC_KEYLENGTH];

	uint8_t inner_key[HMAC_KEYLENGTH];
	uint8_t outer_key[HMAC_KEYLENGTH];
};

static const uint8_t ipad = 0x36;
static const uint8_t opad = 0x5c;

void hmac_load_key(hmac_state *cs, uint8_t *key, int keysize);
void hmac_tag_generation(hmac_state *cs, uint8_t* tag, uint8_t *message, uint64_t dataLength, int tagSize);
int hmac_tag_validation(hmac_state *cs, uint8_t *tag, uint8_t *message, uint64_t dataLength, int tagSize);

#endif
