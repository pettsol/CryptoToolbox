//////////////////////////////////
// This implementation has been //
// placed in the public domain  //
// by			        //
//			      	//
// Petter Solnoer - 1/11/2021 	//
//////////////////////////////////

#ifndef JL_H
#define JL_H

#include <gmp.h>
#include <stdint.h>

void joye_libert_keygen(mpz_t N, mpz_t y, mpz_t p, const uint32_t msgsize, const uint32_t keysize);
void joye_libert_encrypt(mpz_t c, gmp_randstate_t state, const mpz_t m, const mpz_t y, const mpz_t N, const uint32_t msgsize);
void joye_libert_decrypt(mpz_t m, const mpz_t c, const mpz_t p, const mpz_t y, const uint32_t msgsize);

#endif
