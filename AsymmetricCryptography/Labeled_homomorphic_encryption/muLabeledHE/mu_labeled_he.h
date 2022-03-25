#ifndef MU_LABELED_HE_H
#define MU_LABELED_HE_H

#include "../HC-128/hc128.h"

#include <gmp.h>

struct he_ct{
	mpz_t a;
	mpz_t beta;
	he_ct(void);
};

void mu_he_setup(
		mpz_t N,
		mpz_t y,
		mpz_t p,
		const uint32_t msgsize,
		const uint32_t keysize);

void mu_he_keygen(
		mpz_t upk,
		mpz_t usk,
		gmp_randstate_t state,
		const mpz_t N,
		const mpz_t y,
		const uint32_t msgsize);

void mu_he_encrypt(
		he_ct *c,
                gmp_randstate_t state,
                hc128_state *hc_cs,
		mpz_t b,
                const mpz_t m,
                const mpz_t y,
                const mpz_t N,
                const mpz_t label,
                const uint32_t msgsize);

void mu_he_eval_mult(
		mpz_t alpha,
                gmp_randstate_t state,
                const he_ct *ct1,
                const he_ct *ct2,
                const mpz_t y,
                const mpz_t N,
                const uint32_t msgsize);

void mu_he_eval_mult_3(
		mpz_t alpha,
		gmp_randstate_t state,
		const he_ct *ct1,
		const he_ct *ct2,
		const he_ct *ct3,
		const mpz_t beta12,
		const mpz_t beta13,
		const mpz_t beta23,
		const mpz_t y,
		const mpz_t N,
		const uint32_t msgsize);

void mu_he_eval_add(
		he_ct *c,
                const he_ct *c1,
                const he_ct *c2,
                const mpz_t N,
                const uint32_t msgsize);

void mu_he_eval_add(
                mpz_t c,
                const mpz_t c1,
                const mpz_t c2,
                const mpz_t N);

void mu_he_eval_sub(
		he_ct *c,
		const he_ct *c1,
		const he_ct *c2,
		const mpz_t N,
		const uint32_t msgsize);

void mu_he_eval_sub(
		mpz_t c,
		const mpz_t c1,
		const mpz_t c2,
		const mpz_t N);

void mu_he_eval_cmult(
		he_ct *c,
                const he_ct *c1,
                const mpz_t a,
                const mpz_t N,
                const uint32_t msgsize);

void mu_he_eval_cmult(
                mpz_t alpha,
                const mpz_t c,
                const mpz_t constant,
                const mpz_t N);

void mu_he_decrypt(
		mpz_t m,
                const he_ct *c1,
                const mpz_t p,
                const mpz_t y,
                const uint32_t msgsize);

void mu_he_decrypt(
                mpz_t m,
                const mpz_t c,
                const mpz_t b,
                const mpz_t p,
                const mpz_t y,
                const uint32_t msgsize);

#endif
