#include "mu_labeled_he.h"
#include "../joye_libert/joye_libert.h"
#include "../HC-128/hc128.h"

#include <iostream>

he_ct::he_ct(void)
{
	mpz_init(a);
	mpz_init(beta);
}

void mu_he_setup(
		mpz_t N,
		mpz_t y,
		mpz_t p,
		const uint32_t msgsize,
		const uint32_t keysize)
{
	// Run joye_libert_keygen() to generate (mpk, msk)
	// mpk = (y, N)
	// msk = (y, p)
	joye_libert_keygen(N, y, p, msgsize, keysize);
}

void mu_he_keygen(
		mpz_t upk,
		mpz_t usk,
		gmp_randstate_t state,
		const mpz_t N,
		const mpz_t y,
		const uint32_t msgsize)
{
	// Sample random seed usk = K
	mpz_urandomb(usk, state, 128);

	// compute upk <- joye_libert_encrypt(mpk, K)
	joye_libert_encrypt(upk, state, usk, y, N, msgsize);
}

void mu_he_encrypt(
		he_ct *c,
		gmp_randstate_t state,
		hc128_state *hc_cs,
		mpz_t b,
		const mpz_t m,
		const mpz_t y,
		const mpz_t N,
		const mpz_t label,
		const uint32_t msgsize)
{
	// Two components - Offline-Enc and Online-Enc
	//
	// Offline-Enc(sk, tau):
	//	Given a label tau, compute b <- F(K, tau)
	//	Output Coff = (b, joye_libert_encrypt(pk, b))
	mpz_t beta;
	mpz_init(beta);
	// I cannot pass an mpz_t as b. I need to convert to a uint32_t array, and then
	// convert back. I need to interpret the label as a 16 byte array, encrypt it,
	// and then load the encrypted value back into b.
	
	// Declare array
	uint8_t keystream[msgsize/8];

	// Load label into the array
        size_t size = (mpz_sizeinbase(label, 2) + CHAR_BIT-1)/CHAR_BIT;
        mpz_export(keystream, &size, 1, 1, 0, 0, label);
	
	// Encrypt the array
	hc128_process_packet(hc_cs, keystream, keystream, msgsize/8);
	
	// Import it back as an mpz_t
	mpz_import(b, msgsize/32, 1, 4, 0, 0, keystream);

	gmp_printf("b: %Zd\n", b);

	joye_libert_encrypt(c->beta, state, b, y, N, msgsize);

	// Online-Enc(Coff):
	//	Parse Coff as (b, beta) and output C = (a, beta)
	//	where a <- m - b (in Message space).
	mpz_t a, ptspace;
	mpz_init(a);
	mpz_init(ptspace);

	mpz_ui_pow_ui(ptspace, 2, msgsize);
	mpz_sub(c->a, m, b);
	mpz_mod(c->a, c->a, ptspace);
}

void mu_he_eval_mult(
		mpz_t alpha,
		gmp_randstate_t state,
		const he_ct *ct1,
		const he_ct *ct2,
		const mpz_t y,
		const mpz_t N,
		const uint32_t msgsize)
{
	// Input: Two ciphertexts C1', C2', on the form (ai, betai)
	// The algorithm computes a 'multiplication ciphertext' C = alpha
	// as:
	// 	alpha = joye_libert_encrypt(pk, a1*a2) + a1*beta2 + a2*beta1
	// Returns alpha
	mpz_t a1a2, a1beta2, a2beta1, ptspace;
	mpz_init(a1a2);
	mpz_init(a1beta2);
	mpz_init(a2beta1);
	mpz_init(ptspace);

	mpz_ui_pow_ui(ptspace, 2, msgsize);

	mpz_mul(a1a2, ct1->a, ct2->a);
	mpz_mod(a1a2, a1a2, ptspace);
	joye_libert_encrypt(alpha, state, a1a2, y, N, msgsize);

	/*mpz_mul(a1beta2, ct1->a, ct2->beta);
	mpz_mod(a1beta2, a1beta2, N);

	mpz_mul(a2beta1, ct2->a, ct1->beta);
	mpz_mod(a2beta1, a2beta1, N);*/

	/* POWM */
	mpz_powm(a2beta1, ct2->beta, ct1->a, N);
	mpz_powm(a1beta2, ct1->beta, ct2->a, N);	

	// Homomorphic addition using Joye-Libert is performed by
	// multiplication in the ciphertext space.
	mpz_mul(alpha, alpha, a1beta2);
	mpz_mod(alpha, alpha, N);
	mpz_mul(alpha, alpha, a2beta1);
	mpz_mod(alpha, alpha, N);
}

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
		const uint32_t msgsize)
{
	mpz_t a1a2a3, a1beta23, a2beta13, a3beta12, a12beta3, a13beta2, a23beta1, ptspace;
	mpz_init(a1a2a3);
	mpz_init(a1beta23);
	mpz_init(a2beta13);
	mpz_init(a3beta12);
	mpz_init(a12beta3);
	mpz_init(a13beta2);
	mpz_init(a23beta1);
	mpz_init(ptspace);

	mpz_ui_pow_ui(ptspace, 2, msgsize);

	mpz_mul(a1a2a3, ct1->a, ct2->a);
	mpz_mod(a1a2a3, a1a2a3, ptspace);
	mpz_mul(a1a2a3, a1a2a3, ct3->a);
	mpz_mod(a1a2a3, a1a2a3, ptspace);
	joye_libert_encrypt(alpha, state, a1a2a3, y, N, msgsize);

	mpz_powm(a1beta23, beta23, ct1->a, N);
	mpz_powm(a2beta13, beta13, ct2->a, N);
	mpz_powm(a3beta12, beta12, ct3->a, N);

	mpz_powm(a12beta3, ct3->beta, ct1->a, N);
	mpz_powm(a12beta3, a12beta3, ct2->a, N);
	
	mpz_powm(a13beta2, ct2->beta, ct1->a, N);
	mpz_powm(a13beta2, a13beta2, ct3->a, N);
	
	mpz_powm(a23beta1, ct1->beta, ct2->a, N);
	mpz_powm(a23beta1, a23beta1, ct3->a, N);

	mpz_mul(alpha, alpha, a1beta23);
	mpz_mod(alpha, alpha, N);

	mpz_mul(alpha, alpha, a2beta13);
	mpz_mod(alpha, alpha, N);

	mpz_mul(alpha, alpha, a3beta12);
	mpz_mod(alpha, alpha, N);

	mpz_mul(alpha, alpha, a12beta3);
	mpz_mod(alpha, alpha, N);

	mpz_mul(alpha, alpha, a13beta2);
	mpz_mod(alpha, alpha, N);

	mpz_mul(alpha, alpha, a23beta1);
	mpz_mod(alpha, alpha, N);
}

void mu_he_eval_add(
		he_ct *c,
		const he_ct *c1,
		const he_ct *c2,
		const mpz_t N,
		const uint32_t msgsize)
{
	// Case 1 - C1, C2 on the form (a, beta):
	// 	C = C1 + C2 = (a1 + a2, beta1 + beta2)
	mpz_t ptspace;
	mpz_init(ptspace);
	
	mpz_ui_pow_ui(ptspace, 2, msgsize);

	mpz_add(c->a, c1->a, c2->a);
	mpz_mod(c->a, c->a, ptspace);

	//mpz_add(c->beta, c1->beta, c2->beta);
	mpz_mul(c->beta, c1->beta, c2->beta);
	mpz_mod(c->beta, c->beta, N);
}

void mu_he_eval_add(
		mpz_t c,
		const mpz_t c1,
		const mpz_t c2,
		const mpz_t N)
{
	// Case 2 - C1, C2 on the form alpha:
	// 	C = C1 + C2 = alpha1 + alpha2
	mpz_mul(c, c1, c2);
	mpz_mod(c, c, N);
}

void mu_he_eval_sub(
		he_ct *c,
		const he_ct *c1,
		const he_ct *c2,
		const mpz_t N,
		const uint32_t msgsize)
{
	// Case 1 - C1, C2 on the form (a, beta)
	// C = C1 - C2
	//
	std::cout << "Inside sub\n";
	mpz_t ptspace, a_inv, beta_inv;
	mpz_init(ptspace);
	mpz_init(a_inv);
	mpz_init(beta_inv);

	mpz_ui_pow_ui(ptspace, 2, msgsize);

	// Invert C2.
	std::cout << "Computing inverse a\n";
	//mpz_invert(a_inv, c2->a, ptspace);
	mpz_neg(a_inv, c2->a);
	mpz_mod(a_inv, a_inv, ptspace);
	gmp_printf("additive inverse a: %Zd\n", a_inv);
	std::cout << "Computing inverse b\n";
	mpz_invert(beta_inv, c2->beta, N);

	std::cout << "Adding a\n";
	mpz_add(c->a, c1->a, a_inv);
	mpz_mod(c->a, c->a, ptspace);

	std::cout << "Multiplying beta\n";
	mpz_mul(c->beta, c1->beta, beta_inv);
	mpz_mod(c->beta, c->beta, N);
}

void mu_he_eval_sub(
		mpz_t c,
		const mpz_t c1,
		const mpz_t c2,
		const mpz_t N)
{
	// Case 2 - C1, C2 on the form alpha
	mpz_t c2_inv;
	mpz_init(c2_inv);

	mpz_invert(c2_inv, c2, N);
	mpz_mul(c, c1, c2_inv);
	mpz_mod(c, c, N);
}

void mu_he_eval_cmult(
		he_ct *c,
		const he_ct *c1,
		const mpz_t a,
		const mpz_t N,
		const uint32_t msgsize)
{
	// Input: a constant c in message space and a ciphertext C.
	// Case 1 - C on the form (a, beta):
	// 	C = (a*c, c*beta)
	mpz_t ptspace;
	mpz_init(ptspace);

	mpz_ui_pow_ui(ptspace, 2, msgsize);

	mpz_mul(c->a, c1->a, a);
	mpz_mod(c->a, c->a, ptspace);

	mpz_powm(c->beta, c1->beta, a, N);
}

void mu_he_eval_cmult(
		mpz_t alpha,
	        const mpz_t c,
		const mpz_t constant, 
		const mpz_t N)
{
	// Input: a constant in message space and a ciphertext c.
	// Case 2 - C on the form alpha:
	// 	C = c*a
	mpz_powm(alpha, c, constant, N);
}

void mu_he_decrypt(
		mpz_t m,
		const he_ct *c,
		const mpz_t p,
		const mpz_t y,
		const uint32_t msgsize)
{
	// Two components - Offline-Dec and Online-Dec
	//
	// Offline-Dec(sk, P):
	// 	Given sk and the labeled program P, parse P and (f, tau1, ... , taut).
	// 	For i = 1, .. , t, the algorithm computes bi <- F(K, taui), b = f(b1, ... , bt)
	// 	and outputs skP = (sk, b)
	//
	// Online-Dec(skP, C):
	// 	Parse skP as (sk, b). Two cases:
	// 		Case 1: C on the form (a, beta), there are two decryption methods:
	// 			(i)  Output m = a + b
	// 			(ii) Output m = a + joye_libert_decrypt(sk, beta)
	mpz_t b, ptspace;
	mpz_init(b);
	mpz_init(ptspace);

	mpz_ui_pow_ui(ptspace, 2, msgsize);
	
	joye_libert_decrypt(b, c->beta, p, y, msgsize);
	mpz_add(m, c->a, b);
	mpz_mod(m, m, ptspace);	
}

void mu_he_decrypt(
		mpz_t m,
		const mpz_t c,
		const mpz_t b,
		const mpz_t p,
		const mpz_t y,
		const uint32_t msgsize)
{
	//  Case 2: C on the form alpha:
	//  set m_hat = joye_libert_decrypt(sk, C) and output m = m_hat + b
	mpz_t ptspace;
	mpz_init(ptspace);

	mpz_ui_pow_ui(ptspace, 2, msgsize);

	joye_libert_decrypt(m, c, p, y, msgsize);
	mpz_add(m, m, b);
	mpz_mod(m, m, ptspace);
}
