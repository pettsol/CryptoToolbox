//////////////////////////////////
// This implementation has been //
// placed in the public domain  //
// by			        //
//			      	//
// Petter Solnoer - 1/11/2021 	//
//////////////////////////////////

#include "joye_libert.h"

#include <iostream>

void joye_libert_keygen(
		mpz_t N,
	       	mpz_t y,
	       	mpz_t p,
	       	const uint32_t msgsize,
	       	const uint32_t keysize
		)
{
	//** Generate primes p, q congruent to 1 mod 2^{k}. **
	// Start by initializing a prng.
	gmp_randstate_t state;
	gmp_randinit_mt(state);

	// Variable to hold q
	mpz_t q;
	mpz_init(q);
	// Variables to hold test primes
	mpz_t p_test, q_test;
	mpz_init(p_test);
	mpz_init(q_test);
	
	// Variable to hold pseudo-safeness test divisor
	// and pseudo_test assume k-bit messages.
	mpz_t pseudo_safeness_divisor, pseudo_test_p, pseudo_test_q;
	mpz_init(pseudo_safeness_divisor);
	mpz_init(pseudo_test_p);
	mpz_init(pseudo_test_q);
	
	// Set divisor to 2^{k}
	mpz_ui_pow_ui(pseudo_safeness_divisor, 2, msgsize);

	// Set p to random value with keysize/2 bits
	mpz_urandomb(p_test, state, keysize/2);
	
	// Find the modulus
	mpz_t mod;
	mpz_init(mod);
	mpz_mod(mod, p_test, pseudo_safeness_divisor);

	mpz_sub(p_test, p_test, mod);
	mpz_add_ui(p_test, p_test, 1);

	// We now have a number that is congruent to 1, as desired.
	// Now we must check if it is prime!

	//mpz_nextprime(p_test, p_test);
	// Start by finding appropriate p
	mpz_t one;
	mpz_init_set_ui(one, 1);
#ifdef DEBUG
	std::cout << "Find appropriate p\n";
#endif
	mpz_t t;
	mpz_init(t);

	mpz_t tmp;
	mpz_init(tmp);
	while(true)
	{
		// check if prime
		//mpz_mod(t, p_test, pseudo_safeness_divisor);
		//gmp_printf("%Zd is the congruence.\n", t);
		//if (mpz_congruent_2exp_p(p_test, one, 32))
		if (mpz_probab_prime_p(p_test, 30))
		{
			// check for pseudo-safeness
			// condition: p_test - 1 / 2^{k} is also prime

			mpz_sub_ui(tmp, p_test, 1);

			mpz_divexact(pseudo_test_p, tmp, pseudo_safeness_divisor);
			if (mpz_probab_prime_p(pseudo_test_p, 30))
			{
				// We have probably found a good value
				// for p
#ifdef DEBUG
				gmp_printf("Good value for p: %Zd\n", p_test);
#endif
				mpz_set(p, p_test);
				break;
			}	
		}
		// Check next prime, probabilistic, chance of composite passing
		// is extremely small
		mpz_add(p_test, p_test, pseudo_safeness_divisor);
	}

	// Proceed to find appropriate q
#ifdef DEBUG
	std::cout << "Find appropriate q\n";
#endif
	mpz_urandomb(q_test, state, keysize/2);
	mpz_nextprime(q_test, q_test);
	while(true)
	{
		// check if prime
		if (mpz_probab_prime_p(q_test, 30))
		{
			// Condition: q_test mod 4 = 3
			//
			mpz_mod_ui(tmp, q_test, 4);
			if(mpz_cmp_ui(tmp, 3) == 0)
			{
#ifdef DEBUG
				gmp_printf("Good value for q: %Zd\n", q_test);
#endif
				mpz_set(q, q_test);
			break;
			}	
		}
		// Check next prime, probabilistic, chance of composite passing
		// is extremely small
		mpz_nextprime(q_test, q_test);
	}

	// Set N = p*q
	mpz_mul(N, p, q);
#ifdef DEBUG
	gmp_printf("Resulting value for N: %Zd\n", N);
#endif
	// Proceed to find a suitable y.

	// NB! Joye and Libert suggest how to find y in Algorithm 2 in their
	// Eurocrypt 2013 conference paper. However, this is overly complicated and involves
	// finding primitive roots of unity, i.e., primitive polynomials. This is complicated in
	// C/C++. Instead, notice that the probability of a non-zero random element not being a
	// quadratic residue is exactly 1/2 - therefore, we can just generate random y's until
	// we find one that satisfies the requirements.
	//
	// Generate a random y in Z_{N}
	mpz_set_ui(y, 0);
	while ((mpz_legendre(y, p) != -1) || (mpz_legendre(y,q) != -1))
	{
		// Generate random y in Z_N
		mpz_urandomm(y, state, N);
	}
#ifdef DEBUG	
	gmp_printf("Good value for y: %Zd\n", y);
#endif
	int32_t jacobi_n = mpz_jacobi(y, N);
	int32_t legendre_p = mpz_legendre(y, p);
	int32_t legendre_q = mpz_legendre(y, q);
#ifdef DEBUG
	std::cout << "Jacobi: " << jacobi_n << std::endl;
	std::cout << "Legendre y/p final: " << legendre_p << std::endl;
	std::cout << "Legendre y/q final: " << legendre_q << std::endl;
#endif
}

void joye_libert_encrypt(
		mpz_t c,
	       	gmp_randstate_t state,
	       	const mpz_t m,
	       	const mpz_t y,
	       	const mpz_t N,
	       	const uint32_t msgsize)
{
	mpz_t x;
	mpz_init_set_ui(x, 0);
	// Pick a random x in Z_N^*
	while(!mpz_cmpabs_ui(x, 0))
	{
		mpz_urandomm(x, state, N);
	}
#ifdef DEBUG
	gmp_printf("x: %Zd\n", x);
#endif
	// Compute 2^msgsize
	mpz_t k_exp;
	mpz_init(k_exp);
	mpz_ui_pow_ui(k_exp, 2, msgsize);

	// Encrypt
	mpz_t tmp1, tmp2;
	mpz_init(tmp1);
	mpz_init(tmp2);

	mpz_powm(tmp1, y, m, N);
	mpz_powm(tmp2, x, k_exp, N);

	mpz_mul(c, tmp1, tmp2);
	mpz_mod(c, c, N);

#ifdef DEBUG
	gmp_printf("c: %Zd\n", c);
#endif
}

void joye_libert_decrypt(
		mpz_t m,
		const mpz_t c,
		const mpz_t p,
		const mpz_t y,
		const uint32_t msgsize)
{
	// Initial operations
	mpz_t B, D, C;

	mpz_set_ui(m, 0);
	mpz_init_set_ui(B, 1);
	mpz_init(D);
	mpz_init(C);

	mpz_t exp_msgsize, exp_y, neg_exp_y, p_1;
	mpz_init(exp_msgsize);
	mpz_init(exp_y);
	mpz_init(neg_exp_y);
	mpz_init(p_1);

	mpz_set(p_1, p);
	mpz_sub_ui(p_1, p_1, 1);

	mpz_ui_pow_ui(exp_msgsize, 2, msgsize);
	mpz_divexact(exp_y, p_1, exp_msgsize);
	mpz_neg(neg_exp_y, exp_y);
	mpz_powm(D, y, neg_exp_y, p);

	mpz_powm(C, c, exp_y, p);

	mpz_t z, exp_c;
	mpz_init(z);
	mpz_init(exp_c);

	// Decryption
	for(uint32_t j = 1; j < msgsize; j++)
	{
		mpz_ui_pow_ui(exp_c, 2, msgsize-j);
		mpz_powm(z, C, exp_c, p);

		// If z is not equal to 1, m_j is 1.
		if( mpz_cmp_ui(z, 1) != 0)
		{
			mpz_add(m, m, B);
			mpz_mul(C, C, D);
			mpz_mod(C, C, p);
		}
		mpz_add(B, B, B);
		mpz_powm_ui(D, D, 2, p);
	}

	// Finalize
	if (mpz_cmp_ui(C, 1) != 0)
	{
		mpz_add(m, m, B);
	}
}
