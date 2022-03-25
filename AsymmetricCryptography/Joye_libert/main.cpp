#include "joye_libert.h"

#include <gmp.h>
//#include <iostream>
//#include <chrono>
//#include <ctime>

int main()
{
	mpz_t N, y, p;

	mpz_init(N);
	mpz_init(y);
	mpz_init(p);

	uint32_t keysize = 2048;
	uint32_t msgsize = 64;

	gmp_printf("Generating appropriate primes. NB! This can take some time.\n");
	joye_libert_keygen(N, y, p, msgsize, keysize);

	mpz_t m1, m2, c1, c2;

	mpz_init_set_ui(m1, 999);
	mpz_init_set_ui(m2, 150);

	mpz_init(c1);
	mpz_init(c2);

	gmp_randstate_t state;
	gmp_randinit_mt(state);

	gmp_printf("Testing the additively homomorphic property\n");
	gmp_printf("m1: %Zd\n", m1);
	gmp_printf("m2: %Zd\n", m2);

	joye_libert_encrypt(c1, state, m1, y, N, msgsize);
	joye_libert_encrypt(c2, state, m2, y, N, msgsize);

	mpz_mul(c1, c1, c2);
	mpz_mod(c1, c1, N);

	mpz_t recov_m;
	mpz_init(recov_m);

	joye_libert_decrypt(recov_m, c1, p, y, msgsize);

	gmp_printf("recov_m = m1 + m2: %Zd\n", recov_m);
}
