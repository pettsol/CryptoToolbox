#include "labeled_he.h"
#include "../joye_libert/joye_libert.h"
#include "../HC-128/hc128.h"

#include <gmp.h>
#include <iostream>

int main()
{
	std::cout << "Starting program\n";

	mpz_t N, y, p, ptspace;
	
	mpz_init(N);
	mpz_init(y);
	mpz_init(p);
	mpz_init(ptspace);

	gmp_randstate_t state;
	gmp_randinit_mt(state);

	// Number of bits
	uint32_t keysize = 2048;
	uint32_t msgsize = 32;

	mpz_ui_pow_ui(ptspace, 2, msgsize);

	std::cout << "Initialized variables, ready to perform labeled HE keygen\n";

	mu_he_setup(N, y, p, msgsize, keysize);

	hc128_state hc_cs;

	uint8_t hc_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			      0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15};
	uint8_t hc_iv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	hc128_initialize(&hc_cs, hc_key, hc_iv);

	he_ct c1, c2, c3;
	mpz_init(c1.a);
	mpz_init(c1.beta);
	mpz_init(c2.a);
	mpz_init(c2.beta);
	mpz_init(c3.a);
	mpz_init(c3.beta);

	mpz_t m1, label1;
	mpz_init_set_ui(m1, 10);
	mpz_init_set_ui(label1, 1);

	mpz_t m2, label2;
	mpz_init_set_ui(m2, 15);
	mpz_init_set_ui(label2, 2);

	mpz_t m3, label3;
	mpz_init_set_ui(m3, 5);
	mpz_init_set_ui(label3, 3);

	mpz_t b1, b2, b3;
	mpz_init(b1);
	mpz_init(b2);
	mpz_init(b3);


	gmp_printf("Original Message m1: %Zd\n", m1);
	gmp_printf("Original Message m2: %Zd\n", m2);
	gmp_printf("Original Message m3: %Zd\n", m3);

	std::cout << "Ready to perform labeled HE encryption\n";

	he_encrypt(&c1, state, &hc_cs, b1, m1, y, N, label1, msgsize);
	he_encrypt(&c2, state, &hc_cs, b2, m2, y, N, label2, msgsize);
	he_encrypt(&c3, state, &hc_cs, b3, m3, y, N, label3, msgsize);

	gmp_printf("a1: %Zd\n", c1.a);
	gmp_printf("beta1: %Zd\n",c1.beta);
	
	gmp_printf("a2: %Zd\n", c2.a);
	gmp_printf("beta2: %Zd\n",c2.beta);
	
	gmp_printf("a3: %Zd\n", c3.a);
	gmp_printf("beta3: %Zd\n", c3.beta);

	std::cout << "Ready to perform labeled HE addition\n";

	he_ct c_add;
	mpz_init(c_add.a);
	mpz_init(c_add.beta);

	he_eval_add(&c_add, &c1, &c2, N, msgsize);

	std::cout << "Ready to perform labeled HE subtraction\n";

	he_ct c_sub;
	mpz_init(c_sub.a);
	mpz_init(c_sub.beta);

	// he_eval_sub?
	he_eval_sub(&c_sub, &c2, &c3, N, msgsize);

	std::cout << "Ready to perform labeled HE multiplication\n";

	mpz_t c_mul, b_mul;
	mpz_init(c_mul);
	mpz_init(b_mul);
	he_eval_mult(c_mul, state, &c1, &c2, y, N, msgsize);
	mpz_mul(b_mul, b1, b2);
	mpz_mod(b_mul, b_mul, ptspace);
	//gmp_printf("c: %Zd\n", c);

	std::cout << "Ready to perform labeled HE triple multiplication\n";

	mpz_t c_triple_mul, b_triple_mul;
	mpz_init(c_triple_mul);
	mpz_init(b_triple_mul);

	mpz_t beta12, beta13, beta23;
	mpz_init(beta12);
	mpz_init(beta13);
	mpz_init(beta23);

	mpz_mul(beta12, b1, b2);
	mpz_mod(beta12, beta12, ptspace);

	mpz_mul(beta13, b1, b3);
	mpz_mod(beta13, beta13, ptspace);

	mpz_mul(beta23, b2, b3);
	mpz_mod(beta23, beta23, ptspace);

	joye_libert_encrypt(beta12, state, beta12, y, N, msgsize);
	joye_libert_encrypt(beta13, state, beta13, y, N, msgsize);
	joye_libert_encrypt(beta23, state, beta23, y, N, msgsize);

	he_eval_mult_3(c_triple_mul, state, &c1, &c2, &c3, beta12, beta13, beta23, y, N, msgsize);
	mpz_mul(b_triple_mul, b1, b2);
	mpz_mod(b_triple_mul, b_triple_mul, ptspace);
	mpz_mul(b_triple_mul, b_triple_mul, b3);
	mpz_mod(b_triple_mul, b_triple_mul, ptspace);

	std::cout << "Perform homomorphic triple multiplication with subtraction element\n";

	mpz_t c_sub_trip, b_sub_trip;
	mpz_init(c_sub_trip);
	mpz_init(b_sub_trip);

	mpz_t b_dt, beta34, beta35, beta45;
	mpz_init(b_dt);
	mpz_init(beta34);
	mpz_init(beta35);
	mpz_init(beta45);

	mpz_sub(b_dt, );
	mpz_mul(beta34, );

	std::cout << "Perform homomorphic addition of triple mul and double mul\n";
	
	mpz_t c_triple_double_add, b_triple_double_add;
	mpz_init(c_triple_double_add);
	mpz_init(b_triple_double_add);
	he_eval_add(c_triple_double_add, c_mul, c_triple_mul, N);
	mpz_add(b_triple_double_add, b_mul, b_triple_mul);
	mpz_mod(b_triple_double_add, b_triple_double_add, ptspace);

	std::cout << "Perform homomorphic subtraction of triple mul and double mul\n";

	mpz_t c_triple_double_sub, b_triple_double_sub;
	mpz_init(c_triple_double_sub);
	mpz_init(b_triple_double_sub);
	he_eval_sub(c_triple_double_sub, c_triple_mul, c_mul, N);
	mpz_sub(b_triple_double_sub, b_triple_mul, b_mul);
	mpz_mod(b_triple_double_sub, b_triple_double_sub, ptspace);

	std::cout << "Ready to perform labeled HE decryption\n";

	mpz_t recov_m1, recov_m2, recov_add, recov_sub, recov_mul,
	      recov_triple_mul, recov_triple_double_add, recov_triple_double_sub;

	mpz_init(recov_m1);
	mpz_init(recov_m2);
	mpz_init(recov_add);
	mpz_init(recov_sub);
	mpz_init(recov_mul);
	mpz_init(recov_triple_mul);
	mpz_init(recov_triple_double_add);
	mpz_init(recov_triple_double_sub);

	he_decrypt(recov_m1, &c1, p, y, msgsize);
	he_decrypt(recov_m2, &c2, p, y, msgsize);
	he_decrypt(recov_add, &c_add, p, y, msgsize);
	he_decrypt(recov_sub, &c_sub, p, y, msgsize);
	he_decrypt(recov_mul, c_mul, b_mul, p, y, msgsize);
	he_decrypt(recov_triple_mul, c_triple_mul, b_triple_mul, p, y, msgsize);
	he_decrypt(recov_triple_double_add, c_triple_double_add, b_triple_double_add,
			p, y, msgsize);
	he_decrypt(recov_triple_double_sub, c_triple_double_sub, b_triple_double_sub,
			p, y, msgsize);

	//mpz_t new_b = 
	//
	gmp_printf("Recovered message 1: %Zd\n", recov_m1);
	gmp_printf("Recovered message 2: %Zd\n", recov_m2);
	gmp_printf("Recovered message add: %Zd\n", recov_add);
	gmp_printf("Recovered message sub: %Zd\n", recov_sub);
	gmp_printf("Recovered message mul: %Zd\n", recov_mul);
	gmp_printf("Recovered message triple mul: %Zd\n", recov_triple_mul);
	gmp_printf("Recovered message triple-double add: %Zd\n", recov_triple_double_add);
	gmp_printf("Recovered message triple-double sub: %Zd\n", recov_triple_double_sub);

	std::cout << "Done\n";
}
