#include "serpent.h"
#include <cstring>
#include <iostream>

#define phi 0x9e3779b9

#define SOSEMANUK_H

#ifdef SOSEMANUK_H
void serpent1(u32 *r0, u32 *r1, u32 *r2, u32 *r3)
{
	u32 *r4 = new u32;
	// Apply S2
	S2(r0, r1, r2, r3, r4);

	// Get correct output order
	*r0 = *r2;
	*r2 = *r1;
	*r1 = *r3;
	*r3 = *r4;

	delete r4;
}
#endif

#ifdef SOSEMANUK_H
void rounds(serpent_state *ctx, u32 *r0, u32 *r1, u32 *r2, u32 *r3, u32 *output_buffer)
#else
void rounds(serpent_state *ctx, u32 *r0, u32 *r1, u32 *r2, u32 *r3)
#endif
{
	// A fifth working register is needed
	u32 *r4 = new u32;;

	// Rounds
	/* 0 */ ARK(ctx, r0, r1, r2, r3, 0); S0(r0, r1, r2, r3, r4); LT(r1, r4, r2, r0);
	/* 1 */ ARK(ctx, r1, r4, r2, r0, 1); S1(r1, r4, r2, r0, r3); LT(r2, r1, r0, r4);
	/* 2 */ ARK(ctx, r2, r1, r0, r4, 2); S2(r2, r1, r0, r4, r3); LT(r0, r4, r1, r3);
	/* 3 */ ARK(ctx, r0, r4, r1, r3, 3); S3(r0, r4, r1, r3, r2); LT(r4, r1, r3, r2);
	/* 4 */ ARK(ctx, r4, r1, r3, r2, 4); S4(r4, r1, r3, r2, r0); LT(r1, r0, r4, r2);
	/* 5 */ ARK(ctx, r1, r0, r4, r2, 5); S5(r1, r0, r4, r2, r3); LT(r0, r2, r1, r4);
	/* 6 */ ARK(ctx, r0, r2, r1, r4, 6); S6(r0, r2, r1, r4, r3); LT(r0, r2, r3, r1);
	/* 7 */ ARK(ctx, r0, r2, r3, r1, 7); S7(r0, r2, r3, r1, r4); LT(r4, r1, r2, r0);

	/* 8 */ ARK(ctx, r4, r1, r2, r0, 8); S0(r4, r1, r2, r0, r3); LT(r1, r3, r2, r4);
	/* 9 */ ARK(ctx, r1, r3, r2, r4, 9); S1(r1, r3, r2, r4, r0); LT(r2, r1, r4, r3);
	/* 10 */ ARK(ctx, r2, r1, r4, r3, 10); S2(r2, r1, r4, r3, r0); LT(r4, r3, r1, r0);
	/* 11 */ ARK(ctx, r4, r3, r1, r0, 11); S3(r4, r3, r1, r0, r2); LT(r3, r1, r0, r2);
	// Take output for Sosemanuk
#ifdef SOSEMANUK_H
	*output_buffer = *r3; output_buffer++; *output_buffer = *r1; output_buffer++;
	*output_buffer = *r0; output_buffer++; *output_buffer = *r2; output_buffer++;
#endif
	/* 12 */ ARK(ctx, r3, r1, r0, r2, 12); S4(r3, r1, r0, r2, r4); LT(r1, r4, r3, r2);
	/* 13 */ ARK(ctx, r1, r4, r3, r2, 13); S5(r1, r4, r3, r2, r0); LT(r4, r2, r1, r3);
	/* 14 */ ARK(ctx, r4, r2, r1, r3, 14); S6(r4, r2, r1, r3, r0); LT(r4, r2, r0, r1);
	/* 15 */ ARK(ctx, r4, r2, r0, r1, 15); S7(r4, r2, r0, r1, r3); LT(r3, r1, r2, r4);
	
	/* 16 */ ARK(ctx, r3, r1, r2, r4, 16); S0(r3, r1, r2, r4, r0); LT(r1, r0, r2, r3);
	/* 17 */ ARK(ctx, r1, r0, r2, r3, 17); S1(r1, r0, r2, r3, r4); LT(r2, r1, r3, r0);
	// Take output for Sosemanuk
#ifdef SOSEMANUK_H
	*output_buffer = *r2; output_buffer++; *output_buffer = *r1; output_buffer++;
	*output_buffer = *r3; output_buffer++; *output_buffer = *r0; output_buffer++;
#endif
	/* 18 */ ARK(ctx, r2, r1, r3, r0, 18); S2(r2, r1, r3, r0, r4); LT(r3, r0, r1, r4);
	/* 19 */ ARK(ctx, r3, r0, r1, r4, 19); S3(r3, r0, r1, r4, r2); LT(r0, r1, r4, r2);
	/* 20 */ ARK(ctx, r0, r1, r4, r2, 20); S4(r0, r1, r4, r2, r3); LT(r1, r3, r0, r2);
	/* 21 */ ARK(ctx, r1, r3, r0, r2, 21); S5(r1, r3, r0, r2, r4); LT(r3, r2, r1, r0);
	/* 22 */ ARK(ctx, r3, r2, r1, r0, 22); S6(r3, r2, r1, r0, r4); LT(r3, r2, r4, r1);
	
	// Special case for Sosemanuk, which only executes 24 rounds
#ifdef SOSEMANUK_H
	ARK(ctx, r3, r2, r4, r1, 23); S7(r3, r2, r4, r1, r0); LT(r0, r1, r2, r3); 
	ARK(ctx, r0, r1, r2, r3, 24);

	*output_buffer = *r0; output_buffer++; *output_buffer = *r1; output_buffer++;
	*output_buffer = *r2; output_buffer++; *output_buffer = *r3;
#else

	/* 23 */ ARK(ctx, r3, r2, r4, r1, 23); S7(r3, r2, r4, r1, r0); LT(r0, r1, r2, r3);

	/* 24 */ ARK(ctx, r0, r1, r2, r3, 24); S0(r0, r1, r2, r3, r4); LT(r1, r4, r2, r0);
	/* 25 */ ARK(ctx, r1, r4, r2, r0, 25); S1(r1, r4, r2, r0, r3); LT(r2, r1, r0, r4);
	/* 26 */ ARK(ctx, r2, r1, r0, r4, 26); S2(r2, r1, r0, r4, r3); LT(r0, r4, r1, r3);
	/* 27 */ ARK(ctx, r0, r4, r1, r3, 27); S3(r0, r4, r1, r3, r2); LT(r4, r1, r3, r2);
	/* 28 */ ARK(ctx, r4, r1, r3, r2, 28); S4(r4, r1, r3, r2, r0); LT(r1, r0, r4, r2);
	/* 29 */ ARK(ctx, r1, r0, r4, r2, 29); S5(r1, r0, r4, r2, r3); LT(r0, r2, r1, r4);
	/* 30 */ ARK(ctx, r0, r2, r1, r4, 30); S6(r0, r2, r1, r4, r3); LT(r0, r2, r3, r1);
	// In the last round, the LT is replaced with a final key addition
	/* 31 */ ARK(ctx, r0, r2, r3, r1, 31); S7(r0, r2, r3, r1, r4); ARK(ctx, r4, r1, r2, r0, 32);

	// Order the contents, R1 and R2 has correct contents already
	*r3 = *r0;
	*r0 = *r4;
#endif
	delete r4;

}
void serpent_process_packet(serpent_state *ctx, u32 *out, u32 *in, u64 size)
{
	u64 org_size = size;
	u32 tmp[4];
	std::memcpy(tmp, in, size);
	for ( int i = 0; i < size; i += 16 )
	{
		// Process full block
#ifdef SOSEMANUK_H
		rounds(ctx, tmp, tmp+1, tmp+2, tmp+3, out);

#else
		rounds(ctx, tmp, tmp+1, tmp+2, tmp+3);
		std::memcpy(out, tmp, org_size+16*i);
#endif
	}
}

void serpent_key_schedule(serpent_state *ctx, u8 *input_key, int size)
{
	// The key_size must be 0 <= key_s <= 32
	// If the key is larger, exit.
	if ( size > 32 ) exit(1);

	u8 key[32];
	// If the key is shorter, pad with a
	// 1-bit followed by 0-bits until the key
	// is 256 bits / 32 bytes long.
	std::memcpy(key, input_key, size);

	if ( size < 32 )
	{
				// Appending a 1-bit followed by 0-bits is
		// similar to appending 0x80 hex:
		// 0x80  = 1000 0000
		key[size] = 0x80; size++;
		for ( ; size < 32; size++)
		{
			key[size] = 0x00;
		}
	}

	u32 w[4*N_ROUNDS];

	w[0] = ROTL_32( (( (u32*)key)[0] ^ ((u32*)key)[3] ^ 
		((u32*)key)[5] ^ ((u32*)key)[7] ^ phi ^ 0), 11);
	w[1] = ROTL_32( (( (u32*)key)[1] ^ ((u32*)key)[4] ^ 
		((u32*)key)[6] ^ w[0] ^ phi ^ 1), 11);
	w[2] = ROTL_32( (( (u32*)key)[2] ^ ((u32*)key)[5] ^ 
		((u32*)key)[7] ^ w[1] ^ phi ^ 2), 11);
	w[3] = ROTL_32( (( (u32*)key)[3] ^ ((u32*)key)[6] ^ 
		w[0] ^ w[2] ^ phi ^ 3), 11);
	w[4] = ROTL_32( (( (u32*)key)[4] ^ ((u32*)key)[7] ^ 
		w[1] ^ w[3] ^ phi ^ 4), 11);
	w[5] = ROTL_32( (( (u32*)key)[5] ^ w[0] ^ 
		w[2] ^ w[4] ^ phi ^ 5), 11);
	w[6] = ROTL_32( (( (u32*)key)[6] ^ w[1] ^ 
		w[3] ^ w[5] ^ phi ^ 6), 11);
	w[7] = ROTL_32( (( (u32*)key)[7] ^ w[2] ^ 
		w[4] ^ w[6] ^ phi ^ 7), 11);

	for ( int i = 8; i < 4*N_ROUNDS; i++ )
	{
		w[i] = ROTL_32( (w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ phi ^ i), 11);
	}
/*	
	// Print working directories
	for ( int i = 0; i < N_ROUNDS; i++ )
	{
		char wv0[9];
		char wv1[9];
		char wv2[9];
		char wv3[9];

		string2hexString(wv0, (u8*)(w + 4*i), 4);
		string2hexString(wv1, (u8*)(w+4*i+1), 4);
		string2hexString(wv2, (u8*)(w+4*i+2), 4);
		string2hexString(wv3, (u8*)(w+4*i+3), 4);

		std::string wv0_string(wv0, 8);
		std::string wv1_string(wv1, 8);
		std::string wv2_string(wv2, 8);
		std::string wv3_string(wv3, 8);

		std::cout << "Wv " << i << ": " << wv0_string <<
		       " " << wv1_string << " " << wv2_string << " " << wv3_string << std::endl;
	}
	//
*/
	// Fifth register to assist with Sbox computations
	u32 *r4 = new u32;
	// k0, k1, k2, k3
	S3(w, w+1, w+2, w+3, r4);
	ctx->RK[0] = *(w+1);
	ctx->RK[1] = *(w+2);
	ctx->RK[2] = *(w+3);
	ctx->RK[3] = *r4;
	// k4, k5, k6, k7
	S2(w+4, w+5, w+6, w+7, r4);
	ctx->RK[4] = *(w+6);
	ctx->RK[5] = *(w+7);
	ctx->RK[6] = *(w+5);
	ctx->RK[7] = *r4;
	// k8, k9, k10, k11
	S1(w+8, w+9, w+10, w+11, r4);
	ctx->RK[8] = *(w+10);
	ctx->RK[9] = *(w+8);
	ctx->RK[10] = *(w+11);
	ctx->RK[11] = *(w+9);
	// k12, k13, k14, k15
	S0(w+12, w+13, w+14, w+15, r4);
	ctx->RK[12] = *(w+13);
	ctx->RK[13] = *(r4);
	ctx->RK[14] = *(w+14);
	ctx->RK[15] = *(w+12);
	// k16, k17, k18, k19
	S7(w+16, w+17, w+18, w+19, r4);
	ctx->RK[16] = *(r4);
	ctx->RK[17] = *(w+19);
	ctx->RK[18] = *(w+17);
	ctx->RK[19] = *(w+16);
	// k20, k21, k22, k23
	S6(w+20, w+21, w+22, w+23, r4);
	ctx->RK[20] = *(w+20);
	ctx->RK[21] = *(w+21);
	ctx->RK[22] = *(r4);
	ctx->RK[23] = *(w+22);
	// k24, k25, k26, k27
	S5(w+24, w+25, w+26, w+27, r4);
	ctx->RK[24] = *(w+25);
	ctx->RK[25] = *(w+27);
	ctx->RK[26] = *(w+24);
	ctx->RK[27] = *(w+26);
	// k28, k29, k30, k31
	S4(w+28, w+29, w+30, w+31, r4);
	ctx->RK[28] = *(w+29);
	ctx->RK[29] = *(r4);
	ctx->RK[30] = *(w+28);
	ctx->RK[31] = *(w+31);
	// k32, k33, k34, k35
	S3(w+32, w+33, w+34, w+35, r4);
	ctx->RK[32] = *(w+33);
	ctx->RK[33] = *(w+34);
	ctx->RK[34] = *(w+35);
	ctx->RK[35] = *(r4);
	// k36, k37, k38, k39
	S2(w+36, w+37, w+38, w+39, r4);
	ctx->RK[36] = *(w+38);
	ctx->RK[37] = *(w+39);
	ctx->RK[38] = *(w+37);
	ctx->RK[39] = *(r4);
	// k40, k41, k42, k43
	S1(w+40, w+41, w+42, w+43, r4);
	ctx->RK[40] = *(w+42);
	ctx->RK[41] = *(w+40);
	ctx->RK[42] = *(w+43);
	ctx->RK[43] = *(w+41);
	// k44, k45, k46, k47
	S0(w+44, w+45, w+46, w+47, r4);
	ctx->RK[44] = *(w+45);
	ctx->RK[45] = *(r4);
	ctx->RK[46] = *(w+46);
	ctx->RK[47] = *(w+44);
	// k48, k49, k50, k51
	S7(w+48, w+49, w+50, w+51, r4);
	ctx->RK[48] = *(r4);
	ctx->RK[49] = *(w+51);
	ctx->RK[50] = *(w+49);
	ctx->RK[51] = *(w+48);
	// k52, k53, k54, k55
	S6(w+52, w+53, w+54, w+55, r4);
	ctx->RK[52] = *(w+52);
	ctx->RK[53] = *(w+53);
	ctx->RK[54] = *(r4);
	ctx->RK[55] = *(w+54);
	// k56, k57, k58, k59
	S5(w+56, w+57, w+58, w+59, r4);
	ctx->RK[56] = *(w+57);
	ctx->RK[57] = *(w+59);
	ctx->RK[58] = *(w+56);
	ctx->RK[59] = *(w+58);
	// k60, k61, k62, k63
	S4(w+60, w+61, w+62, w+63, r4);
	ctx->RK[60] = *(w+61);
	ctx->RK[61] = *(r4);
	ctx->RK[62] = *(w+60);
	ctx->RK[63] = *(w+63);
	// k64, k65, k66, k67
	S3(w+64, w+65, w+66, w+67, r4);
	ctx->RK[64] = *(w+65);
	ctx->RK[65] = *(w+66);
	ctx->RK[66] = *(w+67);
	ctx->RK[67] = *(r4);
	// k68, k69, k70, k71
	S2(w+68, w+69, w+70, w+71, r4);
	ctx->RK[68] = *(w+70);
	ctx->RK[69] = *(w+71);
	ctx->RK[70] = *(w+69);
	ctx->RK[71] = *(r4);
	// k72, k73, k74, k75
	S1(w+72, w+73, w+74, w+75, r4);
	ctx->RK[72] = *(w+74);
	ctx->RK[73] = *(w+72);
	ctx->RK[74] = *(w+75);
	ctx->RK[75] = *(w+73);
	// k76, k77, k78, k79
	S0(w+76, w+77, w+78, w+79, r4);
	ctx->RK[76] = *(w+77);
	ctx->RK[77] = *(r4);
	ctx->RK[78] = *(w+78);
	ctx->RK[79] = *(w+76);
	// k80, k81, k82, k83
	S7(w+80, w+81, w+82, w+83, r4);
	ctx->RK[80] = *(r4);
	ctx->RK[81] = *(w+83);
	ctx->RK[82] = *(w+81);
	ctx->RK[83] = *(w+80);
	// k84, k85, k86, k87
	S6(w+84, w+85, w+86, w+87, r4);
	ctx->RK[84] = *(w+84);
	ctx->RK[85] = *(w+85);
	ctx->RK[86] = *(r4);
	ctx->RK[87] = *(w+86);
	// k88, k89, k90, k91
	S5(w+88, w+89, w+90, w+91, r4);
	ctx->RK[88] = *(w+89);
	ctx->RK[89] = *(w+91);
	ctx->RK[90] = *(w+88);
	ctx->RK[91] = *(w+90);
	// k92, k93, k94, k95
	S4(w+92, w+93, w+94, w+95, r4);
	ctx->RK[92] = *(w+93);
	ctx->RK[93] = *(r4);
	ctx->RK[94] = *(w+92);
	ctx->RK[95] = *(w+95);
	// k96, k97, k98, k99
	S3(w+96, w+97, w+98, w+99, r4);
	ctx->RK[96] = *(w+97);
	ctx->RK[97] = *(w+98);
	ctx->RK[98] = *(w+99);
	ctx->RK[99] = *(r4);

	// If SERPENT is called as a
	// sub-component of Sosemanuk,
	// only 24 rounds are executed
	// and 25 round-keys are required
#ifdef SOSEMANUK_H
	goto wrapUp;
#endif

	// k100, k101, k102, k103
	S2(w+100, w+101, w+102, w+103, r4);
	ctx->RK[100] = *(w+102);
	ctx->RK[101] = *(w+103);
	ctx->RK[102] = *(w+101);
	ctx->RK[103] = *(r4);
	// k104, k105, k106, k107
	S1(w+104, w+105, w+106, w+107, r4);
	ctx->RK[104] = *(w+106);
	ctx->RK[105] = *(w+104);
	ctx->RK[106] = *(w+107);
	ctx->RK[107] = *(w+105);
	// k108, k109, k110, k111
	S0(w+108, w+109, w+110, w+111, r4);
	ctx->RK[108] = *(w+109);
	ctx->RK[109] = *(r4);
	ctx->RK[110] = *(w+110);
	ctx->RK[111] = *(w+108);
	// k112, k113, k114, k115
	S7(w+112, w+113, w+114, w+115, r4);
	ctx->RK[112] = *(r4);
	ctx->RK[113] = *(w+115);
	ctx->RK[114] = *(w+113);
	ctx->RK[115] = *(w+112);
	// k116, k117, k118, k119
	S6(w+116, w+117, w+118, w+119, r4);
	ctx->RK[116] = *(w+116);
	ctx->RK[117] = *(w+117);
	ctx->RK[118] = *(r4);
	ctx->RK[119] = *(w+118);
	// k120, k121, k122, k123
	S5(w+120, w+121, w+122, w+123, r4);
	ctx->RK[120] = *(w+121);
	ctx->RK[121] = *(w+123);
	ctx->RK[122] = *(w+120);
	ctx->RK[123] = *(w+122);
	// k124, k125, k126, k127
	S4(w+124, w+125, w+126, w+127, r4);
	ctx->RK[124] = *(w+125);
	ctx->RK[125] = *(r4);
	ctx->RK[126] = *(w+124);
	ctx->RK[127] = *(w+127);
	// k128, k129, k130, k131
	S3(w+128, w+129, w+130, w+131, r4);
	ctx->RK[128] = *(w+129);
	ctx->RK[129] = *(w+130);
	ctx->RK[130] = *(w+131);
	ctx->RK[131] = *(r4);

wrapUp:

	delete r4;
/*	
	// Print the round keys
	for (int i = 0; i < N_ROUNDS; i++)
	{
		char hexRK0[9];
		char hexRK1[9];
		char hexRK2[9];
		char hexRK3[9];
		string2hexString(hexRK0, (u8*)&ctx->RK[4*i], 4);
		string2hexString(hexRK1, (u8*)&ctx->RK[4*i+1], 4);
		string2hexString(hexRK2, (u8*)&ctx->RK[4*i+2], 4);
		string2hexString(hexRK3, (u8*)&ctx->RK[4*i+3], 4);

		std::string hexRK0String(hexRK0, 8);
		std::string hexRK1String(hexRK1, 8);
		std::string hexRK2String(hexRK2, 8);
		std::string hexRK3String(hexRK3, 8);

		std::cout << "Round key " << i << ": " << hexRK0String 
			<< " " << hexRK1String << " " << hexRK2String << " " << hexRK3String << std::endl;
	}
	*/
}
