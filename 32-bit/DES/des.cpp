#include "des.h"

void des_key_schedule_encrypt(des_state *cs, u8 *key)
{
	int i;
	u32 X, Y, T;

	u32 *key_ptr = (u32*)key;

	X = *key_ptr++;
	Y = *key_ptr;

	u32 *rk_ptr = cs->rk;

	T = (( Y >> 4) ^ X) & 0x0f0f0f0f; X ^= T; Y ^= (T << 4);
	T = (( Y     ) ^ X) & 0x10101010; X ^= T; Y ^= (T     );

	X =   (LHs[ (X      ) & 0xf] << 3) | (LHs[ (X >>  8) & 0xf ] << 2)
        | (LHs[ (X >> 16) & 0xf] << 1) | (LHs[ (X >> 24) & 0xf ]     )
        | (LHs[ (X >>  5) & 0xf] << 7) | (LHs[ (X >> 13) & 0xf ] << 6)
        | (LHs[ (X >> 21) & 0xf] << 5) | (LHs[ (X >> 29) & 0xf ] << 4);

    	Y =   (RHs[ (Y >>  1) & 0xf] << 3) | (RHs[ (Y >>  9) & 0xf ] << 2)
        | (RHs[ (Y >> 17) & 0xf] << 1) | (RHs[ (Y >> 25) & 0xf ]     )
        | (RHs[ (Y >>  4) & 0xf] << 7) | (RHs[ (Y >> 12) & 0xf ] << 6)
        | (RHs[ (Y >> 20) & 0xf] << 5) | (RHs[ (Y >> 28) & 0xf ] << 4);

    	X &= 0x0fffffff;
    	Y &= 0x0fffffff;

    	/*
     	* calculate subkeys
     	*/
    	for( i = 0; i < 16; i++ )
    	{
        	if( i < 2 || i == 8 || i == 15 )
        	{
            		X = ((X <<  1) | (X >> 27)) & 0x0fffffff;
            		Y = ((Y <<  1) | (Y >> 27)) & 0x0fffffff;
        	}
        	else
        	{
            		X = ((X <<  2) | (X >> 26)) & 0x0fffffff;
            		Y = ((Y <<  2) | (Y >> 26)) & 0x0fffffff;
        	}

        	*rk_ptr++ =   ((X <<  4) & 0x24000000) | ((X << 28) & 0x10000000)
                	| ((X << 14) & 0x08000000) | ((X << 18) & 0x02080000)
                	| ((X <<  6) & 0x01000000) | ((X <<  9) & 0x00200000)
                	| ((X >>  1) & 0x00100000) | ((X << 10) & 0x00040000)
                	| ((X <<  2) & 0x00020000) | ((X >> 10) & 0x00010000)
                	| ((Y >> 13) & 0x00002000) | ((Y >>  4) & 0x00001000)
                	| ((Y <<  6) & 0x00000800) | ((Y >>  1) & 0x00000400)
                	| ((Y >> 14) & 0x00000200) | ((Y      ) & 0x00000100)
                	| ((Y >>  5) & 0x00000020) | ((Y >> 10) & 0x00000010)
                	| ((Y >>  3) & 0x00000008) | ((Y >> 18) & 0x00000004)
                	| ((Y >> 26) & 0x00000002) | ((Y >> 24) & 0x00000001);

        	*rk_ptr++ =   ((X << 15) & 0x20000000) | ((X << 17) & 0x10000000)
                	| ((X << 10) & 0x08000000) | ((X << 22) & 0x04000000)
                	| ((X >>  2) & 0x02000000) | ((X <<  1) & 0x01000000)
                	| ((X << 16) & 0x00200000) | ((X << 11) & 0x00100000)
                	| ((X <<  3) & 0x00080000) | ((X >>  6) & 0x00040000)
                	| ((X << 15) & 0x00020000) | ((X >>  4) & 0x00010000)
                	| ((Y >>  2) & 0x00002000) | ((Y <<  8) & 0x00001000)
                	| ((Y >> 14) & 0x00000808) | ((Y >>  9) & 0x00000400)
                	| ((Y      ) & 0x00000200) | ((Y <<  7) & 0x00000100)
                	| ((Y >>  7) & 0x00000020) | ((Y >>  3) & 0x00000011)
                	| ((Y <<  2) & 0x00000004) | ((Y >> 21) & 0x00000002);
    }
}

void des_key_schedule_decrypt(des_state *cs, u32 *key)
{
	des_key_schedule_encrypt(cs, (u8*)key);

	// Swap order of the keys
	for ( int i = 0; i < 16; i+=2 )
	{
		u32 tmp;
		tmp = cs->rk[i]; cs->rk[i] = cs->rk[30-i]; cs->rk[30-i] = tmp;
		tmp = cs->rk[i+1]; cs->rk[i+1] = cs->rk[31-i];  cs->rk[31-i] = tmp;
	}
}

void des_ecb_block(des_state *cs, u32 *output, u32 *input)
{
	u32 X, Y, T;

	X = *input++; Y = *input; 

	DES_IP(&X, &Y, &T);

	for (int i = 0; i < 8; i++)
	{
		DES_ROUND(cs, &Y, &X, &T);
		DES_ROUND(cs, &X, &Y, &T);
	}

	DES_FP(&Y, &X, &T);

	*output++ = Y; *output = X;
}

void des_process_packet(des_state *cs, u32 *output, u32 *input, u64 size)
{
	// We always assume that the size divides the block size, 8.
	while (size > 0)
	{
		des_ecb_block(cs, output, input);
		output += 2; input += 2; size -= 8;
	}
}
