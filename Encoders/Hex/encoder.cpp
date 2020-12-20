//////////////////////////////////////
// This implementation of a         //
// hex encoder / decoder was        //
// placed in the public domain by:  //
//                                  //
// Petter Solnoer - 15/04/2020      //
//////////////////////////////////////


#include "encoder.h"
#include <iostream>
#include <string>

void hex_encode(char* output, const uint8_t* input, int size)
{
	int loop;
	int i;

	i = 0;
	loop = 0;

	while(loop != size)
	{
	//	std::cout << "loop: " << loop << " | i = " << i << std::endl;
		sprintf((char*)(output+i), "%02X", input[loop]);
		loop+=1;
		i+=2;
	}
	output[i++] = '\0';
}

int hex_to_int(uint8_t c)
{
	int first = c / 16 - 3;
	int second = c % 16;
	int result = first*10+second;
	if (result > 9) result--;
	return result;
}

int hex_to_ascii(uint8_t c, uint8_t d)
{
	int high = hex_to_int(c)*16;
	int low = hex_to_int(d);
	return high+low;
}

void hex_decode(uint8_t* output, const char* input, int size)
{
	int loop = 0;
	uint8_t buf = 0;
	uint8_t tmp;
	for(int i = 0; i < size; i++)
	{
		if(i % 2 != 0)
		{
			//std::cout << input[i] << std::endl;
			tmp = hex_to_ascii(buf, input[i]);
			*output = tmp; output++;
			//printf("%c", hex_to_ascii(buf, input[i]));
		} else {
			//std::cout << input[i];
			buf = input[i];
		}
	}
}
