#include "encoder.h"
#include <iostream>
#include <string>
void string2hexString(const unsigned char* input, char* output, int size)
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
/*void string2hexString(const char* input, char* output, int size)
{
	int loop, i;
	loop = 0;

	while (loop != size )
	{
		int first = 
	}
}*/

int hex_to_int(unsigned char c)
{
	int first = c / 16 - 3;
	int second = c % 16;
	int result = first*10+second;
	if (result > 9) result--;
	return result;
}

int hex_to_ascii(unsigned char c, unsigned char d)
{
	int high = hex_to_int(c)*16;
	int low = hex_to_int(d);
	return high+low;
}

void hex2stringString(const char* input, unsigned char* output, int size)
{
	int loop = 0;
	unsigned char buf = 0;
	unsigned char tmp;
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
/*
void hex2stringString(const char* input, char* output, int hexSize)
{
	for (int i = 0; i < hexSize; i += 2)
	{
		std::string part = "";
		part += input[i];
		part += input[i+1];
		*output = std::stoul(part, nullptr, 16); output++;	
	}
}*/
