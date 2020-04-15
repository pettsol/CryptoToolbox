#include "serialization.h"

#include <chrono>
#include <iostream>
#include <ctime>
#include "aes_cfb.h"

void serialize(data_struct* data, u8* serialized_data)
{

	int *r = (int*) serialized_data;
	*r = data->is_broken; r++;

	float *q = (float*) r;
	*q = data->data; q++;

	double *x = (double*) q;
	for ( int i = 0; i < LOAD_SIZE; i++ )
	{
		*x = data->load[i]; x++;
	}

	std::chrono::system_clock::time_point *p = (std::chrono::system_clock::time_point *) x;
	*p = data->time_stamp; p++;
}

void deserialize(const u8* serialized_data, data_struct* data)
{

	int *r = (int*) serialized_data;
	data->is_broken = *r; r++;

	float *q = (float*) r;
	data->data = *q; q++;

	double *x = (double*) q;
	for (int i = 0; i < LOAD_SIZE; i++)
	{
		data->load[i] = *x; x++;
	}

	std::chrono::system_clock::time_point *p = (std::chrono::system_clock::time_point *) x;
	data->time_stamp = *p; p++;
}
