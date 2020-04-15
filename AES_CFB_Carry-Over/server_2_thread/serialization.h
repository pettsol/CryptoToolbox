#ifndef _SERIALIZATION_H
#define _SERIALIZATION_H

#include "structs.h"

void serialize(data_struct* data, unsigned char* serialized_data);
void deserialize(const unsigned char* serialized_data, data_struct* data);

#endif
