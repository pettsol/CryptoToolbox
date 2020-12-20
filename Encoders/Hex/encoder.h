//////////////////////////////////////
// This implementation of a         //
// hex encoder / decoder was        //
// placed in the public domain by:  //
//                                  //
// Petter Solnoer - 15/04/2020      //
//////////////////////////////////////

#ifndef ENCODER_H
#define ENCODER_H

#include <stdint.h>
#include <fstream>

void hex_encode(char* output, const uint8_t* input, int size);
void hex_decode(uint8_t* output, const char* input, int size);

#endif
