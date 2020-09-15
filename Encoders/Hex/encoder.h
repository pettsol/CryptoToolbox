//////////////////////////////////////
// This implementation of a         //
// hex encoder / decoder was        //
// placed in the public domain by:  //
//                                  //
// Petter Solnoer - 15/04/2020      //
//////////////////////////////////////

#ifndef ENCODER_H
#define ENCODER_H

void hex_encode(char* output, const unsigned char* input, int size);
void hex_decode(unsigned char* output, const char* input, int size);

#endif
