//////////////////////////////////////
// This implementation of a         //
// hex encoder / decoder was        //
// placed in the public domain by:  //
//                                  //
// Petter Solnoer - 15/04/2020      //
//////////////////////////////////////

#ifndef ENCODER_H
#define ENCODER_H

void string2hexString(const unsigned char* input, char* output, int size);
void hex2stringString(const char* input, unsigned char* output, int size);

#endif
