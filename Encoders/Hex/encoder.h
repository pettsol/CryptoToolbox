//////////////////////////////////////
// This implementation of a         //
// hex encoder / decoder was        //
// placed in the public domain by:  //
//                                  //
// Petter Solnoer - 15/04/2020      //
//////////////////////////////////////

#ifndef ENCODER_H
#define ENCODER_H

#include <climits>
#include <fstream>

// Check that the size of
// data types are as 
// expected

#if (UCHAR_MAX != 0xFFU)
#error UCHAR IS NOT 8 BITS
#endif

#if (USHRT_MAX != 0xFFFFU)
#error USHORT IS NOT 16 BITS
#endif

#if (UINT_MAX != 0xFFFFFFFFU)
#error UINT IS NOT 32 BITS
#endif

#if (ULLONG_MAX != 0xFFFFFFFFFFFFFFFFU)
#error ULONGLONG IS NOT 64 BITS
#endif

// We can now typedef variables of fixed sizes

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

void hex_encode(char* output, const u8* input, int size);
void hex_decode(u8* output, const char* input, int size);

#endif
