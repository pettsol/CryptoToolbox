///////////////////////////////////////////////

This document briefly describes how to
use the accompanied implementation of
the Advanced Encryption Standard (AES)
in Counter (CTR) mode.

Compilation:

Using g++ the program to verify the test vectors can be compiled
as follows:

g++ test_vectors.cpp aes_ctr.cpp ../../HexEncoder/encoder.cpp -o test_vectors

To compile using ARM-v8-A Crypto intrinsics (Hardware acceleration), use the following command:

g++ test_vectors.cpp aes_ctr.cpp ../../HexEncoder/encoder.cpp -o test_vectors -D ARM_INTRINSICS -march=armv8-a+crypto

Run program using: ./test_vectors

The implementation has been verified
using test vectors from the official
NIST documentation.


Petter Solnoer - 07/09/2020
/////////////////////////////////////////////////
