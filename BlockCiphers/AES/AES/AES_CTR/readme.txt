///////////////////////////////////////////////

This document briefly describes how to
use the accompanied implementation of
the Advanced Encryption Standard (AES)
in Counter (CTR) mode.

Compilation:

Using g++ the program to verify the test vectors can be compiled
as follows:

g++ test_vectors.cpp aes_ctr.cpp ../../../../Encoders/Hex/encoder.cpp -o test_vectors

Run program using: ./test_vectors

The implementation has been verified
using test vectors from the official
NIST documentation.


Petter Solnoer - 07/09/2020
/////////////////////////////////////////////////
