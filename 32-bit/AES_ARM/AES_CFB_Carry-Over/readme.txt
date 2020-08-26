///////////////////////////////////////////////

This document briefly describes how to
use the accompanied implementation of
the Advanced Encryption Standard (AES)
in 128-bit cipher-feedback (CFB) mode
with a carry-over IV. Thus, the cipher
is only initialized with the IV once.

NB: According to the official NIST
documentation the IV should be
unpredictable in the CFB mode. In this
implementation, the IV consists of
the ciphertext from previous
messages, and is thus predictable
to an adversary. Contrary to the
cipher block-chaining (CBC) mode
of operation however, no attacks 
against the CFB mode with a predictable
IV is known.

Both a full version of the cipher
and a round-reduced variant is
available.

Compilation:

Using g++ the cipher can be compiled
as follows:

FULL VERSION:

g++ main.cpp aes_cfb.cpp -o main

ROUND-REDUCED VERSION (6 rounds)

g++ main.cpp aes_cfb.cpp -o main -D ROUND_REDUCED

The implementation has been verified
using test vectors from the official
NIST documentation.


Petter Solnoer - 31/03/2020
/////////////////////////////////////////////////
