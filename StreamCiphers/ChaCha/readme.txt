////////////////////////////////////////////////

This folder contain an implementation of the 
ChaCha20 stream cipher. The stream cipher
was designed by Dr. Daniel J. Bernstein
and the documentation is found at the IETF
RFC7539.

The stream cipher requires a 256-bit key and a
96-bit nonce. Additionally, it uses a 32-bit
counter, initialized to 1 for a given message
as per RFC7539 specification.

Following the initialization, the cipher
generates 64 bytes of keystream per iteration
in the keystream generation phase.

This implementation was verified with the
test vectors in RFC7539. Observe that the
RFC7539 give the test vectors hexadecimal
form of 32-bit unsigned integers. These
integers have to be serialized to 
little-endian byte arrays.

Compile the sample program with g++ using
the following command:

g++ main.cpp chacha.cpp ../../Encoders/Hex/encoder.cpp -o main

For round reduced variants, compile with the following flags:
	- 12 rounds: -D TWELVE_ROUNDS
	- 8 rounds:  -D EIGHT_ROUNDS

Petter Solnoer - 09/07/2020
////////////////////////////////////////////////
