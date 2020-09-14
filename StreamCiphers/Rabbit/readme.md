*****************************************************************

This folder contain an implementation of the Rabbit stream cipher.
The stream cipher was designed by Cryptico A/S and the documentation
can be found in IETF RFC4503 and at the eSTREAM website.

The stream cipher accepts a 128-bit key and a 64-bit IV. The
key-injection and IV-injection procedures are separate, thus
the key-injection is only called once for a given key
while the IV-injection is usually called on a per-message
basis in order to guarrantee synchronous behaviour between the
sender and the receiver.

This implementation was verified with official test vectors
from RFC4503. Note that the order of the bytes in RFC4503
is "reversed" (I2OSP standard) and thus have to be input in
reversed order for correct input/output.

Compile the sample program with g++ using the following
command:

g++ main.cpp rabbit.cpp ../../Encoders/Hex/encoder.cpp -o main

Petter Solnoer - 19/06/2020

******************************************************************
