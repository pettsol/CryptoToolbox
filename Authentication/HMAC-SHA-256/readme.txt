///////////////////////////////////////////////

This folder contain a HMAC-SHA-256 implementation.

The tag size is a parameter 0 < tagSize <= 32
chosen by the user. A larger tag provides better
security.

Compile with g++ using the following command:

g++ main.cpp hmac.cpp ../../Hash/SHA/SHA-2/SHA-256/sha-256.cpp ../../Encoders/Hex/encoder.cpp -o main


Petter Solnoer - 15/04/2020
/////////////////////////////////////////////////
