*********************************************************

This is an implementation of the AEGIS authenticated
encryption algorithm. This particular variant uses
the ARM AES operations.

Run the test_vectors program to verify that the
algorithm produce the expected results on your
system.

Compile test_vectors using:

g++ test_vectors.cpp aegis_128.cpp ../HexEncoder/encoder.cpp -o test_vectors -march=armv8-a+crypto -D ARM_INTRINSICS

Run test_vectors using ./test_vectors

Compile sample_program using:

g++ main.cpp aegis_128.cpp ../HexEncoder/encoder.cpp -o main test_vectors -march=armv8-a+crypto -D ARM_INTRINSICS

Run sample program using ./main

Petter Solnoer 26/08/20

**********************************************************
