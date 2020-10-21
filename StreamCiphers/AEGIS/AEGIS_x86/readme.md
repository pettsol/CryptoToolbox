*********************************************************

This is an implementation of the AEGIS authenticated
encryption algorithm. This particular variant uses
the x86 AES operations.

Run the test_vectors program to verify that the
algorithm produce the expected results on your
system.

Compile test_vectors using:

g++ test_vectors.cpp aegis_128.cpp ../../../Encoders/Hex/encoder.cpp -o test_vectors -D x86_INTRINSICS -march=native

Run test_vectors using ./test_vectors

Compile sample_program using:

g++ main.cpp aegis_128.cpp ../../../Encoders/Hex/encoder.cpp -o main -D x86_INTRINSICS -march=native

Run sample program using ./main

Petter Solnoer 26/08/20

**********************************************************
