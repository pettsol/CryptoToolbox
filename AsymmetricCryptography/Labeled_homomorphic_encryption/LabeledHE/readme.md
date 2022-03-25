************************************************************************

This is an implementation of a symmetric-key variant of the labeled 
homomorphic encryption scheme with the Joye-Libert cryptosystem
serving the role as the underlying additively homomorphic
cryptosystem.

A description of the labeled homomorphic cryptosystem can be found in
the following article:

Barbosa M., Catalano D., Fiore D. (2017) Labeled Homomorphic Encryption. In: Foley S., Gollmann D., Snekkenes E. (eds) Computer Security – ESORICS 2017. ESORICS 2017. Lecture Notes in Computer Science, vol 10492. Springer, Cham. https://doi.org/10.1007/978-3-319-66402-6_10

Using g++, a sample program can be compiled using:

g++ main.cpp labeled_he.cpp ../../Joye_libert/joye_libert.cpp ../../../StreamCiphers/HC-128/hc128.cpp -o main -lgmp

Petter Solnoer - 25/03/22
**************************************************************************
