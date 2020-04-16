///////////////////////////////////////////////

This folder contain an implementation of the 
HC-128 stream cipher. The stream cipher 
documentation was submitted to eStream and is 
currently part of the software-oriented stream 
cipher portfolio.

The stream cipher requres a 128-bit key
and a 128-bit initialization vector (IV) as
inputs. The key and IV is then thoroughly
mixed to deduce an initial state of the cipher.
The state of the cipher consists of the two
substitution tables P and Q.

Following the initialization phase of the cipher,
the cipher proceeds to the keystream generation
phase. During the keystream generation phase,
each iteration produces a 32-bit keystream as
output while continuously updating the state
of the cipher.

Because the initialization phase of the cipher is
time consuming, the HC-128 stream cipher should
be reserved for bulk encryption of larger samples
of data.

This implementation is provided as-is, with no
known backdoors. The implementation has been
verified with official test vectors. The
implementation does not at the time of this
writing incorporate all optimization techniques
mentioned in the cipher documentation.

Compile the sample program with g++ using the 
following command:

g++ main.cpp hc128.cpp ../HexEncoder/encoder.cpp -o main


Petter Solnoer - 16/04/2020
/////////////////////////////////////////////////
