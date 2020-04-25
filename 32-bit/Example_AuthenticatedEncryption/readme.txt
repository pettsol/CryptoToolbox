//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Compile the authenticated encryption
example with the following command:

g++ example_ae.cpp ../AES/AES_CFB_Carry-Over/aes_cfb.cpp ../Authentication/HMAC-SHA-256/hmac.cpp ../SHA/SHA-2/SHA-256/sha-256.cpp ../HexEncoder/encoder.cpp ../StreamCiphers/HC-128/hc128.cpp -o example_ae

NOTE: HC128 could be replaced with Sosemanuk if needed.

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
