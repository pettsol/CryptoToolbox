//////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Compile the authenticated encryption
example with the following command:

g++ example_ae.cpp ../BlockCiphers/AES/AES/AES_CFB/aes_cfb.cpp ../Authentication/HMAC-SHA-256/hmac.cpp ../Hash/SHA/SHA-2/SHA-256/sha-256.cpp ../Encoders/Hex/encoder.cpp ../StreamCiphers/HC-128/hc128.cpp -o example_ae

NOTE: HC128 could be replaced with Sosemanuk if needed.

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
