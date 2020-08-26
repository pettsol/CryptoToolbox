#include "poly1305.h"

#include <iostream>

void poly1305_mac(u8 *tag, u8 *msg, u8 *key, u8 *msglen)
{
	u8 r[16];
	le_bytes_to_num(r, key);
	clamp(r);
	u8 s[16];
	le_bytes_to_num(s, key[16]);
	u32 accumulator = 0;
	

}
