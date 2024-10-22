#ifndef crypto_verify_32_h
#define crypto_verify_32_h

#include <string.h>
#define crypto_verify_32(a,b) (memcmp(a,b,32) ? 1 : 0)

#endif
