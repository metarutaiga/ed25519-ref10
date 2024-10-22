#ifndef crypto_int8_h
#define crypto_int8_h

#include <inttypes.h>
#define crypto_int8 int8_t

#define crypto_int8_bitmod_01(x, y) (1 & (x >> (y & 7)))
#define crypto_int8_bitmod_mask(x, y) (-crypto_int8_bitmod_01(x, y)) 

#endif
