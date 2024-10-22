#include "sc.h"
#include "crypto_int64.h"
#include "crypto_uint32.h"
#include "crypto_uint64.h"

static crypto_uint64 load_3(const unsigned char *in)
{
  crypto_uint64 result;
  result = (crypto_uint64) in[0];
  result |= ((crypto_uint64) in[1]) << 8;
  result |= ((crypto_uint64) in[2]) << 16;
  return result;
}

static crypto_uint64 load_4(const unsigned char *in)
{
  crypto_uint64 result;
  result = (crypto_uint64) in[0];
  result |= ((crypto_uint64) in[1]) << 8;
  result |= ((crypto_uint64) in[2]) << 16;
  result |= ((crypto_uint64) in[3]) << 24;
  return result;
}

/*
Input:
  s[0]+256*s[1]+...+256^63*s[63] = s

Output:
  s[0]+256*s[1]+...+256^31*s[31] = s mod l
  where l = 2^252 + 27742317777372353535851937790883648493.
  Overwrites s in place.
*/

void sc_reduce(unsigned char *s)
{
  crypto_int64 t[24];
  t[0] = 2097151 & load_3(s);
  t[1] = 2097151 & (load_4(s + 2) >> 5);
  t[2] = 2097151 & (load_3(s + 5) >> 2);
  t[3] = 2097151 & (load_4(s + 7) >> 7);
  t[4] = 2097151 & (load_4(s + 10) >> 4);
  t[5] = 2097151 & (load_3(s + 13) >> 1);
  t[6] = 2097151 & (load_4(s + 15) >> 6);
  t[7] = 2097151 & (load_3(s + 18) >> 3);
  t[8] = 2097151 & load_3(s + 21);
  t[9] = 2097151 & (load_4(s + 23) >> 5);
  t[10] = 2097151 & (load_3(s + 26) >> 2);
  t[11] = 2097151 & (load_4(s + 28) >> 7);
  t[12] = 2097151 & (load_4(s + 31) >> 4);
  t[13] = 2097151 & (load_3(s + 34) >> 1);
  t[14] = 2097151 & (load_4(s + 36) >> 6);
  t[15] = 2097151 & (load_3(s + 39) >> 3);
  t[16] = 2097151 & load_3(s + 42);
  t[17] = 2097151 & (load_4(s + 44) >> 5);
  t[18] = 2097151 & (load_3(s + 47) >> 2);
  t[19] = 2097151 & (load_4(s + 49) >> 7);
  t[20] = 2097151 & (load_4(s + 52) >> 4);
  t[21] = 2097151 & (load_3(s + 55) >> 1);
  t[22] = 2097151 & (load_4(s + 57) >> 6);
  t[23] = (load_4(s + 60) >> 3);
  sc_reduce_internal(s, t);
}
