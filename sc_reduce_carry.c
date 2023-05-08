#include "sc.h"
#include "crypto_int64.h"

void sc_reduce_carry(crypto_int64 *s, int c, int d)
{
  int i,j;
  crypto_int64 carry;

  for (j = 0;j < 2;++j)
  {
    for (i = 0;i < c;++i)
    {
      carry = (s[i*2] + (1<<20)) >> 21;
      s[i*2+1] += carry;
      s[i*2] -= carry << 21;
    }
    s++;
    c = d;
  }
}
