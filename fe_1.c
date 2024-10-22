#include "fe.h"

/*
h = 1
*/

void fe_1(fe h)
{
#if CRYPTO_SHRINK
  int i;

  h[0] = 1;

  for (i = 1;i < 10;++i)
    h[i] = 0;
#else
  h[0] = 1;
  h[1] = 0;
  h[2] = 0;
  h[3] = 0;
  h[4] = 0;
  h[5] = 0;
  h[6] = 0;
  h[7] = 0;
  h[8] = 0;
  h[9] = 0;
#endif
}
