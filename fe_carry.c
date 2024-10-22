#include "fe.h"
#include "crypto_int64.h"

void fe_carry(fe s,crypto_int64 *h)
{
#if CRYPTO_SHRINK
  int i;
#endif
  crypto_int64 carry0;
  crypto_int64 carry1;
  crypto_int64 carry2;
  crypto_int64 carry3;
  crypto_int64 carry4;
  crypto_int64 carry5;
  crypto_int64 carry6;
  crypto_int64 carry7;
  crypto_int64 carry8;
  crypto_int64 carry9;

  /*
  |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
    i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
  |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
    i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
  */

  carry0 = (h[0] + (crypto_int64) (1<<25)) >> 26; h[1] += carry0; h[0] -= carry0 << 26;
  carry4 = (h[4] + (crypto_int64) (1<<25)) >> 26; h[5] += carry4; h[4] -= carry4 << 26;
  /* |h0| <= 2^25 */
  /* |h4| <= 2^25 */
  /* |h1| <= 1.71*2^59 */
  /* |h5| <= 1.71*2^59 */

  carry1 = (h[1] + (crypto_int64) (1<<24)) >> 25; h[2] += carry1; h[1] -= carry1 << 25;
  carry5 = (h[5] + (crypto_int64) (1<<24)) >> 25; h[6] += carry5; h[5] -= carry5 << 25;
  /* |h1| <= 2^24; from now on fits into int32 */
  /* |h5| <= 2^24; from now on fits into int32 */
  /* |h2| <= 1.41*2^60 */
  /* |h6| <= 1.41*2^60 */

  carry2 = (h[2] + (crypto_int64) (1<<25)) >> 26; h[3] += carry2; h[2] -= carry2 << 26;
  carry6 = (h[6] + (crypto_int64) (1<<25)) >> 26; h[7] += carry6; h[6] -= carry6 << 26;
  /* |h2| <= 2^25; from now on fits into int32 unchanged */
  /* |h6| <= 2^25; from now on fits into int32 unchanged */
  /* |h3| <= 1.71*2^59 */
  /* |h7| <= 1.71*2^59 */

  carry3 = (h[3] + (crypto_int64) (1<<24)) >> 25; h[4] += carry3; h[3] -= carry3 << 25;
  carry7 = (h[7] + (crypto_int64) (1<<24)) >> 25; h[8] += carry7; h[7] -= carry7 << 25;
  /* |h3| <= 2^24; from now on fits into int32 unchanged */
  /* |h7| <= 2^24; from now on fits into int32 unchanged */
  /* |h4| <= 1.72*2^34 */
  /* |h8| <= 1.41*2^60 */

  carry4 = (h[4] + (crypto_int64) (1<<25)) >> 26; h[5] += carry4; h[4] -= carry4 << 26;
  carry8 = (h[8] + (crypto_int64) (1<<25)) >> 26; h[9] += carry8; h[8] -= carry8 << 26;
  /* |h4| <= 2^25; from now on fits into int32 unchanged */
  /* |h8| <= 2^25; from now on fits into int32 unchanged */
  /* |h5| <= 1.01*2^24 */
  /* |h9| <= 1.71*2^59 */

  carry9 = (h[9] + (crypto_int64) (1<<24)) >> 25; h[0] += carry9 * 19; h[9] -= carry9 << 25;
  /* |h9| <= 2^24; from now on fits into int32 unchanged */
  /* |h0| <= 1.1*2^39 */

  carry0 = (h[0] + (crypto_int64) (1<<25)) >> 26; h[1] += carry0; h[0] -= carry0 << 26;
  /* |h0| <= 2^25; from now on fits into int32 unchanged */
  /* |h1| <= 1.01*2^24 */

#if CRYPTO_SHRINK
  for (i = 0;i < 10;++i)
    s[i] = h[i];
#else
  s[0] = h[0];
  s[1] = h[1];
  s[2] = h[2];
  s[3] = h[3];
  s[4] = h[4];
  s[5] = h[5];
  s[6] = h[6];
  s[7] = h[7];
  s[8] = h[8];
  s[9] = h[9];
#endif
}
