// 20240806 djb: some automated conversion to cryptoint
#include "ge.h"
#include "crypto_int8.h"

static void slide(signed char *r,const unsigned char *a)
{
  int i;
  int b;
  int k;

  for (i = 0;i < 256;++i)
    r[i] = crypto_int8_bitmod_01(a[i >> 3],i);

  for (i = 0;i < 256;++i)
    if (r[i]) {
      for (b = 1;b <= 6 && i + b < 256;++b) {
        if (r[i + b]) {
          if (r[i] + (r[i + b] << b) <= 15) {
            r[i] += r[i + b] << b; r[i + b] = 0;
          } else if (r[i] - (r[i + b] << b) >= -15) {
            r[i] -= r[i + b] << b;
            for (k = i + b;k < 256;++k) {
              if (!r[k]) {
                r[k] = 1;
                break;
              }
              r[k] = 0;
            }
          } else
            break;
        }
      }
    }

}

static const ge_precomp Bi[8] = {
#include "base2.h"
} ;

/*
r = a * A + b * B
where a = a[0]+256*a[1]+...+256^31 a[31].
and b = b[0]+256*b[1]+...+256^31 b[31].
B is the Ed25519 base point (x,4/5) with x positive.
*/

void ge_double_scalarmult_vartime(ge_p2 *r,const unsigned char *a,const ge_p3 *A,const unsigned char *b)
{
#if CRYPTO_SHRINK
  ge_p3 ta;
  ge_p3 tb;
  ge_cached tc;
  ge_p1p1 tp1p1;

  ge_scalarmult(&ta,A,a);
  ge_scalarmult_base(&tb,b);
  ge_p3_to_cached(&tc,&tb);
  ge_add(&tp1p1,&ta,&tc);
  ge_p1p1_to_p2(r,&tp1p1);
#else
  signed char aslide[256];
  signed char bslide[256];
  ge_cached Ai[8]; /* A,3A,5A,7A,9A,11A,13A,15A */
  ge_p1p1 t;
  ge_p3 u;
  ge_p3 A2;
  int i;

  slide(aslide,a);
  slide(bslide,b);

  ge_p3_to_cached(&Ai[0],A);
  ge_p3_dbl(&t,A); ge_p1p1_to_p3(&A2,&t);
  ge_add(&t,&A2,&Ai[0]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[1],&u);
  ge_add(&t,&A2,&Ai[1]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[2],&u);
  ge_add(&t,&A2,&Ai[2]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[3],&u);
  ge_add(&t,&A2,&Ai[3]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[4],&u);
  ge_add(&t,&A2,&Ai[4]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[5],&u);
  ge_add(&t,&A2,&Ai[5]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[6],&u);
  ge_add(&t,&A2,&Ai[6]); ge_p1p1_to_p3(&u,&t); ge_p3_to_cached(&Ai[7],&u);

  ge_p2_0(r);

  for (i = 255;i >= 0;--i) {
    if (aslide[i] || bslide[i]) break;
  }

  for (;i >= 0;--i) {
    ge_p2_dbl(&t,r);

    if (aslide[i] > 0) {
      ge_p1p1_to_p3(&u,&t);
      ge_add(&t,&u,&Ai[aslide[i]/2]);
    } else if (aslide[i] < 0) {
      ge_p1p1_to_p3(&u,&t);
      ge_sub(&t,&u,&Ai[(-aslide[i])/2]);
    }

    if (bslide[i] > 0) {
      ge_p1p1_to_p3(&u,&t);
      ge_madd(&t,&u,&Bi[bslide[i]/2]);
    } else if (bslide[i] < 0) {
      ge_p1p1_to_p3(&u,&t);
      ge_msub(&t,&u,&Bi[(-bslide[i])/2]);
    }

    ge_p1p1_to_p2(r,&t);
  }
#endif
}
