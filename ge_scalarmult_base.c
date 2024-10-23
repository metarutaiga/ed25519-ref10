#include "ge.h"
#include "crypto_uint32.h"

/* Packed coordinates of the base point */
static const ge_p3 ge25519_base = {
  { -14297830, -7645148, 16144683, -16471763, 27570974, -2696100, -26142465, 8378389, 20764389, 8758491 },
  { -26843541, -6710886, 13421773, -13421773, 26843546, 6710886, -13421773, 13421773, -26843546, -6710886 },
  { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
  { 28827062, -6116119, -27349572, 244363, 8635006, 11264893, 19351346, 13413597, 16611511, -6414980 },
};

static unsigned char equal(signed char b,signed char c)
{
  unsigned char ub = b;
  unsigned char uc = c;
  unsigned char x = ub ^ uc; /* 0: yes; 1..255: no */
  crypto_uint32 y = x; /* 0: yes; 1..255: no */
  y -= 1; /* 4294967295: yes; 0..254: no */
  y >>= 31; /* 1: yes; 0: no */
  return y;
}

static unsigned char negative(signed char b)
{
  unsigned long long x = b; /* 18446744073709551361..18446744073709551615: yes; 0..255: no */
  x >>= 63; /* 1: yes; 0: no */
  return x;
}

/* Constant-time version of: r = b ? p : q */
static void cmov_p3(ge_p3 *r,const ge_p3 *p,const ge_p3 *q,unsigned char b)
{
  fe_copy(r->X,b?p->X:q->X);
  fe_copy(r->Y,b?p->Y:q->Y);
  fe_copy(r->Z,b?p->Z:q->Z);
  fe_copy(r->T,b?p->T:q->T);
}

static void cmov(ge_precomp *t,const ge_precomp *u,unsigned char b)
{
  fe_cmov(t->yplusx,u->yplusx,b);
  fe_cmov(t->yminusx,u->yminusx,b);
  fe_cmov(t->xy2d,u->xy2d,b);
}

/* base[i][j] = (j+1)*256^i*B */
static const ge_precomp base[32][8] = {
#include "base.h"
} ;

static void select(ge_precomp *t,int pos,signed char b)
{
  ge_precomp minust;
  unsigned char bnegative = negative(b);
  unsigned char babs = b - (((-bnegative) & b) << 1);

  ge_precomp_0(t);
  cmov(t,&base[pos][0],equal(babs,1));
  cmov(t,&base[pos][1],equal(babs,2));
  cmov(t,&base[pos][2],equal(babs,3));
  cmov(t,&base[pos][3],equal(babs,4));
  cmov(t,&base[pos][4],equal(babs,5));
  cmov(t,&base[pos][5],equal(babs,6));
  cmov(t,&base[pos][6],equal(babs,7));
  cmov(t,&base[pos][7],equal(babs,8));
  fe_copy(minust.yplusx,t->yminusx);
  fe_copy(minust.yminusx,t->yplusx);
  fe_neg(minust.xy2d,t->xy2d);
  cmov(t,&minust,bnegative);
}

/*
h = a * B
where a = a[0]+256*a[1]+...+256^31 a[31]
B is the Ed25519 base point (x,4/5) with x positive.

Preconditions:
  a[31] <= 127
*/

static void ge_scalarmult(ge_p3 *r,const ge_p3 *p,const unsigned char *s)
{
  int i;

  ge_p3 neutral;
  ge_p3 t;
  ge_cached tc;
  ge_p1p1 tp1p1;

  // Precomputation
  ge_p3_0(&neutral);
  *r = neutral;

  // Scalar multiplication
  for(i=255;i>=0;--i)
  {
    ge_p2_dbl(&tp1p1,(ge_p2 *)r);
    ge_p1p1_to_p3(r,&tp1p1);
    cmov_p3(&t,p,&neutral,(s[i/8]>>(i&7))&1);
    ge_p3_to_cached(&tc,&t);
    ge_add(&tp1p1,r,&tc);
    if((i&7)!=0) ge_p1p1_to_p2((ge_p2 *)r,&tp1p1);
    else ge_p1p1_to_p3(r,&tp1p1); /* convert to p3 representation at the end */
  }
}

void ge_scalarmult_base(ge_p3 *h,const unsigned char *a)
{
#if CRYPTO_SHRINK
  /* XXX: Better algorithm for known-base-point scalar multiplication */
  ge_scalarmult(h,&ge25519_base,a);
#else
  signed char e[64];
  signed char carry;
  ge_p1p1 r;
  ge_p2 s;
  ge_precomp t;
  int i;

  for (i = 0;i < 32;++i) {
    e[2 * i + 0] = (a[i] >> 0) & 15;
    e[2 * i + 1] = (a[i] >> 4) & 15;
  }
  /* each e[i] is between 0 and 15 */
  /* e[63] is between 0 and 7 */

  carry = 0;
  for (i = 0;i < 63;++i) {
    e[i] += carry;
    carry = e[i] + 8;
    carry >>= 4;
    e[i] -= carry << 4;
  }
  e[63] += carry;
  /* each e[i] is between -8 and 8 */

  ge_p3_0(h);
  for (i = 1;i < 64;i += 2) {
    select(&t,i / 2,e[i]);
    ge_madd(&r,h,&t); ge_p1p1_to_p3(h,&r);
  }

  ge_p3_dbl(&r,h);  ge_p1p1_to_p2(&s,&r);
  ge_p2_dbl(&r,&s); ge_p1p1_to_p2(&s,&r);
  ge_p2_dbl(&r,&s); ge_p1p1_to_p2(&s,&r);
  ge_p2_dbl(&r,&s); ge_p1p1_to_p3(h,&r);

  for (i = 0;i < 64;i += 2) {
    select(&t,i / 2,e[i]);
    ge_madd(&r,h,&t); ge_p1p1_to_p3(h,&r);
  }
#endif
}
