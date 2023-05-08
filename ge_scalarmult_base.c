#include "ge.h"
#include "crypto_uint32.h"

/* Packed coordinates of the base point */
static const unsigned char ge25519_base_x[32] = {0x1A, 0xD5, 0x25, 0x8F, 0x60, 0x2D, 0x56, 0xC9, 0xB2, 0xA7, 0x25, 0x95, 0x60, 0xC7, 0x2C, 0x69,
                                                 0x5C, 0xDC, 0xD6, 0xFD, 0x31, 0xE2, 0xA4, 0xC0, 0xFE, 0x53, 0x6E, 0xCD, 0xD3, 0x36, 0x69, 0x21};
static const unsigned char ge25519_base_y[32] = {0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
                                                 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
static const unsigned char ge25519_base_z[32] = {1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static const unsigned char ge25519_base_t[32] = {0xA3, 0xDD, 0xB7, 0xA5, 0xB3, 0x8A, 0xDE, 0x6D, 0xF5, 0x52, 0x51, 0x77, 0x80, 0x9F, 0xF0, 0x20,
                                                 0x7D, 0xE3, 0xAB, 0x64, 0x8E, 0x4E, 0xEA, 0x66, 0x65, 0x76, 0x8B, 0xD7, 0x0F, 0x5F, 0x87, 0x67};

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

/* Constant-time version of: if(b) r = p */
static void cmov_p3(ge_p3 *r,const ge_p3 *p,unsigned char b)
{
  fe_cmov(r->X,p->X,b);
  fe_cmov(r->Y,p->Y,b);
  fe_cmov(r->Z,p->Z,b);
  fe_cmov(r->T,p->T,b);
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
    t = neutral;
    cmov_p3(&t,p,(s[i/8]>>(i&7))&1);
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
  ge_p3 base;
  fe_frombytes(base.X, ge25519_base_x);
  fe_frombytes(base.Y, ge25519_base_y);
  fe_frombytes(base.Z, ge25519_base_z);
  fe_frombytes(base.T, ge25519_base_t);
  ge_scalarmult(h,&base,a);
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
