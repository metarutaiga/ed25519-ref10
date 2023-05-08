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
  a[0]+256*a[1]+...+256^31*a[31] = a
  b[0]+256*b[1]+...+256^31*b[31] = b
  c[0]+256*c[1]+...+256^31*c[31] = c

Output:
  s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
  where l = 2^252 + 27742317777372353535851937790883648493.
*/

void sc_muladd(unsigned char *s,const unsigned char *a,const unsigned char *b,const unsigned char *c)
{
  crypto_int64 a0 = 2097151 & load_3(a);
  crypto_int64 a1 = 2097151 & (load_4(a + 2) >> 5);
  crypto_int64 a2 = 2097151 & (load_3(a + 5) >> 2);
  crypto_int64 a3 = 2097151 & (load_4(a + 7) >> 7);
  crypto_int64 a4 = 2097151 & (load_4(a + 10) >> 4);
  crypto_int64 a5 = 2097151 & (load_3(a + 13) >> 1);
  crypto_int64 a6 = 2097151 & (load_4(a + 15) >> 6);
  crypto_int64 a7 = 2097151 & (load_3(a + 18) >> 3);
  crypto_int64 a8 = 2097151 & load_3(a + 21);
  crypto_int64 a9 = 2097151 & (load_4(a + 23) >> 5);
  crypto_int64 a10 = 2097151 & (load_3(a + 26) >> 2);
  crypto_int64 a11 = (load_4(a + 28) >> 7);
  crypto_int64 b0 = 2097151 & load_3(b);
  crypto_int64 b1 = 2097151 & (load_4(b + 2) >> 5);
  crypto_int64 b2 = 2097151 & (load_3(b + 5) >> 2);
  crypto_int64 b3 = 2097151 & (load_4(b + 7) >> 7);
  crypto_int64 b4 = 2097151 & (load_4(b + 10) >> 4);
  crypto_int64 b5 = 2097151 & (load_3(b + 13) >> 1);
  crypto_int64 b6 = 2097151 & (load_4(b + 15) >> 6);
  crypto_int64 b7 = 2097151 & (load_3(b + 18) >> 3);
  crypto_int64 b8 = 2097151 & load_3(b + 21);
  crypto_int64 b9 = 2097151 & (load_4(b + 23) >> 5);
  crypto_int64 b10 = 2097151 & (load_3(b + 26) >> 2);
  crypto_int64 b11 = (load_4(b + 28) >> 7);
  crypto_int64 c0 = 2097151 & load_3(c);
  crypto_int64 c1 = 2097151 & (load_4(c + 2) >> 5);
  crypto_int64 c2 = 2097151 & (load_3(c + 5) >> 2);
  crypto_int64 c3 = 2097151 & (load_4(c + 7) >> 7);
  crypto_int64 c4 = 2097151 & (load_4(c + 10) >> 4);
  crypto_int64 c5 = 2097151 & (load_3(c + 13) >> 1);
  crypto_int64 c6 = 2097151 & (load_4(c + 15) >> 6);
  crypto_int64 c7 = 2097151 & (load_3(c + 18) >> 3);
  crypto_int64 c8 = 2097151 & load_3(c + 21);
  crypto_int64 c9 = 2097151 & (load_4(c + 23) >> 5);
  crypto_int64 c10 = 2097151 & (load_3(c + 26) >> 2);
  crypto_int64 c11 = (load_4(c + 28) >> 7);
  crypto_int64 t[24];
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
  crypto_int64 carry10;
  crypto_int64 carry11;
  crypto_int64 carry12;
  crypto_int64 carry13;
  crypto_int64 carry14;
  crypto_int64 carry15;
  crypto_int64 carry16;
  crypto_int64 carry17;
  crypto_int64 carry18;
  crypto_int64 carry19;
  crypto_int64 carry20;
  crypto_int64 carry21;
  crypto_int64 carry22;

  t[0] = c0 + a0*b0;
  t[1] = c1 + a0*b1 + a1*b0;
  t[2] = c2 + a0*b2 + a1*b1 + a2*b0;
  t[3] = c3 + a0*b3 + a1*b2 + a2*b1 + a3*b0;
  t[4] = c4 + a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0;
  t[5] = c5 + a0*b5 + a1*b4 + a2*b3 + a3*b2 + a4*b1 + a5*b0;
  t[6] = c6 + a0*b6 + a1*b5 + a2*b4 + a3*b3 + a4*b2 + a5*b1 + a6*b0;
  t[7] = c7 + a0*b7 + a1*b6 + a2*b5 + a3*b4 + a4*b3 + a5*b2 + a6*b1 + a7*b0;
  t[8] = c8 + a0*b8 + a1*b7 + a2*b6 + a3*b5 + a4*b4 + a5*b3 + a6*b2 + a7*b1 + a8*b0;
  t[9] = c9 + a0*b9 + a1*b8 + a2*b7 + a3*b6 + a4*b5 + a5*b4 + a6*b3 + a7*b2 + a8*b1 + a9*b0;
  t[10] = c10 + a0*b10 + a1*b9 + a2*b8 + a3*b7 + a4*b6 + a5*b5 + a6*b4 + a7*b3 + a8*b2 + a9*b1 + a10*b0;
  t[11] = c11 + a0*b11 + a1*b10 + a2*b9 + a3*b8 + a4*b7 + a5*b6 + a6*b5 + a7*b4 + a8*b3 + a9*b2 + a10*b1 + a11*b0;
  t[12] = a1*b11 + a2*b10 + a3*b9 + a4*b8 + a5*b7 + a6*b6 + a7*b5 + a8*b4 + a9*b3 + a10*b2 + a11*b1;
  t[13] = a2*b11 + a3*b10 + a4*b9 + a5*b8 + a6*b7 + a7*b6 + a8*b5 + a9*b4 + a10*b3 + a11*b2;
  t[14] = a3*b11 + a4*b10 + a5*b9 + a6*b8 + a7*b7 + a8*b6 + a9*b5 + a10*b4 + a11*b3;
  t[15] = a4*b11 + a5*b10 + a6*b9 + a7*b8 + a8*b7 + a9*b6 + a10*b5 + a11*b4;
  t[16] = a5*b11 + a6*b10 + a7*b9 + a8*b8 + a9*b7 + a10*b6 + a11*b5;
  t[17] = a6*b11 + a7*b10 + a8*b9 + a9*b8 + a10*b7 + a11*b6;
  t[18] = a7*b11 + a8*b10 + a9*b9 + a10*b8 + a11*b7;
  t[19] = a8*b11 + a9*b10 + a10*b9 + a11*b8;
  t[20] = a9*b11 + a10*b10 + a11*b9;
  t[21] = a10*b11 + a11*b10;
  t[22] = a11*b11;
  t[23] = 0;
#if CRYPTO_SHRINK
  sc_reduce_carry(t, 12, 11);
#else
  carry0 = (t[0] + (1<<20)) >> 21; t[1] += carry0; t[0] -= carry0 << 21;
  carry2 = (t[2] + (1<<20)) >> 21; t[3] += carry2; t[2] -= carry2 << 21;
  carry4 = (t[4] + (1<<20)) >> 21; t[5] += carry4; t[4] -= carry4 << 21;
  carry6 = (t[6] + (1<<20)) >> 21; t[7] += carry6; t[6] -= carry6 << 21;
  carry8 = (t[8] + (1<<20)) >> 21; t[9] += carry8; t[8] -= carry8 << 21;
  carry10 = (t[10] + (1<<20)) >> 21; t[11] += carry10; t[10] -= carry10 << 21;
  carry12 = (t[12] + (1<<20)) >> 21; t[13] += carry12; t[12] -= carry12 << 21;
  carry14 = (t[14] + (1<<20)) >> 21; t[15] += carry14; t[14] -= carry14 << 21;
  carry16 = (t[16] + (1<<20)) >> 21; t[17] += carry16; t[16] -= carry16 << 21;
  carry18 = (t[18] + (1<<20)) >> 21; t[19] += carry18; t[18] -= carry18 << 21;
  carry20 = (t[20] + (1<<20)) >> 21; t[21] += carry20; t[20] -= carry20 << 21;
  carry22 = (t[22] + (1<<20)) >> 21; t[23] += carry22; t[22] -= carry22 << 21;

  carry1 = (t[1] + (1<<20)) >> 21; t[2] += carry1; t[1] -= carry1 << 21;
  carry3 = (t[3] + (1<<20)) >> 21; t[4] += carry3; t[3] -= carry3 << 21;
  carry5 = (t[5] + (1<<20)) >> 21; t[6] += carry5; t[5] -= carry5 << 21;
  carry7 = (t[7] + (1<<20)) >> 21; t[8] += carry7; t[7] -= carry7 << 21;
  carry9 = (t[9] + (1<<20)) >> 21; t[10] += carry9; t[9] -= carry9 << 21;
  carry11 = (t[11] + (1<<20)) >> 21; t[12] += carry11; t[11] -= carry11 << 21;
  carry13 = (t[13] + (1<<20)) >> 21; t[14] += carry13; t[13] -= carry13 << 21;
  carry15 = (t[15] + (1<<20)) >> 21; t[16] += carry15; t[15] -= carry15 << 21;
  carry17 = (t[17] + (1<<20)) >> 21; t[18] += carry17; t[17] -= carry17 << 21;
  carry19 = (t[19] + (1<<20)) >> 21; t[20] += carry19; t[19] -= carry19 << 21;
  carry21 = (t[21] + (1<<20)) >> 21; t[22] += carry21; t[21] -= carry21 << 21;
#endif
  sc_reduce_internal(s, t);
}
