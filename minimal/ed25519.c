#ifndef CRYPTO_NAMESPACE
#define CRYPTO_NAMESPACE(s) s
#endif

#include "api.h"
#include "fe_0.c"
#include "fe_1.c"
#include "fe_add.c"
#include "fe_cmov.c"
#include "fe_copy.c"
#include "fe_cswap.c"
#include "fe_frombytes.c"
#include "fe_invert.c"
#include "fe_isnonzero.c"
#include "fe_isnegative.c"
#include "fe_mul.c"
#include "fe_mul121666.c"
#include "fe_neg.c"
#include "fe_pow22523.c"
#include "fe_sq.c"
#include "fe_sq2.c"
#include "fe_sub.c"
#include "fe_tobytes.c"
#include "ge_add.c"
#include "ge_double_scalarmult.c"
#include "ge_frombytes.c"
#include "ge_madd.c"
#include "ge_msub.c"
#include "ge_p1p1_to_p2.c"
#include "ge_p1p1_to_p3.c"
#include "ge_p2_0.c"
#include "ge_p2_dbl.c"
#include "ge_p3_dbl.c"
#include "ge_p3_0.c"
#include "ge_p3_to_cached.c"
#include "ge_p3_to_p2.c"
#include "ge_p3_tobytes.c"
#include "ge_precomp_0.c"
#include "ge_scalarmult_base.c"
#include "ge_sub.c"
#include "ge_tobytes.c"
#undef load_3
#undef load_4
#define load_3 load_3_muladd
#define load_4 load_4_muladd
#include "sc_muladd.c"
#undef load_3
#undef load_4
#define load_3 load_3_reduce
#define load_4 load_4_reduce
#include "sc_reduce.c"
#include "keypair.c"
#include "open.c"
#include "scalarmult.c"
#include "sign.c"
#include "base.c"
