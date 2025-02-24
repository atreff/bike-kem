/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 *
 * The inversion algorithm in this file is based on:
 * [1] Nir Drucker, Shay Gueron, and Dusan Kostic. 2020. "Fast polynomial
 * inversion for post quantum QC-MDPC cryptography". Cryptology ePrint Archive,
 * 2020. https://eprint.iacr.org/2020/298.pdf
 */

#include "cleanup.h"
#include "gf2x.h"
#include "gf2x_internal.h"

// a = a^2 mod (x^r - 1)
_INLINE_ void gf2x_mod_sqr_in_place(IN OUT pad_r_t *a,
                                    OUT dbl_pad_r_t *secure_buffer,
                                    IN const gf2x_ctx *ctx)
{
  ctx->sqr(secure_buffer, a);
  ctx->red(a, secure_buffer);
}

// c = a^2^2^num_sqrs
_INLINE_ void repeated_squaring(OUT pad_r_t *c,
                                IN pad_r_t *    a,
                                IN const size_t num_sqrs,
                                OUT dbl_pad_r_t *sec_buf,
                                IN const gf2x_ctx *ctx)
{
  c->val = a->val;

  for(size_t i = 0; i < num_sqrs; i++) {
    gf2x_mod_sqr_in_place(c, sec_buf, ctx);
  }
}

// The gf2x_mod_inv function implements inversion in F_2[x]/(x^R - 1)
// based on [1](Algorithm 2).

// In every iteration, [1](Algorithm 2) performs two exponentiations:
// exponentiation 0 (exp0) and exponentiation 1 (exp1) of the form f^(2^k).
// These exponentiations are computed either by repeated squaring of f, k times,
// or by a single k-squaring of f. The method for a specific value of k
// is chosen based on the performance of squaring and k-squaring.
//
// Benchmarks on several platforms indicate that a good threshold
// for switching from repeated squaring to k-squaring is k = 64.
#define K_SQR_THR (64)

// k-squaring is computed by a permutation of bits of the input polynomial,
// as defined in [1](Observation 1). The required parameter for the permutation
// is l = (2^k)^-1 % R.
// Therefore, there are two sets of parameters for every exponentiation:
//   - exp0_k and exp1_k
//   - exp0_l and exp1_l

// Exponentiation 0 computes f^2^2^(i-1) for 0 < i < MAX_I.
// Exponentiation 1 computes f^2^((r-2) % 2^i) for 0 < i < MAX_I,
// only when the i-th bit of (r-2) is 1. Therefore, the value 0 in
// exp1_k[i] and exp1_l[i] means that exp1 is skipped in i-th iteration.

// To quickly generate all the required parameters in Sage:
//   r = DESIRED_R
//   max_i = floor(log(r-2, 2)) + 1
//   exp0_k = [2^i for i in range(max_i)]
//   exp0_l = [inverse_mod((2^k) % r, r) for k in exp0_k]
//   exp1_k = [(r-2)%(2^i) if ((r-2) & (1<<i)) else 0 for i in range(max_i)]
//   exp1_l = [inverse_mod((2^k) % r, r) if k != 0 else 0 for k in exp1_k]

#if(LEVEL == 0)
// The parameters below are hard-coded for R=2053
bike_static_assert((R_BITS == 2053), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define MAX_I (12)
#  define EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048
#  define EXP0_L_VALS                                                           \
    1027, 1540, 385, 409, 988, 969, 740, 1502, 1810, 1565, 2049, 16
#  define EXP1_K_VALS 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3
#  define EXP1_L_VALS 0, 1027, 0, 0, 0, 0, 0, 0, 0, 0, 0, 770

#elif(LEVEL == 10)
// The parameters below are hard-coded for R=7109
bike_static_assert((R_BITS == 7109), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define MAX_I (13)
#  define EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096
#  define EXP0_L_VALS                                                           \
    3555, 5332, 1333, 6748, 2359, 5643, 2238, 3908, 2332, 6948, 4594, 5324, 1393
#  define EXP1_K_VALS 0, 1, 0, 0, 0, 0, 3, 67, 195, 451, 0, 963, 3011
#  define EXP1_L_VALS 0, 3555, 0, 0, 0, 0, 2666, 2057, 5586, 2864, 0, 981, 4838

#elif(LEVEL == 11)
// The parameters below are hard-coded for R=773
bike_static_assert((R_BITS == 773), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define  MAX_I (10)
#  define  EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512
#  define  EXP0_L_VALS \
    387, 580, 145, 154, 526, 715, 272, 549, 704, 123
#  define  EXP1_K_VALS \
    0, 1, 0, 0, 0, 0, 0, 0, 3, 259
#  define  EXP1_L_VALS \
    0, 387, 0, 0, 0, 0, 0, 0, 290, 88

#elif(LEVEL == 12)
// The parameters below are hard-coded for R=1019
bike_static_assert((R_BITS == 1019), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define  MAX_I (10)
#  define  EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512
#  define  EXP0_L_VALS \
    510, 255, 828, 816, 449, 858, 446, 211, 704, 382
#  define  EXP1_K_VALS \
    0, 0, 0, 1, 9, 25, 57, 121, 249, 505
#  define  EXP1_L_VALS \
    0, 0, 0, 510, 408, 791, 24, 514, 440, 1003

#elif(LEVEL == 13)
// The parameters below are hard-coded for R=1283
bike_static_assert((R_BITS == 1283), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define  MAX_I (11)
#  define  EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024
#  define  EXP0_L_VALS \
    642, 321, 401, 426, 573, 1164, 48, 1021, 645, 333, 551
#  define  EXP1_K_VALS \
    0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 257
#  define  EXP1_L_VALS \
    0, 0, 0, 0, 0, 0, 0, 0, 642, 0, 964

#elif(LEVEL == 14)
// The parameters below are hard-coded for R=2029
bike_static_assert((R_BITS == 2029), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define  MAX_I (11)
#  define  EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024
#  define  EXP0_L_VALS \
    1015, 1522, 1395, 214, 1158, 1824, 1445, 184, 1392, 1998, 961
#  define  EXP1_K_VALS \
    0, 1, 0, 3, 0, 11, 43, 107, 235, 491, 1003
#  define  EXP1_L_VALS \
    0, 1015, 0, 761, 0, 534, 96, 748, 1689, 1506, 2010

#elif(LEVEL == 15)
// The parameters below are hard-coded for R=2053
bike_static_assert((R_BITS == 2053), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define  MAX_I (12)
#  define  EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048
#  define  EXP0_L_VALS \
    1027, 1540, 385, 409, 988, 969, 740, 1502, 1810, 1565, 2049, 16
#  define  EXP1_K_VALS \
    0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3
#  define  EXP1_L_VALS \
    0, 1027, 0, 0, 0, 0, 0, 0, 0, 0, 0, 770

#elif(LEVEL == 16)
// The parameters below are hard-coded for R=2069
bike_static_assert((R_BITS == 2069), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define  MAX_I (12)
#  define  EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048
#  define  EXP0_L_VALS \
    1035, 1552, 388, 1576, 976, 836, 1643, 1473, 1417, 959, 1045, 1662
#  define  EXP1_K_VALS \
    0, 1, 0, 0, 3, 0, 0, 0, 0, 0, 0, 19
#  define  EXP1_L_VALS \
    0, 1035, 0, 0, 776, 0, 0, 0, 0, 0, 0, 122

#elif(LEVEL == 17)
// The parameters below are hard-coded for R=4021
bike_static_assert((R_BITS == 4021), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define  MAX_I (12)
#  define  EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048
#  define  EXP0_L_VALS \
    2011, 3016, 754, 1555, 1404, 926, 1003, 759, 1078, 15, 225, 2373
#  define  EXP1_K_VALS \
    0, 1, 0, 0, 3, 19, 0, 51, 179, 435, 947, 1971
#  define  EXP1_L_VALS \
    0, 2011, 0, 0, 1508, 2186, 0, 1673, 3192, 3021, 1084, 2640

#elif(LEVEL == 18)
// The parameters below are hard-coded for R=4099
bike_static_assert((R_BITS == 4099), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define  MAX_I (13)
#  define  EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096
#  define  EXP0_L_VALS \
    2050, 1025, 1281, 1361, 3672, 1973, 2778, 2966, 702, 924, 1184, 4097, 4
#  define  EXP1_K_VALS \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
#  define  EXP1_L_VALS \
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2050

#elif(LEVEL == 1)
// The parameters below are hard-coded for R=12323
bike_static_assert((R_BITS == 12323), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define MAX_I (14)
#  define EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
#  define EXP0_L_VALS                                                           \
    6162, 3081, 3851, 5632, 22, 484, 119, 1838, 1742, 3106, 10650, 1608, 10157, \
      8816
#  define EXP1_K_VALS 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 33, 4129
#  define EXP1_L_VALS 0, 0, 0, 0, 0, 6162, 0, 0, 0, 0, 0, 0, 242, 5717

#else
// The parameters below are hard-coded for R=24659
bike_static_assert((R_BITS == 24659), gf2x_inv_r_doesnt_match_parameters);

// MAX_I = floor(log(r-2)) + 1
#  define MAX_I (15)
#  define EXP0_K_VALS \
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384
#  define EXP0_L_VALS                                                          \
    12330, 6165, 7706, 3564, 2711, 1139, 15053, 1258, 4388, 20524, 9538, 6393, \
      10486, 1715, 6804
#  define EXP1_K_VALS 0, 0, 0, 0, 1, 0, 17, 0, 0, 0, 0, 0, 0, 81, 8273
#  define EXP1_L_VALS 0, 0, 0, 0, 12330, 0, 13685, 0, 0, 0, 0, 0, 0, 23678, 19056

#endif

// Inversion in F_2[x]/(x^R - 1), [1](Algorithm 2).
// c = a^{-1} mod x^r-1
void gf2x_mod_inv(OUT pad_r_t *c, IN const pad_r_t *a)
{
  // Initialize gf2x methods struct
  gf2x_ctx ctx;
  gf2x_ctx_init(&ctx);

  // Note that exp0/1_k/l are predefined constants that depend only on the value
  // of R. This value is public. Therefore, branches in this function, which
  // depends on R, are also "public". Code that releases these branches
  // (taken/not-taken) does not leak secret information.
  const size_t exp0_k[MAX_I] = {EXP0_K_VALS};
  const size_t exp0_l[MAX_I] = {EXP0_L_VALS};
  const size_t exp1_k[MAX_I] = {EXP1_K_VALS};
  const size_t exp1_l[MAX_I] = {EXP1_L_VALS};

  DEFER_CLEANUP(pad_r_t f = {0}, pad_r_cleanup);
  DEFER_CLEANUP(pad_r_t g = {0}, pad_r_cleanup);
  DEFER_CLEANUP(pad_r_t t = {0}, pad_r_cleanup);
  DEFER_CLEANUP(dbl_pad_r_t sec_buf = {0}, dbl_pad_r_cleanup);

  // Steps 2 and 3 in [1](Algorithm 2)
  f.val = a->val;
  t.val = a->val;

  for(size_t i = 1; i < MAX_I; i++) {
    // Step 5 in [1](Algorithm 2), exponentiation 0: g = f^2^2^(i-1)
    if(exp0_k[i - 1] <= K_SQR_THR) {
      repeated_squaring(&g, &f, exp0_k[i - 1], &sec_buf, &ctx);
    } else {
      ctx.k_sqr(&g, &f, exp0_l[i - 1]);
    }

    // Step 6, [1](Algorithm 2): f = f*g
    gf2x_mod_mul_with_ctx(&f, &g, &f, &ctx);

    if(exp1_k[i] != 0) {
      // Step 8, [1](Algorithm 2), exponentiation 1: g = f^2^((r-2) % 2^i)
      if(exp1_k[i] <= K_SQR_THR) {
        repeated_squaring(&g, &f, exp1_k[i], &sec_buf, &ctx);
      } else {
        ctx.k_sqr(&g, &f, exp1_l[i]);
      }

      // Step 9, [1](Algorithm 2): t = t*g;
      gf2x_mod_mul_with_ctx(&t, &g, &t, &ctx);
    }
  }

  // Step 10, [1](Algorithm 2): c = t^2
  gf2x_mod_sqr_in_place(&t, &sec_buf, &ctx);
  c->val = t.val;
}
