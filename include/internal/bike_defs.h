/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "defs.h"

////////////////////////////////////////////
//             BIKE Parameters
///////////////////////////////////////////
#define N0 2

#if !defined(LEVEL)
#  define LEVEL 1
#endif

#if(LEVEL == 0)
#  define R_BITS 2053
#  define D      23
#  define T      42

#  define THRESHOLD_COEFF0 5.9823
#  define THRESHOLD_COEFF1 0.0176796
#  define THRESHOLD_MIN    12

// The gf2m code is optimized to a block in this case:
#  define BLOCK_BITS 4096
# define MAX_RAND_INDICES_T 271 // taken from level 1

#elif(LEVEL == 10)
#  define R_BITS 7109
#  define D      41
#  define T      42

#  define THRESHOLD_COEFF0 13.530
#  define THRESHOLD_COEFF1 0.0069722
#  define THRESHOLD_MIN    21

// The gf2m code is optimized to a block in this case:
#  define BLOCK_BITS 8192
# define MAX_RAND_INDICES_T 271  // taken from level 1

#elif(LEVEL == 11)
#  define  R_BITS 773
#  define  D      9
#  define  T      34

#  define  THRESHOLD_COEFF0 3.98287671232877
#  define  THRESHOLD_COEFF1 0.0171232876712329
#  define  THRESHOLD_MIN    5

// The gf2m code is optimized to a block in this case:
#  define  BLOCK_BITS 1024
# define MAX_RAND_INDICES_T 271  // taken from level 1

#elif(LEVEL == 12)
#  define  R_BITS 1019
#  define  D      13
#  define  T      39

#  define  THRESHOLD_COEFF0 5.98516949152542
#  define  THRESHOLD_COEFF1 0.0148305084745763
#  define  THRESHOLD_MIN    7

// The gf2m code is optimized to a block in this case:
#  define  BLOCK_BITS 1024
# define MAX_RAND_INDICES_T 271  // taken from level 1

#elif(LEVEL == 13)
#  define  R_BITS 1283
#  define  D      15
#  define  T      43

#  define  THRESHOLD_COEFF0 5.98664440734558
#  define  THRESHOLD_COEFF1 0.0133555926544240
#  define  THRESHOLD_MIN    8

// The gf2m code is optimized to a block in this case:
#  define  BLOCK_BITS 2048
# define MAX_RAND_INDICES_T 271  // taken from level 1

#elif(LEVEL == 14)
#  define  R_BITS 2029
#  define  D      21
#  define  T      54

#  define  THRESHOLD_COEFF0 6.98743961352657
#  define  THRESHOLD_COEFF1 0.0125603864734300
#  define  THRESHOLD_MIN    11
# define MAX_RAND_INDICES_T 271  // taken from level 1

// The gf2m code is optimized to a block in this case:
#  define  BLOCK_BITS 2048

#elif(LEVEL == 15)
#  define  R_BITS 2053
#  define  D      23
#  define  T      55

#  define  THRESHOLD_COEFF0 7.98765432098765
#  define  THRESHOLD_COEFF1 0.0123456790123457
#  define  THRESHOLD_MIN    12

// The gf2m code is optimized to a block in this case:
#  define  BLOCK_BITS 4096
# define MAX_RAND_INDICES_T 271  // taken from level 1

#elif(LEVEL == 16)
#  define  R_BITS 2069
#  define  D      23
#  define  T      55

#  define  THRESHOLD_COEFF0 7.98679577464789
#  define  THRESHOLD_COEFF1 0.0132042253521127
#  define  THRESHOLD_MIN    12

// The gf2m code is optimized to a block in this case:
#  define  BLOCK_BITS 4096
# define MAX_RAND_INDICES_T 271  // taken from level 1

#elif(LEVEL == 17)
#  define  R_BITS 4021
#  define  D      35
#  define  T      76

#  define  THRESHOLD_COEFF0 8.98932536293766
#  define  THRESHOLD_COEFF1 0.0106746370623399
#  define  THRESHOLD_MIN    18

// The gf2m code is optimized to a block in this case:
#  define  BLOCK_BITS 4096
# define MAX_RAND_INDICES_T 271  // taken from level 1

#elif(LEVEL == 18)
#  define  R_BITS 4099
#  define  D      35
#  define  T      77

#  define  THRESHOLD_COEFF0 8.98948254101809
#  define  THRESHOLD_COEFF1 0.0105174589819100
#  define  THRESHOLD_MIN    18

// The gf2m code is optimized to a block in this case:
#  define  BLOCK_BITS 8192
# define MAX_RAND_INDICES_T 271  // taken from level 1

#elif(LEVEL == 3)
#  define R_BITS 24659
#  define D      103
#  define T      199

#  define THRESHOLD_COEFF0 15.2588
#  define THRESHOLD_COEFF1 0.005265
#  define THRESHOLD_MIN    52

// When generating an error vector we can't use rejection sampling because of
// constant-time requirements so we generate always the maximum number
// of indices and then use only the first T valid indices, as explained in:
// https://github.com/awslabs/bike-kem/blob/master/BIKE_Rejection_Sampling.pdf
# define MAX_RAND_INDICES_T 373

// The gf2m code is optimized to a block in this case:
#  define BLOCK_BITS 32768
#elif(LEVEL == 1)
// 64-bits of post-quantum security parameters (BIKE paper):
#  define R_BITS 12323
#  define D      71
#  define T      134

#  define THRESHOLD_COEFF0 13.530
#  define THRESHOLD_COEFF1 0.0069722
#  define THRESHOLD_MIN    36

// When generating an error vector we can't use rejection sampling because of
// constant-time requirements so we generate always the maximum number
// of indices and then use only the first T valid indices, as explained in:
// https://github.com/awslabs/bike-kem/blob/master/BIKE_Rejection_Sampling.pdf
# define MAX_RAND_INDICES_T 271

// The gf2x code is optimized to a block in this case:
#  define BLOCK_BITS       (16384)
#else
#  error "Bad level, choose one of 0/10/1/3"
#endif

#define NUM_OF_SEEDS 2

// Round the size to the nearest byte.
// SIZE suffix, is the number of bytes (uint8_t).
#define N_BITS   (R_BITS * N0)
#define R_BYTES  DIVIDE_AND_CEIL(R_BITS, 8)
#define R_QWORDS DIVIDE_AND_CEIL(R_BITS, 8 * BYTES_IN_QWORD)
#define R_XMM    DIVIDE_AND_CEIL(R_BITS, 8 * BYTES_IN_XMM)
#define R_YMM    DIVIDE_AND_CEIL(R_BITS, 8 * BYTES_IN_YMM)
#define R_ZMM    DIVIDE_AND_CEIL(R_BITS, 8 * BYTES_IN_ZMM)

#define R_BLOCKS        DIVIDE_AND_CEIL(R_BITS, BLOCK_BITS)
#define R_PADDED        (R_BLOCKS * BLOCK_BITS)
#define R_PADDED_BYTES  (R_PADDED / 8)
#define R_PADDED_QWORDS (R_PADDED / 64)

#define LAST_R_QWORD_LEAD  (R_BITS & MASK(6))
#define LAST_R_QWORD_TRAIL (64 - LAST_R_QWORD_LEAD)
#define LAST_R_QWORD_MASK  MASK(LAST_R_QWORD_LEAD)

#define LAST_R_BYTE_LEAD  (R_BITS & MASK(3))
#define LAST_R_BYTE_TRAIL (8 - LAST_R_BYTE_LEAD)
#define LAST_R_BYTE_MASK  MASK(LAST_R_BYTE_LEAD)

// Data alignement
#define ALIGN_BYTES (BYTES_IN_ZMM)

#define M_BITS  256
#define M_BYTES (M_BITS / 8)

#define SS_BITS  256
#define SS_BYTES (SS_BITS / 8)

#define SEED_BYTES (256 / 8)

//////////////////////////////////
// Parameters for the BGF decoder.
//////////////////////////////////
#define BGF_DECODER
#define DELTA  3
#define SLICES (LOG2_MSB(D) + 1)

// GF2X inversion can only handle R < 32768
bike_static_assert((R_BITS < 32768), r_too_large_for_inversion);
