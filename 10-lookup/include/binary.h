#ifndef __BINARY_H__
#define __BINARY_H__

#define ALL_ONE         ( ~ 0U )

#define PREFIX_ZERO(i)  ( (i) >= 32 ? 0U : (ALL_ONE >> (i)) )
#define PREFIX_ONE(i)   ( ~ PREFIX_ZERO(i) )

#define SUFFIX_ZERO(i)  ( (i) >= 32 ? 0U : (ALL_ONE << (i)) )
#define SUFFIX_ONE(i)   ( ~ SUFFIX_ZERO(i) )

#define PREFIX_OF(n, i) ( n & PREFIX_ONE(i) )
#define SUFFIX_OF(n, i) ( n & SUFFIX_ONE(i) )

#define I_BIT(i)        ( 1U << (i) )
#define BIT_OF(n, i)    ( ((unsigned)(n) >> (i)) & 1U )

#endif