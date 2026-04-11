/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "assertions.h"
#include "utils.h"

#ifndef CONVERSIONS_H_
#define CONVERSIONS_H_

/* Big-endian integer decode from a byte buffer */
#define ntoh_int32_buf(bUF) \
    ((uint32_t)(*((uint8_t*)bUF)) << 24) | ((*((uint8_t*)bUF + 1)) << 16) | ((*((uint8_t*)bUF + 2)) << 8)   \
  | (*((uint8_t*)bUF + 3))

#define ntoh_int24_buf(bUF) \
  ((*(uint8_t*)bUF << 16) | ((*((uint8_t*)bUF + 1)) << 8) | (*((uint8_t*)bUF + 2)))

#define BUFFER_TO_INT8(buf, x) (x = ((buf)[0]))

/* Pack uint64_t big-endian into buf[0..n), with n in [1..8] */
static inline void uint_to_be(uint64_t x, uint8_t *buf, size_t n)
{
  DevAssert(n >= 1 && n <= 8);
  for (size_t i = 0; i < n; i++)
    buf[i] = (uint8_t)((x >> (8 * (n - 1 - i))) & 0xff);
}

/* Pack an integer into an asn1c OCTET STRING as n big-endian octets (n in [1..8]) */
#define UINT_TO_OCTET_STRING(x, aSN, n)                \
  do {                                                 \
    (aSN)->buf = calloc_or_fail((n), sizeof(uint8_t)); \
    uint_to_be((x), (aSN)->buf, (n));                  \
    (aSN)->size = (n);                                 \
  } while (0)

/* Pack an integer into an asn1c BIT STRING as n big-endian octets (bits_unused = 0) */
#define UINT_TO_BIT_STRING(x, aSN, n)      \
  do {                                     \
    UINT_TO_OCTET_STRING((x), (aSN), (n)); \
    (aSN)->bits_unused = 0;                \
  } while (0)

/* aliases: INT16/INT32/... mean bit/octet width, not signedness. */
#define INT8_TO_OCTET_STRING(x, aSN)  UINT_TO_OCTET_STRING((x), (aSN), 1)
#define INT16_TO_OCTET_STRING(x, aSN) UINT_TO_OCTET_STRING((x), (aSN), 2)
#define INT24_TO_OCTET_STRING(x, aSN) UINT_TO_OCTET_STRING((x), (aSN), 3)
#define INT32_TO_OCTET_STRING(x, aSN) UINT_TO_OCTET_STRING((x), (aSN), 4)
#define INT40_TO_OCTET_STRING(x, aSN) UINT_TO_OCTET_STRING((x), (aSN), 5)
#define INT48_TO_OCTET_STRING(x, aSN) UINT_TO_OCTET_STRING((x), (aSN), 6)

#define INT8_TO_BIT_STRING(x, aSN)  UINT_TO_BIT_STRING((x), (aSN), 1)
#define INT16_TO_BIT_STRING(x, aSN) UINT_TO_BIT_STRING((x), (aSN), 2)
#define INT24_TO_BIT_STRING(x, aSN) UINT_TO_BIT_STRING((x), (aSN), 3)
#define INT32_TO_BIT_STRING(x, aSN) UINT_TO_BIT_STRING((x), (aSN), 4)
#define INT40_TO_BIT_STRING(x, aSN) UINT_TO_BIT_STRING((x), (aSN), 5)
#define INT48_TO_BIT_STRING(x, aSN) UINT_TO_BIT_STRING((x), (aSN), 6)

#define INT8_TO_BUFFER(x, buf)  uint_to_be((x), (buf), 1)
#define INT16_TO_BUFFER(x, buf) uint_to_be((x), (buf), 2)
#define INT24_TO_BUFFER(x, buf) uint_to_be((x), (buf), 3)
#define INT32_TO_BUFFER(x, buf) uint_to_be((x), (buf), 4)
#define INT40_TO_BUFFER(x, buf) uint_to_be((x), (buf), 5)
#define INT48_TO_BUFFER(x, buf) uint_to_be((x), (buf), 6)

/** Pack an integer into left-aligned asn1c BIT STRING fields (buf/size/bits_unused).
 * Allocates ceil(bits / 8) octets: low `bits` of x are shifted to the MSB side.
 * bits_unused is set to the number of bits unused in the last octet, matching asn1c
 * BIT STRING layout (BIT_STRING.c), bits in [1..63]. */
static inline void uint_to_left_aligned_bit_string(uint64_t x, uint8_t **buf, size_t *size, int *bits_unused, unsigned bits)
{
  DevAssert(buf != NULL && size != NULL && bits_unused != NULL);
  DevAssert(bits >= 1 && bits <= 63);
  const unsigned n = (bits + 7) / 8;
  const unsigned u = (8 - (bits & 7)) & 7;
  *buf = calloc_or_fail(n, sizeof(uint8_t));
  uint_to_be((x & ((UINT64_C(1) << bits) - 1)) << u, *buf, n);
  *size = n;
  *bits_unused = u;
}

#define UINT10_TO_BIT_STRING(x, aSN) uint_to_left_aligned_bit_string((x), &(aSN)->buf, &(aSN)->size, &(aSN)->bits_unused, 10)
#define UINT6_TO_BIT_STRING(x, aSN) uint_to_left_aligned_bit_string((x), &(aSN)->buf, &(aSN)->size, &(aSN)->bits_unused, 6)

/* Convert an array of char containing vALUE to x */
#define BUFFER_TO_INT16(buf, x) \
do {                            \
    x = ((buf)[0] << 8)  |      \
        ((buf)[1]);             \
} while(0)

#define BUFFER_TO_INT24(buf, x) \
do {                            \
    x = ((buf)[0] << 16)  |     \
        ((buf)[1] << 8  )   |   \
        ((buf)[2]);             \
} while(0)

#define BUFFER_TO_INT32(buf, x) \
do {                            \
    x = (((uint32_t)(buf)[0]) << 24) |      \
        (((uint32_t)(buf)[1]) << 16) |      \
        (((uint32_t)(buf)[2]) << 8)  |      \
        (((uint32_t)(buf)[3]));             \
} while(0)

#define MME_CODE_TO_OCTET_STRING INT8_TO_OCTET_STRING
#define M_TMSI_TO_OCTET_STRING INT32_TO_OCTET_STRING
#define MME_GID_TO_OCTET_STRING INT16_TO_OCTET_STRING
#define AMF_REGION_TO_BIT_STRING INT8_TO_BIT_STRING

#define AMF_SETID_TO_BIT_STRING UINT10_TO_BIT_STRING
#define UEIDENTITYINDEX_TO_BIT_STRING UINT10_TO_BIT_STRING
#define AMF_POINTER_TO_BIT_STRING UINT6_TO_BIT_STRING

#define ENCRALG_TO_BIT_STRING INT16_TO_BIT_STRING
#define INTPROTALG_TO_BIT_STRING INT16_TO_BIT_STRING

#define UEAMBR_TO_OCTET_STRING INT40_TO_OCTET_STRING

#define AS_KEY_STAR_TO_BIT_STRING(askeystar, bitstring)        \
  do {                                                         \
    (bitstring)->size = 32;                                    \
    (bitstring)->bits_unused = 0;                              \
    (bitstring)->buf = calloc_or_fail(32, sizeof(uint8_t));    \
    memcpy((bitstring)->buf, askeystar, 32 * sizeof(uint8_t)); \
  } while (0)

#define OCTET_STRING_TO_INT8(aSN, x)    \
do {                                    \
    DevCheck((aSN)->size == 1, (aSN)->size, 0, 0);           \
    BUFFER_TO_INT8((aSN)->buf, x);    \
} while(0)

#define OCTET_STRING_TO_INT16(aSN, x)   \
do {                                    \
    DevCheck((aSN)->size == 2 || (aSN)->size == 3, (aSN)->size, 0, 0);           \
    BUFFER_TO_INT16((aSN)->buf, x);    \
} while(0)

#define OCTET_STRING_TO_INT24(aSN, x)              \
  do {                                             \
    DevCheck((aSN)->size == 3, (aSN)->size, 3, 0); \
    BUFFER_TO_INT24((aSN)->buf, x);                \
  } while (0)

#define OCTET_STRING_TO_INT32(aSN, x)   \
do {                                    \
    DevCheck((aSN)->size == 4, (aSN)->size, 0, 0);           \
    BUFFER_TO_INT32((aSN)->buf, x);    \
} while(0)

#define BIT_STRING_TO_NR_CELL_IDENTITY(aSN, vALUE)                                                                \
  do {                                                                                                            \
    DevCheck((aSN)->bits_unused == 4, (aSN)->bits_unused, 4, 0);                                                  \
    (vALUE) = ((uint64_t)(aSN)->buf[0] << 28) | ((uint64_t)(aSN)->buf[1] << 20) | ((uint64_t)(aSN)->buf[2] << 12) \
              | ((uint64_t)(aSN)->buf[3] << 4) | ((uint64_t)(aSN)->buf[4] >> 4);                                  \
  } while (0)

#define MCC_HUNDREDS(vALUE) \
    ((vALUE) / 100)
/* When MNC is only composed of 2 digits, set the hundreds unit to 0xf */
#define MNC_HUNDREDS(vALUE, mNCdIGITlENGTH) \
    ( mNCdIGITlENGTH == 2 ? 15 : (vALUE) / 100)
#define MCC_MNC_DECIMAL(vALUE) \
    (((vALUE) / 10) % 10)
#define MCC_MNC_DIGIT(vALUE) \
    ((vALUE) % 10)

#define MCC_MNC_TO_PLMNID(mCC, mNC, mNCdIGITlENGTH, oCTETsTRING)                           \
  do {                                                                                     \
    (oCTETsTRING)->buf = calloc_or_fail(3, sizeof(uint8_t));                               \
    (oCTETsTRING)->buf[0] = (MCC_MNC_DECIMAL(mCC) << 4) | MCC_HUNDREDS(mCC);               \
    (oCTETsTRING)->buf[1] = (MNC_HUNDREDS(mNC, mNCdIGITlENGTH) << 4) | MCC_MNC_DIGIT(mCC); \
    (oCTETsTRING)->buf[2] = (MCC_MNC_DIGIT(mNC) << 4) | MCC_MNC_DECIMAL(mNC);              \
    (oCTETsTRING)->size = 3;                                                               \
  } while (0)

#define PLMNID_TO_MCC_MNC(oCTETsTRING, mCC, mNC, mNCdIGITlENGTH)                  \
do {                                                                              \
    mCC = ((oCTETsTRING)->buf[0] & 0x0F) * 100 +                                  \
          ((oCTETsTRING)->buf[0] >> 4 & 0x0F) * 10 +                              \
          ((oCTETsTRING)->buf[1] & 0x0F);                                         \
    mNCdIGITlENGTH = ((oCTETsTRING)->buf[1] >> 4 & 0x0F) == 0xF ? 2 : 3;          \
    mNC = (mNCdIGITlENGTH == 2 ? 0 : ((oCTETsTRING)->buf[1] >> 4 & 0x0F) * 100) + \
          ((oCTETsTRING)->buf[2] & 0x0F) * 10 +                                   \
          ((oCTETsTRING)->buf[2] >> 4 & 0x0F);                                    \
} while (0)

#define MCC_MNC_TO_TBCD(mCC, mNC, mNCdIGITlENGTH, tBCDsTRING)        \
do {                                                                 \
    char _buf[3];                                                    \
     DevAssert((mNCdIGITlENGTH == 3) || (mNCdIGITlENGTH == 2));      \
    _buf[0] = (MCC_MNC_DECIMAL(mCC) << 4) | MCC_HUNDREDS(mCC);       \
    _buf[1] = (MNC_HUNDREDS(mNC,mNCdIGITlENGTH) << 4) | MCC_MNC_DIGIT(mCC);\
    _buf[2] = (MCC_MNC_DIGIT(mNC) << 4) | MCC_MNC_DECIMAL(mNC);      \
    OCTET_STRING_fromBuf(tBCDsTRING, _buf, 3);                       \
} while(0)

#define TBCD_TO_MCC_MNC(tBCDsTRING, mCC, mNC, mNCdIGITlENGTH)    \
do {                                                             \
    int mNC_hundred;                                             \
    DevAssert((tBCDsTRING)->size == 3);                          \
    mNC_hundred = (((tBCDsTRING)->buf[1] & 0xf0) >> 4);          \
    if (mNC_hundred == 0xf) {                                    \
        mNC_hundred = 0;                                         \
        mNCdIGITlENGTH = 2;                                      \
    } else {                                                     \
            mNCdIGITlENGTH = 3;                                  \
    }                                                            \
    mCC = (((((tBCDsTRING)->buf[0]) & 0xf0) >> 4) * 10) +        \
        ((((tBCDsTRING)->buf[0]) & 0x0f) * 100) +                \
        (((tBCDsTRING)->buf[1]) & 0x0f);                         \
    mNC = (mNC_hundred * 100) +                                  \
        ((((tBCDsTRING)->buf[2]) & 0xf0) >> 4) +                 \
        ((((tBCDsTRING)->buf[2]) & 0x0f) * 10);                  \
} while(0)

/* TS 38.473 v15.2.1 section 9.3.2.3:
 * TRANSPORT LAYER ADDRESS for IPv4 is 32bit (TS 38.414)
 */
#define TRANSPORT_LAYER_ADDRESS_IPv4_TO_BIT_STRING(mACRO, bITsTRING) \
  do {                                                               \
    (bITsTRING)->buf = calloc_or_fail(4, sizeof(uint8_t));           \
    (bITsTRING)->buf[3] = (mACRO) >> 24 & 0xFF;                      \
    (bITsTRING)->buf[2] = (mACRO) >> 16 & 0xFF;                      \
    (bITsTRING)->buf[1] = (mACRO) >> 8 & 0xFF;                       \
    (bITsTRING)->buf[0] = (mACRO)&0xFF;                              \
    (bITsTRING)->size = 4;                                           \
    (bITsTRING)->bits_unused = 0;                                    \
  } while (0)

#define BIT_STRING_TO_TRANSPORT_LAYER_ADDRESS_IPv4(bITsTRING, mACRO)    \
do {                                                                    \
    DevCheck((bITsTRING)->size == 4, (bITsTRING)->size, 4, 0);          \
    DevCheck((bITsTRING)->bits_unused == 0, (bITsTRING)->bits_unused, 0, 0); \
    mACRO = (((uint32_t) (bITsTRING)->buf[3]) << 24) +                               \
            (((uint32_t) (bITsTRING)->buf[2]) << 16) +                               \
            (((uint32_t) (bITsTRING)->buf[1]) << 8) +                                \
            (((uint32_t) (bITsTRING)->buf[0]));                                      \
} while (0)


/* TS 38.473 v15.1.1 section 9.3.1.12:
 * NR CELL ID
 */
#define NR_CELL_ID_TO_BIT_STRING(mACRO, bITsTRING) \
  uint_to_left_aligned_bit_string((mACRO), &(bITsTRING)->buf, &(bITsTRING)->size, &(bITsTRING)->bits_unused, 36)

#define NR_FIVEGS_TAC_TO_OCTET_STRING INT24_TO_OCTET_STRING

/* TS 36.413 v10.9.0 section 9.2.1.37:
 * Macro eNB ID:
 * Equal to the 20 leftmost bits of the Cell
 * Identity IE contained in the E-UTRAN CGI
 * IE (see subclause 9.2.1.38) of each cell
 * served by the eNB.
 */
#define MACRO_ENB_ID_TO_BIT_STRING(mACRO, bITsTRING) \
  uint_to_left_aligned_bit_string((mACRO), &(bITsTRING)->buf, &(bITsTRING)->size, &(bITsTRING)->bits_unused, 20)
#define MACRO_GNB_ID_TO_BIT_STRING(mACRO, bITsTRING) \
  uint_to_left_aligned_bit_string((mACRO), &(bITsTRING)->buf, &(bITsTRING)->size, &(bITsTRING)->bits_unused, 28)

#define MACRO_BIT_STRING_TO_GNB_ID(bITsTRING, oUT)          \
do {                                                        \
    uint8_t *_buf = (bITsTRING)->buf;                       \
    (oUT) =                                                 \
        ((uint32_t)_buf[0] << 20) |                         \
        ((uint32_t)_buf[1] << 12) |                         \
        ((uint32_t)_buf[2] << 4)  |                         \
        (((uint32_t)_buf[3] & 0xF0) >> 4);                  \
} while (0)

/* TS 36.413 v10.9.0 section 9.2.1.38:
 * E-UTRAN CGI/Cell Identity
 * The leftmost bits of the Cell
 * Identity correspond to the eNB
 * ID (defined in subclause 9.2.1.37).
 */
#define MACRO_ENB_ID_TO_CELL_IDENTITY(mACRO, cELL_iD, bITsTRING)    \
  do {                                                              \
    (bITsTRING)->buf = calloc_or_fail(4, sizeof(uint8_t));          \
    (bITsTRING)->buf[0] = ((mACRO) >> 12);                          \
    (bITsTRING)->buf[1] = (mACRO) >> 4;                             \
    (bITsTRING)->buf[2] = (((mACRO)&0x0f) << 4) | ((cELL_iD) >> 4); \
    (bITsTRING)->buf[3] = ((cELL_iD)&0x0f) << 4;                    \
    (bITsTRING)->size = 4;                                          \
    (bITsTRING)->bits_unused = 4;                                   \
  } while (0)

#define MACRO_GNB_ID_TO_CELL_IDENTITY(mACRO, cELL_iD, bITsTRING)    \
  do {                                                              \
    (bITsTRING)->buf = calloc_or_fail(5, sizeof(uint8_t));          \
    (bITsTRING)->buf[0] = ((mACRO) >> 20);                          \
    (bITsTRING)->buf[1] = (mACRO) >> 12;                            \
    (bITsTRING)->buf[2] = (mACRO) >> 4;                             \
    (bITsTRING)->buf[3] = (((mACRO)&0x0f) << 4) | ((cELL_iD) >> 4); \
    (bITsTRING)->buf[4] = ((cELL_iD)&0x0f) << 4;                    \
    (bITsTRING)->size = 5;                                          \
    (bITsTRING)->bits_unused = 4;                                   \
  } while (0)

#define FIVEG_S_TMSI_TO_BIT_STRING INT48_TO_BIT_STRING

#define IRNTI_TO_BIT_STRING INT40_TO_BIT_STRING

/* Used to format an uint32_t containing an ipv4 address */
#define IPV4_ADDR    "%u.%u.%u.%u"
#define IPV4_ADDR_FORMAT(aDDRESS)               \
    (uint8_t)((aDDRESS)  & 0x000000ff),         \
    (uint8_t)(((aDDRESS) & 0x0000ff00) >> 8 ),  \
    (uint8_t)(((aDDRESS) & 0x00ff0000) >> 16),  \
    (uint8_t)(((aDDRESS) & 0xff000000) >> 24)

#define TAC_TO_ASN1 INT16_TO_OCTET_STRING
#define GTP_TEID_TO_ASN1 INT32_TO_OCTET_STRING

#endif /* CONVERSIONS_H_ */
