/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Common functionality
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-July-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMUTILS_H_
#define _CMUTILS_H_

typedef char NQ_SCHAR;
typedef unsigned char NQ_SBYTE;

#ifdef SY_COMPILERPACK

/* integer values for initialization */
#define cmPack16(_val) ( _val )
#define cmPack32(_val) ( _val )

/* 16-bit and 32-bit types for use in non-aligned structures */
typedef unsigned short NQ_SUINT16;
#ifdef SY_INT32
typedef unsigned SY_INT32 NQ_SUINT32;
#else
typedef unsigned long NQ_SUINT32;
#endif


/* access to aligned words and longs */
#define cmGetSUint16(_a)      (_a)
#define cmGetSUint32(_a)      (_a)
#define cmPutSUint16(_a, _v)  ((_a) = _v)
#define cmPutSUint32(_a, _v)  ((_a) = _v)

/* Beginning of packed structures definition */

#include "sypackon.h"

typedef SY_PACK_PREFIX struct
{
    NQ_SUINT16 value;
} SY_PACK_ATTR
OddUint16;
typedef SY_PACK_PREFIX struct
{
    NQ_SUINT32 value;
} SY_PACK_ATTR
OddUint32;

#include "sypackof.h"

/* End of packed structures definition */

/* access to non-aligned words and longs */

#define cmGetUint16(_a)      (((OddUint16*)(_a))->value)
#define cmGetUint32(_a)      (((OddUint32*)(_a))->value)
#define cmPutUint16(_a, _v)  ((OddUint16*)(_a))->value = _v
#define cmPutUint32(_a, _v)  ((OddUint32*)(_a))->value = _v

#else /* SY_COMPILERPACK */

#ifdef SY_BIGENDIANHOST
#define cmPack16(_val) { ((_val>>8)&0xff), ((_val)&0xff)}
#define cmPack32(_val) { ((_val>>24)&0xffL), ((_val>>16)&0xffL), ((_val>>8)&0xffL), ((_val)&0xffL) }
#else /* SY_BIGENDIANHOST */
#define cmPack16(_val) { ((_val)&0xff), ((_val>>8)&0xff)}
#define cmPack32(_val) { ((_val)&0xffL), ((_val>>8)&0xffL), ((_val>>16)&0xffL), ((_val>>24)&0xffL) }
#endif /* SY_BIGENDIANHOST */

/* 16-bit and 32-bit types for use in non-aligned structures */
typedef NQ_BYTE NQ_SUINT16[2];
typedef NQ_BYTE NQ_SUINT32[4];

/* access to aligned words and longs */
#ifdef SY_LITTLEENDIANHOST
#define cmGetSUint16(_a)     ((_a[1]) << 8 | (_a[0]))
#define cmGetSUint32(_a)     ((_a[3]) << 24 | (_a[2]) << 16 | (_a[1]) << 8 | (_a[0]))
#define cmPutSUint16(_a, _v) {NQ_UINT16 _i = (_v); (_a[1]) = ((_i)>>8)&0xff; (_a[0]) = (_i)&0xff;}
#define cmPutSUint32(_a, _v) {NQ_UINT32 _i = (_v); (_a[3]) = ((_i)>>24)&0xff; (_a[2]) = ((_i)>>16)&0xff; (_a[1]) = ((_i)>>8)&0xff; (_a[0]) = (_i)&0xff;}
#else
#define cmGetSUint16(_a)     ((_a[0]) << 8 | (_a[1]))
#define cmGetSUint32(_a)     ((_a[0]) << 24 | (_a[1]) << 16 | (_a[2]) << 8 | (_a[3]))
#define cmPutSUint16(_a, _v) ((_a[0]) = ((_v)>>8)&0xff, (_a[1]) = (_v)&0xff)
#define cmPutSUint32(_a, _v) ((_a[0]) =((_v)>>24)&0xff, (_a[1]) = ((_v)>>16)&0xff, (_a[2]) = ((_v)>>8)&0xff, (_a[3]) = (_v)&0xff)
#endif

#define cmGetUint16(_a)      cmGetSUint16(((NQ_BYTE*)(_a)))
#define cmGetUint32(_a)      cmGetSUint32(((NQ_BYTE*)(_a)))
#define cmPutUint16(_a, _v)  cmPutSUint16(((NQ_BYTE*)(_a)), (_v))
#define cmPutUint32(_a, _v)  cmPutSUint32(((NQ_BYTE*)(_a)), (_v))

#endif /* SY_COMPILERPACK */

typedef NQ_SUINT16 NQ_SWCHAR;

/* the most platform-independent way to allign a pointer */

#define cmAllignTwo(_p)    ((NQ_BYTE *)(_p) + (((NQ_ULONG)(_p)) & 1))
#define cmAllignFour(_p)   ((NQ_BYTE *)(_p) +((4 - (((NQ_ULONG)(_p)) & 3)) % 4))

/* converting LITTLE ENDIAN to the host byte order */

#ifdef SY_LITTLEENDIANHOST

#ifdef SY_BIGENDIANHOST
#error "Both big and little endian defined"
#endif /* SY_BIGENDIANHOST */

#define cmLtoh16(_v)    (_v)
#define cmLtoh32(_v)    (_v)
#define cmHtol16(_v)    (_v)
#define cmHtol32(_v)    (_v)

#else /* SY_LITTLEENDIANHOST */

#ifndef SY_BIGENDIANHOST
#error "Neither big nor little endian defined"
#endif /* SY_BIGENDIANHOST */

#define cmLtoh16(_v)    ((((_v) & 0xFF00) >> 8) | (((_v) & 0x00FF) << 8))
#define cmLtoh32(_v)    ((((_v) & 0xFF000000) >> 24) |  \
                         (((_v) & 0x00FF0000) >> 8)  |  \
                         (((_v) & 0x0000FF00) << 8)  |  \
                         (((_v) & 0x000000FF) << 24)    \
                        )
#define cmHtol16(_v)    ((((_v) & 0xFF00) / 256) | (((_v) & 0x00FF) * 256))
#define cmHtol32(_v)    ((((_v) & 0xFF000000) >> 24) |  \
                         (((_v) & 0x00FF0000) >> 8)  |  \
                         (((_v) & 0x0000FF00) << 8)  |  \
                         (((_v) & 0x000000FF) << 24)    \
                        )

#endif /* SY_LITTLEENDIANHOST */

#endif  /* _CMUTILS_H_ */
