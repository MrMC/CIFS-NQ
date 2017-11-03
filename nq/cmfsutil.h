/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : The most common CIFS routines
 *--------------------------------------------------------------------
 * MODULE        : CM - Common Library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMFSUTIL_H_
#define _CMFSUTIL_H_

#include "cmapi.h"

/*
    Filename conversion
    -------------------
 */

/* initialize this module */

/*
	  GUID structure
	  --------------
 */

typedef struct
{
    NQ_SUINT32 timeLow;
    NQ_SUINT16 timeMid;
    NQ_SUINT16 timeHiVersion;
    NQ_SBYTE clockSeq[2];
    NQ_SBYTE node[6];
}
NQ_Uuid;

NQ_STATUS
cmCifsUtilsInit(
    void
    );

/* stop this module */

void
cmCifsUtilsExit(
    void
    );

/* converts network filename to the host system filename */

NQ_WCHAR*                       /* filename in the host filesystem */
cmCifsNtohFilename(
	NQ_WCHAR * buffer, 				/* to compose full path */
    const NQ_WCHAR* shareName,    	/* path to the filesystem (share mapping) */
    const NQ_WCHAR* netFilename,  	/* network filename */
    NQ_BOOL unicodeRequired,       	/* true if the above name is unicode */
	NQ_BOOL isSpecialChars       		/* true if special characters is allowed */
    );

/* Convert host filename to the network file name */

void
cmCifsHtonFilename(
    NQ_WCHAR* pFileName          /* file name to convert */
    );

/* extracts filename from a full name (including path) */

const NQ_WCHAR*                  /* filename without the path */
cmCifsExtractFilenameFromFullName(
    const NQ_WCHAR* fullName     /* filename including path */
    );

/*
    Time & Date conversion
    ----------------------
 */

NQ_UINT32
cmTimeConvertMSecToSec(
	NQ_TIME * t
    );

NQ_TIME cmTimeConvertSecToMSec(
	NQ_UINT32 secTime
	);

void
cmCifsTimeToSmbTime(
	NQ_TIME time,                  /* Unix time */
    NQ_UINT16* smbTime,            /* CIFS encoded time (host order) */
    NQ_UINT16* smbDate             /* CIFS encoded date (host order) */
    );

NQ_UINT32                          /* Unix time */
cmCifsSmbTimeToTime(
    NQ_UINT16 smbTime,             /* CIFS encoded time (host order) */
    NQ_UINT16 smbDate              /* CIFS encoded date (host order) */
    );

void
cmCifsTimeToUTC(
	NQ_TIME time,                  /* UNIX time */
    NQ_UINT32* low,                /* low portion of UTC time */
    NQ_UINT32* high                /* high portion of UTC time */
    );

NQ_TIME                           /* Unix time */
cmCifsUTCToTime(
    NQ_UINT32 low,                /* low portion of UTC time */
    NQ_UINT32 high                /* high portion of UTC time */
    );

#ifdef CM_NQ_STORAGE
NQ_BOOL
cmU64TimeToString(
    NQ_BYTE * strTime,			  /* utc time as string */
    NQ_UINT64 time				  /* system time */
    );
#endif
#ifdef SY_INT64
#define NQ_64 SY_INT64
#define NQ_U64 SY_UINT64
#else
#define NQ_64 NQ_INT64
#define NQ_U64 NQ_UINT64
#endif

#define cmU64Zero(_i64_) (_i64_)->low = (_i64_)->high = 0; 

/* add */

void cmU64Inc(NQ_UINT64 *i64);

void cmU64AddU32(NQ_UINT64 *i64, NQ_UINT32 low);

void cmU64AddS64(NQ_UINT64 *u, const NQ_INT64 *s);

void cmU64AddU64(NQ_UINT64 *u, const NQ_UINT64 *a);

/* substract */

void cmU64SubU64U64(NQ_UINT64 *c, const NQ_UINT64 *a, const NQ_UINT64 *b);

/* compare */

NQ_INT32 cmU64Cmp(NQ_UINT64 *i, NQ_UINT64 *j);

/* assignment */

void cmU64AssignU64(NQ_UINT64 *d, const NQ_UINT64 *s);
NQ_UINT cmNQ_UINT64toU32(NQ_UINT64 j);

/* find min */
NQ_UINT64 cmU64Min(NQ_UINT64 *i, NQ_UINT64 *j);

/* multiply */

void cmU64MultU32U32(NQ_UINT64 *r, const NQ_UINT32 i, const NQ_UINT32 j);

void cmU128MultU64U64(NQ_UINT64 *resultLow, NQ_UINT64 *resultHigh, const NQ_UINT64 *a, const NQ_UINT64 *b);




#ifdef SY_INT64
#define SET_CONST64(a, x) a = x;
#define SET_64(a, x) a = x;
#define SET_SPLIT64_TO64(a, x) ( (a) = ((SY_UINT64)(x.high) << 32) | (x.low) );
#define SWAP64(dst, src)\
  dst = ((((src) & 0x00000000000000FFULL) << 56) |\
		 (((src) & 0x000000000000FF00ULL) << 40) |\
		 (((src) & 0x0000000000FF0000ULL) << 24) |\
		 (((src) & 0x00000000FF000000ULL) << 8)  |\
		 (((src) & 0x000000FF00000000ULL) >> 8)  |\
		 (((src) & 0x0000FF0000000000ULL) >> 24) |\
		 (((src) & 0x00FF000000000000ULL) >> 40) |\
		 (((src) & 0xFF00000000000000ULL) >> 56));
#else
#define SET_CONST64(a, lo, hi) a.low =  lo;\
							   a.high = hi;
#define SET_64(a, x) a.low = x.low;\
		 	 	 	 a.high = x.high;
#define SET_SPLIT64_TO64(a, x) a.high = x.high; a.low = x.low;
/* PURPOSE: Shift right 64 bit int composed out of two 32 bit unsigned int
 * PARAMS:  src - source (64 bit uint) dst: - destination of shift (64 bit uint) n: shift value
*/

#define SHIFTR64(src, dst, n)\
{\
	dst.low = n < 32 ? ((src.low >> n) | (src.high << (32 - n))):\
			  src.high >> (n - 32);\
	dst.high = n < 32 ? src.high >> n : 0;\
}
#define SWAP64(dst, src)\
{	NQ_UINT32 temp = src.low;\
    dst.low = ((((src.high) & 0x000000FF) << 24)|\
		      (((src.high) & 0x0000FF00) << 8) |\
			  (((src.high) & 0x00FF0000) >> 8) |\
			  (((src.high) & 0xFF000000) >> 24));\
    dst.high = ((((temp) & 0x000000FF) << 24)|\
	      	  (((temp) & 0x0000FF00) << 8) |\
			  (((temp) & 0x00FF0000) >> 8) |\
			  (((temp) & 0xFF000000) >> 24));\
}
#endif

#endif  /* _CMFSUTIL_H_ */

