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

NQ_TCHAR*                       /* filename in the host filesystem */
cmCifsNtohFilename(
    const NQ_TCHAR* shareName,   /* path to the filesystem (share mapping) */
    const NQ_TCHAR* netFilename,/* network filename */
    NQ_BOOL unicodeRequired     /* true if the above name is unicode */
    );

/* Convert host filename to the network file name */

void
cmCifsHtonFilename(
    NQ_TCHAR* pFileName          /* file name to convert */
    );

/* extracts filename from a full name (including path) */

const NQ_TCHAR*                  /* filename without the path */
cmCifsExtractFilenameFromFullName(
    const NQ_TCHAR* fullName     /* filename including path */
    );

/*
    Time & Date conversion
    ----------------------
 */

void
cmCifsTimeToSmbTime(
    NQ_UINT32 time,                /* Unix time */
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
    NQ_UINT32 time,                /* UNIX time */
    NQ_UINT32* low,                /* low portion of UTC time */
    NQ_UINT32* high                /* high portion of UTC time */
    );

NQ_UINT32                          /* Unix time */
cmCifsUTCToTime(
    NQ_UINT32 low,                /* low portion of UTC time */
    NQ_UINT32 high                /* high portion of UTC time */
    );

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

/*
    64 bit integer definition and limited math
    ------------------------------------------
*/

typedef struct {
    NQ_UINT32 low;
    NQ_UINT32 high;
} NQ_UINT64;

typedef struct {
    NQ_UINT32 low;
    NQ_UINT32 high;
    NQ_INT32  sign;
} NQ_INT64;

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

/* multiply */

void cmU64MultU32U32(NQ_UINT64 *r, const NQ_UINT32 i, const NQ_UINT32 j);

void cmU128MultU64U64(NQ_UINT64 *resultLow, NQ_UINT64 *resultHigh, const NQ_UINT64 *a, const NQ_UINT64 *b);

#endif  /* _CMFSUTIL_H_ */


