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

#include "cmapi.h"

/* static data */

typedef struct
{
    NQ_WCHAR pipeName[7];                                               /* buffer for pipe name */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/*
 *====================================================================
 * PURPOSE: Initialize resources
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS:  NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   Prepares commongly used names and constants
 *====================================================================
 */

NQ_STATUS
cmCifsUtilsInit(
    void
    )
{
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

    cmAnsiToUnicode(staticData->pipeName, "\\PIPE\\");
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Release resources
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS:  NONE
 *
 * NOTES:   Prepares commongly used names and constants
 *====================================================================
 */

void
cmCifsUtilsExit(
    void
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        cmMemoryFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 *====================================================================
 * PURPOSE: converts network filename to the host system filename
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT result buffer
 *          IN path to the filesystem (share mapping)
 *          IN network filename
 *          IN true if the above name is UNICODE
 *          IN true if special characters are allowed
 *
 * RETURNS: filename in the host format or NULL on error
 *
 * NOTES:   the following is done:
 *          - conversion from the network encoding (ANSI or UNICODE) to
 *            the host filesystem encoding as defined by
 *            SY_UNICODEFILESYSTEM
 *          - path separator conversion from network "\" to host (whatever)
 *          - processing wildcards
 *====================================================================
 */

NQ_WCHAR * cmCifsNtohFilename(NQ_WCHAR * buffer, const NQ_WCHAR* shareName, const NQ_WCHAR* netFilename, NQ_BOOL unicodeRequired, NQ_BOOL isSpecialChars)
{
    NQ_UINT shareLen = NULL == shareName? 0: (NQ_UINT)cmWStrlen(shareName);              /* partial string length */
    NQ_UINT nameLen = (NQ_UINT)(unicodeRequired? cmWStrlen((NQ_WCHAR*)netFilename) : syStrlen((NQ_CHAR*)netFilename));
    NQ_WCHAR * pName;		/* pointer to file name after the share path */
    NQ_WCHAR * pFileName = NULL;
    NQ_WCHAR * pResult = NULL;
    NQ_BOOL hasWildcards = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "buffer:%p, shareName:%p netFilename:%p unicodeRequired:%s", buffer, shareName, netFilename, unicodeRequired ? "TRUE" : "FALSE");
 
    /* check that the result will fit into the maximum file name length of the local file system */
    if (nameLen + shareLen > CM_MAXFILENAMELEN)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Local file name too long: %d", nameLen + shareLen);
        goto Exit;
    }

    /* 1) convert filename to the host filesystem encoding
       2) convert path separators '\' in the file name into host path separators
       3) if file name does not start with a path separator - add one
       4) compose a full file name from the share path and the file name */

    /* convert filename from whatever encoding into the host filesystem encoding */
    /* full local file name = local share path + separator + network file name */
    /* max network file name length = SY_MAXFILENAMELEN- local share path length - separator length */

    if (unicodeRequired)
    {
        netFilename = (NQ_WCHAR*)cmAllignTwo(netFilename);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "netFilename:%s", cmWDump(netFilename));
        if (*netFilename != cmWChar(SY_PATHSEPARATOR) && *netFilename != cmWChar('\\') && NULL != shareName)
        {
            pName = buffer + shareLen + 1;
        }
        else
        {
            pName = buffer + shareLen;
        }
        cmWStrncpy(pName, (NQ_WCHAR*)netFilename, CM_MAXFILENAMELEN - shareLen - 1);
    }
    else
    {
        if ((NQ_CHAR)*netFilename != SY_PATHSEPARATOR && (NQ_CHAR)*netFilename != '\\' && NULL != shareName)
        {
            pName = buffer + shareLen + 1;
        }
        else
        {
            pName = buffer + shareLen;
        }
        cmAnsiToUnicodeN(pName, (NQ_CHAR*)netFilename, CM_MAXFILENAMELEN - shareLen - 1);
    }
   
    /* change SMB path separator (backslash) into host path separator */
    {
        NQ_WCHAR* nextSeparator; /* pointer to the next separator in the string */

        nextSeparator = pName;
        pFileName = nextSeparator;

        while ((nextSeparator = cmWStrchr(nextSeparator, cmWChar('\\'))) != NULL )
        {
            *nextSeparator++ = cmWChar(SY_PATHSEPARATOR);
            pFileName = nextSeparator;
        }
    }

    if (NULL != shareName)
    {
        /* convert share path into file system encoding */
    	cmWStrcpy(buffer, shareName);

        /* add leading path separator */
    	if (*pName != cmWChar(SY_PATHSEPARATOR))
    	{
    		buffer[shareLen] = cmWChar(SY_PATHSEPARATOR);
    	}
    }

    /* remove possible trailing path separator */
    {
        NQ_INT len; /* name length */

        len = (NQ_INT)cmWStrlen(buffer);
        if (len > 0 && buffer[len - 1] == cmWChar(SY_PATHSEPARATOR))
        {
        	buffer[len - 1] = cmWChar('\0');
        }
    }

    if (!cmWStrncmp(buffer, staticData->pipeName, 6))
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "PIPE is requested. Pipes are not supported");
        goto Exit;
    }

    hasWildcards = pFileName && !isSpecialChars && (
           (cmWStrchr(pFileName, cmWChar('*')) != NULL)
        || (cmWStrchr(pFileName, cmWChar('?')) != NULL)
        || (cmWStrchr(pFileName, cmWChar('<')) != NULL)
        || (cmWStrchr(pFileName, cmWChar('>')) != NULL)
        || (cmWStrchr(pFileName, cmWChar('"')) != NULL)
		|| (cmWStrchr(pFileName, cmWChar('\\')) != NULL)
		|| (cmWStrchr(pFileName, cmWChar('/')) != NULL))
        ;
    if (hasWildcards)
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "Local file name has illegal characters");
        goto Exit;
    }
    pResult = buffer;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p %s", pResult, cmWDump(pResult));
    return pResult;
}

/*
 *====================================================================
 * PURPOSE: converts host filename to the network filename
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT host filename
 *
 * RETURNS: None
 *
 * NOTES:   the following is done:
 *          - path separator conversion to network "\"
 *====================================================================
 */

void
cmCifsHtonFilename(
	NQ_WCHAR* pFileName
	)
{
    /* convert path separators into '\' */

    while ((pFileName = cmWStrchr(pFileName, cmWChar(SY_PATHSEPARATOR))) != NULL )
    {
        *pFileName++ = cmWChar('\\');
    }
}

/*
 *====================================================================
 * PURPOSE: extracts filename from a full name (including path)
 *--------------------------------------------------------------------
 * PARAMS:  IN full name
 *
 * RETURNS: filename without path
 *
 * NOTES:
 *====================================================================
 */

const NQ_WCHAR*
cmCifsExtractFilenameFromFullName(
    const NQ_WCHAR* fullName
    )
{
    NQ_WCHAR* fName; /* the result */

    fName = cmWStrrchr(fullName, cmWChar(SY_PATHSEPARATOR));

    return (fName == NULL)? fullName: fName + 1;
}

/*
 *====================================================================
 * PURPOSE: converts UNIX style time to SMB time & date
 *--------------------------------------------------------------------
 * PARAMS:  IN Unix time
 *          OUT buffer for SMB time
 *          OUT buffer for SMB date
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
cmCifsTimeToSmbTime(
    NQ_TIME time,
    NQ_UINT16* smbTime,
    NQ_UINT16* smbDate
    )
{
    SYTimeFragments frag;      /* time, decomposed */
    NQ_UINT32 tmpTime = cmTimeConvertMSecToSec(&time);

    /* if time is less then Jan 1, 1980, convert it to Jan 1, 1980 */

    if (tmpTime < (60 * 60 * 24 * (365 * 10 + 3)))
    {
    	tmpTime = 60 * 60 * 24 * (365 * 10 + 3);
    }

    /* decompose into fragments */

    syDecomposeTime(tmpTime, &frag);

    *smbTime = (NQ_UINT16) ((frag.hour << 11) | (frag.min << 5) | (frag.sec + 1) / 2);
    *smbDate = (NQ_UINT16) (((frag.year + 1900 - 1980) << 9) | ((frag.month + 1) << 5) | frag.day);
}

NQ_UINT32
cmTimeConvertMSecToSec(
	NQ_TIME * t
    )
{
	NQ_UINT32 a0;        /* 16 bit, low    bits */
	NQ_UINT32 a1;        /* 16 bit, medium bits */
	NQ_UINT32 a2;        /* 32 bit, high   bits */

	/* Copy the time values to a2/a1/a0 */

	a2 =  t->high;
	a1 = t->low >> 16;
	a0 = t->low & 0xffff;

	/* divide a by 1000 (a = a2/a1/a0), put the rest into r. */

	a1 += (a2 % 1000) << 16;
	a2 /=       1000;
	a0 += (a1 % 1000) << 16;
	a1 /=       1000;
	a0 /=       1000;

	return (a1 << 16) + a0;
}

NQ_TIME cmTimeConvertSecToMSec(NQ_UINT32 secTime)
{
	NQ_TIME curTime;

	cmU64MultU32U32(&curTime, secTime, 1000);

	return curTime;
}
/*
 *====================================================================
 * PURPOSE: converts SMB time & date into UNIX style time
 *--------------------------------------------------------------------
 * PARAMS:  IN SMB time
 *          IN SMB date
 *
 * RETURNS: Unix time
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
cmCifsSmbTimeToTime(
    NQ_UINT16 smbTime,
    NQ_UINT16 smbDate
    )
{
    SYTimeFragments frag;      /* time, decomposed */

    frag.hour  =  (smbTime >> 11) & 0x1F;
    frag.min   = (smbTime >> 5) & 0x3F;
    frag.sec   = (NQ_UINT16)((smbTime & 0x1F) * 2);
    frag.year  = (NQ_UINT16)(((smbDate >> 9) & 0x7F ) + 1980 - 1900);
    frag.month = (NQ_UINT16)(((smbDate >> 5) & 0x0F ) - 1);
    frag.day   = smbDate & 0x1F;

    return (NQ_UINT32)syComposeTime(&frag);
}

/*
 *====================================================================
 * PURPOSE: Convert system time to the UTC format
 *--------------------------------------------------------------------
 * PARAMS:  IN system time
 *          OUT high portion of the UTC
 *          OUT low portion of the UTC
 *
 * RETURNS: NONE
 *
 * NOTES:   We emulate "very long" 64-bit integer by three 32-bit longs.
 *          Two lower values keep 16-bit portions, while the upper 16 bits
 *          are used in add and multiply operations for "carry" to the
 *          next portion.
 *====================================================================
 */

void
cmCifsTimeToUTC(
    NQ_TIME timeConv,
    NQ_UINT32* low,
    NQ_UINT32* high
    )
{
    /* Several constants represent the difference between the UTC (Gregorian)
       time (1-Jan-1601) to the UNIX K & R time (1-Jan-1970).

       The difference between 1 January 1601, 00:00:00 and
       1 January 1970, 00:00:00 is 369 years, plus the leap years
       from 1604 to 1968, excluding 1700, 1800, 1900.
       This makes (1968 - 1600) / 4 - 3 = 89 leap days, and a total
       of 134774 days.

       Any day in that period had 24 * 60 * 60 = 86400 seconds.

       The time difference is 134774 * 86400 * 10000000, which can be written
       116444736000000000 = 27111902 * 2^32 + 3577643008 =
       413 * 2^48 + 45534 * 2^32 + 54590 * 2^16 + 32768 */

    NQ_UINT32 a0;          /* 16 bit, low    bits */
    NQ_UINT32 a1;          /* 16 bit, medium bits */
    NQ_UINT32 a2;          /* 32 bit, high   bits */
    NQ_UINT32 accuracy;    /* system timer accuracy - adds a number of units to the result */
    NQ_TIME zero = {0, 0};

    /* zero-time remains unconverted */
    
    if (!cmU64Cmp(&zero, &timeConv))
    {
        *low = 0;
        *high = 0;
        return;
    }

    accuracy = syGetTimeAccuracy();

    /* copy the time to a2/a1/a0 */

    a0 = timeConv.low & 0xffff;
    a1 = (timeConv.low >> 16) & 0xffff;
    a2 = timeConv.high;

    /* multiply 'a' by 10000 (a = a2/a1/a0). */

    a0 *= 10000;
    a1 = a1 * 10000 + (a0 >> 16);
    a2 = a2 * 10000 + (a1 >> 16);
    a0 &= 0xffff;
    a1 &= 0xffff;

    /* add the time difference and the accuracy of the system timer  */

    a0 += 32768 + (accuracy & 0xffff);
    a1 += 54590 + (accuracy >> 16) + (a0 >> 16);
    a2 += 27111902 + (a1 >> 16);
    a0 &= 0xffff;
    a1 &= 0xffff;

    /* set UTC time */

    *low  = (a1 << 16) + a0;
    *high = a2;
}

/*
 *====================================================================
 * PURPOSE: Convert UTC time to system time
 *--------------------------------------------------------------------
 * PARAMS:  IN high portion of the UTC
 *          IN low portion of the UTC
 *
 * RETURNS: UNIX time
 *
 * NOTES:
 *====================================================================
 */

NQ_TIME
cmCifsUTCToTime(
    NQ_UINT32 low,
    NQ_UINT32 high
    )
{
    NQ_UINT32 a0;        /* 16 bit, low    bits */
    NQ_UINT32 a1;        /* 16 bit, medium bits */
    NQ_UINT32 a2;        /* 32 bit, high   bits */
    NQ_UINT32 r;         /* remainder of division */

    NQ_UINT carry;       /* carry bit for subtraction */
    NQ_BOOL negative;    /* whether a represents a negative value */
    NQ_TIME time;

    /* Copy the time values to a2/a1/a0 */

    a2 =  high;
    a1 = low >> 16;
    a0 = low & 0xffff;

    /* Subtract the time difference */

    if (a0 >= 32768)
    {
        a0 -= 32768;
        carry = 0;
    }
    else
    {
        a0 += (1 << 16) - 32768;
        carry = 1;
    }

    if (a1 >= 54590 + carry)
    {
        a1 -= 54590 + carry;
        carry = 0;
    }
    else
    {
        a1 += (1 << 16) - 54590 - carry;
        carry = 1;
    }

    a2 -= 27111902 + carry;

    /* if 'a' is negative, replace 'a' by (-1-a) */

    negative = (a2 >= ((NQ_UINT32)1) << 31);
    if (negative)
    {
        /* set 'a' to '-a - 1' '(a is a2/a1/a0)' */

        a0 = 0xffff - a0;
        a1 = 0xffff - a1;
        a2 = ~a2;
    }

    /* divide a by 10000 (a = a2/a1/a0), put the rest into r. */

    a1 += (a2 % 10000) << 16;
    a2 /=       10000;
    a0 += (a1 % 10000) << 16;
    a1 /=       10000;
    r   =  a0 % 10000;
    a0 /=       10000;

    /* if a was negative, replace a by (-1-a) and r by (9999999 - r) */

    if (negative)
    {
        /* set a to -a - 1 (a is a2/a1/a0) */

        a0 = 0xffff - a0;
        a1 = 0xffff - a1;
        a2 = ~a2;

        r  = 9999999 - r;
    }

    time.low = (a1 << 16) + a0;
    time.high = a2;

    return time;
}


/*
 *====================================================================
 * PURPOSE: Convert NQ_UINT time to UTC time as string
 *--------------------------------------------------------------------
 * PARAMS:  OUT time string
 *          IN system time
 *
 * RETURNS: TRUE in success FALSE in fail.
 *
 * NOTES: the format is : "@GMT-YYYY.MM.DD-HH.MM.SS"
 *====================================================================
 */
#ifdef CM_NQ_STORAGE
NQ_BOOL
cmU64TimeToString(
    NQ_BYTE * strTime,			  /* utc time as string */
    NQ_UINT64 time				  /* system time */
    )
{
	NQ_TIME t;
    const char* fmt = "@GMT-%Y.%m.%d-%H.%M.%S";

    t = cmCifsUTCToTime(time.low, time.high);

    return syGmtToString(strTime, 200, t.low, fmt);
}
#endif
/*
 *====================================================================
 * PURPOSE: Increment a 64 bit unsigned integer structure
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the 64 bit unsigned integer structure
 *
 * RETURNS: NONE
 *
 * NOTES:   Changes the 64 bit unsigned int value (i += low)
 *====================================================================
 */

void cmU64Inc(NQ_UINT64 *i64)
{
	i64->low++;
	if (i64->low == 0)
		i64->high++;
}

/*
 *====================================================================
 * PURPOSE: Add 32 bit unsigned integer value to 64 bit unsigned
 *          integer structure
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the 64 bit unsigned integer structure
 *          IN 32 bit unsigned integer
 *
 * RETURNS: NONE
 *
 * NOTES:   Changes the 64 bit unsigned int value (i += low)
 *====================================================================
 */

void
cmU64AddU32(
    NQ_UINT64 *i,
    NQ_UINT32 low
    )
{
    NQ_UINT32 old = i->low;

    i->low += low;
    /* check for overflow */
    if (i->low < old || i->low < low)
        i->high++;
}

/*
 *====================================================================
 * PURPOSE: Add 64 bit signed integer to 64 bit unsigned integer (u += s)
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the 64 bit unsigned integer structure
 *          IN pointer to the 64 bit signed integer structure
 *
 * RETURNS: NONE
 *
 * NOTES:   Changes the 64 bit unsigned int value
 *====================================================================
 */
void
cmU64AddS64(
    NQ_UINT64 *u,
    const NQ_INT64 *s
    )
{
    NQ_UINT32 low = u->low;

    if (s->sign == -1)
    {
        u->high -= s->high;
        u->low -= s->low;
        /* check for overflow */
        if (u->low > low && u->low > s->low)
           u->high--;
    }
    else
    {
        u->high += s->high;
        u->low += s->low;
        /* check for overflow */
        if (u->low < low || u->low < s->low)
           u->high++;
    }
}

/*
 *====================================================================
 * PURPOSE: Add 64 bit unsigned integer to 64 bit unsigned integer (u += a)
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the 64 bit unsigned integer structure
 *          IN pointer to the 64 bit unsigned integer structure
 *
 * RETURNS: NONE
 *
 * NOTES:   Changes the 64 bit unsigned int value
 *====================================================================
 */
void
cmU64AddU64(
    NQ_UINT64 *u,
    const NQ_UINT64 *a
    )
{
    NQ_UINT32 low = u->low;

    u->low += a->low;
    /* check for overflow */
    if (u->low < low || u->low < a->low)
       u->high++;

    u->high += a->high;
}

/*
 *====================================================================
 * PURPOSE: 64 bit math (c = a - b)
 *--------------------------------------------------------------------
 * PARAMS:  OUT result
 *          IN  64 bit unsigned integer
 *          IN  64 bit unsigned integer
 *
 * RETURNS: NONE
 *
 * NOTES:   'c' and 'a' must point to different structures
 *====================================================================
 */
void
cmU64SubU64U64(
    NQ_UINT64 *c,
    const NQ_UINT64 *a,
    const NQ_UINT64 *b
    )
{
    c->high = a->high - b->high;
    c->low = a->low - b->low;
    /* check for overflow */
    if (c->low > a->low)
       --c->high;
}

/*
 *====================================================================
 * PURPOSE: Compare two 64 bit unsigned integer values
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the first 64 bit unsigned integer structure
 *          IN pointer to the second 64 bit unsigned integer structure
 *
 * RETURNS: -1 (i < j), 0 (i == j), 1(i > j)
 *
 * NOTES:
 *====================================================================
 */

NQ_INT32
cmU64Cmp(
    NQ_UINT64 *i,
    NQ_UINT64 *j
    )
{
    NQ_INT32 result;

    if (i->high == j->high)
        if (i->low == j->low)
            result = 0;
        else
          result = i->low > j->low ? 1 : -1;
    else
        result = i->high > j->high ? 1 : -1;

    return result;
}

/*
 *====================================================================
 * PURPOSE: Return lower value for two 64 bit unsigned integer values
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the first 64 bit unsigned integer structure
 *          IN pointer to the second 64 bit unsigned integer structure
 *
 * RETURNS: Smaller between i and j
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT64
cmU64Min(
    NQ_UINT64 *i,
    NQ_UINT64 *j
    )
{
    if (i->high == j->high)
        if (i->low == j->low)
            return *i;
        else
          return i->low > j->low ? *j : *i;
    else
        return i->high > j->high ? *j : *i;
}

/*
 *====================================================================
 * PURPOSE: Assignment two 64 bit unsigned integer values (d = s)
 *--------------------------------------------------------------------
 * PARAMS:  OUT result
 * 			IN  64 bit unsigned integer dst
 *          IN  64 bit unsigned integer src
 *
 * RETURNS: NONE
 *
 * NOTES:   Changes the 64 bit unsigned int value
 *====================================================================
 */

void
cmU64AssignU64(
    NQ_UINT64 *d,
    const NQ_UINT64 *s
    )
{
	d->low  = s->low;
	d->high = s->high;
}

/*
 *====================================================================
 * PURPOSE: Multiply two 32 bit unsigned integer values, result 64 bit
 *--------------------------------------------------------------------
 * PARAMS:  OUT 64 bit unsigned integer result of multiplication
 *          IN  32 bit unsigned integer
 *          IN  32 bit unsigned integer
 *
 * RETURNS: none
 *
 * NOTES:
 *====================================================================
 */
void
cmU64MultU32U32(
    NQ_UINT64 *r,
    const NQ_UINT32 i,
    const NQ_UINT32 j
    )
{
    NQ_UINT16 a, b, c, d;
    NQ_UINT32 x, y;

    a = (NQ_UINT16)(i >> 16) & 0xffff;
    b = i & 0xffff;
    c = (NQ_UINT16)(j >> 16) & 0xffff;
    d = j & 0xffff;

    r->low = (NQ_UINT32)(b * d);                   
    x = (NQ_UINT32)(a * d + c * b);            
    y = ((r->low >> 16) & 0xffff) + x;
    r->low = (r->low & 0xffff) | ((y & 0xffff) << 16);
    r->high = (y >> 16) & 0xffff;
    r->high += (NQ_UINT32)(a * c);  
}


/*
 *====================================================================
 * PURPOSE: Multiply two 64 bit unsigned integer values, result 128 bit
 *--------------------------------------------------------------------
 * PARAMS:  OUT 64 bit unsigned integer result of multiplication - low
 *          OUT 64 bit unsigned integer result of multiplication - high
 *          IN  64 bit unsigned integer
 *          IN  64 bit unsigned integer
 *
 * RETURNS: none
 *
 * NOTES:  Karatsuba multiply algorithm
 *====================================================================
 */

void cmU128MultU64U64(
    NQ_UINT64 *resultLow,
    NQ_UINT64 *resultHigh, 
    const NQ_UINT64 *a, 
    const NQ_UINT64 *b 
    )
{
    NQ_UINT32 x0, x1, y0, y1;
    NQ_UINT64 lowWord, midWord, highWord, m1, m2;
    NQ_UINT32 *highByte = &highWord.high;

    x0 = a->low;
    x1 = a->high;
    y0 = b->low;
    y1 = b->high;

    cmU64MultU32U32(&lowWord, x0, y0);  
    cmU64MultU32U32(&highWord, x1, y1);
    cmU64MultU32U32(&m1, x0, y1); 
    cmU64MultU32U32(&m2, x1, y0); 

    midWord.low = lowWord.high;
    midWord.high = highWord.low;
    cmU64AddU64(&midWord, &m1); 

    if (cmU64Cmp(&midWord, &m1) == -1) 
        (*highByte)++; 

    cmU64AddU64(&midWord, &m2); 
    if (cmU64Cmp(&midWord, &m2) == -1) 
        (*highByte)++; 

    resultLow->low = lowWord.low;
    resultLow->high = midWord.low;
    resultHigh->low = midWord.high;
    resultHigh->high = highWord.high;
}

/*
  *====================================================================
 * PURPOSE: get value from 64 bit integer to 32 bit integer
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the 64 bit unsigned integer structure
 *
 * RETURNS: value in 32 bit unsigned integer, if its too high returns max integer.
 *
 * NOTES:
 *====================================================================
*/

NQ_UINT
cmNQ_UINT64toU32(NQ_UINT64 j)
{
	if (j.high > 0)
		return (0xFFFFFFFFL);
	return j.low;
}

#ifdef SY_INT64
NQ_UINT
cmU64toU32(SY_UINT64 j)
{
 if ((j >> 32) > 0)
    	return (0xFFFFFFFFL);
    return (NQ_UINT) j;
}
#endif

