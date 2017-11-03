
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : String manipulations
 *--------------------------------------------------------------------
 * MODULE        : CN - Common Library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMSTRING_H_
#define _CMSTRING_H_

#include "cmapi.h"

/* Calculate buffer size according to string character type.
    For Unicode buffer is allocated as N + 1 2-byte characters.
    For ASCII string buffer is allocated as 2 * N + 1 bytes because
    of two-byte ASCII encoding */
#define CM_BUFFERLENGTH(_type, _num)  \
   (sizeof(_type) * (_num + 1))

/* Calculate buffer size in bytes */
#define CM_DATALENGTH(_type, _num)  \
   (sizeof(_type) * CM_BUFFERLENGTH(_type, _num))

/* According to whether the host filesystem supports UNICODE, define character type
   for filenames and the appropriate functions. */

#define cmAnsiToUnicodeN(_to, _from, _size)   syAnsiToUnicodeN(_to, _from, _size)

#ifdef UD_CM_UNICODEAPPLICATION

#define cmTcharToUnicode(_to, _from)    syWStrcpy(_to, _from)
#define cmUnicodeToTchar(_to, _from)    syWStrcpy(_to, _from)

#else /* UD_CM_UNICODEAPPLICATION */

#define cmTcharToUnicode(_to, _from)    cmAnsiToUnicode(_to, _from)
#define cmUnicodeToTchar(_to, _from)    cmUnicodeToAnsi(_to, _from)

#endif /* UD_CM_UNICODEAPPLICATION */

#ifdef UD_CC_INCLUDELDAP
#define cmUnicodeToUTF8N(_to, _from, _size)   syUnicodeToUTF8N(_to, _from, _size)
#define cmUTF8ToUnicodeN(_to, _from, _size)   syUTF8ToUnicodeN(_to, _from, _size)
#endif /* UD_CC_INCLUDELDAP */

#ifdef UD_NQ_INCLUDECODEPAGE

#define cmAnsiToFs     cmCpAnsiToFs
#define cmFsToAnsi     cmCpFsToAnsi

#else

#define cmAnsiToFs(_str, _size)
#define cmFsToAnsi(_str, _size)

#endif

#define cmWChar(c)     cmHtol16((NQ_WCHAR)(c&0xff))

#define CM_WCHAR_NULL_STRING {cmWChar('/'), cmWChar(0)}

/* copy WCHAR string to either ASCII or UNICODE */

NQ_BYTE*                    /* returns address of the first byte after the result */
cmWcharToStr(
    NQ_BYTE *pp,            /* destination */
    const NQ_WCHAR *str,    /* source */
    NQ_BOOL useUnicode      /* unicode flag */
    );

/* copy ASCII string to either ASCII or UNICODE */

NQ_BYTE*                    /* returns address of the first byte after the result */
cmAnsiToStr(
    NQ_BYTE *pp,            /* destination */
    const NQ_CHAR *str,     /* source */
    NQ_BOOL useUnicode      /* unicode flag */
    );

/* copy UNICODE string to either UNICODE or ASCII */

NQ_BYTE*                    /* returns address of the first byte after the result */
cmUnicodeToStr(
    NQ_BYTE *pp,            /* destination */
    const NQ_WCHAR *str,    /* source */
    NQ_BOOL useUnicode      /* unicode flag */
    );

/* compare two strings ignoring case */

NQ_INT                         /* -1, 0, 1 */
cmAStricmp(
    const NQ_CHAR* s1,    /* first string */
    const NQ_CHAR* s2     /* second string */
    );

/* compare the beginning of two strings ignoring case */

NQ_INT                         /* -1, 0, 1 */
cmAStrincmp(
    const NQ_CHAR* s1,    /* first string */
    const NQ_CHAR* s2,    /* second string */
    NQ_COUNT n            /* number of chars to compare */
    );

/* convert string to uppercase */

void
cmAStrupr(
    NQ_CHAR* s
    );

/* convert a character to uppercase */

NQ_INT
cmAToupper(
    NQ_CHAR* dst,
    const NQ_CHAR* src
    );

/* Find a character in a string */

NQ_CHAR*
cmAStrchr(
    const NQ_CHAR* str,
    NQ_INT c
    );

/* Scan a string for the last occurrence of a character */

NQ_CHAR*
cmAStrrchr(
    const NQ_CHAR* str,
    NQ_INT c
    );

#endif  /* _CMSTRING_H_ */
