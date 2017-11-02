
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
   (sizeof(_type)==sizeof(NQ_CHAR)? (2 * _num + 2) : _num + 1)

/* Calculate buffer size in bytes */
#define CM_DATALENGTH(_type, _num)  \
   (sizeof(_type) * CM_BUFFERLENGTH(_type, _num))

/* According to whether the host filesystem supports UNICODE, define character type
   for filenames and the appropriate functions. */

#ifdef UD_CM_UNICODEAPPLICATION

#define cmTStrlen      syWStrlen
#define cmTStrcpy      syWStrcpy
#define cmTStrcat      syWStrcat
#define cmTStrncpy     syWStrncpy
#define cmTStrcmp      syWStrcmp
#define cmTStrncmp     syWStrncmp
#define cmTStrincmp    cmWStrincmp
#define cmTStricmp     cmWStricmp
#define cmTStrchr      syWStrchr
#define cmTStrrchr     syWStrrchr
#define cmTStrupr(_s)  cmWStrupr(_s)
#define cmTToupper(_to, _from)    cmWToupper(_to, _from)
#define cmTChar(c)     cmHtol16((NQ_WCHAR)(c&0xff))
#define cmTcharToAnsi(_to, _from)  syUnicodeToAnsi(_to, _from)
#define cmAnsiToTchar(_to, _from)  syAnsiToUnicode(_to, _from)
#define cmTcharToUnicode(_to, _from)    syWStrcpy(_to, _from)
#define cmUnicodeToTchar(_to, _from)    syWStrcpy(_to, _from)
#define cmTcharToAnsiN(_to, _from, _size)   syUnicodeToAnsiN(_to, _from, _size)
#define cmAnsiToTcharN(_to, _from, _size)   syAnsiToUnicodeN(_to, _from, _size)
#define cmTcharToUnicodeN(_to, _from, _size)   syWStrncpy(_to, _from, _size)
#define cmUnicodeToTcharN(_to, _from, _size)   syWStrncpy(_to, _from, _size)
#ifdef UD_CC_INCLUDELDAP
#define cmTcharToUTF8N(_to, _from, _size)   syUnicodeToUTF8N(_to, _from, _size)
#define cmUTF8ToTcharN(_to, _from, _size)   syUTF8ToUnicodeN(_to, _from, _size)
#endif
#define cmTDump(_str)               cmWDump(_str)

#else

#define cmTStrlen      syStrlen
#define cmTStrcpy      syStrcpy
#define cmTStrcat      syStrcat
#define cmTStrncpy     syStrncpy
#define cmTStrcmp      syStrcmp
#define cmTStrncmp     syStrncmp
#define cmTStricmp     cmAStricmp
#define cmTStrincmp    cmAStrincmp
#define cmTStrchr      cmAStrchr
#define cmTStrrchr     cmAStrrchr
#define cmTStrupr(_s)  cmAStrupr(_s)
#define cmTToupper(_to, _from) cmAToupper(_to, _from)
#define cmTChar(_c)    _c
#define cmTcharToAnsi(_to, _from)       syStrcpy(_to, _from)
#define cmAnsiToTchar(_to, _from)     syStrcpy(_to, _from)
#define cmTcharToUnicode(_to, _from)    syAnsiToUnicode(_to, _from)
#define cmUnicodeToTchar(_to, _from)  syUnicodeToAnsi(_to, _from)
#define cmTcharToAnsiN(_to, _from, _size)         syStrncpy(_to, _from, _size)
#define cmAnsiToTcharN(_to, _from, _size)       syStrncpy(_to, _from, _size)
#define cmTcharToUnicodeN(_to, _from, _size)      syAnsiToUnicodeN(_to, _from, _size)
#define cmUnicodeToTcharN(_to, _from, _size)    syUnicodeToAnsiN(_to, _from, _size)
#ifdef UD_CC_INCLUDELDAP
#define cmTcharToUTF8N(_to, _from, _size)   syStrncpy(_to, _from, _size)
#define cmUTF8ToTcharN(_to, _from, _size)   syStrncpy(_to, _from, _size)
#endif
#define cmTDump(_str)               _str

#endif

#ifdef UD_NQ_INCLUDECODEPAGE

#define cmAnsiToFs     cmCpAnsiToFs
#define cmFsToAnsi     cmCpFsToAnsi

#else

#define cmAnsiToFs(_str, _size)
#define cmFsToAnsi(_str, _size)

#endif

#define cmWChar(c)     cmHtol16((NQ_WCHAR)(c&0xff))

/* copy TCHAR string to either ASCII or UNICODE */

NQ_BYTE*                    /* returns address of the first byte after the result */
cmTcharToStr(
    NQ_BYTE *pp,            /* destination */
    const NQ_TCHAR *str,    /* source */
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
