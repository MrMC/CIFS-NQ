
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Unicode string manipulation
 *--------------------------------------------------------------------
 * MODULE        : CM - Common Library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 26-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMUNICOD_H_
#define _CMUNICOD_H_

#include "cmapi.h"

#define cmWideCharToMultiByte 	cmUnicodeToAnsi
#define cmMultiByteToWideChar 	cmAnsiToUnicode

/* equivalents to the ansiString ANSI functions */

NQ_UINT
cmWStrlen(
    const NQ_WCHAR* s
    );

void
cmWStrcpy(
    NQ_WCHAR* to,
    const NQ_WCHAR* from
    );

void
cmWStrcat(
    NQ_WCHAR* to,
    const NQ_WCHAR* from
    );

NQ_UINT
cmWStrncpy(
    NQ_WCHAR* to,
    const NQ_WCHAR* from,
    NQ_UINT n
    );

NQ_INT
cmWStrcmp(
    const NQ_WCHAR* s1,
    const NQ_WCHAR* s2
    );

NQ_INT
cmWStrncmp(
    const NQ_WCHAR* s1,
    const NQ_WCHAR* s2,
    NQ_UINT n
    );

NQ_INT
cmWStricmp(
    const NQ_WCHAR* s1,
    const NQ_WCHAR* s2
    );

NQ_INT
cmWStrincmp(
    const NQ_WCHAR* s1,
    const NQ_WCHAR* s2,
    NQ_UINT n
    );

NQ_WCHAR*
cmWStrchr(
    const NQ_WCHAR* s,
    NQ_WCHAR c
    );

NQ_WCHAR*
cmWStrrchr(
    const NQ_WCHAR* s,
    NQ_WCHAR c
    );

void
cmUnicodeToAnsi(
    NQ_CHAR *s,
    const NQ_WCHAR* w
    );

void
cmAnsiToUnicode(
    NQ_WCHAR* w,
    const NQ_CHAR *s
    );

void
cmUnicodeToAnsiN(
    NQ_CHAR *s,
    const NQ_WCHAR* w,
    NQ_UINT size
    );

void
cmAnsiToUnicodeN(
    NQ_WCHAR* w,
    const NQ_CHAR *s,
    NQ_UINT size
    );

NQ_CHAR*
cmWDump(
    const NQ_WCHAR* w
    );

void
cmWStrupr(
    NQ_WCHAR* s
    );

NQ_INT
cmWToupper(
    NQ_WCHAR *to,
    const NQ_WCHAR *from
    );

#endif  /* _CMUNICOD_H_ */
