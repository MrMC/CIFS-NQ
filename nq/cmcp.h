/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Code page module, CP API functions
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 12-Sept-2005
 * CREATED BY    : Jenya Rivkin
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CMCP_H_
#define _CMCP_H_

#ifdef UD_NQ_INCLUDECODEPAGE
#include "cmapi.h"


typedef struct _range {
    NQ_WCHAR start;
    NQ_WCHAR end;
    NQ_WCHAR diff;
} CMCPRange;

NQ_INT
cmCpAnsiToUnicode(
    NQ_WCHAR* wStr,
    const NQ_CHAR* aStr,
    NQ_INT outLength,
    NQ_INT inLength
    );

NQ_INT
cmCpUnicodeToAnsi(
    NQ_CHAR* aStr,
    const NQ_WCHAR* wStr,
    NQ_INT outLength,
    NQ_INT inLength
    );


NQ_INT
cmCpAToUpper(
    NQ_CHAR* dst,
    const NQ_CHAR* src
    );

NQ_INT
cmCpWToUpper(
    NQ_WCHAR* dst,
    const NQ_WCHAR* src
);

void
cmCpAnsiToFs(
    NQ_CHAR *str,
    NQ_INT size
    );

void
cmCpFsToAnsi(
    NQ_CHAR *str,
    NQ_INT size
    );

NQ_INT
cmCpSingleByteAnsiToUnicode(
    NQ_WCHAR* wStr,
    const NQ_CHAR* aStr,
    NQ_INT inLength,
    NQ_INT outLength,
    const NQ_WCHAR* a2uTable
    );

void cmSplitUint16(NQ_WCHAR src, NQ_BYTE *msb, NQ_BYTE *lsb);

void cmSplitUnicode(NQ_WCHAR src, NQ_BYTE *msb, NQ_BYTE *lsb);


#endif /* UD_NQ_INCLUDECODEPAGE */
#endif /* _CMCP_H_ */
