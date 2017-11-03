/*********************************************************************
 *
 *           Copyright (c) 2005 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Codepage UTF-8
 *--------------------------------------------------------------------
 * MODULE        : CM - Common library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 23-Jan-2006
 * CREATED BY    : Jenya Rivkin
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"
#include "cmcp.h"
#include "syopsyst.h"


#ifdef UD_NQ_CODEPAGEUTF8

static NQ_INT
cp8Utf8ToUtf16LE(
    NQ_WCHAR* wStr,
    const NQ_CHAR* aStr,
    NQ_INT inLength,
    NQ_INT outLength
    )
{
    NQ_CHAR *outStr = (NQ_CHAR*)wStr;
    /* regular call the out length is set to -1. but iconv can't recieve -1.*/
    NQ_UINT32 outLen;
    NQ_UINT32 inLen = (NQ_UINT32)inLength;
    if (outLength < 0 || outLength < inLength / 2)
        outLen = (NQ_UINT32)(inLength * 2 + 1);
    else 
        outLen = (NQ_UINT32)outLength * 2;

    return (NQ_INT)convertCodePageUTF8toUtf16LE((NQ_CHAR**)&aStr, &inLen, &outStr, &outLen);   
}

static NQ_INT
cp8Utf16LEToUtf8(
    NQ_CHAR* aStr,
    const NQ_WCHAR* wStr,
    NQ_INT inLength,
    NQ_INT outLength
    )
{
    NQ_CHAR *inStr = (NQ_CHAR*)wStr;
    NQ_UINT32 outLen;
    NQ_UINT32 inLen = (NQ_UINT32)inLength * 2;
    if (outLength < 0 || outLength < inLength * 2)
        outLen = (NQ_UINT32)(inLength / 2 + 1);
    else 
        outLen = (NQ_UINT32)outLength / 2 + 1;

    return (NQ_INT)convertCodePageUtf16LEtoUTF8(&inStr, &inLen, &aStr, &outLen);
}

static NQ_INT
cpUtf8ToUpper(
    NQ_CHAR* dst,
    const NQ_CHAR* src
    )
{
    *dst = syToupper(*src);
    return 1;
}

const static CMCodepage encUTF8 = {
    UD_NQ_CODEPAGEUTF8,
    cp8Utf16LEToUtf8,
    cp8Utf8ToUtf16LE,
    cpUtf8ToUpper,
    NULL,
    NULL,
    NULL
};

const CMCodepage* cmCpInitUtf8(
    void
    )
{
    initCodePageUTF8();
    return &encUTF8;
}


#endif

