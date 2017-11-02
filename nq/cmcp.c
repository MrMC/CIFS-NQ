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

#include "cmapi.h"
#include "cmcp.h"

#ifdef UD_NQ_INCLUDECODEPAGE

const CMCodepage*
cmCpInit437(
    void
    );

#ifdef UD_NQ_CODEPAGE932
const CMCodepage*
cmCpInit932(
    void
    );
#endif

#ifdef UD_NQ_CODEPAGE862
CMCodepage*
cmCpInit862(
    void
    );
#endif

#ifdef UD_NQ_CODEPAGE850
CMCodepage*
cmCpInit850(
    void
    );
#endif

#ifdef UD_NQ_CODEPAGE852
CMCodepage*
cmCpInit852(
    void
    );
#endif

#ifdef UD_NQ_CODEPAGE858
CMCodepage*
cmCpInit858(
    void
    );
#endif

#ifdef UD_NQ_CODEPAGE936
CMCodepage*
cmCpInit936(
    void
    );
#endif

#ifdef UD_NQ_CODEPAGE950
CMCodepage*
cmCpInit950(
    void
    );
#endif

const CMCodepage* encodings[30];

#if (defined(SY_CP_FIRSTILLEGALCHAR) && defined(SY_CP_ANYILLEGALCHAR))

static const NQ_BYTE firstIllegalChar[] = SY_CP_FIRSTILLEGALCHAR;
static const NQ_BYTE anyIllegalChar[] = SY_CP_ANYILLEGALCHAR;

#define FIRST_ILLEGAL_CHAR_NUM    (sizeof(firstIllegalChar) / sizeof(NQ_BYTE))
#define ANY_ILLEGAL_CHAR_NUM      (sizeof(anyIllegalChar) / sizeof(NQ_BYTE))

#endif /* (defined(SY_CP_FIRSTILLEGALCHAR) && defined(SY_CP_ANYILLEGALCHAR)) */

static
NQ_INT
cmCpGetCodePage(
    void
    );

static
void
cmCpInitEncodings(
    void
    );

NQ_BOOL
cmCodepageAdd(
    const CMCodepage * codePage
    )
{
    NQ_INT index;

    cmCpInitEncodings();

    for (index = 0; index < sizeof(encodings)/sizeof(CMCodepage * ); index++)
    {
        if ( encodings[index] != NULL)
        {
            if (encodings[index]->id == codePage->id)
            {
                encodings[index] = codePage;
                return TRUE;
            }
        }
    }
    for (index = 0; index < sizeof(encodings)/sizeof(CMCodepage *); index++)
    {
        if (encodings[index] == NULL)
        {
            encodings[index] = codePage;
            return TRUE;
        }
    }
    return FALSE;
}
 
/*
Uninstalls code page.
codePage - descriptor should have the same id value as was specified in the cmCodepageAdd call. Other fields are ignored.
This call can also remove a pre-defined page.
  
*/
NQ_BOOL
cmCodepageRemove(
    const CMCodepage * codePage
    )
{
    NQ_INT index;
    
    for (index = 0; index < sizeof(encodings)/sizeof(CMCodepage *); index++)
    {
        
        if ( encodings[index] != NULL)
        {
            if (encodings[index]->id == codePage->id)
            {
                encodings[index] = NULL;
                return TRUE;
            }
        }
    }
    sySetLastError(NQ_ERR_NOTFOUND);
    return FALSE;
}
        

/*
 *====================================================================
 * PURPOSE: Convert Ascii string to Unicode according to codepage
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT result Unicode string
 *          IN Ascii string to be converted
 *          IN length of result Unicode string (in bytes)
 *          IN length of Ascii string (in bytes)
 *
 * RETURNS: length of result string, 0 if failed
 *
 * NOTES:

 *====================================================================
 */

NQ_INT
cmCpAnsiToUnicode(
    NQ_WCHAR* wStr,
    const NQ_CHAR* aStr,
    NQ_INT outLength,
    NQ_INT inLength
    )
{
    NQ_INT codePageIdx = cmCpGetCodePage();

    if (encodings[codePageIdx] != NULL && encodings[codePageIdx]->a2uTab)
        return cmCpSingleByteAnsiToUnicode(wStr, aStr, inLength, outLength, encodings[codePageIdx]->a2uTab);
    
    if (encodings[codePageIdx] != NULL)
        return encodings[codePageIdx]->toUnicode(wStr, aStr, inLength, outLength);
    else
        return 0;
}

/*
 *====================================================================
 * PURPOSE: Convert Unicode string to Ascii according to codepage
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT Ascii result string
 *          IN Unicode string to be converted
 *          IN length of result Ascii string (in bytes)
 *          IN length of Unicode string (in bytes)
 *
 * RETURNS: length of result string, 0 if failed
 *
 * NOTES:

 *====================================================================
 */

NQ_INT
cmCpUnicodeToAnsi(
    NQ_CHAR* aStr,
    const NQ_WCHAR* wStr,
    NQ_INT outLength,
    NQ_INT inLength
    )
{
    NQ_INT codePageIdx = cmCpGetCodePage();

    if (encodings[codePageIdx] != NULL)
        return encodings[codePageIdx]->toAnsi(aStr, wStr, inLength, outLength);
    else
        return 0;
}

/*
 *====================================================================
 * PURPOSE: Capitalize a single Ascii symbol
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT pointer to result
 *          IN pointer to character to be converted
 *
 * RETURNS: length of result string, 0 if failed
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
cmCpAToUpper(
    NQ_CHAR* dest,
    const NQ_CHAR* src
    )
{
    NQ_INT codePageIdx = cmCpGetCodePage();

    if (encodings[codePageIdx] != NULL)
        return encodings[codePageIdx]->toUpper(dest, src);
    else
        return 0;
}

/*
 *====================================================================
 * PURPOSE: convert string from ANSI with possible two-byte encoding
 *          to a string acceptable by the file system as a file name
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT Ascii string/converted string
 *          IN its lenth before and after conversion
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
cmCpAnsiToFs(
    NQ_CHAR *str,
    NQ_INT size
    )
{
#if (defined(SY_CP_FIRSTILLEGALCHAR) && defined(SY_CP_ANYILLEGALCHAR))
    NQ_INT codePageIdx = cmCpGetCodePage();
    if (encodings[codePageIdx] != NULL && encodings[codePageIdx]->ansiToFs)
    {
        encodings[codePageIdx]->ansiToFs(str, size, firstIllegalChar,
                                         anyIllegalChar, FIRST_ILLEGAL_CHAR_NUM, ANY_ILLEGAL_CHAR_NUM );
    }
#endif
}

/*
 *====================================================================
 * PURPOSE: convert file name (encoded by the previous call)
 *          into a valid ANSI string
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT Ascii string/converted string
 *          IN its lenth before and after conversion
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
cmCpFsToAnsi(
    NQ_CHAR *str,
    NQ_INT size
    )
{
#if (defined(SY_CP_FIRSTILLEGALCHAR) && defined(SY_CP_ANYILLEGALCHAR))
    NQ_INT codePageIdx = cmCpGetCodePage();
    if (encodings[codePageIdx] != NULL && encodings[codePageIdx]->fsToAnsi)
    {
        encodings[codePageIdx]->fsToAnsi(str, size, firstIllegalChar,
                                         anyIllegalChar, FIRST_ILLEGAL_CHAR_NUM, ANY_ILLEGAL_CHAR_NUM );
    }
#endif
}


NQ_INT
cmCpSingleByteAnsiToUnicode(
    NQ_WCHAR* wStr,
    const NQ_CHAR* aStr,
    NQ_INT inLength,
    NQ_INT outLength,
    const NQ_WCHAR* a2uTable
    )
{
    NQ_WCHAR* pW = wStr;
    const NQ_CHAR* pA = aStr;
    NQ_INT length = 0;
    NQ_BOOL ignoreInLength = (inLength == -1);
    NQ_BOOL ignoreOutLength = (outLength == -1);

    if (wStr && aStr)
    {
        for ( ; *pA && (ignoreInLength || inLength) && (ignoreOutLength || (length < outLength)); pA++, pW++, inLength--, length++)
        {
            NQ_BYTE a = (NQ_BYTE)*pA;

            if ( a <= 0x7F)
            {
                *pW = cmHtol16((NQ_WCHAR)a);
            }
            else
            {
                *pW = cmHtol16(a2uTable[a-0x80]);
            }
        }
    }
    else
    {
        if (!wStr)
            return 0;
    }

    if (ignoreOutLength || (length < outLength))
        *pW = 0;

    return length*2;
}

static
NQ_INT
cmCpGetCodePage(
    void
    )
{
    NQ_INT i = 0;
    NQ_INT codePage = udGetCodePage();

    cmCpInitEncodings();
  
    for (i = 0; i < sizeof(encodings)/sizeof(CMCodepage *); i++)
    {
        if (encodings[i] != NULL)
        {
            if (encodings[i]->id == codePage)
                return i;
        }
    }
    for (i = 0; i < sizeof(encodings)/sizeof(CMCodepage *); i++)
    {
        if (encodings[i] != NULL)
        {
            return i;  /* return first existing codepage*/
        }
    }
    return 0;
}

static
void
cmCpInitEncodings(
    void
    )
{
    static NQ_BOOL isInit = FALSE;
    NQ_INT index;

    if(!isInit)
    {
    	isInit = TRUE;
        for (index = 0; index < sizeof(encodings)/sizeof(CMCodepage *); index++)
        {
            encodings[index] = NULL;
        }
        cmCodepageAdd(cmCpInit437());

#ifdef UD_NQ_CODEPAGE932
        cmCodepageAdd(cmCpInit932());
#endif

#ifdef UD_NQ_CODEPAGE862
        cmCodepageAdd(cmCpInit862());
#endif

#ifdef UD_NQ_CODEPAGE850
        cmCodepageAdd(cmCpInit850());
#endif

#ifdef UD_NQ_CODEPAGE852
        cmCodepageAdd(cmCpInit852());
#endif

#ifdef UD_NQ_CODEPAGE858
        cmCodepageAdd(cmCpInit858());
#endif

    }
    return;
}


void cmSplitUint16(NQ_UINT16 src, NQ_BYTE *msb, NQ_BYTE *lsb)
{                                    
    *lsb = (NQ_BYTE)(src);         
    *msb = (NQ_BYTE)((src) >> 8);  
}

void cmSplitUnicode(NQ_WCHAR src, NQ_BYTE *msb, NQ_BYTE *lsb)
{                                  
    NQ_WCHAR _u = cmLtoh16(src);
    cmSplitUint16(_u, msb, lsb);
}

#endif /* UD_NQ_INCLUDECODEPAGE*/

