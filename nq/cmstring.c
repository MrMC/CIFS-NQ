
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : String operations
 *--------------------------------------------------------------------
 * MODULE        : CM - Common Library
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 02-July-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cmapi.h"

#ifdef UD_NQ_INCLUDECODEPAGE
#include "cmcp.h"
#endif

/*
 *====================================================================
 * PURPOSE: Compare two strings ignoring case
 *--------------------------------------------------------------------
 * PARAMS:  IN first string
 *          IN second string
 *
 * RETURNS: -1, 0, 1
 *
 * NOTES:

 *====================================================================
 */

NQ_INT
cmAStricmp(
    const NQ_CHAR* s1,
    const NQ_CHAR* s2
    )
{
#ifdef UD_NQ_INCLUDECODEPAGE
    NQ_CHAR c1[2], c2[2];
    NQ_INT l1, l2;
    for (;;)
    {
        c1[1] = c2[1] = 0;
        l1 = cmCpAToUpper(c1, s1);
        l2 = cmCpAToUpper(c2, s2);
        if (l1 != l2 || c1[0] != c2[0] || (l1 == 2 && c1[1] != c2[1]))
            break;
        if (c1[0] == 0)
            return 0;
        s1 += l1;
        s2 += l2;
    }
    return (c1[0] == c2[0]) ? (c1[1] - c2[1]) : (c1[0] - c2[0]);
#else
    NQ_CHAR c1, c2;
    for (;;)
    {
        c1 = *s1++;
        c2 = *s2++;

        c1 = syToupper(c1);
        c2 = syToupper(c2);
        if (c1 != c2)
            break;
        if (c1 == 0)
            break;
    }
    return (c1 - c2);
#endif
}

/*
 *====================================================================
 * PURPOSE: Compare the beginning of two strings ignoring case
 *--------------------------------------------------------------------
 * PARAMS:  IN first string
 *          IN second string
 *          IN number of chars to compare
 *
 * RETURNS: -1, 0, 1
 *
 * NOTES:

 *====================================================================
 */

NQ_INT
cmAStrincmp(
    const NQ_CHAR* s1,
    const NQ_CHAR* s2,
    NQ_COUNT n
    )
{
#ifdef UD_NQ_INCLUDECODEPAGE
    NQ_CHAR c1[2], c2[2];
    for (;;)
    {
        NQ_INT l1, l2;
        l1 = cmCpAToUpper(c1, s1);
        l2 = cmCpAToUpper(c2, s2);

        if (l1 != l2 || c1[0] != c2[0] || (l1 == 2 && c1[1] != c2[1]))
            break;
        n -= (NQ_COUNT)l1;
        if (n <= 0 || c1[0] == 0)
            break;
        s1 += l1;
        s2 += l2;
    }
    if (n <= 0)
        return (NQ_INT)n; /* if n == -1, the input is wrong and an error is returned */
    return (c1[0] == c2[0]) ? (c1[1] - c2[1]) : (c1[0] - c2[0]);
#else
    NQ_CHAR c1, c2;

    for (;;)
    {
        c1 = *s1++;
        c2 = *s2++;
        c1 = syToupper(c1);
        c2 = syToupper(c2);

        if (c1 != c2 || n-- <= 0)
            break;
        if (c1 == 0)
            return 0;
    }
    if (n == 0)
        return 0;
    return c1 - c2;
#endif
}

/*
 *====================================================================
 * PURPOSE: Convert string to uppercase
 *--------------------------------------------------------------------
 * PARAMS:  IN string
 *
 * RETURNS: none
 *
 * NOTES:

 *====================================================================
 */

void
cmAStrupr(
    NQ_CHAR* s
    )
{
#ifdef UD_NQ_INCLUDECODEPAGE
    while (*s != 0)
    {
        s += cmCpAToUpper(s, s);
    }
#else
    while ((*s = syToupper(*s)) != 0)
    {
        s++;
    }
#endif
}

/*
 *====================================================================
 * PURPOSE: Copy TCHAR string to either ASCII or UNICODE
 *--------------------------------------------------------------------
 * PARAMS:  IN destination
 *          IN source
 *          IN unicode flag
 *
 * RETURNS: pointer to the first byte after the result
 *
 * NOTES:
 *====================================================================
 */

NQ_BYTE*
cmTcharToStr(
    NQ_BYTE *pp,
    const NQ_TCHAR *str,
    NQ_BOOL useUnicode
    )
{
    if (useUnicode)
    {
        cmTcharToUnicode((NQ_WCHAR*)pp, str);
        pp = cmAllignTwo(pp);
        pp += (syWStrlen((NQ_WCHAR*)pp) + 1) * sizeof(NQ_WCHAR);
    }
    else
    {
        cmTcharToAnsi((NQ_CHAR*)pp, str);
        pp += syStrlen((NQ_CHAR*)pp) + sizeof(NQ_CHAR);
    }

    return pp;
}

/*
 *====================================================================
 * PURPOSE: Copy ASCII string to either ASCII or UNICODE
 *--------------------------------------------------------------------
 * PARAMS:  IN destination
 *          IN source
 *          IN unicode flag
 *
 * RETURNS: pointer to the first byte after the result
 *
 * NOTES:
 *====================================================================
 */

NQ_BYTE*
cmAnsiToStr(
    NQ_BYTE *pp,
    const NQ_CHAR *str,
    NQ_BOOL useUnicode
    )
{
    if (useUnicode)
    {
        syAnsiToUnicode((NQ_WCHAR*)pp, str);
        pp = cmAllignTwo(pp);
        pp += (syWStrlen((NQ_WCHAR*)pp) + 1) * sizeof(NQ_WCHAR);
    }
    else
    {
        syStrcpy((NQ_CHAR*)pp, str);
        pp += syStrlen((NQ_CHAR*)pp) + sizeof(NQ_CHAR);
    }

    return pp;
}

/*
 *====================================================================
 * PURPOSE: Copy UNICODE string to either UNICODE or ASCII
 *--------------------------------------------------------------------
 * PARAMS:  IN destination
 *          IN source
 *          IN unicode flag
 *
 * RETURNS: pointer to the first byte after the result
 *
 * NOTES:
 *====================================================================
 */

NQ_BYTE*
cmUnicodeToStr(
    NQ_BYTE *pp,
    const NQ_WCHAR *str,
    NQ_BOOL useUnicode
    )
{
    if (useUnicode)
    {
        syWStrcpy((NQ_WCHAR*)pp, str);
        pp = cmAllignTwo(pp);
        pp += (syWStrlen((NQ_WCHAR*)pp) + 1) * sizeof(NQ_WCHAR);
    }
    else
    {
        syUnicodeToAnsi((NQ_CHAR*)pp, str);
        pp += syStrlen((NQ_CHAR*)pp) + sizeof(NQ_CHAR);
    }

    return pp;
}

/*
 *====================================================================
 * PURPOSE: Convert ASCII character to uppercase
 *--------------------------------------------------------------------
 * PARAMS:  IN destination
 *          IN source
 *
 * RETURNS: length (in bytes) of the converted character
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
cmAToupper(
    NQ_CHAR* dst,
    const NQ_CHAR* src
    )
{
#ifdef UD_NQ_INCLUDECODEPAGE
    return cmCpAToUpper(dst, src);
#else
    *dst = syToupper(*src);
    return 1;
#endif
}

/*
 *====================================================================
 * PURPOSE: Find a character in a string
 *--------------------------------------------------------------------
 * PARAMS:  IN Null-terminated string to search
 *          IN Character to be located
 *
 * RETURNS: pointer to the first occurrence of c in str, or NULL if c is not found
 *
 * NOTES:
 *====================================================================
 */

NQ_CHAR*
cmAStrchr(
    const NQ_CHAR* str,
    NQ_INT c
    )
{
#ifdef UD_NQ_INCLUDECODEPAGE
    while (*str)
    {
        NQ_CHAR upperStr[2];
        NQ_INT len = cmAToupper(upperStr, str);

        if (len == 1 && *str == c)
        {
            return (NQ_CHAR*)str;
        }
        str += len;
    }
    return NULL;
#else
    return syStrchr(str, c);
#endif

}

/*
 *====================================================================
 * PURPOSE: Scan a string for the last occurrence of a character
 *--------------------------------------------------------------------
 * PARAMS:  IN Null-terminated string to search
 *          IN Character to be located
 *
 * RETURNS: pointer to the last occurrence of c in str, or NULL if c is not found
 *
 * NOTES:
 *====================================================================
 */

NQ_CHAR*
cmAStrrchr(
    const NQ_CHAR* str,
    NQ_INT c
    )
{
#ifdef UD_NQ_INCLUDECODEPAGE
    NQ_CHAR* pFound = NULL;

    while (*str)
    {
        NQ_CHAR upperStr[2];
        NQ_INT len = cmAToupper(upperStr, str);

        if (len == 1 && *str == c)
        {
            pFound = (NQ_CHAR*)str;
        }
        str += len;
    }
    return pFound;
#else
    return syStrrchr(str, c);
#endif

}
