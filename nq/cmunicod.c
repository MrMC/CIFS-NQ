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

#include "cmunicod.h"

#define CM_WDUMP_NUMOFCHARS UD_FS_FILENAMELEN

/* This file implements UNICODE equivalents to the ansiString.h functions
   We assume that strings is not necessarily word aligned. */
   
typedef struct{
    NQ_WCHAR start;
    NQ_WCHAR end;
    NQ_WCHAR diff;
} CMRange;

static const CMRange plainRangeTable[] = {
    {0x0061, 0x007a, 0x0020},
    {0x00e0, 0x00f6, 0x0020},
    {0x00f8, 0x00fe, 0x0020},
    {0x00ff, 0x00ff, 0xff87},
    {0x0188, 0x0188, 0x0001},
    {0x018C, 0x018C, 0x0001},
    {0x0192, 0x0192, 0x0001},
    {0x0199, 0x0199, 0x0001},
    {0x01a8, 0x01a8, 0x0001},
    {0x01ad, 0x01ad, 0x0001},
    {0x01b0, 0x01b0, 0x0001},
    {0x01b9, 0x01b9, 0x0001},
    {0x01bd, 0x01bd, 0x0001},
    {0x01c6, 0x01c6, 0x0002},
    {0x01c9, 0x01c9, 0x0002},
    {0x01cc, 0x01cc, 0x0002},
    {0x01DD, 0x01dd, 0x004f},
    {0x01f3, 0x01f3, 0x0002},
    {0x01F5, 0x01f5, 0x0001},
    {0x0253, 0x0253, 0x00d2},
    {0x0254, 0x0254, 0x00ce},
    {0x0256, 0x0257, 0x00cd},
    {0x0259, 0x0259, 0x00ca},
    {0x025b, 0x025b, 0x00cb},
    {0x0260, 0x0260, 0x00cd},
    {0x0263, 0x0263, 0x00cf},
    {0x0268, 0x0268, 0x00d1},
    {0x0269, 0x0269, 0x00d3},
    {0x026F, 0x026F, 0x00d3},
    {0x0272, 0x0272, 0x00d5},
    {0x0275, 0x0275, 0x00d6},
    {0x0283, 0x0283, 0x00da},
    {0x0288, 0x0288, 0x00da},
    {0x028A, 0x028b, 0x00d9},
    {0x0292, 0x0292, 0x00db},
    {0x03ac, 0x03ac, 0x0026},
    {0x03ad, 0x03af, 0x0025},
    {0x03b1, 0x03c1, 0x0020},
    {0x03c2, 0x03c2, 0x001f},
    {0x03c3, 0x03cb, 0x0020},
    {0x03cc, 0x03cc, 0x0040},
    {0x03cd, 0x03ce, 0x003f},
    {0x0430, 0x044f, 0x0020},
    {0x0451, 0x045c, 0x0050},
    {0x045e, 0x045f, 0x0050},
    {0x04c8, 0x04c8, 0x0001},
    {0x04cc, 0x04cc, 0x0001},
    {0x04f9, 0x04f9, 0x0001},
    {0x0561, 0x0586, 0x0030},
    {0x1f00, 0x1f07, 0xfff8},
    {0x1f10, 0x1f15, 0xfff8},
    {0x1f20, 0x1f27, 0xfff8},
    {0x1f30, 0x1f37, 0xfff8},
    {0x1f40, 0x1f45, 0xfff8},
    {0x1f60, 0x1f67, 0xfff8},
    {0x1f70, 0x1f71, 0xffb6},
    {0x1f72, 0x1f75, 0xffaa},
    {0x1f76, 0x1f77, 0xff9c},
    {0x1f78, 0x1f79, 0xff80},
    {0x1f7a, 0x1f7b, 0xff90},
    {0x1f7c, 0x1f7d, 0xff82},
    {0x1fb0, 0x1fb1, 0xfff8},
    {0x1fd0, 0x1fd1, 0xfff8},
    {0x1fe0, 0x1fe1, 0xfff8},
    {0x1fe5, 0x1fe5, 0xfff9},
    {0x2170, 0x217f, 0x0010},
    {0x24d0, 0x24e9, 0x001a},
    {0xff41, 0xff5a, 0x0020}
};

#define PLAIN_TABLE_SIZE (sizeof(plainRangeTable) / sizeof(CMRange))

static const CMRange oddRangeTable[] = {
    {0x0101, 0x012f, 0x0001},
    {0x0133, 0x0137, 0x0001},
    {0x013a, 0x0148, 0x0001},
    {0x014b, 0x0177, 0x0001},
    {0x017a, 0x017e, 0x0001},
    {0x0183, 0x0185, 0x0001},
    {0x01a1, 0x01a5, 0x0001},
    {0x01b4, 0x01b6, 0x0001},
    {0x01ce, 0x01dc, 0x0001},
    {0x01df, 0x01ef, 0x0001},
    {0x01fb, 0x0217, 0x0001},
    {0x03e3, 0x03ef, 0x0001},
    {0x0461, 0x0481, 0x0001},
    {0x0491, 0x04bf, 0x0001},
    {0x04c2, 0x04c4, 0x0001},
    {0x04d1, 0x04eb, 0x0001},
    {0x04ef, 0x04f5, 0x0001},
    {0x1e01, 0x1ef9, 0x0001},
    {0x1f51, 0x1f57, 0xfff8}
};

#define ODD_TABLE_SIZE (sizeof(oddRangeTable) / sizeof(CMRange))

/* convert one character to upper case */
static NQ_WCHAR     /* converted character */
unicodeToupper(
    NQ_WCHAR w      /* source character */
    );
    
/*
 *====================================================================
 * PURPOSE: Calculate string length
 *--------------------------------------------------------------------
 * PARAMS:  IN source string
 *
 * RETURNS: number of characters in the string not including the
 *          terminator
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT
cmWStrlen(
    const NQ_WCHAR* s
    )
{
    const NQ_WCHAR* p;

    p = (NQ_WCHAR*)cmAllignTwo(s);
    while (*p++)
    {};
    return (NQ_UINT)((NQ_BYTE*)(--p) - (NQ_BYTE*)s)/sizeof(NQ_WCHAR);
}

/*
 *====================================================================
 * PURPOSE: Copy a string
 *--------------------------------------------------------------------
 * PARAMS:  OUT destination string
 *          IN source string
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
cmWStrcpy(
    NQ_WCHAR* to,
    const NQ_WCHAR* from
    )
{
    to = (NQ_WCHAR*)cmAllignTwo(to);
    from = (NQ_WCHAR*)cmAllignTwo(from);
    do
    {
        *to++ = *from++;
    }
    while (*(from-1));
}


/*
 *====================================================================
 * PURPOSE: Concatenate two strings
 *--------------------------------------------------------------------
 * PARAMS:  OUT destination string
 *          IN source string
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
cmWStrcat(
    NQ_WCHAR* to,
    const NQ_WCHAR* from
    )
{
    to += cmWStrlen(to);
    from = (NQ_WCHAR*)cmAllignTwo(from);
    do
    {
        *to++ = *from++;
    }
    while (*(from-1));
}

/*
 *====================================================================
 * PURPOSE: Copy a string
 *--------------------------------------------------------------------
 * PARAMS:  OUT destination string
 *          IN source string
 *          IN number of UNICODE characters
 *
 * RETURNS: Number of copied characters
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT
cmWStrncpy(
    NQ_WCHAR* to,
    const NQ_WCHAR* from,
    NQ_UINT n
    )
{
    NQ_UINT n1;

    if (0 == n)
        return 0;
    to = (NQ_WCHAR*)cmAllignTwo(to);
    from = (const NQ_WCHAR*)cmAllignTwo(from);
    n1 = n;
    do
    {
        *to++ = *from++;
    }
    while (--n1 && *(from -1));
    return n - n1;
}

/*
 *====================================================================
 * PURPOSE: Compare two strings
 *--------------------------------------------------------------------
 * PARAMS:  IN first string
 *          IN second string
 *
 * RETURNS: 1, 0, -1
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
cmWStrcmp(
    const NQ_WCHAR* s1,
    const NQ_WCHAR* s2
    )
{
    s1 = (const NQ_WCHAR*)cmAllignTwo(s1);
    s2 = (const NQ_WCHAR*)cmAllignTwo(s2);
    while (*s1 == *s2)
    {
        if (*s1 == 0)
            return 0;
        s1++;
        s2++;
    }

    return *s1 - *s2;
}

/*
 *====================================================================
 * PURPOSE: Compare the rightmost fragments of two strings
 *--------------------------------------------------------------------
 * PARAMS:  IN first string
 *          IN second string
 *          IN number of characters to compare
 *
 * RETURNS: 1, 0, -1
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
cmWStrncmp(
    const NQ_WCHAR* s1,
    const NQ_WCHAR* s2,
    NQ_UINT n
    )
{
    if (0 == n)
            return 0;
    s1 = (const NQ_WCHAR*)cmAllignTwo(s1);
    s2 = (const NQ_WCHAR*)cmAllignTwo(s2);
    while (*s1 == *s2 && n-- > 0)
    {
        if (*s1 == 0)
            return 0;
        s1++;
        s2++;
    }
    return ( n==0 )? 0 : *s1 - *s2;
}

/*
 *====================================================================
 * PURPOSE: Compare the two strings ignoring case
 *--------------------------------------------------------------------
 * PARAMS:  IN first string
 *          IN second string
 *
 * RETURNS: 1, 0, -1
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
cmWStricmp(
    const NQ_WCHAR* s1,
    const NQ_WCHAR* s2
    )
{
    NQ_WCHAR c1, c2;

    s1 = (const NQ_WCHAR*)cmAllignTwo(s1);
    s2 = (const NQ_WCHAR*)cmAllignTwo(s2);
    for (;;)
    {
        c1 = *s1++;
        c2 = *s2++;
        c1 = unicodeToupper(c1);
        c2 = unicodeToupper(c2);
        if (c1 != c2)
            break;
        if (c1 == 0)
            break;
    }

    return (c1 - c2);
}

/*
 *====================================================================
 * PURPOSE: Compare the beginning of two strings ignoring case
 *--------------------------------------------------------------------
 * PARAMS:  IN first string
 *          IN second string
 *          IN number of chars to compare
 *
 * RETURNS: 1, 0, -1
 *
 * NOTES:
 *====================================================================
 */

NQ_INT
cmWStrincmp(
    const NQ_WCHAR* s1,
    const NQ_WCHAR* s2,
    NQ_UINT n
    )
{
    NQ_WCHAR c1, c2;

    s1 = (const NQ_WCHAR*)cmAllignTwo(s1);
    s2 = (const NQ_WCHAR*)cmAllignTwo(s2);

    if (0 == n)
            return 0;
    for (;;)
    {
        c1 = *s1++;
        c2 = *s2++;
        c1 = unicodeToupper(c1);
        c2 = unicodeToupper(c2);
        if (c1 != c2 || n-- <= 0)
            break;
        if (c1 == 0)
            return 0;
    }
    if (n == 0)
        return 0;
    return c1 - c2;
}

/*
 *====================================================================
 * PURPOSE: Find character in a string
 *--------------------------------------------------------------------
 * PARAMS:  IN string
 *          IN character
 *
 * RETURNS: Pointer to the 1st occurence of this characater in the string
 *          or NULL
 *
 * NOTES:
 *====================================================================
 */

NQ_WCHAR*
cmWStrchr(
    const NQ_WCHAR* s,
    NQ_WCHAR c
    )
{
    s = (const NQ_WCHAR*)cmAllignTwo(s);
    while (*s != c)
    {
        if (!*s++)
            return NULL;
    }
    return (NQ_WCHAR*)s;
}

/*
 *====================================================================
 * PURPOSE: Find the rightmost occurence of a character in a string
 *--------------------------------------------------------------------
 * PARAMS:  IN string
 *          IN character
 *
 * RETURNS: Pointer to the rightmost occurence of this characater in the string
 *          or NULL
 *
 * NOTES:
 *====================================================================
 */

NQ_WCHAR*
cmWStrrchr(
    const NQ_WCHAR* s,
    NQ_WCHAR c
    )
{
    const NQ_WCHAR* s1;
    NQ_UINT i;

    s = (const NQ_WCHAR*)cmAllignTwo(s);
    i = cmWStrlen(s);
    s1 = (s + i);

    for (; i > 0; i--)
    {
        if (*--s1 == c)
        {
            return (NQ_WCHAR*)s1;
        }
    }
    return NULL;
}

/*
 *====================================================================
 * PURPOSE: Convert UNICODE string to ANSI string
 *--------------------------------------------------------------------
 * PARAMS:  OUT destination string
 *          IN source string
 *
 * RETURNS: None
 *
 * NOTES:   Converts only ASCII characters
 *====================================================================
 */

void
cmUnicodeToAnsi(
    NQ_CHAR *s,
    const NQ_WCHAR* w
    )
{
    cmUnicodeToAnsiN(s, w, 2*(syWStrlen(w) + 1));
}

/*
 *====================================================================
 * PURPOSE: Convert ANSII string to UNICODE string
 *--------------------------------------------------------------------
 * PARAMS:  OUT destination string
 *          IN source string
 *
 * RETURNS: None
 *
 * NOTES:   Converts only ASCII characters
 *====================================================================
 */

void
cmAnsiToUnicode(
    NQ_WCHAR *w,
    const NQ_CHAR *s
    )
{
    w = (NQ_WCHAR*)cmAllignTwo(w);
    cmAnsiToUnicodeN (w, s, (NQ_UINT)(syStrlen(s) + 1));
}

/*
 *====================================================================
 * PURPOSE: Convert UNICODE string to ANSI string
 *--------------------------------------------------------------------
 * PARAMS:  OUT destination string
 *          IN source string
 *          IN number of chars
 *
 * RETURNS: None
 *
 * NOTES:   Converts only ASCII characters
 *====================================================================
 */

void
cmUnicodeToAnsiN(
    NQ_CHAR *s,
    const NQ_WCHAR* w,
    NQ_UINT size
    )
{
#ifdef UD_NQ_INCLUDECODEPAGE
    cmCpUnicodeToAnsi(s, w, -1, (NQ_INT)size);
#else
    for (size = size/2; (size > 0) && (*w != 0); size--, w++, s++)
    {
        *s = (NQ_CHAR)cmLtoh16(*w);
    }
    /* Place trailing zero */
    *s = 0;
#endif
}

/*
 *====================================================================
 * PURPOSE: Convert ANSII string to UNICODE string
 *--------------------------------------------------------------------
 * PARAMS:  OUT destination string
 *          IN source string
 *          IN number of chars
 *
 * RETURNS: None
 *
 * NOTES:   Converts only ASCII characters
 *====================================================================
 */

void
cmAnsiToUnicodeN(
    NQ_WCHAR* w,
    const NQ_CHAR *s,
    NQ_UINT size
    )
{
    w = (NQ_WCHAR*)cmAllignTwo(w);
#ifdef UD_NQ_INCLUDECODEPAGE
    cmCpAnsiToUnicode(w, s, -1, (NQ_INT)size);
#else
    for (; (size > 0) && (*s != 0); size--, s++)
    {
        NQ_WCHAR c = (NQ_BYTE)*s;
        *w++ = cmHtol16(c);
    }
    /* Place trailing zero */
    *w = 0;
#endif
}

/*
 *====================================================================
 * PURPOSE: Convert Unicode string into an ANSI string for immediate printout
 *--------------------------------------------------------------------
 * PARAMS:  IN source string
 *
 * RETURNS: None
 *
 * NOTES:   Converts only ASCII characters
 *====================================================================
 */

NQ_CHAR*
cmWDump(
    const NQ_WCHAR* w
    )
{
#if SY_DEBUGMODE
    static NQ_CHAR temp[CM_WDUMP_NUMOFCHARS*2+1];

    cmUnicodeToAnsiN(temp, w, 2*CM_WDUMP_NUMOFCHARS);
    return temp;
#else
    return (NQ_CHAR*)w;
#endif
}


/*
 *====================================================================
 * PURPOSE: Convert WCHAR string to uppercase
 *--------------------------------------------------------------------
 * PARAMS:  IN string
 *
 * RETURNS: none
 *
 * NOTES:

 *====================================================================
 */

void
cmWStrupr(
    NQ_WCHAR* s
    )
{
    while (*s != 0)
    {
        *s = unicodeToupper(*s);
        s++;
    }
}

/*
 *====================================================================
 * PURPOSE: Convert a single WCHAR to uppercase
 *--------------------------------------------------------------------
 * PARAMS:  OUT destination buffer
 *          IN pointer to sourc character
 *
 * RETURNS: number of bytes converted
 *
 * NOTES:

 *====================================================================
 */

NQ_INT
cmWToupper(
    NQ_WCHAR* to,
    const NQ_WCHAR* from
    )
{
    *to = unicodeToupper(*from);
    return 1;
}

/*
 *====================================================================
 * PURPOSE: Convert a single WCHAR to uppercase
 *--------------------------------------------------------------------
 * PARAMS:  IN WCHAR
 *
 * RETURNS: converted WCHAR
 *
 * NOTES:

 *====================================================================
 */

static NQ_WCHAR
unicodeToupper(
    NQ_WCHAR w
    )
{
    NQ_INDEX i;  
    NQ_WCHAR c = cmLtoh16(w);
    
    for (i = 0; i < PLAIN_TABLE_SIZE && plainRangeTable[i].start <= c ; i++)
    {
        if (c <= plainRangeTable[i].end)
        {            
            return cmHtol16((NQ_WCHAR)(c - plainRangeTable[i].diff));
        }
    }

    for (i = 0; i < ODD_TABLE_SIZE && oddRangeTable[i].start <= c; i++)
    {
        if (c <= oddRangeTable[i].end)
        {
            if ((c - oddRangeTable[i].start) % 2 == 0)
            {                
                return cmHtol16((NQ_WCHAR)(c - oddRangeTable[i].diff));
            }
        }
    }

    return cmHtol16(c);
}

