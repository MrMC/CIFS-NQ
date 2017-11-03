/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : File name processing
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 07-July-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csfnames.h"

#include "csutils.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/*
  This code implements wildcard name resolving for search and rename commands.

  Since a search may consist of more then one command (FindFirst + FindNext) our
  operations are persistent and mu;tiplle search contents may exists simultaneously.
  For this reason we use the CSFileEnumeration structure as a search context descriptor.
  We do not expect concarent Rename operations, therefore a local context is used for this
  purpose.

  We use a full name, consisting of a (possible) directory path and a file name.
  If there is no directory name we assume that this is relative ".\" path

  In case a full name has the directory path component we use "in place" decomposition
  by placing a string terminator instead of the last path separator.

  When we are through with the name enumeration we restore the full name by placing this separator
  back.

  File name is the only component that may contain wildcards.

  A search operation may continue over several CIFS commands (e.g., TRANSACT2: FIND_FIRST +
  FIND_NEXT). To save the search context we use CSFileEnumeration structure.
 */

/*
    Static functions & data
    -----------------------
 */

/* special names: ".." and "." */

static const NQ_WCHAR currentDirectory[] = { cmWChar('.'), cmWChar(0) };
static const NQ_WCHAR parentDirectory[] = { cmWChar('.'), cmWChar('.'), cmWChar(0) };

static const NQ_WCHAR anyFile[] = { cmWChar('*'), cmWChar(0) };
static const NQ_WCHAR anyFile1[] = { cmWChar('*'), cmWChar('.'), cmWChar(0) };
static const NQ_WCHAR anyFile2[] = { cmWChar('*'), cmWChar('.'), cmWChar('*'), cmWChar(0) };
/* descriptors used for file pairs (in Rename) */

typedef struct
{
    CSFileEnumeration srcEnumerator;
    CSFileEnumeration dstEnumerator;
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* substitute a pattern using a sample name */

static NQ_BOOL                         /* TRUE on success, FALSE when substitution is impossible */
substituteName(
    const NQ_WCHAR* srcPattern,      /* source pattern */
    const NQ_WCHAR* source,          /* source file name */
    const NQ_WCHAR* dstPattern,      /* destination pattern */
    NQ_WCHAR* destination            /* buffer for destinatio name */
    );

/* wildcard pattern match */

static NQ_BOOL
nameMatch(
    const NQ_WCHAR *pattern,
    const NQ_WCHAR *name
    );

/* decompose name into directory name and file name, find wildcards in a file name */

static void
decomposeName(
    CSFileEnumeration* descriptor,          /* name enumerator */
    const NQ_WCHAR* name                     /* source name or pattern */
    );

/* recreate a full name from a decomposed name */

static void
restoreName(
    CSFileEnumeration* descriptor
    );

/*
 *====================================================================
 * PURPOSE: initilize this module
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csFnamesInit(
    void
    )
{
    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syMalloc(sizeof(*staticData));
    if (NULL == staticData)
       return NQ_FAIL;
#endif /* SY_FORCEALLOCATION */
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: release this module
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csFnamesExit(
    void
    )
{
    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

/*
 *====================================================================
 * PURPOSE: Prepare for enumerating a source name with possible wildcards
 *--------------------------------------------------------------------
 * PARAMS:  IN enumeration descriptor
 *          IN source name
 *          IN whether client file system is case preserving
 *
 * RETURNS: NONE
 *
 * NOTES:   In this function we prepare the search context, no seach is done yet
 *          the real search will be done in csNextSourceName()
 *====================================================================
 */

void
csEnumerateSourceName(
    CSFileEnumeration* enumerator,
    NQ_WCHAR* srcName,
    NQ_BOOL preservesCase
    )
{
    syInvalidateDirectory(&enumerator->directory);
    decomposeName(enumerator, srcName);
    if (enumerator->hasWildcards)
    {
        syWStrncpy(enumerator->nextPath, enumerator->path, sizeof(enumerator->nextPath));
        enumerator->nextFile = enumerator->nextPath + syWStrlen(enumerator->nextPath);
        *enumerator->nextFile++ = cmWChar(SY_PATHSEPARATOR);
    }
    else
    {
        restoreName(enumerator);
    }
    enumerator->isReady = TRUE;
    enumerator->useOldName = FALSE;
    enumerator->preservesCase = preservesCase;
    enumerator->bringLinks = FALSE;
    enumerator->isCurrDirReported = FALSE;
    enumerator->isParentDirReported = FALSE;
}

/*
 *====================================================================
 * PURPOSE: get next source name
 *--------------------------------------------------------------------
 * PARAMS:  IN enumeration descriptor (search context)
 *
 * RETURNS: next name or NULL when no more names
 *
 * NOTES:   - open directory if necessary using the (stupid) Windows approach
 *            of "first" and "next"
 *          - read directory entry
 *====================================================================
 */

NQ_WCHAR*
csNextSourceName(
    CSFileEnumeration* enumerator
    )
{
    NQ_STATUS status;           /* result of directory operation */
    const NQ_WCHAR* nextName = NULL;    /* next directory entry */

    if (!enumerator->isReady)
        return NULL;

    if (enumerator->useOldName)
    {
        enumerator->useOldName = FALSE;
        return enumerator->nextPath;
    }
    if (enumerator->hasWildcards)
    {
        while (TRUE)
        {
        	if (cmWStrlen(enumerator->file) <= 3 &&
				(cmWStrcmp(enumerator->file , anyFile) == 0  ||
				 cmWStrcmp(enumerator->file , anyFile1) == 0 ||
				 cmWStrcmp(enumerator->file , anyFile2) == 0)
        		)
        	{
				if (!enumerator->isCurrDirReported)
				{
					syWStrncpy(enumerator->nextFile, currentDirectory, UD_FS_FILENAMELEN - syWStrlen(enumerator->path) - 1);
					enumerator->isCurrDirReported = TRUE;
					return enumerator->nextPath;
				}
				if (!enumerator->isParentDirReported)
				{
					syWStrncpy(enumerator->nextFile, parentDirectory, UD_FS_FILENAMELEN - syWStrlen(enumerator->path) - 1);
					enumerator->isParentDirReported = TRUE;
					return enumerator->nextPath;
				}
        	}

            if (!syIsValidDirectory(enumerator->directory))
            {
                status = syFirstDirectoryFile(
                    enumerator->path,
                    &enumerator->directory,
                    &nextName
                    );
            }
            else
            {
                status = syNextDirectoryFile(
                    enumerator->directory,
                    &nextName
                    );
            }

            if (status != NQ_SUCCESS || nextName == NULL)
            {
                csCancelEnumeration(enumerator);
                return NULL;
            }
             
            if ((   syWStrcmp(nextName, currentDirectory) == 0
                 || syWStrcmp(nextName, parentDirectory) == 0
                ) && !enumerator->bringLinks
               )
            {
                continue;
            }

            if (nameMatch(enumerator->file, nextName))
            {
                syWStrncpy(enumerator->nextFile, nextName, UD_FS_FILENAMELEN - syWStrlen(enumerator->path) - 1);
                return enumerator->nextPath;
            }
        }
    }
    else
    {
        enumerator->isReady = FALSE;
        return csCheckFile(NULL, enumerator->name, enumerator->preservesCase) ? enumerator->name : NULL;
    }
}

/*
 *====================================================================
 * PURPOSE: close sourcename enumeration
 *--------------------------------------------------------------------
 * PARAMS:  IN enumeration descriptor
 *
 * RETURNS: None
 *
 * NOTES:   close the directory if was used
 *====================================================================
 */

void
csCancelEnumeration(
    CSFileEnumeration* enumerator
    )
{
    if (syIsValidDirectory(enumerator->directory))
    {
        if (syCloseDirectory(enumerator->directory) != NQ_SUCCESS)
        {
            TRCERR("Close operation failed");
            TRC1P("File name %s", cmWDump(enumerator->path));
        }
        syInvalidateDirectory(&enumerator->directory);
    }
    restoreName(enumerator);
    enumerator->isReady = FALSE;
}

/*
 *====================================================================
 * PURPOSE: prepare for enumerating a pair of source and destination
 *          name with wildcards
 *--------------------------------------------------------------------
 * PARAMS:  IN source name
 *          IN destination name
 *          IN whether client file system is case preserving
 *
 * RETURNS: NONE
 *
 * NOTES:   We are using local search context for enumerating source names which
 *          does not allow multiple operations simulteneusly. Since this function
 *          is used for Copy/Move/Rename operations, the enumeration is complete
 *          inside the same CIFS command thus does not require global context.
 *
 *          This call prepares the local context. The real enumeration is done by
 *          subsequent csGetNextSourceAndDestinationName() calls
 *====================================================================
 */

void
csEnumerateSourceAndDestinationName(
    NQ_WCHAR* srcName,
    NQ_WCHAR* dstName,
    NQ_BOOL preservesCase
    )
{
    csEnumerateSourceName(&staticData->srcEnumerator, srcName, preservesCase);
    decomposeName(&staticData->dstEnumerator, dstName);
    if (staticData->dstEnumerator.hasWildcards)
    {
        syWStrncpy(staticData->dstEnumerator.nextPath, staticData->dstEnumerator.path, sizeof(staticData->dstEnumerator.nextPath) - 1);
        staticData->dstEnumerator.nextFile = staticData->dstEnumerator.nextPath + syWStrlen(staticData->dstEnumerator.nextPath);
        *staticData->dstEnumerator.nextFile++ = cmWChar(SY_PATHSEPARATOR);
        *staticData->dstEnumerator.nextFile = cmWChar(0);
    }
    else
    {
        restoreName(&staticData->dstEnumerator);
    }
}

/*
 *====================================================================
 * PURPOSE: close sourcename enumeration for the pair of source and destination
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   close the directory if was used
 *====================================================================
 */

void
csCancelDefaultEnumeration(
    void
    )
{
    csCancelEnumeration(&staticData->srcEnumerator);
}

/*
 *====================================================================
 * PURPOSE: get next pair of source and destination name matching the
 *          pattern
 *--------------------------------------------------------------------
 * PARAMS:  OUT buffer for next source name
 *          OUT buffer for next destination name
 *          IN whether client file system is case preserving
 *
 * RETURNS: TRUE if done and FALSE if no more names
 *
 * NOTES:   returns next pair of source/destination names for a
 *          Copy/Move/Rename operation
 *====================================================================
 */

NQ_BOOL
csNextSourceAndDestinationName(
    NQ_WCHAR** srcName,
    NQ_WCHAR** dstName
    )
{
    *srcName = (NQ_WCHAR*)csNextSourceName(&staticData->srcEnumerator);
    if (*srcName == NULL)
    {
        csCancelEnumeration(&staticData->srcEnumerator);
        return FALSE;
    }

    if (staticData->srcEnumerator.hasWildcards && staticData->dstEnumerator.hasWildcards)
    {
        if (!substituteName(
                staticData->srcEnumerator.file,
                staticData->srcEnumerator.nextFile,
                staticData->dstEnumerator.file,
                staticData->dstEnumerator.nextFile
                )
           )
        {
            csCancelEnumeration(&staticData->srcEnumerator);
            return FALSE;
        }
        *dstName = staticData->dstEnumerator.nextPath;
    }
    else
    {
        *dstName = staticData->dstEnumerator.name;
    }
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: find the nearest wildcard character in a string
 *--------------------------------------------------------------------
 * PARAMS:  IN pattern
 *
 * RETURNS: pointer or NULL
 *
 * NOTES:   parses string for a wildcard character
 *====================================================================
 */

static const NQ_WCHAR*
findNextWildcard(
    const NQ_WCHAR* src
    )
{
    NQ_WCHAR nextChar[3];

    while (*src)
    {
        if (*src==cmWChar('>') || *src==cmWChar('?') || *src==cmWChar('*'))
            return src;
        src += cmWToupper(nextChar, src);
    }
    return NULL;
}

/*
 *====================================================================
 * PURPOSE: finds a destination name corresponding to the next source name
 *--------------------------------------------------------------------
 * PARAMS:  IN source pattern
 *          IN source name
 *          IN destination pattern
 *          OUT destination name
 *
 * RETURNS: TRUE if substituted, FALSE if substitution is impossible
 *
 * NOTES:   substitutes wildcards in the destination name by appropriate fragments
 *          from the source
 *====================================================================
 */

static NQ_BOOL
substituteName(
    const NQ_WCHAR* srcPattern,
    const NQ_WCHAR* source,
    const NQ_WCHAR* dstPattern,
    NQ_WCHAR* destination
    )
{
    const NQ_WCHAR* sp;  /* pointer in source pattern */
    const NQ_WCHAR* s;   /* pointer in source name */
    const NQ_WCHAR* dp;  /* pointer in destination pattern */
    NQ_WCHAR* d;         /* pointer in destination name */

    sp = srcPattern;
    s = source;
    dp = dstPattern;
    d = destination;

    *d = cmWChar(0);

    while(*s)
    {
        const NQ_WCHAR* ws;    /* next wildchar pointer in the source */
        const NQ_WCHAR* wd;    /* next wildchar pointer in the destination */

        /* find text fragment in the source pattern
           skip the same text fragment in the source */

        ws = findNextWildcard(sp);
        if (ws == NULL)
            ws = sp + syWStrlen(sp);
        while (*sp)
        {
            NQ_WCHAR c1[2], c2[2];     /* chars to compare */
            NQ_INT l1, l2;

            l1 = cmWToupper(c1, s);
            l2 = cmWToupper(c2, sp);
            if (l1 != l2 || c1[0] != c2[0] || (l1 == 2 && c1[1]!= c2[1]))
                break;
            s += l1;
            sp += l2;
        }

        /* find text fragment in the destination patterns.
           copy destination's pattern fragment to the result */

        wd = findNextWildcard(dp);
        if (wd == NULL)
            wd = dp + syWStrlen(dp);
        while (wd>dp)
            *d++ = *dp++;

        /* analyse wildchar in the source pattern
           copy source fragment into the result */

        dp = wd;
        if (*dp)
            dp++;
        sp = ws;
        if (*sp)
            sp++;
        switch (*ws)
        {
        case cmWChar('?'):
        case cmWChar('>'):
            {
                NQ_WCHAR c[2];
                NQ_INT len;

                len = cmWToupper(c, s);
                syMemcpy(d, s, len * (NQ_INT)sizeof(NQ_WCHAR));
                d += len;
                s += len;
            }
            break;
        case cmWChar('*'):
            while (*s)
            {
                NQ_WCHAR c[2];
                NQ_INT len;

                len = cmWToupper(c, s);
                syMemcpy(d, s, len * (NQ_INT)sizeof(NQ_WCHAR));
                d += len;
                s += len;
                if (nameMatch(sp, s))
                    break;
            }
            break;
        default:
            break;
        }
    }
    while (*dp)
    {
        const NQ_WCHAR* wd;    /* next wildchar pointer in the destination */

        wd = findNextWildcard(dp);
        if (wd == NULL)
            wd = dp + syWStrlen(dp);
        while (wd>dp)
            *d++ = *dp++;
        dp = wd;
        if (*dp)
            dp++;
    }
    *d = cmWChar(0);

    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: Match a name with a wildcard pattern
 *--------------------------------------------------------------------
 * PARAMS:  IN pattern
 *          IN name
 *
 * RETURNS: TRUE on match
 *
 * NOTES:   matches each segment of a patern with a part of the name
 *====================================================================
 */

static NQ_BOOL
nameMatch(
    const NQ_WCHAR *pattern,
    const NQ_WCHAR *name
    )
{
    NQ_WCHAR nextPatternChar[3];
    NQ_WCHAR nextNameChar[3];

    while (*pattern != 0)
    {
        NQ_INT len;     /* ANSI character length in bytes */

        len = cmWToupper(nextPatternChar, pattern);
        pattern += len;

        switch (nextPatternChar[0])
        {
        case cmWChar('?'):
            if (!*name)
                return FALSE;
            name += cmWToupper(nextNameChar, name);
            break;
        case cmWChar('>'):
            if (*name == cmWChar('.'))
            {
                if (!*(name+1) && nameMatch(pattern, name+1))
                    return TRUE;
                if (nameMatch(pattern, name))
                    return TRUE;
                return FALSE;
            }
            if (!*name)
                return nameMatch(pattern, name);
            name += cmWToupper(nextNameChar, name);
            break;
        case cmWChar('*'):
            for (; *name; name += cmWToupper(nextNameChar, name))
                if (nameMatch(pattern, name))
                    return TRUE;
            break;
        case cmWChar('<'):
            for (; *name; name += cmWToupper(nextNameChar, name))
            {
                if (nameMatch(pattern, name))
                    return TRUE;
                if (*name == cmWChar('.') && !syWStrchr(name+1, cmWChar('.')))
                {
                    break;
                }
            }
            break;
        case cmWChar('"'):
            if (!*name && nameMatch(pattern, name))
                return TRUE;
            if (*name != cmWChar('.'))
                return FALSE;
            name++;
            break;
        default:
            name += cmWToupper(nextNameChar, name);
            if (0 != syWStrncmp(nextPatternChar, nextNameChar, (NQ_UINT)len))
                return FALSE;
            break;
        }
    }

    return *name == 0;
}

/*
 *====================================================================
 * PURPOSE: decompose name into directory name and file name
 *--------------------------------------------------------------------
 * PARAMS:  OUT name descriptor
 *          IN source name or pattern
 *
 * RETURNS: NONE
 *
 * NOTES:   we also find wildcards in a file name
 *          full name pointer is also set in the descriptor
 *====================================================================
 */

static void
decomposeName(
    CSFileEnumeration* descriptor,
    const NQ_WCHAR* name
    )
{
    NQ_WCHAR* pSeparator;

    syWStrncpy(descriptor->name, name, sizeof(descriptor->name));
    pSeparator = syWStrrchr(descriptor->name, cmWChar(SY_PATHSEPARATOR));

    if (pSeparator == NULL)
    {
        descriptor->hasDirectory = FALSE;
        descriptor->file = descriptor->name;
        descriptor->path = (NQ_WCHAR*)currentDirectory;
    }
    else
    {
        *pSeparator = cmWChar(0);
        descriptor->hasDirectory = TRUE;
        descriptor->file = ++pSeparator;
        descriptor->path = descriptor->name;
    }
    descriptor->hasWildcards =
           (syWStrchr(descriptor->file, cmWChar('*')) != NULL)
        || (syWStrchr(descriptor->file, cmWChar('?')) != NULL)
        || (syWStrchr(descriptor->file, cmWChar('<')) != NULL)
        || (syWStrchr(descriptor->file, cmWChar('>')) != NULL)
        || (syWStrchr(descriptor->file, cmWChar('"')) != NULL)
        ;
}

/*
 *====================================================================
 * PURPOSE: recreate a full name from a decomposed name
 *--------------------------------------------------------------------
 * PARAMS:  name descriptor
 *
 * RETURNS: NONE
 *
 * NOTES:   this operation is a reverse of the previous
 *====================================================================
 */

static void
restoreName(
    CSFileEnumeration* descriptor
    )
{
    if (descriptor->hasDirectory)
    {
        *(descriptor->file - 1) = cmWChar(SY_PATHSEPARATOR);
    }
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

