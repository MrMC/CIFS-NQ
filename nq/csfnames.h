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

#ifndef _CSFNAMES_H_
#define _CSFNAMES_H_

#include "cmapi.h"

/*
  This file contains "wildcard name" API. Name may be either a source name or a
  destination name. Source name is independent, while a destination name depends on
  source name and exists in its context.
 */

typedef struct                  /* descriptor of a file name with possible wildcards */
{
    NQ_BOOL isReady;                        /* descriptor is ready for enumeration */
    NQ_BOOL useOldName;                     /* descriptor was "rolled back" one name */
    NQ_BOOL hasWildcards;                   /* wildcards flag */
    NQ_BOOL hasDirectory;                   /* TRUE when the name has directory path */
    NQ_WCHAR name[UD_FS_FILENAMELEN];       /* pointer to the full name */
    NQ_WCHAR* path;                         /* pointer to the path */
    NQ_WCHAR* file;                         /* pointer to the file name in the full name */
    SYDirectory directory;                  /* opened directory */
    NQ_WCHAR* nextName;                     /* next filename */
    NQ_WCHAR nextPath[UD_FS_FILENAMELEN];   /* full path for the next file */
    NQ_WCHAR* nextFile;                     /* pointer to the file name in this path */
    NQ_BOOL preservesCase;                  /* whether the client's file system preserves case */
    NQ_BOOL bringLinks;                     /* TRUE to consider ./ and ../ entries */
    NQ_BOOL isCurrDirReported;              /* TRUE when ./ entry was reported */
    NQ_BOOL isParentDirReported;            /* TRUE when ../ entry was reported */
} CSFileEnumeration;

/* initilize this module */

NQ_STATUS            /* NQ_SUCCESS or NQ_FAIL */
csFnamesInit(
    void
    );

/* release this module */

void
csFnamesExit(
    void
    );

/* prepare for enumerating a source file name with possible wildcards */

void
csEnumerateSourceName(
    CSFileEnumeration* enumerator,  /* enumeration descriptor */
    NQ_WCHAR* srcName,              /* source file name */
    NQ_BOOL preservesCase           /* whether the client's file system preserves case */
    );

/* get next source name matching the pattern */

NQ_WCHAR*                           /* filename or NULL if no more files */
csNextSourceName(
    CSFileEnumeration* enumerator   /* enumeration descriptor */
    );

/* Roll back one step in the enumeration thus causing it next time to return the same
   name */

#define csRollbackEnumeration(_e)   (_e).useOldName = TRUE

/* cancel file enumertion */

void
csCancelEnumeration(
    CSFileEnumeration* enumerator   /* enumeration descriptor */
    );

/* prepare for enumerating a pair of source and destination name with wildcards */

void
csEnumerateSourceAndDestinationName(
    NQ_WCHAR* srcName,               /* source file name */
    NQ_WCHAR* dstName,               /* destination file name */
    NQ_BOOL preservesCase           /* whether the client's file system preserves case */
    );

/* get next pair of source and destination name matching the pattern */

NQ_BOOL                             /* TRUE if done and FALSE if no more names */
csNextSourceAndDestinationName(
    NQ_WCHAR** srcName,              /* buffer for source name pointer */
    NQ_WCHAR** dstName               /* buffer for destination name pointer */
    );

/* close sourcename enumeration for the pair of source and destination */

void
csCancelDefaultEnumeration(
    void
    );

#endif  /* _CSFNAMES_H_ */


