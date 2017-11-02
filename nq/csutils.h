/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Common functions
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSUTILS_H_
#define _CSUTILS_H_

#include "nsapi.h"

#include "csdataba.h"

#define     csGetPidFromHeader(_h) syNtoh16(cmGetSUint16(_h->pid)) + ((NQ_UINT32)syNtoh16(cmGetSUint16(_h->status1.extra.pidHigh)) << 16);

/* create a socket and bind it to the host name */

NSSocketHandle                  /* socket handle or NULL */
csPrepareSocket(
    NQ_UINT type,               /* stream or datagram */
    NQ_UINT transport           /* NetBIOS, TCPv4 or TCPv6 */
    );

/* check whether file attributes match the desired attributes */

NQ_BOOL                            /* TRUE on match */
csMatchFileAttributes(
    NQ_UINT16 searchAttributes,    /* desired attributes */
    NQ_UINT16 fileAttributes       /* file attributes */
    );

/* change file attributes preserving file type */

NQ_UINT32                           /* new file attributes */
csChangeFileAttributes(
    NQ_UINT32 oldAttributes,        /* old attributes */
    NQ_UINT32 desiredAttributes     /* desired attributes */
    );

/* find the file (case insensitive) providing the path exists */

NQ_BOOL                             /* TRUE if the file exists */
csCheckFile(
    const CSShare* pShare,          /* share pointer */
    NQ_TCHAR* pName,                /* full path pointer */
    NQ_BOOL preservesCase           /* whether the client's file system preserves case */
    );

/* find the path of a given name in a case insensitive manner */

NQ_BOOL                             /* TRUE if the path exists */
csCheckPath(
    const CSShare* pShare,          /* share pointer */
    NQ_TCHAR* pName,                /* full path pointer */
    NQ_UINT treeLen,                /* length of the tree map */
    NQ_BOOL preservesCase           /* whether the client's file system preserves case */
    );

/* find the full path to a file in a case insensitive manner */

NQ_BOOL                             /* TRUE if the full path exists */
csCheckPathAndFile(
    const CSShare* pShare,          /* share pointer */
    NQ_TCHAR* pName,                /* full path pointer */
    NQ_UINT treeLen,                /* length of the tree map */
    NQ_BOOL preservesCase           /* whether the client's file system preserves case */
    );

/* get file information according to the file type (file, share, etc.) */

NQ_STATUS                           /* NQ_SUCCESS or NQ_FAIL */
csGetFileInformation(
    const CSFile* pFile,            /* file structure pointer */
    const NQ_TCHAR* pFileName,      /* file name pointer */
    SYFileInformation* pFileInfo    /* pointer to the file information structure */
    );

/* get file information by file name according to the file type (file, share, etc.) */

NQ_STATUS                           /* NQ_SUCCESS or NQ_FAIL */
csGetFileInformationByName(
    const CSShare* pShare,          /* file structure pointer */
    const NQ_TCHAR* pFileName,      /* file name pointer */
    SYFileInformation* pFileInfo    /* pointer to the file information structure */
#ifdef UD_NQ_INCLUDEEVENTLOG
    ,const CSUser	*			pUser
#endif /* UD_NQ_INCLUDEEVENTLOG */
    );

/* get file information according to the file type (file, share, etc.) */

NQ_STATUS                           /* NQ_SUCCESS or NQ_FAIL */
csSetFileInformation(
    const CSFile* pFile,                /* file structure pointer */
    const NQ_TCHAR* pFileName,          /* file name pointer */
    const SYFileInformation* pFileInfo  /* pointer to the file information structure */
    );

/* check whether this file can be deleted */

NQ_BOOL                           /* TRUE or FALSE */
csCanDeleteFile(
    const NQ_TCHAR* pFileName     /* file name pointer */
#ifdef UD_NQ_INCLUDEEVENTLOG
    ,const CSUser * pUser,
    const UDFileAccessEvent eventLogInfo
#endif /* UD_NQ_INCLUDEEVENTLOG */
    );

/* truncate file */

NQ_UINT32                        /* NQ_SUCCESS or error code */
csTruncateFile(
    CSFile* pFile,               /* file structure pointer */
    const NQ_TCHAR* pFileName,   /* file name */
    NQ_UINT32 sizeLow,           /* low 32 bits of the new size */
    NQ_UINT32 sizeHigh           /* high 32 bits of the new size */
    );

    
/* calculate host type */

NQ_UINT32                           /* host type */
csGetHostType(
    void
    );

/* check if the given user can read from share */

NQ_UINT32                   /* NQ_SUCCESS when user is allowed to access for read or error code */
csCanReadShare(
    CSTid tid               /* TID to use */
    );

/* check if the given user can write to share */

NQ_UINT32                   /* NQ_SUCCESS when user is allowed to access for write or error code */
csCanWriteShare(
    CSTid tid               /* TID to use */
    );


/* check the existence of the underlying path  */

NQ_BOOL                     /* TRUE or FALSE */
csCheckShareMapping(
    CSShare* pShare         /* share descriptor to check */
    );
    
/* write file times in response packet */

void
csWriteFileTimes(
    const SYFileInformation *fileInfo, /* file info structure */
    const CSName *pName,    /* pointer to name structure */
    NQ_BYTE *pResponse      /* pointer to response buffer */
    );

/* reset file times in name structure */

void
csResetFileTimes(
    CSName *pName           /* pointer to name structure */
    );

#endif  /* _CSUTILS_H_ */


