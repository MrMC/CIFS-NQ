/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of file information command
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 16-Feb-2009
 * CREATED BY    : Lilia Wasserman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSINFORM_H_
#define _CSINFORM_H_

#include "cstrans2.h"
 
/* query file information providing file name */

typedef struct {
    CSUid uid;                             /* user id */
    CSTid tid;                             /* tree id */
    const NQ_WCHAR* pFileName;             /* name of the file to query on     */
    NQ_UINT level;                         /* information level required       */
    const NQ_BYTE* pData;                  /* pointer to the data area in the request */
} InfoContext;
/* This code implements information commands and sub commands */

NQ_UINT32									/* NQ file access rights */
convertNqAccessToNtAccess(
	NQ_UINT16 nqAccess						/* NQ file access rights */
	);

NQ_UINT32                                   /* error or 0 */
csQueryFileInformationByName(
    const CSFile* pFile,                    /* file descriptor (may be NULL)    */
    const NQ_WCHAR* pFileName,              /* name of the file to query on     */
    NQ_COUNT shareNameLen,                  /* length of the share map name     */
    NQ_UINT level,                          /* information level required       */
    NQ_BOOL unicodeRequired,                /* whether the client asks for UNICODE names */
    NQ_UINT spaceAvailable,                 /* available space in the buffer    */
    CSTransaction2Descriptor* descriptor    /* subcommand parameters structure  */
    );

/* query file system information providing share name */

NQ_UINT32                                   /* error or 0 */
csQueryFsInformation(
    const CSShare* pShare,                  /* name of the share to query on    */
    NQ_UINT informationLevel,               /* information level required       */
    NQ_BOOL unicodeRequired,                /* whether the client asks for UNICODE names */
    CSTransaction2Descriptor* descriptor    /* subcommand parameters structure  */ 
#ifdef UD_NQ_INCLUDEEVENTLOG
	, CSTree * pTree
#endif /* UD_NQ_INCLUDEEVENTLOG */
    );    

/* change file information providing file name */

NQ_UINT32                                   /* error or 0 */
csSetFileInformationByName(
    CSFile* pFile,                          /* file structure (optional) */
#ifdef UD_NQ_INCLUDEEVENTLOG
    const CSUser* pUser,                    /* user for event log */
#endif /* UD_NQ_INCLUDEEVENTLOG */
    const InfoContext *ctx                  /* information context */ 
    );

#endif /* _CSINFORM_H_ */
