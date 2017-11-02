/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of file search commands
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 19-Feb-2009
 * CREATED BY    : Lilia Wasserman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSSEARCH_H_
#define _CSSEARCH_H_

#define INTERNAL_ERROR      0xff100000      /* error code for internal usage between functions
                                               signals buffer overflow */

/* get file information and fill a directory entry for Find */

NQ_UINT32                                   /* SMB error or 0 */
csFillFindEntry(
    const NQ_TCHAR* pFileName,              /* file name */
    SYFileInformation* fileInfo,            /* file infromation structure */
    NQ_BYTE** entry,                        /* IN: double pointer to the entry
                                               OUT: double pointer to the next entry */
    NQ_UINT16 level,                        /* information level as required by FIND */
    NQ_UINT32 fileIndex,                    /* file index in search */
    NQ_BOOL unicodeRequired,                /* whether UNICODE names ought to be returned */
    const NQ_BYTE* messageStart,            /* pointer to the beginning of the SMB message */
    NQ_UINT maxLength,                      /* max response length */
    NQ_BOOL resumeKey,                      /* whether to return resume key for particular levels */
    NQ_BYTE** pNextEntryOffset              /* double pointer to nextEntryOffset field in the entry */
    );
    
#endif /* _CSSEARCH_H_ */
