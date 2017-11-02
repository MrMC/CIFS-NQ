/*********************************************************************
 *
 *           Copyright (c) 2009 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Rename file processing (SMB1 and SMB2)
 * NOTES:
 *                 This header defines functions common for both SMB1 
 *                 and SMB2 processing
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 26-Mar-2009
 ********************************************************************/
 
#ifndef _CSDELETE_H_
#define _CSDELETE_H_

NQ_UINT32
csRenameFile( 
    CSUser* pUser,                              /* pointer to the user descriptor */
    const CSShare* pShare,                      /* pointer to the share */
    NQ_BOOL unicodeRequired,                    /* whether client requires UNICODE */
    NQ_UINT16 searchAttributes,                 /* allowed attributes of the file */
    NQ_TCHAR* srcName,                          /* source file name in host filename format */
    NQ_TCHAR* dstName                           /* destination file name in host filename format */
    );

#endif /* _CSDELETE_H_ */
