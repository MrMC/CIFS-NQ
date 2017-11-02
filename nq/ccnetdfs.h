/*********************************************************************
 *
 *           Copyright (c) 2010 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : CIFS Client NETDFS pipe related operations
 *--------------------------------------------------------------------
 * MODULE        : CC
 * DEPENDENCIES  : None
 *--------------------------------------------------------------------
 * CREATION DATE : 29-Apr-2010
 ********************************************************************/

#ifndef _CCNETDFS_H_
#define _CCNETDFS_H_

#if defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEDFS)

NQ_UINT32
ccNetDfsGetStatus(
    const NQ_WCHAR * server,
    const NQ_WCHAR * dfsPath,
    NQ_UINT32 * state,
    NQ_UINT32 * flags
    );

#endif /*  defined(UD_NQ_INCLUDECIFSCLIENT) && defined(UD_CC_INCLUDEDFS) */
#endif /* _CCNETDFS_H_ */    
