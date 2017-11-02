/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SRVSVC pipe
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 19-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/


#ifndef _CSSPOOLS_H_
#define _CSSPOOLS_H_

#include "csrpcdef.h"

#ifdef UD_CS_INCLUDERPC_SPOOLSS

/* get a pointer to a pipe descriptor */

const CSRpcPipeDescriptor*
csRpcSpoolss(
    void
    );

/* clean up resources belonging to a user */

void csRpcSpoolssCleanupUser(
    const NQ_UINT16 uid             /* user ID */
    );

#endif /* UD_CS_INCLUDERPC_SPOOLSS */
#endif /* _CSSPOOLS_H_ */
