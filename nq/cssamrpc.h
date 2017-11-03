/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SAMR pipe
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 19-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/


#ifndef _CSSAMRPC_H_
#define _CSSAMRPC_H_

#include "csrpcdef.h"

#ifdef UD_CS_INCLUDERPC_SAMRPC

/* get a pointer to a pipe descriptor */

const CSRpcPipeDescriptor*
csRpcSamr(
    void
    );

#endif /* UD_CS_INCLUDERPC_SAMRPC */

#endif /* _CSSAMRPC_H_ */
