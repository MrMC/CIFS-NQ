/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : LSA pipe
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 19-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/


#ifndef _CSLSARPC_H_
#define _CSLSARPC_H_
#ifdef UD_CS_INCLUDERPC_LSARPC

#include "csrpcdef.h"

/* get a pointer to the LSA pipe descriptor */

const CSRpcPipeDescriptor*
csRpcLsa(
    void
    );

/* get a pointer to the LSA_DS pipe descriptor */

const CSRpcPipeDescriptor*
csRpcLsads(
    void
    );

#endif /* UD_CS_INCLUDERPC_LSARPC */
#endif /* _CSLSARPC_H_ */
