/*********************************************************************
 *
 *           Copyright (c) 2006 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : WINREG pipe
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-October-2006
 * CREATED BY    : Igor Gokhman
 * LAST AUTHOR   : $Author:$
 ********************************************************************/


#ifndef _CSWRGRPC_H_
#define _CSWRGRPC_H_

#include "csrpcdef.h"

#ifdef UD_CS_INCLUDERPC_WINREG

/* get a pointer to a pipe descriptor */

const CSRpcPipeDescriptor*
csRpcWinReg(
    void
    );

#endif /* UD_CS_INCLUDERPC_WINREG */

#endif /* _CSWRGRPC_H_ */
