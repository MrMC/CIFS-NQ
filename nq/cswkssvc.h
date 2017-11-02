/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : WKSSVC pipe
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 19-October-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/


#ifndef _CSWKSSVC_H_
#define _CSWKSSVC_H_

#include "csrpcdef.h"

#ifdef UD_CS_INCLUDERPC_WKSSVC

/* get a pointer to a pipe descriptor */

const CSRpcPipeDescriptor*
csRpcWkssvc(
    void
    );

#endif /* UD_CS_INCLUDERPC_WKSSVC */
#endif /* _CSWKSSVC_H_ */
