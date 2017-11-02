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


#ifndef _CSSRVSVC_H_
#define _CSSRVSVC_H_

#include "csrpcdef.h"

/* get a pointer to a pipe descriptor */

const CSRpcPipeDescriptor*
csRpcSrvsvc(
    void
    );

#endif /* _CSSRVSVC_H_ */
