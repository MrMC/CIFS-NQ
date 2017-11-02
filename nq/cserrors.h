/*********************************************************************
 *
 *           Copyright (c) 2007 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Error conversion
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 18-Jan-2007
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSERRORS_H_
#define _CSERRORS_H_

#include "cmapi.h"

/* return appropriate error code */

NQ_UINT32
csErrorReturn(
    NQ_UINT32 nt,
    NQ_UINT32 dos
    );

/* obtain last system error converted to SMB error */

NQ_UINT32                   /* code to return */
csErrorGetLast(
    void
    );

#endif /* _CSERRORS_H_ */

