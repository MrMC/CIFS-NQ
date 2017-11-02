/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Buffer pool
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NSBUFFER_H_
#define _NSBUFFER_H_

#include "nsapi.h"

/* Initialize buffer pool */

NQ_STATUS
nsInitMessageBufferPool(
    void
    );                      /* initialization */

/* release buffer pool */

void
nsReleaseMessageBufferPool(
    void
    );

#endif  /* _NSBUFFER_H_ */
