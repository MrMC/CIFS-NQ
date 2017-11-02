
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Proceesing incoming message and timeouts for Session Service
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBios Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 31-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NDSESPRO_H_
#define _NDSESPRO_H_

#include "cmapi.h"

#include "ndadaptr.h"

/* External message processing: parse message, call processing and change the state */

NQ_STATUS                          /* NQ_SUCCESS or NQ_FAIL */
ndSessionProcessExternalMessage(
    NDAdapterInfo* adapter      /* message origin */
    );

#endif  /* _NDSESPRO_H_ */


