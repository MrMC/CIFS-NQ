
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Proceesing incoming message and timeouts for Datagram Service
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBios Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 26-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NDDATPRO_H_
#define _NDDATPRO_H_

#include "cmapi.h"

#include "ndadaptr.h"

/* initalize internal data */

NQ_STATUS                          /* NQ_SUCCESS or NQ_FAIL */
ndDatagramInit(
    void
    );

/* release internal data */

void
ndDatagramStop(
    void
    );

/* Internal message processing: parse message, call processing and change the state */

NQ_STATUS                          /* NQ_SUCCESS or NQ_FAIL */
ndDatagramProcessInternalMessage(
    NDAdapterInfo* adapter      /* origin of the incoming NB message */
    );

/* External message processing: parse message, call processing and change the state */

NQ_STATUS                          /* NQ_SUCCESS or NQ_FAIL */
ndDatagramProcessExternalMessage(
    NDAdapterInfo* adapter      /* origin of the incoming NB message */
    );

#endif  /* _NDDATPRO_H_ */


