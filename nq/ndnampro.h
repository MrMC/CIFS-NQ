/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Proceesing incoming message and timeouts for Name Service
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBios Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 26-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NDNAMPRO_H_
#define _NDNAMPRO_H_

#include "cmapi.h"
#include "ndadaptr.h"
#include "ndapi.h"

/* initalize internal data */

NQ_STATUS                          /* NQ_SUCCESS or NQ_FAIL */
ndNameInit(
    void
    );

/* release internal data */

void
ndNameStop(
    void
    );

/* Incoming message processing: parse message, call processing and change the state */

NQ_STATUS                       /* NQ_SUCCESS or NQ_FAIL */
ndNameProcessExternalMessage(
    NDAdapterInfo* adapter      /* message origin */
    );

/* Internal message processing: parse message, call processing and change the state */

NQ_STATUS                       /* NQ_SUCCESS or NQ_FAIL */
ndNameProcessInternalMessage(
    NDAdapterInfo* adapter      /* message origin */
    );

/* Timeout processing: finding expired entries and timed out operations */

NQ_COUNT                        /* next timeout interval */
ndNameProcessTimeout(
    NQ_INT delta                /* elapsed time in seconds */
    );

#endif  /* _NDNAMPRO_H_ */
