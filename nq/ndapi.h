/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Name Daemon Interface
 *--------------------------------------------------------------------
 * MODULE        : NM - Name Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 26-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NDAPI_H_
#define _NDAPI_H_

#include "cmapi.h"
#include "ndadaptr.h"

/*@@ndStart
   Description
   Startup point for NetBIOS Daemon.
   Returns
   <i>NQ_SUCCESS</i> when the daemon has started and <i>NQ_FAIL</i>
   when it failed to start.                                         */
NQ_STATUS ndStart(SYSemaphore * sem);

/*@@
 Description
 Shutdown point for NetBIOS Daemon.
void ndStop(void);
Returns
None*/
void ndStop(void);

/*@@
Notification about a change in the network configuration.

The application may call this function when the list of adapters changes or when wins servers are updated. 
This call causes NetBIS Daemon to reload the list of adapters and send new registrations to WINS servers.
 */
void ndNotifyConfigurationChange(NDAdapterInfo* adapter);

#endif  /* _NDAPI_H_ */
