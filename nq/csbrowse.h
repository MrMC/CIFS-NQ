
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Browse processing (Server Announcement processing)
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-June-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _CSBROWSE_H_
#define _CSBROWSE_H_

#include "cmapi.h"
#include "cstransa.h"

/* initialize server announcement interval */

NQ_STATUS                  /* NQ_SUCCESS or NQ_FAIL */
csInitBrowse(
    void
    );

/* release resources */

void
csStopBrowse(
    void
    );

/* perform Host Announcement for our server */

NQ_TIME                   /* next announcement interval in seconds */
csAnnounceServer(
    void
    );

/* mailslot client */

NQ_UINT32              /* returns error code o 0 on success */
csMailslotBrowse(
    CSTransactionDescriptor* descriptor /* transaction descriptor */
    );

#endif  /* _CSBROWSE_H_ */

