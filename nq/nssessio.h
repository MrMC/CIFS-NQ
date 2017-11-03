/*********************************************************************
 *
 *           Copyright (c) 2007 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Interface to NB session management
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NSSESSION_H_
#define _NSSESSION_H_

#include "nsapi.h"

NQ_STATUS        /* NQ_SUCCESS or NQ_FAIL */
nsInitSession(
    void
    );           /* initialization */

void
nsExitSession(
    void
    );           /* clean up */

NQ_IPADDRESS4  cmNetBiosGetWins(NQ_COUNT winsID);
NQ_COUNT cmNetBiosGetNumWinsServers(void);

void nsRefreshNetBios(const NQ_WCHAR * servers);

void ndSetWinsW(const NQ_WCHAR * servers);

#endif  /* _NSSESSION_H_ */
