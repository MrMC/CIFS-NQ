/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Pool of sockets for internal communications with
 *                 Name Daemon and Datagram Daemon
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 27-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NSINSOCK_H_
#define _NSINSOCK_H_

#include "nsapi.h"
#include "nssocket.h"

/*
 Types and functions for allocating an internal communication socket
 */


typedef struct              /* internal socket descriptor */
{
    SYSocketHandle socket;  /* socket from the underlying system */
    NQ_UINT idx;            /* slot index for checking (not necessary used) */
}
InternalSocket;

NQ_STATUS
nsInitInternalSockets(
    void
    );                      /* initialization */

NQ_STATUS
nsExitInternalSockets(
    void
    );                      /* clean up */

InternalSocket*
getInternalSocketND(
    void
    );                      /* take a socket from the pool */

void
putInternalSocketND(
    InternalSocket* sock
    );
                            /* return a socket to the pool */
InternalSocket*
getInternalSocketDD(
    void
    );                      /* take a socket from the pool */

void
putInternalSocketDD(
    InternalSocket* sock
    );                      /* return a socket to the pool */

#endif  /* _NSINSOCK_H_ */
