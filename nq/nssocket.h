/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Socket list management
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NSSOCKET_H_
#define _NSSOCKET_H_

#include "nsapi.h"

/*
 NS keeps trek of all sockets created by means of nsSocket. We use
 socket descriptor and a pool of socket descriptor.
 */

typedef struct
{
	CMItem 				item;		/* inheritance */
    SYSocketHandle      socket;     /* underlying socket's handle */
    NQ_UINT             transport;  /* socket transport type */
    NQ_BOOL             isNetBios;  /* TRUE for NetBIOS socket, FALSE for TCP */
    NQ_UINT             type;       /* socket protocol (stream or datagram) */
    CMNetBiosNameInfo   name;       /* bind name */
    CMNetBiosNameInfo   remoteName; /* name on the other side */
    NQ_PORT             remotePort; /* port connected to on the other side */
    NQ_IPADDRESS        remoteIP;   /* remote host IP */
    NQ_IPADDRESS        ip;         /* self socket IP */
    NQ_PORT             port;       /* self dynamic port number */
    NQ_BOOL             isListening;/* in listen() */
    NQ_BOOL             isBind;     /* if TRUE - this socket is bound */
    NQ_BOOL             isDead;     /* */
    NQ_BOOL 			isAccepted;	/* */
    SYMutex				guard;		/* making thread-safe - only used on accepted sockets */
}
SocketSlot;

NQ_STATUS         /* NQ_SUCCESS or NQ_FAIL */
nsInitSocketPool(
    void
    );           /* initialization */

void
nsExitSocketPool(
    void
    );           /* clean up */

SocketSlot*
getSocketSlot(
    void
    );           /* take a socket descriptor from the pool */

void
putSocketSlot(
    SocketSlot* sock
    );  /* return a socket descriptor to the pool */

#define checkSocketSlot(_sock)          \
    (_sock!=NULL    &&                  \
     syIsValidSocket((_sock)->socket)   \
    )                                       /* Check that the socket slot is in use */

#define SYSOCK(_s_)         (((SocketSlot *)(_s_))->socket)

#endif  /* _NSSOCKET_H_ */
