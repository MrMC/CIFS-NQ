/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Management of common NS frames
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NSFRAMES_H_
#define _NSFRAMES_H_

#include "nsapi.h"

#include "nssocket.h"

/* parse an incoming datagram */

NQ_INT                                      /* actual user data length */
frameParseDatagram(
    const NQ_BYTE *receiveBuf,              /* datagram */
    NQ_UINT bytesRead,                      /* datagram length */
    CMNetBiosName sourceName,               /* buffer to place the name of the sender */
    NQ_BYTE *userBuf,                       /* buffer for user data */
    NQ_UINT userLen,                        /* this buffer size */
    const CMNetBiosName expectedName        /* expected destination anme in the response */
    );

/* generate a generic datagram message */
                                            /* actual message length */
NQ_INT
frameComposeDatagram(
    CMNetBiosDatagramMessage* msgBuf,       /* buffer of enough size for creating a message */
    const SocketSlot* pSock,                /* socket to use for additional info */
    NQ_BYTE type,                           /* datagram type */
    const CMNetBiosName callingName,        /* destination name */
    const CMNetBiosName calledName,         /* sender name */
    const NQ_BYTE* data,                    /* user data */
    NQ_UINT dataLen                         /* user data length */
    );

/* generate Session Message packet to called */

NQ_UINT                                     /* actual message length */
frameSessionMessage(
    NQ_BYTE* msgBuf,                        /* buffer of enough size for creating a message */
    const NQ_BYTE* data,                    /* bytes to send */
    NQ_UINT dataLen                         /* number of data bytes */
    );

/* generate Positive Session Response to caller */

NQ_INT                                      /* actual message length */
framePositiveSessionResponse( 
    NQ_BYTE* msgBuf                         /* buffer of enough size for creating a message */
    );

#ifdef UD_NB_CHECKCALLEDNAME

/* generate Negative Session Response to caller */

NQ_INT                                      /* actual message length */
frameNegativeSessionResponse(
    NQ_BYTE* msgBuf                         /* buffer of enough size for creating a message */
    );

#endif /* UD_NB_CHECKCALLEDNAME */

/* generate Name Query Request to ND */

NQ_INT                                      /* actual message length */
frameInternalNameQueryRequest(
    NQ_BYTE* msgBuf,                        /* buffer of enough size for creating a message */
    const CMNetBiosNameInfo* name           /* name to resolve */
    );

/* generate Name Registration Request packet to ND
   this packet will have PID in place of IP address (NB_ADDRESS) */

NQ_INT                                      /* actual message length */
frameInternalNameRegistrationRequest(
    NQ_BYTE* msgBuf,                        /* buffer of enough size for creatinga message */
    const CMNetBiosNameInfo* name           /* name to register */
    );

/* generate Name Release Request packet to ND
   this packet will have PID in place of IP address (NB_ADDRESS) */

NQ_INT                                      /* actual message length */
frameInternalNameReleaseRequest(
    NQ_BYTE* msgBuf,                        /* buffer of enough size for creatinga message */
    const CMNetBiosNameInfo* name           /* name to release */
    );

/* generate Session Request packet to DD */

NQ_INT                                      /* actual message length */
frameInternalSessionRequest(
    NQ_BYTE* msgBuf,                        /* buffer of enough size for creating a message */
    const CMNetBiosNameInfo* calledName,    /* called name */
    const SocketSlot* pSock                 /* socket info to identify it for the DD */
    );

/* generate Listen Request packet to DD
   this packet is a Visuality NetBIOS extension */

NQ_INT                                      /* actual message length */
frameInternalListenRequest(
    NQ_BYTE* msgBuf,                        /* buffer of enough size for creatinga message */
    const SocketSlot* socket                /* socket info to identify it for the DD */
    );

/* generate Cancel Listen packet to DD
   this packet is a Visuality NetBIOS extension */

NQ_INT                                      /* actual message length */
frameInternalCancelListen(
    NQ_BYTE* msgBuf,                        /* buffer of enough size for creatinga message */
    const SocketSlot* socket                /* socket info to identify it for the DD */
    );

#endif  /* _NSFRAMES_H_ */

