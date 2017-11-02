/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of listen, accept, select mechanism
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "nsapi.h"

#include "nsbuffer.h"
#include "nssocket.h"
#include "nscommon.h"
#include "nsframes.h"

/*
  This file implements functions for listening and accepting connections
 */

/*
 *====================================================================
 * PURPOSE: Listen to incoming connect requests
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          IN listen queue length
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   For TCP socket we listen directly on the underlying socket
 *          For UDP socket we delegate listening to DD
 *          In any case we send a Listen Request in the VIPC proprietary protocol
 *====================================================================
 */

NQ_STATUS
nsListen(
    NSSocketHandle sockHandle,
    NQ_INT backlog
    )
{
    SocketSlot* pSock;      /* pointer to the socket descriptor */

    TRCB();


    pSock = (SocketSlot*)sockHandle;
#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        TRCERR("Illegal slot");
        TRCE();
        return NQ_FAIL;
    }
#endif

    /* check if there was a prevous bind() */

    if (!pSock->isBind)
    {
        sySetLastError(CM_NBERR_NOBINDBEFORELISTEN);
        TRCERR("Illegal slot");
        TRCE();
        return NQ_FAIL;
    }

    /* if name was previously registered with the DD - do nothing */

    if (pSock->isListening)
    {
        TRC("Socket is already listening");
        TRCE();
        return NQ_SUCCESS;
    }

    /* for non-NetBIOS socket - just perform listen */

    if (!pSock->isNetBios)
    {
        sySetStreamSocketOptions(pSock->socket);

        if (syListenSocket(pSock->socket, backlog) == NQ_FAIL)
        {
            TRCERR("Unable to start listening");
            TRCE();
            return NQ_FAIL;
        }

        TRCE();
        return NQ_SUCCESS;
    }

    /* we listen directly to stream sockets,
       for datagram sockets - the DD listens instead, we only register our socket with
       DD by means of the Listen Request packet (Visuality-internal) */

    switch (pSock->type)
    {
    case NS_SOCKET_STREAM:
        sySetStreamSocketOptions(pSock->socket);

        if (syListenSocket(pSock->socket, backlog) == NQ_FAIL)
        {
            TRCERR("Unable to start listening");
            TRCE();
            return NQ_FAIL;
        }
#ifndef UD_NB_RETARGETSESSIONS
        TRCE();
        return NQ_SUCCESS;
#else
        break;
#endif

    case NS_SOCKET_DATAGRAM:
        break;

    default:
        TRCERR("Internal error - illegal socket type");
        TRCE();
        return NQ_FAIL;
    }

    /* create Listen Request and send it to DD thus registering our socket
       with the DD */

#ifdef UD_ND_INCLUDENBDAEMON
    {
        void*       msgBuf;         /* buffer for Cancel Listen packet */
        NQ_INT        msgLen;       /* length of the message in this buffer */

        msgBuf = (void *)nsGetSendDatagramBuffer();

        if ((msgLen = frameInternalListenRequest((NQ_BYTE*)msgBuf, pSock))==NQ_FAIL)
        {
            sySetLastError(CM_NBERR_CANCELLISTENFAIL);
            nsPutSendDatagramBuffer();

            TRCERR("Unable to create Cancel Listen packet");
            TRCE();
            return NQ_FAIL;
        }

        /* send the Cancel Listen packet to the DD and wait for response */
        if (nsProceedRequestToDD((NQ_BYTE*)msgBuf, (NQ_UINT)msgLen, pSock->name.name) == NQ_FAIL)
        {
            nsPutSendDatagramBuffer();

            syShutdownSocket(pSock->socket);    /* close the connection */
            sySetLastError(CM_NBERR_TIMEOUT);   /*the functin timed out */

            TRCERR("Failed to register the socket with the DD: timeout");
            TRCE();
            return NQ_FAIL;
        }
        nsPutSendDatagramBuffer();

     }
#endif /* UD_ND_INCLUDENBDAEMON */

    /* this socket will listen to any client */

    syMemcpy(pSock->remoteName.name, CM_NB_NETBIOSANYNAME, sizeof(CM_NB_NETBIOSANYNAME));
    pSock->remoteName.isGroup = FALSE;

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Accept an incoming connection request
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *          OUT buffer for the peer IP
 *
 * RETURNS: New (dynamically created) socket handle
 *
 * NOTES:   This call will create a new socket that will be connected to
 *          the remote (client) socket
 *          We expect an incoming SESSION REQUEST on this connection just
 *          after the connection established. This is achieved by nsPostAccept()
 *====================================================================
 */

NSSocketHandle
nsAccept(
    NSSocketHandle sockHandle,
    NQ_IPADDRESS *peerIp
    )
{

    SocketSlot* pSock;      /* pointer to the socket descriptor */
    SocketSlot* pNew;       /* pointer to a socket descriptor for a dynamically created socket */
    SYSocketHandle newSock; /* dynamically created socket */
    NQ_PORT port;           /* accepted port */
    NQ_IPADDRESS ipAddr;    /* accepted IP */

    TRCB();

    pSock = (SocketSlot*)sockHandle;
#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        TRCERR("Illegal slot");
        TRCE();
        return NULL;
    }
#endif

    if (pSock->type==NS_SOCKET_DATAGRAM)
    {
        sySetDatagramSocketOptions(pSock->socket);
    }
    else
    {
        sySetStreamSocketOptions(pSock->socket);
    }

    newSock = syAcceptSocket(pSock->socket, &ipAddr, &port);

    if (!syIsValidSocket(newSock))
    {
        TRCERR("Accept did not create a new socket");
        TRCE();
        return NULL;
    }

    sySetClientSocketOptions(newSock);

    /* save information for a new socket */

    pNew = getSocketSlot();

    if (pNew == NULL)
    {
        syCloseSocket(newSock);

        TRCERR("Failed to allocate a socket slot");
        TRCE();
        return NULL;
    }

    /* set up the new socket's data */

    pNew->socket = newSock;
    /*
     * this value is always set to TRUE even for a "naked" connection
     * since even such a connection carries NBT-like 4-byte header
     * and this value controls parsing that header
     */
    pNew->isNetBios = TRUE;
    pNew->type = pSock->type;
    syMemcpy(&pNew->name, &pSock->name, sizeof(pSock->name));
    pNew->isListening = FALSE;
    pNew->isBind = FALSE;
    pNew->remoteIP = ipAddr;
    *peerIp = ipAddr;
    syGetSocketPortAndIP(newSock, &pNew->ip, &pNew->port);

    TRCE();

    return pNew;    /* new socket descriptor */

}/* end of nsAccept */

#ifdef UD_NQ_USETRANSPORTNETBIOS

/*
 *====================================================================
 * PURPOSE: accept SESSION REQUEST on a newly connected socket
 *--------------------------------------------------------------------
 * PARAMS:  IN socket descriptor
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This function is called from NetBIOS only 
 *          We expect an incoming SESSION REQUEST on this connection just
 *          after the connection established
 *          On success we respond with POSITIVE SESSION RESPONSE
 *          On invalid request message we do not respond (unless UD_NB_CHECKCALLEDNAME)
 *====================================================================
 */

NQ_STATUS
nsPostAccept(
    NSSocketHandle *sockHandle
    )
{

    SocketSlot* pSock;      /* pointer to the socket descriptor */
    NQ_BYTE* inBuf;         /* incoming message */
    NQ_INT inLen;           /* incoming message length */
    CMNetBiosSessionMessage* sessionHeader; /* pointer to a Session Request message */
    NQ_BYTE* pCurr;         /* temporary pointer to the currently parsed clause in the
                               message */
    CMNetBiosName   inName; /* for parsing incoming names (called and caller) */
    NQ_CHAR inScope[10];    /* for parsing incoming scopes (called and caller)
                               not used meanwhile */
    SYSocketSet socketSet;  /* read set */
#ifdef UD_NB_CHECKCALLEDNAME
    NQ_CHAR asciiIp[16];    /* for socket ip */
#endif

    TRCB();

    pSock = (SocketSlot*)*sockHandle;
#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        TRCERR("Illegal slot");
        TRCE();
        return NQ_FAIL;
    }
#endif

    /* read incoming packet */
    syClearSocketSet(&socketSet);
    syAddSocketToSet(pSock->socket, &socketSet);

    switch (sySelectSocket(&socketSet, CM_NB_UNICASTREQRETRYTIMEOUT))
    {
        case 0:
        case NQ_FAIL:
            nsClose(*sockHandle);
            *sockHandle = NULL;

            TRCERR("Error during reading from an accepted socket");
            TRCE();
            return NQ_FAIL;
    }

    inBuf = nsGetRecvDatagramBuffer();     /* allocate a buffer */
    inLen = syRecvSocket(pSock->socket, (NQ_BYTE*)inBuf, CM_NB_DATAGRAMBUFFERSIZE);

    if (inLen == 0 || inLen == NQ_FAIL)
    {
        nsPutRecvDatagramBuffer();
        nsClose(*sockHandle);
        *sockHandle = NULL;

        TRCERR("Error during reading from an accepted socket");
        TRCE();
        return NQ_FAIL;
    }

    /* parse the message header */

    sessionHeader = (CMNetBiosSessionMessage*)inBuf;  /* inspect packet code */

    if (sessionHeader->type != CM_NB_SESSIONREQUEST)    /* we expect just a Session Request */
    {
        nsPutRecvDatagramBuffer();
        nsClose(*sockHandle);
        *sockHandle = NULL;

        TRCERR("Unexpected Session Message - Session Request expected");
        TRC1P(" packet code - %d", sessionHeader->type);
        TRCE();
        return NQ_FAIL;
    }

    /* parse the called name */

    pCurr = cmNetBiosParseName(inBuf, sessionHeader + 1, inName, inScope, sizeof(inScope));

    if (pCurr == NULL)  /* name parsing error */
    {
        nsPutRecvDatagramBuffer();
        nsClose(*sockHandle);
        *sockHandle = NULL;

        TRCERR("Failed to parse the called name");
        TRCE();
        return NQ_FAIL;
    }

#ifdef UD_NB_CHECKCALLEDNAME
    cmIpToAscii(asciiIp, &pSock->ip);
    if (!cmNetBiosSameNames(inName, pSock->name.name) && !cmNetBiosIsHostAlias(inName) && syStrncmp(inName, asciiIp, syStrlen(asciiIp)) != 0)
    {
        /* not a name bound to the socket and not *SMBSERV */

        TRCERR("Unexpected called name");
        TRC(" expected - %s or %s, called - %s", pSock->name.name, asciiIp, inName);

        /* generate and send a Negative Session Response */

        inLen = frameNegativeSessionResponse((NQ_BYTE*)inBuf);
        inLen = sySendSocket(pSock->socket, (NQ_BYTE*)inBuf, (NQ_UINT)inLen);
        if (inLen <= 0)
        {
            TRCERR("Failed to send negative session response");
        }
        nsPutRecvDatagramBuffer();
/*        syCloseSocket(pSock->socket); */

        TRCE();
        return NQ_FAIL;
    }
#endif /* UD_NB_CHECKCALLEDNAME */

    /* parse the calling name */

    pCurr = cmNetBiosParseName(inBuf, pCurr, inName, inScope, sizeof(inScope));

    if (pCurr == NULL)  /* name parsing error */
    {
        nsPutRecvDatagramBuffer();
        nsClose(*sockHandle);
        *sockHandle = NULL;

        TRCERR("Failed to parse the calling name");
        TRCE();
        return NQ_FAIL;
    }

    /* generate and send a Positive Session Response */

    inLen = framePositiveSessionResponse((NQ_BYTE*)inBuf);

    inLen = sySendSocket(pSock->socket, (NQ_BYTE*)inBuf, (NQ_UINT)inLen);
    if (inLen <= 0)
    {
        nsPutRecvDatagramBuffer();
        nsClose(*sockHandle);
        *sockHandle = NULL;

        TRCERR("Failed to send positive session response");
        TRCE();
        return NQ_FAIL;
    }

    nsPutRecvDatagramBuffer();    /* release the buffer */

    syMemcpy(pSock->remoteName.name, inName, sizeof(inName));
    pSock->remoteName.isGroup = FALSE;

    TRCE();

    return NQ_SUCCESS;

}/* end of nsPostAccept */

#endif /* UD_NQ_USETRANSPORTNETBIOS */

/*
 *====================================================================
 * PURPOSE: Wait for data on a set of sockets
 *--------------------------------------------------------------------
 * PARAMS:  IN: number of sockets to wait
 *          IN: socket set
 *          IN: timeout (seconds)
 *
 * RETURNS: Positive number - number of sockets with data, 0 - timeout,
 *          NQ_FAIL
 *
 * NOTES:   We delegate this call to the underlying socket
 *====================================================================
 */

NQ_INT
nsSelect(
    NSSocketSet* set,
    NQ_TIME timeout
    )
{
    NQ_INT res;

    TRCB();

    res = sySelectSocket(set, timeout);

    TRCE();
    return res;      /* number of ready-to-read descriptors in the set */
}

