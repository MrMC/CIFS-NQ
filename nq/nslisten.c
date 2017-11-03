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
    NQ_STATUS result = NQ_FAIL;
#ifdef UD_ND_INCLUDENBDAEMON
    void*       msgBuf;     /* buffer for Cancel Listen packet */
    NQ_INT      msgLen;     /* length of the message in this buffer */
#endif /* UD_ND_INCLUDENBDAEMON */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "sockHandle:%p backlog:%d", sockHandle, backlog);

#ifdef UD_ND_INCLUDENBDAEMON
    msgBuf = (void *)nsGetSendDatagramBuffer();
#endif /* UD_ND_INCLUDENBDAEMON */

    pSock = (SocketSlot*)sockHandle;
#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {        
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal slot");
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        goto Exit;
    }
#endif

    /* check if there was a prevous bind() */

    if (!pSock->isBind)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal slot");
        sySetLastError(CM_NBERR_NOBINDBEFORELISTEN);
        goto Exit;
    }

    /* if name was previously registered with the DD - do nothing */

    if (pSock->isListening)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Socket is already listening");
        result = NQ_SUCCESS;
        goto Exit;
    }

    /* for non-NetBIOS socket - just perform listen */

    if (!pSock->isNetBios)
    {
        sySetStreamSocketOptions(pSock->socket);

        if (syListenSocket(pSock->socket, backlog) == NQ_FAIL)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to start listening");
            sySetLastError(CM_NBERR_LISTENFAIL);
            goto Exit;
        }
        result = NQ_SUCCESS;
        goto Exit;
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
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to start listening");
            sySetLastError(CM_NBERR_LISTENFAIL);
            goto Exit;
        }
#ifndef UD_NB_RETARGETSESSIONS
        result = NQ_SUCCESS;
        goto Exit;
#else
        break;
#endif

    case NS_SOCKET_DATAGRAM:
        break;

    default:
        LOGERR(CM_TRC_LEVEL_ERROR, "Internal error - illegal socket type");
        goto Exit;
    }

    /* create Listen Request and send it to DD thus registering our socket
       with the DD */

#ifdef UD_ND_INCLUDENBDAEMON
	if ((msgLen = frameInternalListenRequest((NQ_BYTE*)msgBuf, pSock))==NQ_FAIL)
	{
	    LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create Cancel Listen packet");
        sySetLastError(CM_NBERR_CANCELLISTENFAIL);
	    goto Exit;
	}

	/* send the Cancel Listen packet to the DD and wait for response */
	if (nsProceedRequestToDD((NQ_BYTE*)msgBuf, (NQ_UINT)msgLen, pSock->name.name) == NQ_FAIL)
	{
	    syShutdownSocket(pSock->socket);    /* close the connection */
	    LOGERR(CM_TRC_LEVEL_ERROR, "Failed to register the socket with the DD: timeout");
        sySetLastError(CM_NBERR_TIMEOUT);   /*the functin timed out */
	    goto Exit;
	}
#endif /* UD_ND_INCLUDENBDAEMON */

    /* this socket will listen to any client */

    syMemcpy(pSock->remoteName.name, CM_NB_NETBIOSANYNAME, sizeof(CM_NB_NETBIOSANYNAME));
    pSock->remoteName.isGroup = FALSE;
    result = NQ_SUCCESS;

Exit:
#ifdef UD_ND_INCLUDENBDAEMON
    nsPutSendDatagramBuffer();
#endif /* UD_ND_INCLUDENBDAEMON */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
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
    NSSocketHandle resultHdl = NULL;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "sockHandle:%p peerIp:%p %s", sockHandle, peerIp, peerIp ? cmIPDump(peerIp) : "");

    pSock = (SocketSlot*)sockHandle;
#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal slot");
        goto Exit;
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Accept did not create a new socket");
        goto Exit;
    }
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "sock: %d", newSock);

    sySetClientSocketOptions(newSock);

    /* save information for a new socket */

    pNew = getSocketSlot();

    if (pNew == NULL)
    {
        syCloseSocket(newSock);
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to allocate a socket slot");
        goto Exit;
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
    pNew->isAccepted = TRUE;
    syMutexCreate(&pNew->guard);
    *peerIp = ipAddr;
    syGetSocketPortAndIP(newSock, &pNew->ip, &pNew->port);
    resultHdl = pNew;    /* new socket descriptor */

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", resultHdl);
    return resultHdl;

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
    NQ_CHAR inScope[10];    /* for parsing incoming scopes (called and caller) not used meanwhile */
#ifndef CM_NQ_STORAGE
    SYSocketSet socketSet;  /* read set */
#endif

#ifdef UD_NB_CHECKCALLEDNAME
    NQ_CHAR asciiIp[16];    /* for socket ip */
#endif
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "sockHandle:%p", sockHandle);

    inBuf = nsGetRecvDatagramBuffer();     /* allocate a buffer */
    pSock = (SocketSlot*)*sockHandle;

#if SY_DEBUGMODE
    if (!checkSocketSlot(pSock))    /* Is a valid slot (used)? */
    {
        sySetLastError(CM_NBERR_ILLEGALSOCKETSLOT);
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal slot");
        goto Exit;
    }
#endif

    /* read incoming packet */
#ifndef CM_NQ_STORAGE
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
#else /* == CM_NQ_STORAGE */
    inLen = syRecvSocketWithTimeout(pSock->socket, (NQ_BYTE*)inBuf, CM_NB_DATAGRAMBUFFERSIZE, CM_NB_UNICASTREQRETRYTIMEOUT);
#endif

    if (inLen == 0 || inLen == NQ_FAIL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error during reading from an accepted socket");
        goto Error;
    }

    /* parse the message header */

    sessionHeader = (CMNetBiosSessionMessage*)inBuf;  /* inspect packet code */

    if (sessionHeader->type != CM_NB_SESSIONREQUEST)    /* we expect just a Session Request */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected Session Message - Session Request expected");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " packet code - %d", sessionHeader->type);
        goto Error;
    }

    /* parse the called name */

    pCurr = cmNetBiosParseName(inBuf, sessionHeader + 1, inName, inScope, sizeof(inScope));

    if (pCurr == NULL)  /* name parsing error */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to parse the called name");
        goto Error;
    }

#ifdef UD_NB_CHECKCALLEDNAME
    cmIpToAscii(asciiIp, &pSock->ip);
    if (!cmNetBiosSameNames(inName, pSock->name.name) && !cmNetBiosIsHostAlias(inName) && syStrncmp(inName, asciiIp, syStrlen(asciiIp)) != 0)
    {
        /* not a name bound to the socket and not *SMBSERV */

        LOGERR(CM_TRC_LEVEL_ERROR, "Unexpected called name");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " expected - %s or %s, called - %s", pSock->name.name, asciiIp, inName);

        /* generate and send a Negative Session Response */

        inLen = frameNegativeSessionResponse((NQ_BYTE*)inBuf);
        inLen = sySendSocket(pSock->socket, (NQ_BYTE*)inBuf, (NQ_UINT)inLen);
        if (inLen <= 0)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send negative session response");
        }
        goto Error;
    }
#endif /* UD_NB_CHECKCALLEDNAME */

    /* parse the calling name */

    pCurr = cmNetBiosParseName(inBuf, pCurr, inName, inScope, sizeof(inScope));

    if (pCurr == NULL)  /* name parsing error */
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to parse the calling name");
        goto Error;
    }

    /* generate and send a Positive Session Response */

    inLen = framePositiveSessionResponse((NQ_BYTE*)inBuf);

    inLen = sySendSocket(pSock->socket, (NQ_BYTE*)inBuf, (NQ_UINT)inLen);
    if (inLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send positive session response");
        goto Error;
    }

    syMemcpy(pSock->remoteName.name, inName, sizeof(inName));
    pSock->remoteName.isGroup = FALSE;
    result = NQ_SUCCESS;
    goto Exit;

Error:
    nsClose(*sockHandle);
    *sockHandle = NULL;

Exit:
    nsPutRecvDatagramBuffer();
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;

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
	NQ_UINT32 timeout
    )
{
    NQ_INT res;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "set:%p timeout:%u", set, timeout);

    res = sySelectSocket(set, timeout);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", res);
    return res;      /* number of ready-to-read descriptors in the set */
}

