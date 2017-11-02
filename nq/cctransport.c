/*************************************************************************
 * Copyright 2011-2012 by Visuality Systems, Ltd.
 *
 *                     All Rights Reserved
 *
 * This item is the property of Visuality Systems, Ltd., and contains
 * confidential, proprietary, and trade-secret information. It may not
 * be transferred from the custody or control of Visuality Systems, Ltd.,
 * except as expressly authorized in writing by an officer of Visuality
 * Systems, Ltd. Neither this item nor the information it contains may
 * be used, transferred, reproduced, published, or disclosed, in whole
 * or in part, and directly or indirectly, except as expressly authorized
 * by an officer of Visuality Systems, Ltd., pursuant to written agreement.
 **************************************************************************/

#include "cctransport.h"
#include "ccapi.h"
#include "cmbufman.h"
#include "cmfinddc.h"
#include "cmlist.h"

/* -- Constants -- */
#define TRANSPORT_IDLETIMEOUT (15*60) /* 15 min Timeout for transport , this mimics windows disconnection after 15 min*/


/*#define SIMULATE_DISCONNECT*/ /* simulate transport disconnect - debug purposes only */
#define SIMULATE_DISCONNECT_AFTER 30

/* -- Static data -- */

static NQ_BOOL doReceive;			    /* when TRUE - receive responses */ 
static CMList connections;			    /* list of sockets to listen */
static SYThread receiveThread;		    /* receiving thread */
static SYSocketHandle notifyingSocket;  /* we send a message over this socket to signal that the list 
                                           above has changed */
static SYSocketHandle notifiedSocket;   /* we send a message to this socket to signal that the list 
                                           above has changed */
static const NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;	/* local IP in NBO */
static NQ_PORT notifyPort;              /* port to use for notification (in HBO) */

/* -- Static functions -- */

/* signal that the list of connections has changed */
static void notifyListChange()
{
    const static NQ_BYTE dummyMsg[] = {0};   /* a voluntary message to send over the notify socket */
    sySendToSocket(notifyingSocket, dummyMsg, sizeof(dummyMsg), &localhost, syHton16(notifyPort));
}

/*
 * Receive thread body
 */
static void receiveThreadBody(void)
{
#ifdef SIMULATE_DISCONNECT
	static NQ_INT cmdCount = 0;	/* count commands and disconnect after SIMULATE_DISCONNECT_AFTER of them */
#endif /* SIMULATE_DISCONNECT */

	while (doReceive)
	{
		NSSocketSet readList;		/* socket set for select */
		CMIterator iterator;		/* to go through the list */
		NQ_STATUS res;				/* operation status */
		
		/* Prepare socket descriptor */
		
		nsClearSocketSet(&readList);
		cmListIteratorStart(&connections, &iterator);
		while (cmListIteratorHasNext(&iterator))
		{
			CCTransport * pTransport;	/* casted pointer */
			
			pTransport = (CCTransport *)cmListIteratorNext(&iterator);
			if (NULL == pTransport->socket || !nsIsSocketAlive(pTransport->socket))
            {
                cmListItemRemove((CMItem *)pTransport);
                break;
            }
            syMutexTake(&pTransport->guard);
            if (!pTransport->isReceiving)
			{
				nsAddSocketToSet(&readList, pTransport->socket);
			}
            syMutexGive(&pTransport->guard);
		}
		cmListIteratorTerminate(&iterator);
        syAddSocketToSet(notifiedSocket, &readList);

		res = nsSelect(&readList, 1);	/* each second */

		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Select returned %d", res);

		if (res == 0)
		{
			LOGERR(CM_TRC_LEVEL_LOW_ERROR, "Select() timeout");
			continue;
		}
		if (res == NQ_FAIL)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Select() error");
			continue;
    	}
#ifdef SIMULATE_DISCONNECT
		cmdCount++;
#endif /* SIMULATE_DISCONNECT */
        /* check notfy */
        if (syIsSocketSet(notifiedSocket, &readList))
        {
            NQ_BYTE buf[2];         /* buffer for dummy */
            NQ_IPADDRESS ip;        /* dummy ip */
            NQ_PORT port;           /* dummy port */
            syRecvFromSocket(notifiedSocket, buf, sizeof(buf), &ip, &port); 
            continue;
        }
		cmListIteratorStart(&connections, &iterator);
		while (cmListIteratorHasNext(&iterator))
		{
			CCTransport * pTransport;	/* casted pointer */
			
			pTransport = (CCTransport *)cmListIteratorNext(&iterator);
#ifdef SIMULATE_DISCONNECT
			if (cmdCount >= SIMULATE_DISCONNECT_AFTER)
			{
				nsClose(pTransport->socket);
			}
			else
#endif /* SIMULATE_DISCONNECT */
			{
                if (NULL != pTransport->socket && nsIsSocketAlive(pTransport->socket) && nsSocketInSet(&readList, pTransport->socket))
                {
                    NQ_INT res;                             /* number of bytes or error */

                    res = ccTransportReceivePacketLength(pTransport);
                    if (res != 0)  /* skip NBSS control messages */
                    {
                        if (res < 0)
                        {
                            ccTransportDisconnect(pTransport);
                        }
				        pTransport->callback(pTransport);
                    }
                }
			}
		}
		cmListIteratorTerminate(&iterator);
#ifdef SIMULATE_DISCONNECT
		if (cmdCount >= SIMULATE_DISCONNECT_AFTER)
		{
			cmdCount = 0;
		}
#endif /* SIMULATE_DISCONNECT */
	}
}

/*
 * An attempt to connect server 
 */
static NSSocketHandle connectOneTransportByOneIp(NQ_INT transportType, const NQ_IPADDRESS * ip, CMNetBiosNameInfo * nbInfo)
{
    NQ_STATUS res;              /* operation result */
    NSSocketHandle socket;      /* socket handle */


	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Transport: %d", transportType);

    /* Create TCP socket */
    socket = nsSocket(NS_SOCKET_STREAM, (NQ_UINT)transportType);
    if (socket == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "nsSocket() failed");
    	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    /* Connect to remote Server */
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "before nsConnect: %s", nbInfo->name);
    res = nsConnect(socket, (NQ_IPADDRESS *)ip, nbInfo);
    if (res == NQ_FAIL)
    {
        nsClose(socket);
        TRCERR("nsConnect() failed");
        TRCE();
        return NULL;
    }

    TRC2P("Connected to %s, %s", cmIPDump(ip), nbInfo->name);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return socket;
}


/* -- API Functions */

NQ_BOOL ccTransportStart(void)
{
	doReceive = TRUE;
	cmListStart(&connections);
    notifiedSocket = syCreateSocket(FALSE, CM_IPADDR_IPV4);
	notifyingSocket = syCreateSocket(FALSE, CM_IPADDR_IPV4);
	if (!syIsValidSocket(notifiedSocket) || !syIsValidSocket(notifyingSocket))
		return FALSE;
    notifyPort = cmThreadBindPort(notifiedSocket);
    if (0 == notifyPort) 
    {
        syCloseSocket(notifiedSocket);
        syCloseSocket(notifyingSocket);
		return FALSE;
    }
	syThreadStart(&receiveThread, receiveThreadBody, TRUE);
    return TRUE;
}

void ccTransportShutdown(void)
{
	doReceive = FALSE;
	cmListShutdown(&connections);
	syThreadDestroy(receiveThread);
    syCloseSocket(notifiedSocket);
    syCloseSocket(notifyingSocket);
    cmThreadFreePort(notifyPort);
}

void ccTransportInit(CCTransport * transport)
{
    transport->connected = FALSE;
}

NQ_BOOL ccTransportConnect(
    CCTransport * pTransport, 
    const NQ_IPADDRESS * ips, 
    NQ_INT numIps, 
    const NQ_WCHAR * host,
    CCTransportCleanupCallback cleanupCallback,
    void * cleanupContext
    )
{
    NSSocketHandle socket;		/* resulting handle */
    CMNetBiosNameInfo nbInfo;	/* NetBIOS name information */
    NQ_CHAR* aHost;				/* host name in ASCII */
    NQ_UINT * transportTypes;   /* transport types ordered by priorities */
   
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "host: %s", cmWDump((const NQ_WCHAR *) host));

    syMutexCreate(&pTransport->item.guard);
    pTransport->connected = FALSE;
    pTransport->cleanupCallback = cleanupCallback;
    pTransport->cleanupContext = cleanupContext;
    /* compose NetBIOS name */
    aHost = cmMemoryCloneWStringAsAscii(host);
	if (NULL == aHost)
	{
		LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
		return FALSE;
	}
    cmNetBiosNameCreate(nbInfo.name, aHost, CM_NB_POSTFIX_SERVER);
    nbInfo.isGroup = FALSE;
    cmMemoryFree(aHost);
    
    for (transportTypes = cmGetTransportPriorities(); *transportTypes != 0; transportTypes++)
    {
    	NQ_INT i;	/* just a counter */
    	for (i = 0; i < numIps; i++)
        {   
#ifdef UD_NQ_USETRANSPORTIPV6                    
            NQ_UINT addrType;        /* address type */

            addrType = CM_IPADDR_VERSION(ips[i]);

            if (addrType == CM_IPADDR_IPV4 && *transportTypes == NS_TRANSPORT_IPV6)
                    continue;
            if (addrType == CM_IPADDR_IPV6 && *transportTypes != NS_TRANSPORT_IPV6)
                continue;
#endif /* UD_NQ_USETRANSPORTIPV6 */   

		    if (NULL != (socket = connectOneTransportByOneIp((NQ_INT)*transportTypes, &ips[i], &nbInfo)))
		    {
			    pTransport->socket = socket;
			    pTransport->connected = TRUE;
                pTransport->isReceiving = TRUE;
                syMutexCreate(&pTransport->guard);
			    cmListItemAdd(&connections, (CMItem *)pTransport, NULL);
                notifyListChange();
    		    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			    return TRUE;
		    }
		}
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return FALSE;
}

NQ_BOOL ccTransportIsTimeoutExpired(CCTransport * transport)
{
    return (syGetTime() - transport->lastTime) > TRANSPORT_IDLETIMEOUT;
}

NQ_BOOL ccTransportIsConnected(CCTransport * pTransport)
{
    return nsIsSocketAlive(pTransport->socket) && pTransport->connected;
}

NQ_BOOL ccTransportDisconnect(CCTransport * pTransport)
{   
    if (pTransport->connected)
    {
        pTransport->connected = FALSE;
        cmListItemRemove((CMItem *)pTransport);
        notifyListChange();
        syMutexDelete(&pTransport->guard);
        syMutexDelete(&pTransport->item.guard);
        (*pTransport->cleanupCallback)(pTransport->cleanupContext);
	    return (NQ_SUCCESS == nsClose(pTransport->socket));
    }
    else
    {   
        return FALSE;
    }
 }

void ccTransportLock(CCTransport * transport)
{
    if (transport->connected)
        syMutexTake(&transport->guard);
}

void ccTransportUnlock(CCTransport * transport)
{
    if (transport->connected)
        syMutexGive(&transport->guard);
}

NQ_BOOL ccTransportSend(CCTransport * pTransport, const NQ_BYTE * buffer, NQ_COUNT packetLen, NQ_COUNT dataLen)
{
    if (!nsIsSocketAlive(pTransport->socket))
    {
        ccTransportDisconnect(pTransport);
        sySetLastError(NQ_ERR_RECONNECTREQUIRED);
        return FALSE;
    }

    /* Send the packet through NetBIOS */
    if (NQ_FAIL == nsSendFromBuffer(pTransport->socket, (NQ_BYTE *)buffer, packetLen, dataLen, NULL)) 
    {
        sySetLastError(NQ_ERR_RECONNECTREQUIRED);
        LOGERR(CM_TRC_LEVEL_ERROR, "Sending failed");
        return FALSE;
    }
    pTransport->lastTime = (NQ_TIME)syGetTime();
    return TRUE;
}

NQ_BOOL ccTransportSendSync(CCTransport * pTransport, const NQ_BYTE * buffer, NQ_COUNT packetLen, NQ_COUNT dataLen)
{
    if (!nsIsSocketAlive(pTransport->socket))
    {
        ccTransportDisconnect(pTransport);
        sySetLastError(NQ_ERR_RECONNECTREQUIRED);
        return FALSE;
    }
    /* Send the packet through NetBIOS */
    if (NQ_FAIL == nsSendFromBuffer(pTransport->socket, (NQ_BYTE *)buffer, packetLen, dataLen, NULL)) 
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Sending failed");
        return FALSE;
    }
    pTransport->lastTime = (NQ_TIME)syGetTime();
    return TRUE;
}

NQ_BOOL ccTransportSendTail(CCTransport * pTransport, const NQ_BYTE * data, NQ_COUNT dataLen)
{
	return dataLen == sySendSocket(nsGetSySocket(pTransport->socket), data, dataLen);
}

void ccTransportSetResponseCallback(CCTransport * pTransport, CCTransportResponseCallback callback, void * context)
{
	pTransport->callback = callback;
	pTransport->context = context;
}

void ccTransportRemoveResponseCallback(CCTransport * pTransport)
{
	cmListItemRemove((CMItem *)pTransport);
}

NQ_BYTE * ccTransportReceiveAll(CCTransport * pTransport, NQ_COUNT * dataLen)
{
    NQ_INT res;				/* Various: number of bytes expected, call result */ 
    NQ_BYTE * pRecvBuffer;	/* Reeceive buffer pointer */

    res = ccTransportReceivePacketLength(pTransport);
	if (res == 0 || res == NQ_FAIL)
	{
        ccTransportReceiveEnd(pTransport);
		return NULL;
	}
	pRecvBuffer = cmBufManTake((NQ_COUNT)res);
	if (NULL == pRecvBuffer)
	{
        ccTransportReceiveEnd(pTransport);
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGERR(CM_TRC_LEVEL_ERROR, "Failed to take buffer");
		return NULL;
	}
    if (NQ_FAIL == ccTransportReceiveBytes(pTransport, pRecvBuffer, (NQ_COUNT)res))
	{
        ccTransportReceiveEnd(pTransport);
		return NULL;
	}
    ccTransportReceiveEnd(pTransport);
	*dataLen = (NQ_COUNT)res;
    return pRecvBuffer;
}

NQ_INT ccTransportReceivePacketLength(CCTransport * pTransport)
{
    NQ_INT res;	/* bytes read */

    ccTransportLock(pTransport);
    pTransport->isReceiving = TRUE;
	res = nsStartRecvIntoBuffer(pTransport->socket, &pTransport->recv);
	if (res == 0 || res == NQ_FAIL)
	{
        pTransport->isReceiving = FALSE;
        ccTransportUnlock(pTransport);
		LOGERR(CM_TRC_LEVEL_ERROR, "Unable to read NBT header or a control message received");
	}
    return res;
}

NQ_COUNT ccTransportReceiveBytes(CCTransport * pTransport, NQ_BYTE * buffer, NQ_COUNT dataLen)
{
    NQ_INT res;				/* Various: number of bytes expected, call result */ 

	res = nsRecvIntoBuffer(&pTransport->recv, buffer, dataLen);
	if (NQ_FAIL == res)
	{
        pTransport->isReceiving = FALSE;
        ccTransportUnlock(pTransport);
	    LOGERR(CM_TRC_LEVEL_ERROR, "Recv() failed");
	}
    return (NQ_COUNT)res;
}

NQ_COUNT ccTransportReceiveEnd(CCTransport * pTransport)
{
    NQ_COUNT res;       /* operation result */
    pTransport->isReceiving = FALSE;
	res = (NQ_COUNT)nsEndRecvIntoBuffer(&pTransport->recv);
    ccTransportUnlock(pTransport);
    return res;
}

void ccTransportDiscardReceive(CCTransport * pTransport)
{
    ccTransportLock(pTransport);
    pTransport->isReceiving = FALSE;
    ccTransportUnlock(pTransport);
}

