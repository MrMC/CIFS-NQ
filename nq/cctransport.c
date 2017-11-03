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
#include "ccserver.h"
#ifdef UD_NQ_INCLUDESMBCAPTURE
#include "nssocket.h"
#endif /* UD_NQ_INCLUDESMBCAPTURE */

/* -- Constants -- */
#define TRANSPORT_IDLETIMEOUT (15*60) /* 15 min Timeout for transport , this mimics windows disconnection after 15 min*/


/*#define SIMULATE_DISCONNECT*/ /* simulate transport disconnect - debug purposes only */
#define SIMULATE_DISCONNECT_AFTER 30

/* -- Static data -- */

static NQ_BOOL isInitDone = FALSE;				/* Was init done  */
static NQ_BOOL doReceive;			    /* when TRUE - receive responses */ 
static CMList connections;			    /* list of sockets to listen */
static SYThread receiveThread;		    /* receiving thread */
static SYSocketHandle notifyingSocket = syInvalidSocket();  /* we send a message over this socket to signal that the list
                                           above has changed */
static SYSocketHandle notifiedSocket = syInvalidSocket();   /* we send a message to this socket to signal that the list
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
		NSSocketSet readList;				/* socket set for select */
		CMIterator iterator;				/* to go through the list */
		NQ_STATUS res = 0;					/* operation status */
		
		/* Prepare socket descriptor */
		nsClearSocketSet(&readList);
		cmListIteratorStart(&connections, &iterator);
		while (cmListIteratorHasNext(&iterator))
		{
			CCTransport * pTransport;	/* casted pointer */

			pTransport = (CCTransport *)cmListIteratorNext(&iterator);
			if (!nsIsSocketAlive(pTransport->socket) || pTransport->doDisconnect)
			{
				pTransport->connected = FALSE;
				cmListItemRemove((CMItem *)pTransport);
				syMutexTake(&pTransport->guard);
				syMutexGive(&pTransport->guard);
				syMutexDelete(&pTransport->guard);
				syMutexDelete(pTransport->item.guard);
				cmMemoryFree(pTransport->item.guard);
				pTransport->item.guard = NULL;
				if (NULL != pTransport->cleanupCallback)
					(*pTransport->cleanupCallback)(pTransport->cleanupContext);
				nsClose(pTransport->socket);
				if (TRUE == pTransport->isWaitingDisconectCond)
				{
					cmThreadCondSignal(&pTransport->disconnectCond);
				}
				continue;
			}
			syMutexTake(&pTransport->guard);
			if (!pTransport->isReceiving && !pTransport->isSettingUp)
			{
				res++;
				nsAddSocketToSet(&readList, pTransport->socket);
			}
			syMutexGive(&pTransport->guard);
		}
		cmListIteratorTerminate(&iterator);

		res = 0;
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
        /* check notify */
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
                    NQ_INT res;         /* number of bytes or error */

                    res = ccTransportReceivePacketLength(pTransport);
                    if (res != 0)  /* skip NBSS control messages */
                    {
                        if (res < 0)
                        {
                        	CCServer	*	pServer = (CCServer *)pTransport->server;

                        	if (pServer->isReconnecting || pServer->item.beingDisposed || !pServer->item.findable)
                        	{
                        		pTransport->doDisconnect = TRUE;
                        		continue;
                        	}
                        	else
                        	{
                        		/* lock order for server / transport is server first. transport second. have to unlock transport */
                        		ccTransportUnlock(pTransport);
                        		cmListItemTake((CMItem *)pServer);
                        		pTransport->doDisconnect = TRUE;
                        		pTransport->connected = FALSE;
								pServer->smb->signalAllMatch(pTransport);
                        	    pServer->connectionBroke = TRUE;
								cmListItemGive((CMItem *)pServer);
                        	}

                        }
                        else
                        	pTransport->callback(pTransport);
                    }
                }
			}
		} /* while (cmListIteratorHasNext(&iterator)) */
		cmListIteratorTerminate(&iterator);
#ifdef SIMULATE_DISCONNECT
		if (cmdCount >= SIMULATE_DISCONNECT_AFTER)
		{
			cmdCount = 0;
		}
#endif /* SIMULATE_DISCONNECT */
	} /* while (doReceive) */
}

/*
 * An attempt to connect server 
 */
static NSSocketHandle connectOneTransportByOneIp(NQ_INT transportType, const NQ_IPADDRESS * ip, CMNetBiosNameInfo * nbInfo)
{
    NQ_STATUS res;              /* operation result */
    NSSocketHandle socket;      /* socket handle */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "transportType:%d ip:%p nbInfo:%p", transportType, ip, nbInfo);
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Transport: %d", transportType);*/

    /* Create TCP socket */
    socket = nsSocket(NS_SOCKET_STREAM, (NQ_UINT)transportType);
    if (socket == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "nsSocket() failed");
        goto Exit;
    }

    /* Connect to remote Server */
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "before nsConnect: %s", nbInfo->name);
    res = nsConnect(socket, (NQ_IPADDRESS *)ip, nbInfo);
    if (res == NQ_FAIL)
    {
        nsClose(socket);
        socket = NULL;
        LOGERR(CM_TRC_LEVEL_ERROR, "nsConnect() failed");
        goto Exit;
    }

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Connected to %s, %s", cmIPDump(ip), nbInfo->name);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", socket);
    return socket;
}


/* -- API Functions */

NQ_BOOL ccTransportStart(void)
{
	NQ_BOOL result = FALSE;
    NQ_INT error = NQ_ERR_OK;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	doReceive = TRUE;
	cmListStart(&connections);

    notifiedSocket = syCreateSocket(FALSE, CM_IPADDR_IPV4);
	notifyingSocket = syCreateSocket(FALSE, CM_IPADDR_IPV4);

	if (!syIsValidSocket(notifiedSocket) || !syIsValidSocket(notifyingSocket))
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "syCreateSocket() failed");
        error = NQ_ERR_SOCKETCREATE;
		goto Error;
	}

    notifyPort = cmThreadBindPort(notifiedSocket);
    if (0 == notifyPort)
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "cmThreadBindPort() failed");
        error = NQ_ERR_SOCKETBIND;
		goto Error;
    }
	syThreadStart(&receiveThread, receiveThreadBody, TRUE);
    result = TRUE;
	goto Exit;

Error:
	if (syIsValidSocket(notifiedSocket))
		syCloseSocket(notifiedSocket);
	if (syIsValidSocket(notifyingSocket))
		syCloseSocket(notifyingSocket);
    sySetLastError(error);
Exit:
	isInitDone = TRUE;
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

NQ_BOOL ccTransportRestartRecieveThread(void)
{
	syThreadStart(&receiveThread, receiveThreadBody, TRUE);

	return TRUE;
}
void ccTransportShutdown(void)
{
	CMIterator itr;

	if (FALSE == isInitDone)
		return;

	doReceive = FALSE;

	/* connections list shut down - can't use regular shutdown because this item isn't allocated in cmmemory. it is part of a server item. */
	cmListIteratorStart(&connections, &itr);
	while (cmListIteratorHasNext(&itr))
	{
		CCTransport *pTransport;
		pTransport = (CCTransport *)cmListIteratorNext(&itr);
		cmListItemRemove((CMItem *)pTransport);

		LOGERR(CM_TRC_LEVEL_ERROR, "Bad shutdown. ccServer item: %x wan't released after usage.", pTransport->server);

		/* transport is part of the server item. if any transport in the list we should remove its corresponding server item */
		cmListItemRemoveAndDispose((CMItem *) pTransport->server);
	}

	/* make sure receiveThread is done before killing it. */
	sySleep(2);

	syThreadDestroy(receiveThread);
	if (syIsValidSocket(notifiedSocket))
		syCloseSocket(notifiedSocket);
	if (syIsValidSocket(notifyingSocket))
		syCloseSocket(notifyingSocket);
    cmThreadFreePort(notifyPort);
}

void ccTransportInit(CCTransport * transport)
{
    transport->connected = FALSE;
    transport->callback  = NULL;
    cmListItemInit(&transport->item);
}

NQ_BOOL ccTransportConnect(
    CCTransport * pTransport, 
    const NQ_IPADDRESS * ips, 
    NQ_INT numIps, 
    const NQ_WCHAR * host,
    CCTransportCleanupCallback cleanupCallback,
    void * cleanupContext
#ifdef UD_NQ_USETRANSPORTNETBIOS
	,NQ_BOOL forceNBSocket
#endif /* UD_NQ_USETRANSPORTNETBIOS */
#ifdef UD_NQ_INCLUDESMBCAPTURE
    ,CMCaptureHeader	*	captureHdr
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    )
{
    NSSocketHandle socket;		/* resulting handle */
    CMNetBiosNameInfo nbInfo;	/* NetBIOS name information */
    NQ_CHAR * aHost = NULL;		/* host name in ASCII */
    NQ_UINT * transportTypes = NULL;   /* transport types ordered by priorities */
    NQ_UINT * transportList = NULL;   /* transport types ordered by priorities */
    NQ_BOOL result = FALSE;
#ifdef UD_NQ_USETRANSPORTNETBIOS
    NQ_BOOL hasNBTransport = FALSE;
#endif /* UD_NQ_USETRANSPORTNETBIOS */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "transport:%p ips:%p numIps:%d host:%s callback:%p context:%p", pTransport, ips, numIps, cmWDump(host), cleanupCallback, cleanupContext);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "host: %s", cmWDump((const NQ_WCHAR *) host));

    pTransport->item.guard = (SYMutex *)cmMemoryAllocate(sizeof(*pTransport->item.guard));
	if (NULL == pTransport->item.guard)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		goto Exit;
	}
    syMutexCreate(pTransport->item.guard);
    pTransport->connected = FALSE;
    pTransport->doDisconnect = FALSE;
    pTransport->isWaitingDisconectCond = FALSE;
    pTransport->cleanupCallback = cleanupCallback;
    pTransport->cleanupContext = cleanupContext;
    /* compose NetBIOS name */
    aHost = cmMemoryCloneWStringAsAscii(host);
	if (NULL == aHost)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		goto Exit;
	}
    cmNetBiosNameCreate(nbInfo.name, aHost, CM_NB_POSTFIX_SERVER);
    nbInfo.isGroup = FALSE;

    transportList = (NQ_UINT *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_UINT) * (cmGetNumOfAvailableTransports() + 1)));
	if (NULL == transportList)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		goto Exit;
	}
    transportTypes = transportList;

#ifdef UD_NQ_USETRANSPORTNETBIOS
    if (forceNBSocket)
    {
    	NQ_UINT	i = 0;

    	cmGetTransportPriorities(transportList);
    	for (i = 0; i < cmGetNumOfAvailableTransports(); i++)
    	{

    		if (*transportList == NS_TRANSPORT_NETBIOS)
    		{
    			hasNBTransport = TRUE;
    			break;
    		}
    		transportList++;
    	}
    	transportList = transportTypes;
    }
#endif /* UD_NQ_USETRANSPORTNETBIOS */

    for (cmGetTransportPriorities(transportList); *transportTypes != 0; transportTypes++)
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

#ifdef UD_NQ_USETRANSPORTNETBIOS
            if (hasNBTransport && forceNBSocket && *transportTypes != NS_TRANSPORT_NETBIOS)
            {
            	continue;
            }
#endif /* UD_NQ_USETRANSPORTNETBIOS */

		    if (NULL != (socket = connectOneTransportByOneIp((NQ_INT)*transportTypes, &ips[i], &nbInfo)))
		    {
#ifdef UD_NQ_INCLUDESMBCAPTURE
		    	{
		    		SocketSlot *	serverSock = (SocketSlot *)socket;
		    		NQ_IPADDRESS 	serverIp;
		    		NQ_PORT			serverPort;

		    		syGetSocketPortAndIP(serverSock->socket , &serverIp , &serverPort);

		    		captureHdr->dstIP = ips[i];
		    		captureHdr->dstPort = *transportTypes == NS_TRANSPORT_NETBIOS ? CM_NB_SESSIONSERVICEPORT : CM_NB_SESSIONSERVICEPORTIP ;
		    		captureHdr->srcIP = serverIp;
		    		captureHdr->srcPort = 0;
		    		captureHdr->receiving = FALSE;
		    	}
#endif /* UD_NQ_INCLUDESMBCAPTURE */
			    pTransport->socket = socket;
			    pTransport->connected = TRUE;
                pTransport->isReceiving = TRUE;
                pTransport->isSettingUp = TRUE;
                syMutexCreate(&pTransport->guard);
			    cmListItemAdd(&connections, (CMItem *)pTransport, NULL);
                notifyListChange();
				result = TRUE;
			    goto Exit;
		    }
		}
    }

Exit:
    cmMemoryFree(aHost);
    cmMemoryFree(transportList);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

NQ_BOOL ccTransportIsTimeoutExpired(CCTransport * transport)
{
	NQ_TIME t, to = {TRANSPORT_IDLETIMEOUT*1000, 0 };
	NQ_TIME curr = syGetTimeInMsec();

	cmU64SubU64U64(&t, &curr, &transport->lastTime);

	return cmU64Cmp(&t,&to) > 0;
}

NQ_BOOL ccTransportIsConnected(CCTransport * pTransport)
{
    return nsIsSocketAlive(pTransport->socket) && pTransport->connected;
}

NQ_BOOL ccTransportDisconnect(CCTransport * pTransport)
{   
	NQ_BOOL result;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "transport:%p", pTransport);

	if (pTransport->connected && pTransport->item.guard != NULL)
    {
		pTransport->doDisconnect = TRUE;
		pTransport->isWaitingDisconectCond = TRUE;
		cmThreadCondSet(&pTransport->disconnectCond);
		notifyListChange();


		cmThreadCondWait(&pTransport->disconnectCond,1);
		cmThreadCondRelease(&pTransport->disconnectCond);
		pTransport->isWaitingDisconectCond = FALSE;
        result = TRUE;
    }
    else
    {   
    	CCServer	*	pServer = NULL;

    	pServer = (CCServer *)pTransport->server;
    	pServer->smb->signalAllMatch(pTransport);
        result = FALSE;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

void ccTransportLock(CCTransport * transport)
{
    if (transport->item.guard != NULL)   /* just to check that ccTransportDisconnect wasn't called previously */
        syMutexTake(&transport->guard);
}

void ccTransportUnlock(CCTransport * transport)
{
    if (transport->item.guard != NULL)   /* just to check that ccTransportDisconnect wasn't called previously */
        syMutexGive(&transport->guard);
}

NQ_BOOL ccTransportSend(CCTransport * pTransport, const NQ_BYTE * buffer, NQ_COUNT packetLen, NQ_COUNT dataLen)
{
	NQ_BOOL result = FALSE;
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "transport:%p buff:%p packetLen:%d dataLen:%d", pTransport, buffer, packetLen, dataLen);

    if (!nsIsSocketAlive(pTransport->socket))
    {
        ccTransportDisconnect(pTransport);
        sySetLastError(NQ_ERR_RECONNECTREQUIRED);
        LOGERR(CM_TRC_LEVEL_ERROR, "Socket is not alive");
		goto Exit;
    }

    /* Send the packet through NetBIOS */
    dataLen = nsPrepareNBBuffer((NQ_BYTE *)buffer, packetLen, dataLen);
    if(0 == dataLen)
    {
    	pTransport->connected = FALSE;
        sySetLastError(NQ_ERR_RECONNECTREQUIRED);
        LOGERR(CM_TRC_LEVEL_ERROR, "prepare buffer failed");
		goto Exit;
    }

    if (NQ_FAIL == nsSendFromBuffer(pTransport->socket, (NQ_BYTE *)buffer, packetLen, dataLen, NULL)) 
    {
    	pTransport->connected = FALSE;
        sySetLastError(NQ_ERR_RECONNECTREQUIRED);
        LOGERR(CM_TRC_LEVEL_ERROR, "Sending failed");
		goto Exit;
    }
    pTransport->lastTime = syGetTimeInMsec();
    result = TRUE;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

NQ_BOOL ccTransportSendSync(CCTransport * pTransport, const NQ_BYTE * buffer, NQ_COUNT packetLen, NQ_COUNT dataLen)
{
	NQ_BOOL result = FALSE;
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "transport:%p buff:%p packetLen:%d dataLen:%d", pTransport, buffer, packetLen, dataLen);

    if (!nsIsSocketAlive(pTransport->socket))
    {
        ccTransportDisconnect(pTransport);
        sySetLastError(NQ_ERR_RECONNECTREQUIRED);
        LOGERR(CM_TRC_LEVEL_ERROR, "Socket is not alive");
		goto Exit;
    }
    /* Send the packet through NetBIOS */
    dataLen = nsPrepareNBBuffer((NQ_BYTE *)buffer, packetLen, dataLen);
    if(0 == dataLen)
    {
    	pTransport->connected = FALSE;
    	sySetLastError(NQ_ERR_RECONNECTREQUIRED);
        LOGERR(CM_TRC_LEVEL_ERROR, "prepare buffer failed");
		goto Exit;
    }

    if (NQ_FAIL == nsSendFromBuffer(pTransport->socket, (NQ_BYTE *)buffer, packetLen, dataLen, NULL)) 
    {
    	pTransport->connected = FALSE;
    	sySetLastError(NQ_ERR_RECONNECTREQUIRED);
        LOGERR(CM_TRC_LEVEL_ERROR, "Sending failed");
		goto Exit;
    }
    pTransport->lastTime = syGetTimeInMsec();
    result = TRUE;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

NQ_BOOL ccTransportSendTail(CCTransport * pTransport, const NQ_BYTE * data, NQ_COUNT dataLen)
{
	return ((NQ_INT) dataLen == sySendSocket(nsGetSySocket(pTransport->socket), data, dataLen));
}

void ccTransportSetResponseCallback(CCTransport * pTransport, CCTransportResponseCallback callback, void * context)
{
	pTransport->callback = callback;
	pTransport->context = context;
}

NQ_BYTE * ccTransportReceiveAll(CCTransport * pTransport, NQ_COUNT * dataLen)
{
    NQ_INT res;				/* Various: number of bytes expected, call result */ 
    NQ_BYTE * pRecvBuffer;	/* Receive buffer pointer */
    NQ_BYTE * pResult = NULL; /* Receive buffer pointer */

    res = ccTransportReceivePacketLength(pTransport);
	if (res == 0 || res == NQ_FAIL)
	{
		goto Exit;
	}
	pRecvBuffer = cmBufManTake((NQ_COUNT)res);
	if (NULL == pRecvBuffer)
	{
		sySetLastError(NQ_ERR_OUTOFMEMORY);
		LOGERR(CM_TRC_LEVEL_ERROR, "Failed to take buffer");
		goto Exit;
	}
    if ((NQ_COUNT) NQ_FAIL == ccTransportReceiveBytes(pTransport, pRecvBuffer, (NQ_COUNT)res))
	{
		cmBufManGive(pRecvBuffer);
		goto Exit;
	}
	*dataLen = (NQ_COUNT)res;
	pResult = pRecvBuffer;

Exit:
    ccTransportReceiveEnd(pTransport);
    return pResult;
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

void ccTransportDiscardSettingUp(CCTransport * pTransport)
{
	ccTransportLock(pTransport);
	pTransport->isSettingUp = FALSE;
	notifyListChange();
	ccTransportUnlock(pTransport);
}
