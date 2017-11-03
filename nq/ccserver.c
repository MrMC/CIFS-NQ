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

#include "ccserver.h"
#include "ccutils.h"
#include "ccuser.h"
#include "ccmount.h"
#include "ccshare.h"
#include "cctransport.h"
#include "ccdfs.h"
#include "ccapi.h"
#include "amspnego.h"
#include "ccfile.h"
#include "ccsearch.h"
#include "ccdummysmb.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static data -- */
static CMList servers;

/* -- local functions -- */

/* 
 * Dump object 
 */
#if SY_DEBUGMODE
/*
 * Print server-specific information 
 */
static void dumpOne(CMItem * pItem)
{
	CCServer * pServer = (CCServer *)pItem;
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  Server:: IP: %s dialect: %s", 
			pServer->numIps == 0? "<NONE>" : cmIPDump(&pServer->ips[0]),
			pServer->smb->name);
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  Users: ");
	cmListDump(&pServer->users);
}
#endif /* SY_DEBUGMODE */

/*
 * Explicitly dispose and disconnect server:
 * 	- disconnects from the server
 *  - disposes private data  
 */
static void disposeServer(CCServer * pServer)
{
    CMItem * pMasterUser = pServer->masterUser;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p", pServer);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "About to dispose server %s", pServer->item.name ? cmWDump(pServer->item.name) : "");

    if (pMasterUser != NULL)
    {
        ccUserLogoff((CCUser *)pMasterUser);
        pServer->masterUser = NULL;
        cmListItemCheck(pMasterUser);
    }
	cmListShutdown(&pServer->users);
	if (pServer->threads.first != NULL)
	{
		CMIterator	itr;
		LOGERR(CM_TRC_LEVEL_ERROR,  "There are items in the CCServer->threads list, Going to remove them" );

		cmListIteratorStart(&pServer->threads,&itr);
		while (cmListIteratorHasNext(&itr))
		{
			CMItem *	pItem;

			pItem = cmListIteratorNext(&itr);
			cmListItemRemove(pItem);
		}
		cmListIteratorTerminate(&itr);
	}
	cmListShutdown(&pServer->threads);
	cmListShutdown(&pServer->async);
	ccServerDisconnect(pServer);
	cmListShutdown(&pServer->expectedResponses);
    cmListShutdown(&pServer->waitingNotifyResponses);
	if (NULL != pServer->calledName)
		cmMemoryFree(pServer->calledName);
	pServer->calledName = NULL;
	syMutexDelete(pServer->creditGuard);
	cmMemoryFree(pServer->creditGuard);
	pServer->creditGuard = NULL;
	cmListItemRemoveAndDispose((CMItem *)pServer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}


static void removeExpectedResponses(CCServer * pServer)
{
    CMIterator      iterator;
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p", pServer);
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "About to remove all expected responses from server %s", pServer->item.name ? cmWDump(pServer->item.name) : "");

    cmListIteratorStart(&pServer->expectedResponses, &iterator);  
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem  * pItem = (CMItem *)cmListIteratorNext(&iterator);

        if (pItem->locks == 0)
            cmListItemRemoveAndDispose(pItem);
        else
            cmListItemRemove(pItem);
    }
    cmListIteratorTerminate(&iterator);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}
/*
 * Callback for server cleanup on connection break
 */
static void connectionBrokenCallback(void * context)
{
    CCServer    *   pServer;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "context:%p", context);

    pServer = (CCServer *)context;
    removeExpectedResponses(pServer);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 * Connect server (on either connect or reconnect) and convey negotiations
 */
static NQ_BOOL connectServer(CCServer * pServer, NQ_BOOL extendedSecurity)
{
	NQ_STATUS res;           /* exchange result */
	NQ_BOOL result = FALSE;  /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p extendedSecurity:%s", pServer, extendedSecurity ? "TRUE" : "FALSE");

	pServer->useExtendedSecurity = extendedSecurity;
	if (!ccTransportConnect(&pServer->transport, pServer->ips, (NQ_INT)pServer->numIps, pServer->item.name, connectionBrokenCallback, pServer
#ifdef UD_NQ_USETRANSPORTNETBIOS
	,pServer->isTemporary
#endif /* UD_NQ_USETRANSPORTNETBIOS */
#ifdef UD_NQ_INCLUDESMBCAPTURE
    ,&pServer->captureHdr
#endif /* UD_NQ_INCLUDESMBCAPTURE */
	))
	{
		syMutexDelete(pServer->transport.item.guard);
		cmMemoryFree(pServer->transport.item.guard);
		pServer->transport.item.guard = NULL;
		LOGERR(CM_TRC_LEVEL_ERROR, "Mount error");
	    sySetLastError(NQ_ERR_MOUNTERROR);
		goto Exit;
	}
	pServer->credits = 0;
	/*
	 * During negotiate phase. SMB will be pointing dummySmb so any SMB operation will not proceed until negotiation phase is done.
	 * The negoSmb will be used with default SMB. this pointer is used only on negotiate phase.
	 * */
	pServer->negoSmb = ccCifsGetDefaultSmb();
	pServer->smb = ccSmbDummyGetCifs();

	pServer->isNegotiationValidated = FALSE;

	pServer->transport.server = pServer;
	/* Repeat Negotiate until success. SMB_STATUS_PENDING means iteration - step
	 * more negotiations.
	 * Example: 
	 * - default is SMB1, 
	 * - 1st step - negotiate SMB1  and SMB2 generic (???)
	 * - server selects SMB generic (???)
	 * - install SMB2.0
	 * - 2n step - negotiate SMB2.0 and SMB2.2
	 * - server selects SMB2.2
	 * - install SMB2.2 
	 */ 
	do 
	{
        if (NULL != pServer->firstSecurityBlob.data)
			cmMemoryFreeBlob(&pServer->firstSecurityBlob);
		res = pServer->negoSmb->doNegotiate(pServer, &pServer->firstSecurityBlob);
		if (NQ_SUCCESS != res && SMB_STATUS_PENDING != res)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Negotiate failed:%d", res);
			sySetLastError((NQ_UINT32)res);
			goto Exit;
		}
	}
	while (res == SMB_STATUS_PENDING);
	
	ccTransportDiscardSettingUp(&pServer->transport);

#if SY_DEBUGMODE
	pServer->item.dump = dumpOne; 
#endif /* SY_DEBUGMODE */
	result = TRUE;

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	if (pServer->smb != pServer->negoSmb)
	{
		/* if negotiation failed, don't want pServer->smb to keep pointing on dummysmb. */
		pServer->smb = pServer->negoSmb;
	}
	return result;
}

/*
 * Callback for server unlock and disposal:
 * 	- disconnects from the server
 *  - disposes private data  
 */
static NQ_BOOL unlockCallback(CMItem * pItem)
{
	disposeServer((CCServer *)pItem);
    return TRUE;
}

/* Find existing server by one of it's IPs */
static CCServer * findServerByIp(const NQ_IPADDRESS * ips, NQ_INT numIps, const CCCifsSmb *pDialect)
{
    CMIterator iterator;         /* server iterator */
    CCServer * pServer;          /* pointer to server */
    CCServer * pResult = NULL;   /* return value */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "ips:%p numIps:%d dialect:%p", ips, numIps, pDialect);
    cmListIteratorStart(&servers, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        NQ_UINT i;
        NQ_INT j;     /* index in IP addresses */

        pServer = (CCServer *)cmListIteratorNext(&iterator);
        for (i = 0; i < pServer->numIps; i++)
        {
            for (j = 0; j < numIps; j++)
            {
                if (CM_IPADDR_EQUAL(ips[j], pServer->ips[i]))
                {
                    cmListIteratorTerminate(&iterator);
                    if (((CMItem *)pServer)->findable)
                    {
                    	if ((pDialect == NULL && pServer->isTemporary) || (pDialect != NULL && pDialect != pServer->smb))
						{
							LOGERR(CM_TRC_LEVEL_ERROR, "Invalid pDialect");
							goto Exit;
						}
                        cmListItemLock((CMItem *)pServer);
                        pResult = pServer;
                        goto Exit;
                    }
                    else
                    {
                        LOGERR(CM_TRC_LEVEL_ERROR, "Not findable");
                        goto Exit;
                  	}
                }
            }
        }
    }
    cmListIteratorTerminate(&iterator);

Exit:
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
    return pResult;
}

/* Find existing server by name */
static CCServer * findServerByName(const NQ_WCHAR * name, const CCCifsSmb *pDialect)
{
	CCServer * pServer;

	pServer = (CCServer *)cmListItemFind(&servers, name, TRUE, TRUE);
	if (pServer != NULL)
	{
		if ((pDialect == NULL && pServer->isTemporary) || (pDialect != NULL && pDialect != pServer->smb))
		{
			cmListItemUnlock((CMItem *)pServer);
			pServer = NULL;
			goto Exit;
		}
	}

Exit:
	return pServer;
}

/* Create and initialize new server */
static CCServer * createNewServer(const NQ_WCHAR * host, NQ_BOOL extendedSecurity, const NQ_IPADDRESS *ips, NQ_INT numIps)
{
	CCServer * pServer;
	CCServer * pResult = NULL;

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "host:%s extendedSecurity:%s ips:%p numIps:%d", cmWDump(host), extendedSecurity ? "TRUE" : "FALSE", ips, numIps);

	pServer = (CCServer *)cmListItemCreateAndAdd(&servers, sizeof(CCServer), host, unlockCallback, CM_LISTITEM_LOCK);
	if (NULL == pServer)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		goto Error;
	}

	/* initialize server */
	cmListStart(&pServer->users);
	cmListStart(&pServer->threads);
	cmListStart(&pServer->async);
	cmListStart(&pServer->expectedResponses);
    cmListStart(&pServer->waitingNotifyResponses);
    ccTransportInit(&pServer->transport);
	pServer->ips = ips;
	pServer->numIps = (NQ_COUNT)numIps;
    pServer->smbContext = NULL;
    pServer->firstSecurityBlob.data = NULL;
    pServer->useSigning = FALSE;
	pServer->calledName = cmMemoryCloneWString(host);
    pServer->masterUser = NULL;
    pServer->useName = TRUE;
    pServer->isReconnecting = FALSE;
    pServer->userSecurity = TRUE;
    pServer->connectionBroke = FALSE;
	if (NULL == pServer->calledName)
	{
	    cmListItemUnlock((CMItem *)pServer);
		LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
		goto Error;
	}
#ifdef UD_NQ_INCLUDESMB2
	pServer->clientGuidPartial = (NQ_UINT32)syGetTimeInSec();
#endif
    pServer->vcNumber = 1;
    pServer->isTemporary = FALSE;
    pServer->useAscii = FALSE;
    pServer->negoAscii = FALSE;
    pServer->isAesGcm = FALSE;
    pServer->capabilities = 0;
#ifdef UD_NQ_INCLUDESMB311
    pServer->isPreauthIntegOn = FALSE;
#endif /* UD_NQ_INCLUDESMB311 */
#ifdef UD_NQ_INCLUDESMBCAPTURE
    syMemset(&pServer->captureHdr , 0 , sizeof(CMCaptureHeader));
#endif /* UD_NQ_INCLUDESMBCAPTURE */
    pServer->creditGuard = (SYMutex *)cmMemoryAllocate(sizeof(*pServer->creditGuard));
   	syMutexCreate(pServer->creditGuard);

    pResult = pServer;
    goto Exit;

Error:
    syMutexGive(&servers.guard);
    sySetLastError(NQ_ERR_OUTOFMEMORY);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
    return pResult;
}

static NQ_BOOL areUsersLoggedOn(CCServer * pServer)
{
	CMIterator	userItr;
	NQ_BOOL		result = FALSE;

	cmListIteratorStart(&pServer->users , &userItr);
	while (cmListIteratorHasNext(&userItr))
	{
		CCUser	*	pUser = NULL;

		pUser = (CCUser *)cmListIteratorNext(&userItr);
		if (pUser->isLogginOff == FALSE)
		{
			result = TRUE;
			goto Exit;
		}
	}

Exit:
	cmListIteratorTerminate(&userItr);
	return !result;
}

/* -- API Functions */

NQ_BOOL ccServerStart(void)
{
	cmListStart(&servers);
#if SY_DEBUGMODE
    servers.name = "servers";
#endif
	return TRUE;
}

void ccServerShutdown(void)
{
    CMIterator  serverItr;
    cmListIteratorStart(&servers, &serverItr);
    while (cmListIteratorHasNext(&serverItr))
    {   
        CMIterator  userItr;
        CCServer    *   pServer;
        
        pServer = (CCServer *)cmListIteratorNext(&serverItr);
 
        cmListItemLock((CMItem *)pServer);
        cmListIteratorStart(&pServer->users, &userItr);
        while (cmListIteratorHasNext(&userItr))
        {
            CMIterator  shareItr; 
            CCUser  *   pUser;

            pUser = (CCUser *)cmListIteratorNext(&userItr);
            
            /* remove files first */
            cmListItemLock((CMItem *)pUser);
            cmListIteratorStart(&pUser->shares, &shareItr);
            while (cmListIteratorHasNext(&shareItr))
            {
                CCShare *   pShare;
                CMIterator  filesItr;
                CMIterator  searchItr;
				
				pShare = (CCShare *)cmListIteratorNext(&shareItr);

                cmListIteratorStart(&pShare->files, &filesItr);
                while (cmListIteratorHasNext(&filesItr))
                {
                    CMItem * pItem;

                    pItem = cmListIteratorNext(&filesItr);
                    cmListItemUnlock(pItem);
                }
                cmListIteratorTerminate(&filesItr);

                cmListIteratorStart(&pShare->searches, &searchItr);
				while (cmListIteratorHasNext(&searchItr))
				{
					CMItem *  pSearch;
					NQ_COUNT  lockCntr = 0 , numOfLocks;

					pSearch = cmListIteratorNext(&searchItr);
					numOfLocks = pSearch->locks;
					for (lockCntr = 0 ; lockCntr < numOfLocks; lockCntr++)
					{
						cmListItemUnlock(pSearch);
					}
				}
				cmListIteratorTerminate(&searchItr);
                /*  share can be already released at this point */	
            }
            cmListIteratorTerminate(&shareItr);
 
            /* unlock shares */
            cmListIteratorStart(&pUser->shares, &shareItr);
            while (cmListIteratorHasNext(&shareItr))
            {
                CCShare *   pShare;
                NQ_COUNT	lockCntr = 0 , numOfLocks;
				
				pShare = (CCShare *)cmListIteratorNext(&shareItr);
				numOfLocks = ((CMItem *)pShare)->locks;
				for (lockCntr = 0 ; lockCntr < numOfLocks; lockCntr++)
				{
				    cmListItemUnlock((CMItem *)pShare);
				}
            }
            cmListIteratorTerminate(&shareItr);
            cmListItemUnlock((CMItem *)pUser);
        }
        cmListIteratorTerminate(&userItr);
        cmListItemUnlock((CMItem *)pServer);
    }
    cmListIteratorTerminate(&serverItr);
	cmListShutdown(&servers);
}

void ccServerDisconnectAll(void)
{
	cmListRemoveAndDisposeAll(&servers);
}

NQ_BOOL ccServerUseSignatures(CCServer * pServer)
{
    return pServer->useSigning && (pServer->capabilities & CC_CAP_MESSAGESIGNING);
}

void ccServerCheckTimeouts(void)
{
	CMIterator serverIterator;		/* to enumerate servers */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
	
	cmListIteratorStart(&servers, &serverIterator);
	while (cmListIteratorHasNext(&serverIterator))
	{
		CCServer * pServer;			/* next server pointer */
		
		pServer = (CCServer *)cmListIteratorNext(&serverIterator);
		if (ccTransportIsTimeoutExpired(&pServer->transport))
        {
        	CMIterator userIterator;		/* to enumerate users */

            cmListIteratorStart(&pServer->users, &userIterator);
	        while (cmListIteratorHasNext(&userIterator))
	        {
		        CCUser * pUser;			    /* next user pointer */
      	        CMIterator shareIterator;   /* to enumerate users */
		
		        pUser = (CCUser *)cmListIteratorNext(&userIterator);

                cmListIteratorStart(&pUser->shares, &shareIterator);
	            while (cmListIteratorHasNext(&shareIterator))
	            {
		            CCShare * pShare;			/* next share pointer */
      	            CMIterator fileIterator;   /* to enumerate users */
    		
		            pShare = (CCShare *)cmListIteratorNext(&shareIterator);

                    cmListIteratorStart(&pShare->files, &fileIterator);
        	        if (cmListIteratorHasNext(&fileIterator))
                    {
                        CCFile  *   pFile;

                        pFile = (CCFile *)cmListIteratorNext(&fileIterator);
                        cmListItemUnlock((CMItem *)pFile);
                    }
        	        cmListIteratorTerminate(&fileIterator);
                    ccMountIterateMounts(&fileIterator);
                    while (cmListIteratorHasNext(&fileIterator))
                    {
                        CCMount *   pMount;
                        pMount = (CCMount *)cmListIteratorNext(&fileIterator);

                        if (pMount->share == pShare)
                            cmListItemUnlock((CMItem *)pMount);
                    }
                    cmListIteratorTerminate(&fileIterator);
                    cmListItemCheck((CMItem *)pShare);    /* will be removed if not locked */
	            }
    	        cmListIteratorTerminate(&shareIterator);
                cmListItemCheck((CMItem *)pUser);    /* will be removed if not locked */
            }
	        cmListIteratorTerminate(&userIterator);
            cmListItemCheck((CMItem *)pServer);    /* will be removed if not locked */
        }
	}
	cmListIteratorTerminate(&serverIterator);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/* 
 * Disconnect server (on shutdown or reconnect)
 */
void ccServerDisconnect(CCServer * pServer)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p", pServer);
    
    syMutexTake(&servers.guard);
    pServer->transport.connected = TRUE;
	if (NULL != pServer->transport.callback)
		ccTransportDisconnect(&pServer->transport);
	if (NULL!= pServer->smb && NULL != pServer->smbContext)
		pServer->smb->freeContext(pServer->smbContext, pServer);
	cmMemoryFreeBlob(&pServer->firstSecurityBlob);
	if (NULL != pServer->ips)
	{
		cmMemoryFree(pServer->ips);
		pServer->ips = NULL;
		pServer->numIps = 0;
	}
	syMutexGive(&servers.guard);
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

CCServer * ccServerFindOrCreate(const NQ_WCHAR * name, NQ_BOOL extendedSecurity, const CCCifsSmb *pDialect)
{
	CCServer * pServer = NULL;       /* server pointer */
	NQ_IPADDRESS ip;	             /* server name converted to IP */
	const NQ_IPADDRESS * ips = NULL; /* array of all server IPs */
	NQ_INT numIps;		             /* number of resolved IPs */
	const NQ_WCHAR * host = NULL;    /* host name */
    NQ_BOOL nameIsIp;                /* to distinguish between a name and an IP */
    const NQ_WCHAR * pdcName = NULL; /* resolved over DFS */
  	NQ_BOOL result;                  /* connect result */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s extendedSecurity:%s dialect:%p", cmWDump(name), extendedSecurity ? "TRUE" : "FALSE", pDialect);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "server: %s, dialect: %s", cmWDump(name), pDialect ? pDialect->name : "n/a");

    /* check server timeouts and remove those whose timeout has expired */
    ccServerCheckTimeouts();

    syMutexTake(&servers.guard);
    
    /* find existing server */
    nameIsIp = ccUtilsNameToIp(name, &ip);
    if (nameIsIp)
	{
	    /* find by IP */
        pServer = findServerByIp(&ip, 1, pDialect);
	}
	else
	{
        /* find by name */
		pServer = findServerByName(name, pDialect);
	}
    if (NULL != pServer)
	{
		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Found existing server by %s %s", nameIsIp ?  " IP" : " name", pDialect ? "(with required dialect)" : "");
		if (!ccTransportIsConnected(&pServer->transport) && !ccServerReconnect(pServer))
		{
			cmListItemUnlock((CMItem *)pServer);
			pServer = NULL;
		}
		goto Exit;
    }

    /* try domain DFS resolution (when name is actually domain's name) */
    if (!nameIsIp && !pDialect)
    {
		pdcName = ccDfsResolveHost(name);
		if (NULL != pdcName)
		{
	        /* find in existing */
			pServer = findServerByName(pdcName, NULL);
            if (NULL != pServer)
            {
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Found existing");
                goto Exit;
            }
	    }
    }

    /* resolve host name if supplied name is IP */
	if (nameIsIp)
	{
		host = cmResolverGetHostName(&ip);
	}
	else
	{
        host = pdcName ? cmMemoryCloneWString(pdcName) : cmMemoryCloneWString(name);
        if (NULL == host)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_OUTOFMEMORY);
    		pServer = NULL;
    		goto Exit;
		}
	}
	
	if (NULL == host) /* name is IP, but IP was not resolved to name */
	{
        host = cmMemoryCloneWString(name);
		ips = (NQ_IPADDRESS *)cmMemoryAllocate(sizeof(NQ_IPADDRESS));
		if (NULL == ips)
		{
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
    		pServer = NULL;
    		goto Exit;
		}
		syMemcpy(ips, &ip, sizeof(NQ_IPADDRESS));
		numIps = 1;
	}
	else
	{
		/* resolve all host IPs */
		ips = cmResolverGetHostIps(host, &numIps);
		if (NULL == ips)
		{
			LOGERR(CM_TRC_LEVEL_ERROR, "Cannot resolve IPs for %s", cmWDump(host));
			sySetLastError(NQ_ERR_BADPATH);
			goto Exit;
		}
	}
	
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Resolved host: %s", cmWDump(host));
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Resolved %d IPs %s for this host", numIps, numIps > 0 ? cmIPDump(&ips[0]) : "");

    /* reuse existing servers, search by IP */
    pServer = findServerByIp(ips, numIps, pDialect);
    if (NULL != pServer)
    {
		LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Found existing server by IP: %s with IP (1st one): %s %s", cmWDump(pServer->item.name), cmIPDump(&pServer->ips[0]), pDialect ? "(with required dialect)" : "");
		cmMemoryFree(ips);
		if (!ccTransportIsConnected(&pServer->transport) && !ccServerReconnect(pServer))
		{
			cmListItemUnlock((CMItem *)pServer);
			pServer = NULL;
		}
		goto Exit;
    }

    /* create new server */
	LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Creating new server %s", pDialect ? "(with required dialect)" : "");
	pServer = createNewServer(host, extendedSecurity, ips, numIps);

	if (NULL == pServer)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Failed to create a server object");
		cmMemoryFree(ips);
		goto Exit;
	}
	if (nameIsIp)
		pServer->useName = FALSE;
	if (pDialect)
		pServer->isTemporary = TRUE;

	/* connect to server (forcing required dialect) */
	if (pDialect)	(pDialect->setSolo)(TRUE);
	result = connectServer(pServer, extendedSecurity);
	if (pDialect)	(pDialect->setSolo)(FALSE);
	if (result == FALSE)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Failed to connect to server");
		cmListItemUnlock((CMItem *)pServer);
		pServer = NULL;
		goto Exit;
	}

Exit:
	/* ips is stored into pServer->ips inside the createNewServer(), so do not free ips unless createNewServer() returns NULL */
    cmMemoryFree(pdcName);
	cmMemoryFree(host);
	syMutexGive(&servers.guard);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pServer);
    return pServer;
}

NQ_BOOL ccServerConnect(CCServer * pServer, const NQ_WCHAR * name)
{
	NQ_IPADDRESS ip;	        /* server name converted to IP */
	const NQ_IPADDRESS * ips;	/* array of all server IPs */
	NQ_INT numIps;		        /* number of resolved IPs */
	const NQ_WCHAR * host;	    /* host name */
	NQ_BOOL result = FALSE;     /* return value */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p name:%s", pServer, cmWDump(name));
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "server: %s", cmWDump(name));*/

    cmListItemTake((CMItem *)pServer);
    if (ccUtilsNameToIp(name, &ip))
	{
		host = cmResolverGetHostName(&ip);
	}
	else
	{
		host = ccDfsResolveHost(name);	/* either PDC or  a copy of itself */
	}
	if (NULL == host)
	{
		sySetLastError(NQ_ERR_BADPATH);
		LOGERR(CM_TRC_LEVEL_ERROR, "Cannot resolve server");
		goto Exit;
	}
	
	/* now resolve all server IPs regardless of how it was specified: by name or by a single ip */
	ips = cmResolverGetHostIps(host, &numIps);
	if (NULL == ips)
	{
		cmMemoryFree(host);
		sySetLastError(NQ_ERR_BADPATH);
		LOGERR(CM_TRC_LEVEL_ERROR, "Cannot resolve IPs for %s", name);
		goto Exit;
	}

   	/* initialize server */
   	cmListStart(&pServer->users);
   	pServer->ips = ips;
   	pServer->numIps = (NQ_COUNT)numIps;
   	pServer->calledName = NULL;
    pServer->item.name = (NQ_WCHAR *)host;
    /* connect to server */
    if (!connectServer(pServer, TRUE))
	{
		cmMemoryFree(host);
        cmMemoryFree(pServer->ips);
		goto Exit;
	}
	result = TRUE;

Exit:
    cmListItemGive((CMItem *)pServer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

NQ_BOOL ccServerReconnect(CCServer * pServer)
{
	CMIterator userIterator;		/* to enumerate users */
    NQ_BOOL result = FALSE;         /* operation result */
	
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p", pServer);
	
    cmListItemTake((CMItem *)pServer);
    if (pServer->isReconnecting)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Server is already reconnecting");
        goto Exit;
    }
    if (ccTransportIsConnected(&pServer->transport))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "False alarm - the server is still connected");
        sySetLastError(NQ_ERR_TIMEOUT);
        result = TRUE;
        goto Exit;
	}

    if (areUsersLoggedOn(pServer))
    {
    	LOGERR(CM_TRC_LEVEL_ERROR, "False alarm - All users are logged off");
    	result = TRUE;
    	goto Exit;
    }

    pServer->isReconnecting = TRUE;
	pServer->connectionBroke = FALSE;
/*  cmListItemGive((CMItem *)pServer); */ /* To free other threads that should exit */
/*	cmListItemTake((CMItem *)pServer); */
    pServer->smb->signalAllMatch(&pServer->transport);
    pServer->transport.connected = TRUE;
    ccTransportDisconnect(&pServer->transport);
    pServer->smb->freeContext(pServer->smbContext, pServer);
	cmMemoryFreeBlob(&pServer->firstSecurityBlob);
	
	cmListIteratorStart(&pServer->users, &userIterator);
	while (cmListIteratorHasNext(&userIterator))
	{
		CCUser * pUser;			        /* next user pointer */
    	CMIterator shareIterator;		/* to enumerate shares */
		
		pUser = (CCUser *)cmListIteratorNext(&userIterator);
        pUser->logged = FALSE;
        cmU64Zero(&pUser->uid);
		amSpnegoFreeKey(&pUser->sessionKey);
		amSpnegoFreeKey(&pUser->macSessionKey);
#ifdef UD_NQ_INCLUDESMB3
		cmMemoryFreeBlob(&pUser->encryptionKey);
		cmMemoryFreeBlob(&pUser->decryptionKey);
		cmMemoryFreeBlob(&pUser->applicationKey);
#endif /* UD_NQ_INCLUDESMB3 */
	    cmListIteratorStart(&pUser->shares, &shareIterator);
	    while (cmListIteratorHasNext(&shareIterator))
	    {
		    CCShare * pShare;			    /* next share pointer */
   		
		    pShare = (CCShare *)cmListIteratorNext(&shareIterator);
            pShare->connected = FALSE;
	    }
	    cmListIteratorTerminate(&shareIterator);
	}
	cmListIteratorTerminate(&userIterator);

	if (!connectServer(pServer, pServer->useExtendedSecurity))
	{
	    pServer->isReconnecting = FALSE;
	}

	cmListItemLock((CMItem *)pServer);
	cmListIteratorStart(&pServer->users, &userIterator);
	while (cmListIteratorHasNext(&userIterator))
	{
		CCUser * pUser;			/* next user pointer */
		NQ_BOOL	 reconRes = FALSE;
		
		pUser = (CCUser *)cmListIteratorNext(&userIterator);
		if (ccUserLogon(pUser))
		{
			result = ccUserReconnectShares(pUser);
			if (result)
			{
				reconRes = TRUE;
			}
		}

		if (!reconRes)
		{
			/* user couldnt logon, cleaning up everything */
			CMIterator  shrItr;

			LOGERR(CM_TRC_LEVEL_ERROR , "Reconnect failed.");
			cmListItemLock((CMItem *)pUser);
			cmListIteratorStart(&pUser->shares,&shrItr);
			while (cmListIteratorHasNext(&shrItr))
			{
				CMIterator	mntItr , iterator;
				CCShare	*	pShare = (CCShare *)cmListIteratorNext(&shrItr);

				/* removing files and searches before removing the mount to avoid SegFault*/
				cmListIteratorStart(&pShare->files, &iterator);
				while (cmListIteratorHasNext(&iterator))
				{
				    CCFile * pFile = NULL;

				    pFile = (CCFile *)cmListIteratorNext(&iterator);
				    pFile->disconnected = TRUE;
				}
				cmListIteratorTerminate(&iterator);
				cmListIteratorStart(&pShare->searches, &iterator);
			    while (cmListIteratorHasNext(&iterator))
			    {
			    	CCSearch * pSearch;

			    	pSearch = (CCSearch *)cmListIteratorNext(&iterator);
			    	pSearch->disconnected = TRUE;
			    }
			    cmListIteratorTerminate(&iterator);
				ccMountIterateMounts(&mntItr);
				while (cmListIteratorHasNext(&mntItr))
				{
					CCMount * pMount = (CCMount *)cmListIteratorNext(&mntItr);

					if (pMount->share == pShare)
					{
						cmListItemUnlock((CMItem *)pMount);
					}
				}
				cmListIteratorTerminate(&mntItr);
			}
			cmListIteratorTerminate(&shrItr);
			cmListItemUnlock((CMItem *)pUser);
		}
	}
	cmListIteratorTerminate(&userIterator);
	cmListItemUnlock((CMItem *)pServer);

	if (result)
	{
		pServer->isReconnecting = FALSE;
	}

Exit:
    cmListItemGive((CMItem *)pServer);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

void ccServerIterateServers(CMIterator * iterator)
{
    cmListIteratorStart(&servers, iterator);
}

void ccServerIterateUsers(CCServer * server, CMIterator * iterator)
{
    cmListIteratorStart(&server->users, iterator);
}

void ccCloseAllConnections(void)
{
	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    cmListRemoveAndDisposeAll(&servers);
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

void ccCloseHiddenConnections(void)
{
    CMIterator serverIterator;      /* server iterator */

	LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    cmListIteratorStart(&servers, &serverIterator);
    while (cmListIteratorHasNext(&serverIterator))
    {
        CCServer * pServer;             /* next server pointer */
        CMIterator userIterator;        /* user iterator */

        pServer = (CCServer *)cmListIteratorNext(&serverIterator);
        cmListIteratorStart(&pServer->users, &userIterator);
        while (cmListIteratorHasNext(&userIterator))
        {
            CCUser * pUser;                 /* next user pointer */
            CMIterator shareIterator;       /* share iterator */

            pUser = (CCUser *)cmListIteratorNext(&userIterator);
            cmListIteratorStart(&pUser->shares, &shareIterator);
            while (cmListIteratorHasNext(&shareIterator))
            {
                CCShare * pShare;               /* next share pointer */
                CMIterator mountIterator;       /* mount iterator */
                CMIterator  fileItr;            /* File Iterator*/
                NQ_BOOL doDisconnect = TRUE;    /* disconnection flag */
				

                pShare = (CCShare *)cmListIteratorNext(&shareIterator);

                ccMountIterateMounts(&mountIterator);
                while (cmListIteratorHasNext(&mountIterator))
                {
                    CCMount * pMount;               /* next mount pointer */

                    pMount = (CCMount *)cmListIteratorNext(&mountIterator);
					
                    if (pShare == pMount->share)
                    {
                        cmListIteratorTerminate(&mountIterator);
                        doDisconnect = FALSE;
						break;
                    }
                }
                cmListIteratorTerminate(&mountIterator);
                cmListIteratorStart(&pShare->files, &fileItr);
                if (cmListIteratorHasNext(&fileItr))
                {
                    doDisconnect = FALSE;  
                }
                cmListIteratorTerminate(&fileItr);
                if (doDisconnect)
			    {
                    cmListItemCheck((CMItem *)pShare);
				}
            }
            cmListIteratorTerminate(&shareIterator);
        }
        cmListIteratorTerminate(&userIterator);
    }
	cmListIteratorTerminate(&serverIterator);
	
	LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

NQ_BOOL ccServerWaitForCredits(CCServer * pServer, NQ_COUNT credits)
{
    NQ_INT newCredits;
    CMThread * curThread;   /* current thread pointer */
    NQ_BOOL res = TRUE;     /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "pServer:%p credits:%d - %d", pServer, pServer->credits, credits);

    cmListItemTake(&pServer->item);
    syMutexTake(pServer->creditGuard);
    newCredits = pServer->credits - (NQ_INT)credits;
    while (newCredits <= 0)
    {
    	syMutexGive(pServer->creditGuard);
        curThread = cmThreadGetCurrent();
        cmListItemAdd(&pServer->threads, &curThread->element.item, NULL);
        cmListItemGive(&pServer->item);

        res = cmThreadCondWait(&curThread->asyncCond, ccConfigGetTimeout());
        if (!res)
        {
            goto Exit;
        }
        cmListItemTake(&pServer->item);
        syMutexTake(pServer->creditGuard);
        newCredits = pServer->credits - (NQ_INT)credits;
    }
    pServer->credits = newCredits;
    syMutexGive(pServer->creditGuard);
    cmListItemGive(&pServer->item);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "%s credits: %d", res ? "TRUE" : "FALSE", pServer->credits);
    return res;
}

void ccServerPostCredits(CCServer * pServer, NQ_COUNT credits)
{
    CMThreadElement * element;  /* waiting thread */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "pServer:%p credits:%d + %d", pServer, pServer->credits, credits);

    syMutexTake(pServer->creditGuard);
    pServer->credits += (NQ_INT)credits;
    syMutexGive(pServer->creditGuard);

    element = (CMThreadElement *)pServer->threads.first;
    if (NULL != element)
    {
        cmListItemRemove(&element->item);
        cmThreadCondSignal(&((CMThread *)element->thread)->asyncCond);
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

#if SY_DEBUGMODE

void ccServerDump(void)
{
	cmListDump(&servers);
}

#endif /* SY_DEBUGMODE */

#endif /* UD_NQ_INCLUDECIFSCLIENT */
