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

#include "ccshare.h"
#include "ccuser.h"
#include "ccfile.h"
#include "ccutils.h"
#include "ccdfs.h"
#include "ccmount.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static functions --- */


/*
 * Explicitly dispose and disconnect server:
 *  - disconnects from the share
 *  - disposes private data  
 */
static void disposeShare(CCShare * pShare)
{
	CMIterator iterator;
	
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p", pShare);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "About to dispose share %s ", cmWDump(pShare->item.name));

	cmListShutdown(&pShare->files);

    /* Currently cmListShutdown doesn't call the item Callback we have to do it manually*/

	cmListIteratorStart(&pShare->searches, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * pItem;
        pItem = cmListIteratorNext(&iterator);
        cmListItemUnlock(pItem);
    }
    cmListIteratorTerminate(&iterator);
	cmListShutdown(&pShare->searches);

    if (pShare->connected)
        ccShareDisconnect(pShare);
    cmListItemRemoveAndDispose((CMItem *)pShare);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 * Callback for share unlock and disposal:
 *  - disconnects from the share
 *  - disposes private data  
 */
static NQ_BOOL unlockCallback(CMItem * pItem)
{
    disposeShare((CCShare *)pItem);
    return TRUE;
}

/*
 * Print share-specific information 
 */
#if SY_DEBUGMODE

static void dumpOne(CMItem * pItem)
{
#if defined (UD_NQ_EXTERNALTRACE) || defined (NQ_INTERNALTRACE)
    CCShare * pShare = (CCShare *)pItem;
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  Share:: TID: %d", pShare->tid);
#endif /* defined (UD_NQ_EXTERNALTRACE) || defined (NQ_INTERNALTRACE) */
}
#endif /* SY_DEBUGMODE */

/*
 * Create new share object and connect 
 */

static CCShare * shareCreate(const NQ_WCHAR * path, const NQ_WCHAR * treeName, NQ_BOOL isIpc, CCUser * pUser,const AMCredentialsW ** pCredentials)
{
    CCShare * pShare;         /* share pointer */
    CCShare * pResult = NULL; /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "path:%s tree:%s isIpc:%s user:%p credentials:%p", cmWDump(path), cmWDump(treeName), isIpc ? "TRUE" : "FALSE", pUser, pCredentials);

    /* create share object */
    pShare = (CCShare *)cmListItemCreateAndAdd(&pUser->shares, sizeof(CCShare), treeName, unlockCallback , CM_LISTITEM_LOCK);
    if (NULL == pShare)
    {
        cmListItemUnlock((CMItem *)pUser);  /* try disposal */
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    cmListStart(&pShare->files);
	cmListStart(&pShare->searches);
    pShare->user = pUser;
    pShare->connected = FALSE;
    pShare->isIpc = isIpc;
    pShare->isPrinter = FALSE;
    pShare->encrypt = FALSE;
    pShare->dfsReferral = NULL;
    pShare->flags = 0;
    pShare->capabilities = 0;
    cmListItemAddReference((CMItem *)pShare, (CMItem *)pUser);
    cmListItemUnlock((CMItem *)pUser);

#if SY_DEBUGMODE
    pShare->item.dump = dumpOne; 
#endif /* SY_DEBUGMODE */

    pResult = pShare;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
    return pResult;
}

/* -- API Functions */

NQ_BOOL ccShareStart(void)
{
    return TRUE;
}

void ccShareShutdown(void)
{
  
}

CCShare * ccShareFindById(CCUser * pUser, NQ_UINT32 tid)
{
    CMIterator iterator;         /* user iterator */
    CCShare * pNextShare = NULL; /* next share pointer */

    ccUserIterateShares(pUser, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {

        pNextShare = (CCShare *)cmListIteratorNext(&iterator);
        if (tid == pNextShare->tid)
        {
            goto Exit;
        }
    }

Exit:
    cmListIteratorTerminate(&iterator);
    return pNextShare;
}

CCShare * ccShareFind(CCServer * pServer, const NQ_WCHAR * path, const NQ_WCHAR * treeName,  CCUser * pUser,const AMCredentialsW ** pCredentials)
{
    CCShare * pShare;     /* share pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p path:%s tree:%s user:%p credentials:%p", pServer, cmWDump(path), cmWDump(treeName), pUser, pCredentials );

    cmListItemTake((CMItem *)pServer);

    pShare = (CCShare *)cmListItemFind(&pUser->shares, treeName, TRUE , TRUE);
    cmListItemGive((CMItem *)pServer);

    if (NULL != pShare)
    {
        cmListItemUnlock((CMItem *)pUser);
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "share: %s %s", cmWDump((const NQ_WCHAR *)treeName), pShare ? "found" : "not found");
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, " result:%p", pShare);
    return pShare;
}


CCShare * ccShareConnect(const NQ_WCHAR * path, void *pMount, const AMCredentialsW ** pCredentials, NQ_BOOL doDfs)
{
    const NQ_WCHAR * serverName = NULL;     /* a copy of host name portion */
    const NQ_WCHAR * treeName = NULL;       /* a copy of tree path portion */
    CCServer       * pServer = NULL;        /* server object pointer */
    CCShare        * pShare = NULL;         /* share object pointer */
    CCUser         * pUser = NULL;          /* user object pointer */
    NQ_BOOL          security[] = {TRUE, FALSE};    /* whether to use extended security */
    NQ_COUNT         i;                     /* just a counter */
    NQ_STATUS        prevStatus = 0;        /* status to handle failed connect tries*/        
    CCShare        * pResult = NULL;        /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "path:%s credentials:%p doDfs:%s", cmWDump(path), pCredentials, doDfs ? "TRUE" : "FALSE");

    serverName = ccUtilsHostFromRemotePath(path);
    if (NULL == serverName)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "serverName: %s", cmWDump((const NQ_WCHAR *)serverName));

    treeName = ccUtilsShareFromRemotePath(path);
    if (NULL == treeName)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "treeName: %s", cmWDump((const NQ_WCHAR *)treeName));

    for (i = 0; i < sizeof(security)/sizeof(security[0]); i++)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "ext.security: %d", security[i]);
        pServer = ccServerFindOrCreate(serverName, security[i], NULL);
        if (NULL != pServer)
        {
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Created or found server: %p %s", pServer, cmWDump((const NQ_WCHAR *)pServer->item.name));
            cmListItemLock((CMItem *)pServer);  
            cmListItemTake((CMItem *)pServer);

            pUser = ccUserGet(pServer, path, pCredentials);
            if (NULL == pUser)
            {
                cmListItemGive((CMItem *)pServer);
                cmListItemUnlock((CMItem *)pServer);
                cmListItemUnlock((CMItem *)pServer);
                LOGERR(CM_TRC_LEVEL_ERROR , "Couldn't Find or Create User");
                continue;
            }
            else
            {
            	if (!pServer->isNegotiationValidated)
            	{
            		if (FALSE == pServer->smb->validateNegotiate(pServer, pUser, NULL))
					{
						cmListItemGive((CMItem *)pServer);
						cmListItemUnlock((CMItem *)pServer);
						cmListItemUnlock((CMItem *)pServer);
						cmListItemGive((CMItem *)pUser);
						cmListItemUnlock((CMItem *)pUser);
						LOGERR(CM_TRC_LEVEL_ERROR , "validate negotiation failed.");
						break;
					}
					else
					{
						pServer->isNegotiationValidated = TRUE;
					}
            	}
            }
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Created or found user: %p %s", pUser, cmWDump((const NQ_WCHAR *)pUser->item.name));
            
            pShare = ccShareFind(pServer, path, treeName, pUser, pCredentials);
            if (NULL == pShare)
            {
                pShare = shareCreate(path, treeName, FALSE, pUser, pCredentials);
            }
            if (NULL != pShare)
            {
                cmListItemUnlock((CMItem *)pServer);
            }
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Created or found share: %p %s", pShare, NULL != pShare? cmWDump((const NQ_WCHAR *)pShare->item.name) : "");
            
            if (NULL != pShare  && !ccShareConnectExisting(pShare, (CCMount *)pMount, doDfs))
            {
                cmListItemGive((CMItem *)pServer);
                prevStatus = syGetLastError();
                if (NULL != pShare)
                    cmListItemUnlock((CMItem *)pShare);
                cmListItemUnlock((CMItem *)pServer);
                sySetLastError(prevStatus);
                goto Exit;
            }
            cmListItemUnlock((CMItem *)pServer);
            if (NULL != pShare && doDfs && NULL != pShare->dfsReferral)
            {
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Resolved share: %p %s", pShare->dfsReferral, cmWDump((const NQ_WCHAR *)pShare->dfsReferral->item.name));
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Resolved server: %p %s", pShare->dfsReferral->user->server, cmWDump((const NQ_WCHAR *)pShare->dfsReferral->user->server->item.name));                
                pShare->connected = pShare->dfsReferral->connected;
            }
            if (NULL != pShare)
            {
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Share: %p %s connected: %d", pShare, cmWDump((const NQ_WCHAR *)pShare->item.name), pShare->connected);
                if (pShare->connected)
                {
                    cmListItemGive((CMItem *)pServer);
                    break;
                }
            }
            cmListItemGive((CMItem *)pServer);
            cmListItemUnlock((CMItem *)pUser);
            cmListItemCheck((CMItem *)pServer);
        }
        else
            break;
    }

    if (NULL == pShare)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to connect to remote path");
    }

    pResult = pShare;

Exit:
    cmMemoryFree(serverName);
    cmMemoryFree(treeName);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
    return pResult;
}

CCShare * ccShareConnectIpc(CCServer * pServer, const AMCredentialsW ** pCredentials)
{
    const NQ_WCHAR treeName[] = {cmWChar('I'), cmWChar('P'), cmWChar('C'), cmWChar('$'), cmWChar(0)};
    CCShare * pShare;         /* share object pointer */
    CCUser  * pUser;
    NQ_WCHAR * path = NULL;   /* full path to IPC */
    NQ_STATUS   prevStatus;   /* Status in case connection failed*/
    CCShare * pResult = NULL; /* share object pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%p credentials:%p", pServer, pCredentials);

    path = ccUtilsComposeRemotePathToShare(pServer->item.name, treeName);
    if (NULL == path)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    pUser = ccUserGet(pServer, path, pCredentials);
    if (NULL == pUser)
    {
        LOGERR(CM_TRC_LEVEL_ERROR , "Couldn't Find or Create User");
        goto Exit;
    }

    pShare = ccShareFind(pServer, path, treeName, pUser, pCredentials);
    if (NULL == pShare)
    {
        pShare = shareCreate(path, treeName, TRUE, pUser, pCredentials);
    }
    if (NULL == pShare)
    {
    	goto Exit;
    }

    if (!pShare->connected && !ccShareConnectExisting(pShare, NULL, FALSE))
    {
        prevStatus = syGetLastError();
        cmListItemUnlock((CMItem *)pShare);
        sySetLastError(prevStatus);
        goto Exit;
    }

    if (!pServer->isNegotiationValidated)
    {
		if (FALSE == pServer->smb->validateNegotiate(pServer, pUser, pShare))
		{
			cmListItemUnlock((CMItem *)pShare);
			LOGERR(CM_TRC_LEVEL_ERROR , "validate negotiation failed.");
			pShare = NULL;
		}
		else
		{
			pServer->isNegotiationValidated = TRUE;
		}
    }

    pResult = pShare;

Exit:
    cmMemoryFree(path);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
    return pResult;
}

CCShare * ccShareConnectIpcAnonymously(const NQ_WCHAR * server)
{
    CCServer * pServer = NULL;    /* pointer to server */
    CCShare * pShare = NULL;      /* pointer to IPC$ share */
    NQ_BOOL security[] = {TRUE, FALSE}; /* whether to use extended security */
    NQ_COUNT i;                   /* just a counter */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "server:%s", cmWDump(server));

    for (i = 0; i < sizeof(security)/sizeof(security[0]); i++)
    {
        const AMCredentialsW * oldCredentials = ccUserGetAnonymousCredentials(); 
        const AMCredentialsW * newCredentials = oldCredentials; /* try these credentials first */

        pServer = ccServerFindOrCreate(server, security[i], NULL);
        if (NULL != pServer)
        {
            pShare = ccShareConnectIpc(pServer, &newCredentials);
            if (newCredentials !=  oldCredentials)
            {
                /* new credentials were allocated */
                cmMemoryFree(newCredentials);
            }
            if (NULL != pShare)
            {   
                cmListItemUnlock((CMItem *)pServer);
                break;
            }
            cmListItemUnlock((CMItem *)pServer);
        }
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pShare);
    return pShare;
}

void ccShareDisconnect(CCShare * pShare)
{
    CCServer * pServer; /* master server */
    CCUser * pUser;     /* master user */

    pUser = pShare->user;
    if (NULL != pUser)
    {
        pServer = pUser->server;
        if (NULL!= pServer && pServer->smb && pShare->connected)
        {
            pServer->smb->doTreeDisconnect(pShare);
            pShare->connected = FALSE;
        }
    }
}

NQ_BOOL ccShareConnectExisting(CCShare * pShare, void *pMount, NQ_BOOL doDfs)
{
    NQ_STATUS res;            /* exchange status */
    CCServer * pServer;       /* connected server */
    NQ_BOOL result = FALSE;   /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p doDfs:%s", pShare, doDfs ? "TRUE" : "FALSE");

    pServer = pShare->user->server;
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Server: %p, %s", pServer, cmWDump(pServer->item.name));
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Share: %p, %s, doDfs: %d", pShare, cmWDump(pShare->item.name), doDfs);

    cmListItemTake((CMItem *)pServer);
    cmListItemTake((CMItem *)pShare);
    if (pShare->connected)
    {
        cmListItemGive((CMItem *)pShare);
        cmListItemGive((CMItem *)pServer);
        if (!ccShareEcho(pShare))
        {
            cmListItemTake((CMItem *)pServer);
            cmListItemTake((CMItem *)pShare);
            res = ccServerReconnect(pShare->user->server);
            if (res != TRUE)
            {
                goto Exit; 
            }
        }
        else
        {
            cmListItemTake((CMItem *)pServer);
            cmListItemTake((CMItem *)pShare);
        }
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Share already connected");
        result = TRUE;
        goto Exit; 
    }

#ifdef UD_CC_INCLUDEDFS    
    {
        CCDfsResult dfsResult;      /* result of DFS resolution */

        /* resolve share (not file path) over DFS, done once on addMount() */
        if (doDfs && !pShare->isIpc && !pShare->isPrinter)
        {
            dfsResult = ccDfsResolvePath((CCMount *)pMount, pShare, NULL, NULL);
            if (NULL != dfsResult.path)
            {
                pShare->dfsReferral = dfsResult.share;
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Resolved server: %p, %s", pServer, cmWDump(dfsResult.server->item.name));
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Resolved share: %p, %s", pShare, cmWDump(dfsResult.share->item.name));
                ccDfsResolveDispose(&dfsResult);
                /* resolved share is always connected */
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Share connected");
                result = TRUE;
                goto Exit; 
            }
        }
    }
#endif /* UD_CC_INCLUDEDFS */

    /* connect to share */
    if (!pShare->connected)
    {
#ifdef UD_CC_INCLUDEDFS 
        {
            NQ_STATUS lastError = syGetLastError();

            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Last error: 0x%x", lastError);
            if (doDfs && (lastError == NQ_ERR_BADACCESS))
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "DFS was attempted, but got access-related error");
                goto Exit;
            }
        }
#endif /* UD_CC_INCLUDEDFS */ 
        res = pServer->smb->doTreeConnect(pShare);
        if (NQ_SUCCESS != res)
        {
            sySetLastError((NQ_UINT32)res);
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to connect");
            goto Exit; 
        }
        pShare->connected = TRUE;
    }

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Share connected");
    result = TRUE;

Exit:
    cmListItemGive((CMItem *)pShare);
    cmListItemGive((CMItem *)pServer);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", result);
    return result;
}

NQ_BOOL ccShareReopenFiles(CCShare * pShare)
{
    CMIterator  iterator;    /* to enumerate files */
    NQ_BOOL     res = TRUE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p", pShare);

    if (pShare->isIpc)
    {
        /* no file restore for IPC$ */
        LOGERR(CM_TRC_LEVEL_ERROR, "no file restore for IPC");
        res = FALSE;
        goto Exit;
    }

    cmListIteratorStart(&pShare->files, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CCFile * pFile;     /* next file pointer */

        pFile = (CCFile *)cmListIteratorNext(&iterator);
        if (ccFileRestore(pFile) == FALSE)
        	res = FALSE;
    }
    cmListIteratorTerminate(&iterator);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}

NQ_BOOL ccShareEcho(CCShare * pShare)
{
    CCServer *  pServer;
    NQ_STATUS   res;
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p", pShare);

    pServer = pShare->user->server;

    res = pServer->smb->doEcho(pShare);
    if (res == NQ_ERR_NOTCONNECTED || res == NQ_ERR_TIMEOUT || res == (NQ_STATUS) NQ_ERR_RECONNECTREQUIRED)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "doEcho() failed:%d", res);
        goto Exit;
    }
    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
