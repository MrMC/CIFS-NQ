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

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static functions --- */


/*
 * Explicitely dispose and disconnect server:
 *  - disconnects from the share
 *  - disposes private data  
 */
static void disposeShare(CCShare * pShare)
{
	CMIterator iterator;
	
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "About to dispose share %s ", cmWDump(pShare->item.name));

	/* Currently cmListShutdown doesn't call the item Callback we have to do it manually*/

	cmListIteratorStart(&pShare->files, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * pItem;

        pItem = cmListIteratorNext(&iterator);
        cmListItemUnlock(pItem);
    }
    cmListIteratorTerminate(&iterator);
	
	cmListIteratorStart(&pShare->searches, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * pItem;

        pItem = cmListIteratorNext(&iterator);
        cmListItemUnlock(pItem);
    }
    cmListIteratorTerminate(&iterator);
	
    cmListShutdown(&pShare->files);
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
#ifdef UD_NQ_INCLUDETRACE
    CCShare * pShare = (CCShare *)pItem;
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  Share:: TID: %d", pShare->tid);
#endif /* UD_NQ_INCLUDETRACE */
}
#endif /* SY_DEBUGMODE */

/*
 * Create new share object and connect 
 */

static CCShare * shareCreate(const NQ_WCHAR * path, const NQ_WCHAR * treeName, NQ_BOOL isIpc, CCUser * pUser,const AMCredentialsW ** pCredentials)
{
    CCShare * pShare;       /* share pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* create share object */
    pShare = (CCShare *)cmListItemCreateAndAdd(&pUser->shares, sizeof(CCShare), treeName, unlockCallback , TRUE);
    if (NULL == pShare)
    {
        cmListItemUnlock((CMItem *)pUser);  /* try disposal */
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    cmListStart(&pShare->files);
	cmListStart(&pShare->searches);
    pShare->user = pUser;
    pShare->connected = FALSE;
    pShare->isIpc = isIpc;
    pShare->dfsReferral = NULL;
    cmListItemAddReference((CMItem *)pShare, (CMItem *)pUser);
    cmListItemUnlock((CMItem *)pUser);

#if SY_DEBUGMODE
    pShare->item.dump = dumpOne; 
#endif /* SY_DEBUGMODE */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pShare;
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
    CMIterator iterator;    /* user iterator */

    ccUserIterateShares(pUser, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CCShare * pNextShare;     /* next share pointer */

        pNextShare = (CCShare *)cmListIteratorNext(&iterator);
        if (tid == pNextShare->tid)
        {
            return pNextShare;
        }
    }
    cmListIteratorTerminate(&iterator);
    return NULL;
}

CCShare * ccShareFind(CCServer * pServer, const NQ_WCHAR * path, const NQ_WCHAR * treeName,  CCUser * pUser,const AMCredentialsW ** pCredentials)
{
    CCShare * pShare;     /* share pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    cmListItemTake((CMItem *)pServer);

    pShare = (CCShare *)cmListItemFind(&pUser->shares, treeName, TRUE , TRUE);
    cmListItemGive((CMItem *)pServer);

    if (NULL != pShare)
    {
        cmListItemUnlock((CMItem *)pUser);
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "share: %s %s", cmWDump((const NQ_WCHAR *)treeName), pShare ? "found" : "not found");
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pShare;
}


CCShare * ccShareConnect(const NQ_WCHAR * path, const AMCredentialsW ** pCredentials, NQ_BOOL doDfs)
{
    const NQ_WCHAR * serverName;            /* a copy of host name portion */
    const NQ_WCHAR * treeName;              /* a copy of three path portion */
    CCServer       * pServer = NULL;        /* server object pointer */
    CCShare        * pShare = NULL;         /* share object pointer */
    CCUser         * pUser = NULL;          /* user object pointer */
    NQ_BOOL          security[] = {TRUE, FALSE};    /* whether to use extended security */
    NQ_INT           i;                     /* just a counter */
    NQ_STATUS        prevStatus = 0;        /* status to handle failed connect tries*/        

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "path: %s, doDfs: %d", cmWDump((const NQ_WCHAR *)path), doDfs);

    serverName = ccUtilsHostFromRemotePath(path);
    if (NULL == serverName)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "serverName: %s", cmWDump((const NQ_WCHAR *)serverName));

    treeName = ccUtilsShareFromRemotePath(path);
    if (NULL == treeName)
    {
        cmMemoryFree(serverName);
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
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
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Created or found share: %p %s", pShare, cmWDump((const NQ_WCHAR *)pShare->item.name));
            
            if (NULL != pShare  && !ccShareConnectExisting(pShare, doDfs))
            {
                cmListItemGive((CMItem *)pServer);
                prevStatus = syGetLastError();
                if (NULL != pShare)
                    cmListItemUnlock((CMItem *)pShare); 
                cmListItemUnlock((CMItem *)pServer);
                cmMemoryFree(serverName);
                cmMemoryFree(treeName);
                sySetLastError(prevStatus);
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return NULL;
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

    cmMemoryFree(serverName);
    cmMemoryFree(treeName);
    if (NULL == pShare)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to connect to remote path");
    }    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pShare;
}

CCShare * ccShareConnectIpc(CCServer * pServer, const AMCredentialsW ** pCredentials)
{
    const NQ_WCHAR treeName[] = {cmWChar('I'), cmWChar('P'), cmWChar('C'), cmWChar('$'), cmWChar(0)};
    CCShare * pShare;       /* share object pointer */
    CCUser  * pUser;
    NQ_WCHAR * path;        /* full path to IPC */
    NQ_STATUS   prevStatus; /* Status in case connection failed*/

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    path = ccUtilsComposeRemotePathToShare(pServer->item.name, treeName);
    if (NULL == path)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    pUser = ccUserGet(pServer, path, pCredentials);
    if (NULL == pUser)
    {
        cmMemoryFree(path);
        LOGERR(CM_TRC_LEVEL_ERROR , "Couldn't Find or Create User");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    pShare = ccShareFind(pServer, path, treeName, pUser, pCredentials);
    if (NULL == pShare)
    {
        pShare = shareCreate(path, treeName, TRUE, pUser, pCredentials);
    }
    if (NULL != pShare && !pShare->connected && !ccShareConnectExisting(pShare, FALSE))
    {
        prevStatus = syGetLastError();
        cmListItemUnlock((CMItem *)pShare);
        cmMemoryFree(path);
        sySetLastError(prevStatus);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    cmMemoryFree(path);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pShare;
}

CCShare * ccShareConnectIpcAnonymously(const NQ_WCHAR * server)
{
    CCServer * pServer = NULL;    /* pointer to server */
    CCShare * pShare = NULL;    /* pointer to IPC$ share */
    NQ_BOOL security[] = {TRUE, FALSE}; /* whether to use extended security */
    NQ_INT i;                       /* just a counter */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

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

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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

NQ_BOOL ccShareConnectExisting(CCShare * pShare, NQ_BOOL doDfs)
{
    NQ_STATUS res;            /* exchange status */
    CCServer * pServer;       /* connected server */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    pServer = pShare->user->server;
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Server: %p, %s", pServer, cmWDump(pServer->item.name));
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Share: %p, %s, doDfs: %d", pShare, cmWDump(pShare->item.name), doDfs);

    cmListItemTake((CMItem *)pShare);
    if (pShare->connected)
    {
        if (!ccShareEcho(pShare))
        {
            pShare->user->server->transport.connected = FALSE;
            res = ccServerReconnect(pShare->user->server);
            if (res != TRUE)
            {
                cmListItemGive((CMItem *)pShare);
                return FALSE; 
            }
        }
        cmListItemGive((CMItem *)pShare);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Share already connected");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return TRUE;
    }

#ifdef UD_CC_INCLUDEDFS    
    {
        CCDfsResult dfsResult;      /* result of DFS resolution */

        /* resolve share (not file path) over DFS, done once on addMount() */
        if (doDfs && !pShare->isIpc)
        {
            dfsResult = ccDfsResolvePath(pShare, NULL); 
            if (NULL != dfsResult.path)
            {
                pShare->dfsReferral = dfsResult.share;
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Resolved server: %p, %s", pServer, cmWDump(dfsResult.server->item.name));
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Resolved share: %p, %s", pShare, cmWDump(dfsResult.share->item.name));
                ccDfsResolveDispose(&dfsResult);
                /* resolved share is always connected */
                cmListItemGive((CMItem *)pShare);
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Share connected");
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return TRUE;
            }
        }
    }
#endif /* UD_CC_INCLUDEDFS */

    /* connect to share */
    if (!pShare->connected)
    {
#ifdef UD_CC_INCLUDEDFS 
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Last error: %d", syGetLastError()); 
        if (doDfs && (syGetLastError() == NQ_ERR_BADACCESS)) 
        { 
            cmListItemGive((CMItem *)pShare); 
            LOGERR(CM_TRC_LEVEL_ERROR, "DFS was attempted, but got access-related error"); 
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON); 
            return FALSE; 
        } 
#endif /* UD_CC_INCLUDEDFS */ 
        res = pServer->smb->doTreeConnect(pShare);
        if (NQ_SUCCESS != res)
        {
            cmListItemGive((CMItem *)pShare);
            sySetLastError((NQ_UINT32)res);
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to connect");
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return FALSE;
        }
        pShare->connected = TRUE;
    }
    cmListItemGive((CMItem *)pShare);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Share connected");
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

void ccShareReopenFiles(CCShare * pShare)
{
    CMIterator iterator;    /* to enumerate files */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    if (pShare->isIpc)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return;   /* no file restore for IPC$ */
    }

    cmListIteratorStart(&pShare->files, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CCFile * pFile;     /* next file pointer */

        pFile = (CCFile *)cmListIteratorNext(&iterator);
        ccFileRestore(pFile);
    }
    cmListIteratorTerminate(&iterator);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

NQ_BOOL ccShareEcho(CCShare * pShare)
{
    CCServer *  pServer;
    NQ_STATUS   res;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    pServer = pShare->user->server;

    res = pServer->smb->doEcho(pShare);
    if (res == NQ_ERR_NOTCONNECTED || res == NQ_ERR_TIMEOUT || res == NQ_ERR_RECONNECTREQUIRED)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return FALSE;
    }
    
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */

