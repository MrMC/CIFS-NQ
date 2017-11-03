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

#include "ccdfs.h"
#include "ccutils.h"
#include "cmresolver.h"
#include "cmfinddc.h"
#include "ccdfscache.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static functions -- */

#ifdef UD_CC_INCLUDEDFS
static NQ_BOOL dfsIsOn = TRUE; /* turn DFS on/off */

static void logPrintResult(CCDfsResult result)
{
    if (result.path)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Resolved: path: %s", result.path ? cmWDump(result.path) : "");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Resolved: server: %s", result.server ? cmWDump(result.server->item.name) : "");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Resolved: share: %s", result.share ? cmWDump(result.share->item.name) : "");
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to resolve path");
    }
}

static void printReferrals(CMList *pList)
{
#if defined (UD_NQ_EXTERNALTRACE) || defined (NQ_INTERNALTRACE)
    CMIterator iterator;

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Referrals:");
    cmListIteratorStart(pList, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * item = cmListIteratorNext(&iterator);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " %s", cmWDump(item->name));
    }
    cmListIteratorTerminate(&iterator);
#endif /* defined (UD_NQ_EXTERNALTRACE) || defined (NQ_INTERNALTRACE) */
}

static void createResultPath(const NQ_WCHAR *path, NQ_UINT16 numPathConsumed, CMItem *item, CCDfsResult *res)
{
    if (item != NULL && res->share != NULL)
    {
        res->path = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(item->name) + cmWStrlen(path) + 2)));
        if (NULL != res->path)
        {
            const NQ_WCHAR oneSlash[] = { cmWChar('\\'), cmWChar(0) };
            const NQ_WCHAR *from = cmWStrlen(path) > numPathConsumed ? path + numPathConsumed : NULL;

            cmWStrcpy(res->path, item->name);

            if (NULL != from)
            {
                if ((res->path[cmWStrlen(res->path) - 1] != cmWChar('\\')) && (from[0] != cmWChar('\\')))
                    cmWStrcat(res->path, oneSlash);
                cmWStrcat(res->path, from);
            }
        }
        else
        {
             LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        }
        res->server = res->share->user->server;
    }
}

/*
 * Explicitly close and dispose referral (see above):
 *  - disconnects from the share
 *  - disposes private data
 */
static NQ_BOOL disposeReferralCallback(CMItem * pItem)
{
    CCDfsReferral * pRef;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "item:%p", pItem);

    pRef = (CCDfsReferral *)pItem;
    if (NULL!= pRef->dfsPath)
        cmMemoryFree(pRef->dfsPath);
    if (NULL!= pRef->netPath)
        cmMemoryFree(pRef->netPath);
    cmListItemRemoveAndDispose(pItem);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return TRUE;
}


/* Parser referrals. This function gets a reader pointed to the beginning of the
 * DFS response structure. This structure is the same for any SMB protocol.
 */
static void parseReferralCallback(CMBufferReader * pReader, CMList * pList)
{
    NQ_UINT16 vers;             /* referral version */
    NQ_UINT16 pathConsumed;     /* path consumed in bytes including null terminating (unicode) */
    NQ_UINT16 serverType;       /* server type */
    NQ_UINT16 flags;            /* referral entry flags */
    NQ_UINT32 ttl;              /* time to live */
    NQ_BYTE * entryStart;       /* start of the referral entry */
    NQ_UINT16 offset;           /* various offsets to strings */
    const NQ_WCHAR * dfsPath;   /* DFS path */
    const NQ_WCHAR * netPath;   /* resolved */
    CCDfsReferral * ref;        /* referral entry */
    NQ_UINT16 numRefs;          /* number of referrals */

    cmBufferReadUint16(pReader, &pathConsumed);             /* PathConsumed */
    cmBufferReadUint16(pReader, &numRefs);                  /* NumberOfReferrals */
    cmBufferReaderSkip(pReader, sizeof(NQ_UINT32));         /* flags */
    for (   ; numRefs > 0; numRefs--)
    {
        entryStart = cmBufferReaderGetPosition(pReader);
        cmBufferReadUint16(pReader, &vers);                 /* version number */
        cmBufferReaderSkip(pReader, sizeof(NQ_UINT16));     /* size */
        cmBufferReadUint16(pReader, &serverType);           /* server type */
        cmBufferReadUint16(pReader, &flags);                /* referral entry flags */
        switch (vers)
        {
            case 1:
                dfsPath = NULL;
                netPath = (const NQ_WCHAR *)cmBufferReaderGetPosition(pReader);
                ttl = 0;
                break;
            case 2:
                cmBufferReaderSkip(pReader, sizeof(NQ_UINT32));      /* proximity */
                /* continue */
            case 3:
            case 4:
                cmBufferReadUint32(pReader, &ttl);                   /* time to live */
                cmBufferReadUint16(pReader, &offset);                /* DFS path offset */

                if (flags & 2) /* domain referral */
                {
                    NQ_UINT16 num, expOffset;

                    dfsPath = (const NQ_WCHAR *)(entryStart + offset);
                    cmBufferReadUint16(pReader, &num);                /* number of expanded names */
                    cmBufferReadUint16(pReader, &expOffset);          /* expanded names offset */
                    if (num == 0)
                    {
                        dfsPath = NULL;
                        netPath = (const NQ_WCHAR *)(entryStart + offset);
                    }
                    else
                        netPath = (const NQ_WCHAR *)(entryStart + expOffset);
                }
                else
                {
                    dfsPath = (const NQ_WCHAR *)(entryStart + offset);
                    cmBufferReaderSkip(pReader, sizeof(NQ_UINT16));   /* alternate path offset */
                    cmBufferReadUint16(pReader, &offset);             /* network address offset */
                    cmBufferReaderSkip(pReader, 16);                  /* GUID */
                    netPath = (const NQ_WCHAR *)(entryStart + offset);
                }
                break;
            default:
                return;
        }

        ref = (CCDfsReferral *)cmListItemCreate(sizeof(CCDfsReferral), NULL, CM_LISTITEM_NOLOCK);
        if (NULL != ref)
        {
			ref->numPathConsumed = (NQ_UINT16)(pathConsumed / 2 + 1);
			ref->serverType = (serverType == DFS_ROOT_TARGET);
			ref->flags = flags;
			ref->ttl = ttl;
			ref->dfsPath = (dfsPath == NULL) ? NULL : cmMemoryCloneWString(dfsPath);
			ref->netPath = cmMemoryCloneWString(netPath);
			ref->isConnected = FALSE;
			ref->isIOPerformed = FALSE;
			ref->lastIOStatus = NQ_SUCCESS;
			cmListItemAdd(pList, (CMItem *)ref, disposeReferralCallback);
        }
    }
}

static NQ_WCHAR * getDomainReferral(const NQ_WCHAR *dcName, const NQ_WCHAR *path)
{
    CCShare *pShare;
    NQ_WCHAR *ipcPath;
    NQ_WCHAR *resultReferral = NULL;
    const AMCredentialsW *pCredentials = NULL;
    static const NQ_WCHAR ipcName[] = {cmWChar('I'), cmWChar('P'), cmWChar('C'), cmWChar('$'), cmWChar(0)};

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s path:%s", cmWDump(dcName), cmWDump(path));
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "dc name: %s", cmWDump((const NQ_WCHAR *)dcName));*/
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "path: %s", cmWDump(path));*/

    /* connect to IPC$ share */
    ipcPath = ccUtilsComposeRemotePathToShare(dcName, ipcName);
    if (NULL == ipcPath)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    pShare = ccShareConnect(ipcPath, NULL, &pCredentials, FALSE);
    cmMemoryFree(ipcPath);
    if (NULL != pShare)
    {
        CMList domainRefs;
        CMIterator domainIter;
        NQ_STATUS status;

        cmListStart(&domainRefs);
        /* send get referrals (get domain dfs name) */
        status = pShare->user->server->smb->doQueryDfsReferrals(pShare, path + 1, parseReferralCallback, &domainRefs);
        if (NQ_SUCCESS == status)
        {
            cmListIteratorStart(&domainRefs, &domainIter);
            while (cmListIteratorHasNext(&domainIter))
            {
                CCDfsReferral * pDomainRef;
                CCShare * pShareReferral;

                pDomainRef = (CCDfsReferral *)cmListIteratorNext(&domainIter);
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "got domain dfs referral: %s, rootOrLink: %s", cmWDump(pDomainRef->netPath), pDomainRef->serverType == DFS_ROOT_TARGET ? "root" : "link");

                pCredentials = pShare->user->credentials;
                pShareReferral = ccShareConnect(pDomainRef->netPath, NULL, &pCredentials, FALSE);
                if (pCredentials !=  pShare->user->credentials)
                    cmMemoryFree(pCredentials);
                if (pShareReferral != NULL)
                {
                    ccDfsCacheAddPath(path, pDomainRef);
                    resultReferral = cmMemoryCloneWString(pDomainRef->netPath);
                    if (NULL == resultReferral)
                    {
                        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                        sySetLastError(NQ_ERR_OUTOFMEMORY);
                    }
                    break;
                }
            }
            cmListIteratorTerminate(&domainIter);
        }

        cmListIteratorStart(&domainRefs, &domainIter);
        while (cmListIteratorHasNext(&domainIter))
        {
            CMItem * pItem;

            pItem = cmListIteratorNext(&domainIter);
            cmListItemCheck(pItem);
        }
        cmListIteratorTerminate(&domainIter);
        cmListShutdown(&domainRefs);
        cmListItemUnlock((CMItem *)pShare);
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", resultReferral);
    return resultReferral;
}

static NQ_BOOL getReferrals(CCMount *pMount, CCShare *pShare, const NQ_WCHAR *path, CCCifsParseReferral parser)
{
    CCShare * ipc;
    CMList refs;
    NQ_STATUS result = NQ_FAIL;
    NQ_BOOL isPathAdded = FALSE;
    const AMCredentialsW * pCredentials = pShare->user->credentials;
    NQ_STATUS prevStatus = 0;        /* status to handle failed connect tries*/
    CMIterator iterator;
    NQ_WCHAR * pDomain = NULL;
    NQ_WCHAR * domainReferral = NULL;
    NQ_WCHAR * netPath = NULL;
    NQ_WCHAR * serverHostComponent = NULL;
    NQ_WCHAR * pathComponent = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p path:%s parser:%p", pShare, cmWDump(path), parser);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "path: %s", cmWDump((const NQ_WCHAR *)path));

    /* connect to IPC$ share */
    ipc = ccShareConnectIpc(pShare->user->server, &pCredentials);
    if (pCredentials != pShare->user->credentials)
        cmMemoryFree(pCredentials);

    /* send get referrals request */
    if (NULL != ipc)
    {
        cmListStart(&refs);
        result = pShare->user->server->smb->doQueryDfsReferrals(ipc, path + 1, parseReferralCallback, &refs);

        /* try to connect and store into cache only successfully connected */
        if (NQ_SUCCESS == result)
        {
            CCShare *pShareReferral;

            cmListIteratorStart(&refs, &iterator);
            while (cmListIteratorHasNext(&iterator))
            {
                CCDfsReferral * pRef;            /* next referral */
                CCDfsCacheEntry * pEntry;        /* DFS cache entry */

                pRef = (CCDfsReferral *)cmListIteratorNext(&iterator);

                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "got referral: %s, rootOrLink: %s, pathConsumed: %d", cmWDump(pRef->netPath), pRef->serverType == DFS_ROOT_TARGET ? "root" : "link", pRef->numPathConsumed);

                /* look in domain cache by first path component */
                pDomain = ccUtilsHostFromRemotePath(pRef->netPath);
                if (NULL == pDomain)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    goto Error;
                }
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "pDomain: %s", cmWDump(pDomain));
#ifndef UD_NQ_USETRANSPORTIPV6
                if (cmIsIPv6Literal(pDomain))
                {
                	/* if we received IPV6 literal and IPv6 not supported, we shouldn't handle this result
                	 * otherwise it will be identified as IP on server find or create */
                	cmMemoryFree(pDomain);
                	pDomain = NULL;
                	continue;
                }
#endif
                pEntry = ccDfsCacheFindDomain(pDomain);
                cmMemoryFree(pDomain);
                pDomain = NULL;
                if (NULL != pEntry && NULL != pEntry->refList && NULL != pEntry->refList->first)
                {
                    /* printReferrals(pEntry->refList); */
                    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Found in domain cache DC: %s", cmWDump(pEntry->refList->first->name));

                    /* ask domain's dc for referral */
                    serverHostComponent = ccUtilsHostShareFromRemotePath(pRef->netPath);
                    if (NULL == serverHostComponent)
                    {
                        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                        goto Error;
                    }

                    pathComponent = ccUtilsFilePathFromRemotePath(pRef->netPath, TRUE);

                    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "serverHostComponent: %s", cmWDump(serverHostComponent));
                    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "pathComponent: %s", cmWDump(pathComponent));

                    domainReferral = getDomainReferral(pEntry->refList->first->name, serverHostComponent);
                    cmMemoryFree(serverHostComponent);
                    serverHostComponent = NULL;
                    if (NULL != domainReferral)
                    {
                        netPath = ccUtilsComposePath(domainReferral, pathComponent);
                        cmMemoryFree(domainReferral);
                        domainReferral = NULL;
                        if (NULL == netPath)
                        {
                            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                            goto Error;
                        }
                        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "New path: %s", cmWDump(netPath));
                    }
                    cmMemoryFree(pathComponent);
                    pathComponent = NULL;
                }

                if (NULL == netPath)
                {
                    netPath = cmMemoryCloneWString(pRef->netPath);
                    if (NULL == netPath)
                    {
                        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                        goto Error;
                    }
                }

                pCredentials = pShare->user->credentials;
                pShareReferral = ccShareConnect(netPath, pMount, &pCredentials, FALSE);
                if (NULL != pShareReferral)
                	ccMountAddShareLink(pMount ,pShareReferral);

                if (pCredentials != pShare->user->credentials)
                {
                    cmMemoryFree(pCredentials);
                    pCredentials = NULL;
                }
                if (NULL != pShareReferral)
                { 
                    cmMemoryFree(pRef->netPath);
                    pRef->netPath = cmMemoryCloneWString(netPath);
                    if (NULL == pRef->netPath)
                    {
                        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                        goto Error;
                    }
                    ccDfsCacheAddPath(path, pRef);
                    isPathAdded = TRUE;
                }
                cmMemoryFree(netPath);
                netPath = NULL;
            }
            cmListIteratorTerminate(&iterator);
        }
                        
        cmListIteratorStart(&refs, &iterator);
        while (cmListIteratorHasNext(&iterator))
        {
            CMItem * pItem;

            pItem = cmListIteratorNext(&iterator);
            cmListItemCheck(pItem);
        }
        
        prevStatus = syGetLastError();
        cmListIteratorTerminate(&iterator);
        cmListShutdown(&refs);
        cmListItemUnlock((CMItem *)ipc);                      
        sySetLastError(prevStatus);
    }
    goto Exit;

Error:
    result = NQ_FAIL;
    cmListItemUnlock((CMItem *)ipc);
    cmListIteratorTerminate(&iterator);
    cmListIteratorStart(&refs, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * pItem;

        pItem = cmListIteratorNext(&iterator);
        cmListItemCheck(pItem);
    }
    cmListIteratorTerminate(&iterator);
    cmListShutdown(&refs);
    sySetLastError(NQ_ERR_OUTOFMEMORY);

Exit:
    cmMemoryFree(pDomain);
    cmMemoryFree(domainReferral);
    cmMemoryFree(netPath);
    cmMemoryFree(serverHostComponent);
    cmMemoryFree(pathComponent);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", (result == NQ_SUCCESS && isPathAdded) ? "TRUE" : "FALSE");
    return (result == NQ_SUCCESS && isPathAdded);
}

static void getDomainDC(const NQ_WCHAR *dcName)
{
    CCShare *pShare;
    NQ_WCHAR *ipcPath;
    NQ_STATUS result;
    const AMCredentialsW *pCredentials = NULL;
    static const NQ_WCHAR emptyPath[] = {cmWChar('\0')};
    static const NQ_WCHAR ipcName[] = {cmWChar('I'), cmWChar('P'), cmWChar('C'), cmWChar('$'), cmWChar(0)};

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s", cmWDump(dcName));
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "dc name: %s", cmWDump((const NQ_WCHAR *)dcName));*/

    /* connect to IPC$ share */
    ipcPath = ccUtilsComposeRemotePathToShare(dcName, ipcName);
    if (NULL == ipcPath)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    pShare = ccShareConnect(ipcPath, NULL, &pCredentials, FALSE);
    cmMemoryFree(ipcPath);
    if (NULL != pShare)
    {
        CMList domainRefs;
        CMIterator domainIter;

        cmListStart(&domainRefs);
        /* send get referrals (get domain dfs name) */
        result = pShare->user->server->smb->doQueryDfsReferrals(pShare, emptyPath, parseReferralCallback, &domainRefs);
        if (NQ_SUCCESS == result)
        {
            cmListIteratorStart(&domainRefs, &domainIter);
            while (cmListIteratorHasNext(&domainIter))
            {
                CCDfsReferral * pDomainRef;
                CMList dcRefs;
                CMIterator dcIter;

                pDomainRef = (CCDfsReferral *)cmListIteratorNext(&domainIter);
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "got domain referral: %s, rootOrLink: %s", cmWDump(pDomainRef->netPath), pDomainRef->serverType == DFS_ROOT_TARGET ? "root" : "link");
                cmListStart(&dcRefs);
                /* send get referrals (for each domain dfs name get it's dc) */
                result = pShare->user->server->smb->doQueryDfsReferrals(pShare, pDomainRef->netPath, parseReferralCallback, &dcRefs);
                if (NQ_SUCCESS == result)
                {
                    cmListIteratorStart(&dcRefs, &dcIter);
                    while (cmListIteratorHasNext(&dcIter))
                    {
                        CCDfsReferral * pRootRef;

                        pRootRef = (CCDfsReferral *)cmListIteratorNext(&dcIter);
                        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "got dc referral: %s, rootOrLink: %s", cmWDump(pRootRef->netPath), pRootRef->serverType == DFS_ROOT_TARGET ? "root" : "link");

                        /* store into referral cache pair of domain and it's dc */
                        ccDfsCacheAddDomain(pDomainRef->netPath + 1, pRootRef->netPath + 1, 0);
                        cmListItemCheck((CMItem *)pRootRef);
                    }
                    cmListIteratorTerminate(&dcIter);
                }
                cmListIteratorStart(&dcRefs, &dcIter);
                while (cmListIteratorHasNext(&dcIter))
                {
                    CMItem * pItem;

                    pItem = cmListIteratorNext(&dcIter);
                    cmListItemCheck(pItem);
                }
                cmListIteratorTerminate(&dcIter);
                cmListShutdown(&dcRefs);
                cmListItemCheck((CMItem *)pDomainRef);
            }
            cmListIteratorTerminate(&domainIter);
        }
        cmListIteratorStart(&domainRefs, &domainIter);
        while (cmListIteratorHasNext(&domainIter))
        {
            CMItem * pItem;

            pItem = cmListIteratorNext(&domainIter);
            cmListItemCheck(pItem);
        }
        cmListIteratorTerminate(&domainIter);
        cmListShutdown(&domainRefs);
        cmListItemUnlock((CMItem *)pShare);
    }
    cmMemoryFree(pCredentials);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}
#endif /* UD_CC_INCLUDEDFS */

static NQ_STATUS errorCodes[] =
{
    NQ_ERR_PATHNOTCOVERED,
    NQ_ERR_BADSHARE,
    NQ_ERR_NOSHARE,
    NQ_ERR_BADPATH,
    NQ_ERR_NETWORKERROR,
    NQ_ERR_BADMEDIA,
    NQ_ERR_DIFFDEVICE,
    NQ_ERR_BADDFS,
    NQ_ERR_NOMEM,
    NQ_ERR_IOTIMEOUT,
    NQ_ERR_NOSUPPORT,
    NQ_ERR_NORESOURCE,
    NQ_ERR_BADCONNECTION,
    NQ_ERR_SHARINGPAUSED,
    NQ_ERR_BADACCESS
};

/* -- API Functions */

void ccDfsResolveOn(NQ_BOOL on)
{
#ifdef UD_CC_INCLUDEDFS
    dfsIsOn = on;
#endif /* UD_CC_INCLUDEDFS */
}

NQ_BOOL ccDfsIsError(NQ_STATUS errorCode)
{
    NQ_COUNT i;
    NQ_BOOL result = TRUE;

    for (i = 0; i < sizeof(errorCodes) / sizeof(errorCodes[0]); i++)
    {
        if (errorCodes[i] == errorCode)
            goto Exit;
    }

    result = FALSE;

Exit:
    return result;
}

NQ_BOOL ccDfsStart(void)
{
#ifdef UD_CC_INCLUDEDFS
    NQ_BOOL result = FALSE;
    NQ_CHAR *dcNameA = NULL;
    NQ_WCHAR *dcName = NULL;
    const NQ_CHAR *domainA = NULL;
    NQ_WCHAR *domain = NULL;
    NQ_STATUS status;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    ccDfsResolveOn(TRUE);

    /* get default domain dc */
    dcNameA = (NQ_CHAR *)cmMemoryAllocate(sizeof(NQ_CHAR) * (CM_NQ_HOSTNAMESIZE + 1));
    if (NULL == dcNameA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    domainA = (NQ_CHAR *)cmMemoryAllocate(sizeof(NQ_CHAR) * (CM_NQ_HOSTNAMESIZE + 1));
    if (NULL == domainA)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    if ((status = cmGetDCName(dcNameA, &domainA)) != NQ_SUCCESS)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "dfs: default domain dc not resolved, status: %d", status);
        result = TRUE; /* DFS module starts even if DC not resolved */
        goto Exit;
    }

    dcName = cmMemoryCloneAString(dcNameA);
    domain = cmMemoryCloneAString(domainA);
    if (NULL == dcName || NULL == domain)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

    ccDfsCacheAddDomain(domain, dcName, 0);
    getDomainDC(dcName);

    result = TRUE;

Exit:
    cmMemoryFree(dcNameA);
    cmMemoryFree(domainA);
    cmMemoryFree(dcName);
    cmMemoryFree(domain);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
    return result;
#else /* UD_CC_INCLUDEDFS */
    return TRUE;
#endif /* UD_CC_INCLUDEDFS */
}

void ccDfsShutdown(void)
{

}

const NQ_WCHAR * ccDfsResolveHost(const NQ_WCHAR * host)
{
#ifdef UD_CC_INCLUDEDFS
    CCDfsCacheEntry * pEntry;          /* DFS cache entry */
    const NQ_WCHAR * pResult = NULL;   /* return value */
    const NQ_CHAR *domainA = NULL;
    const NQ_WCHAR * dcNameW = NULL;
    NQ_CHAR * dcNameA = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "host:%s", cmWDump(host));
    /*LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "host: %s", cmWDump(host));*/

    if (!dfsIsOn)
    {
        pResult = cmMemoryCloneWString(host);
        goto Exit;
    }

    /* assume required host is a domain name */
    /* look in domain cache first */
    pEntry = ccDfsCacheFindDomain(host);
    if (NULL != pEntry && NULL != pEntry->refList && NULL != pEntry->refList->first)
    {
        printReferrals(pEntry->refList);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Found in domain cache: %s", cmWDump(pEntry->refList->first->name));
        pResult = cmMemoryCloneWString(pEntry->refList->first->name);
        if (NULL == pResult)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_OUTOFMEMORY);
        }
        goto Exit;
    }
    else
    {
        NQ_STATUS status;

        domainA = cmMemoryCloneWStringAsAscii(host);
        dcNameA = (NQ_CHAR *)cmMemoryAllocate(sizeof(NQ_CHAR) * (CM_NQ_HOSTNAMESIZE + 1));
        if (NULL == dcNameA || NULL == domainA)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            goto Exit;
        }

        /* try to resolve it as domain, return DC name, add to domain cache */
        status = cmGetDCNameByDomain(domainA, dcNameA);
        if (status != NQ_SUCCESS)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "status: %d", status);
            sySetLastError((NQ_UINT32)syGetLastError());
            goto Exit;
        }
        dcNameW = cmMemoryCloneAString(dcNameA);
        if (NULL == dcNameW)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            goto Exit;
        }
        ccDfsCacheAddDomain(host, dcNameW, 0);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Resolved DC: %s", cmWDump(dcNameW));
        pResult = dcNameW;
    }

Exit:
    cmMemoryFree(dcNameA);
    cmMemoryFree(domainA);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
    return pResult;

#else /* UD_CC_INCLUDEDFS */

    return cmMemoryCloneWString(host);

#endif /* UD_CC_INCLUDEDFS */
}

CCDfsResult ccDfsResolvePath(CCMount *pMount, CCShare * pShare, const NQ_WCHAR * file, CCDfsContext * context)
{
#ifdef UD_CC_INCLUDEDFS
    CCDfsCacheEntry      *pCache;           /* cache entry pointer */
    NQ_WCHAR             *path = NULL;      /* network path to file */
    const AMCredentialsW *pCredentials;     /* pointer to credentials */
#endif /* UD_CC_INCLUDEDFS */
    CCDfsResult          res;               /* operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "share:%p file:%s context:%p", pShare, cmWDump(file), context);

    syMemset(&res, 0, sizeof(res));

#ifdef UD_CC_INCLUDEDFS
    if (!dfsIsOn)
#endif /* UD_CC_INCLUDEDFS */
    {
        goto Exit;
    }

#ifdef UD_CC_INCLUDEDFS

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "server: %s", cmWDump((const NQ_WCHAR *)pShare->user->server->item.name));
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "share: %s", cmWDump((const NQ_WCHAR *)pShare->item.name));
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "file: %s", file ? cmWDump((const NQ_WCHAR *)file) : "null");

    if (context && context->referral && context->lastError != NQ_ERR_PATHNOTCOVERED)
    {
        /* here a required path was fully resolved and IO operation was tried on it,
           but some IO error occurred, so need to try another referral (if available) */
        CCDfsReferral * referralContext = (CCDfsReferral *)context->referral;
        CCDfsReferral * referral = NULL;
        CMIterator iterator;

        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "IO error on %p, %s, trying other referrals", referralContext, cmWDump(referralContext->item.name));

        referralContext->isIOPerformed = TRUE;
        referralContext->lastIOStatus = context->lastError;

        cmListIteratorStart(referralContext->item.master, &iterator);
        while (cmListIteratorHasNext(&iterator) && res.share == NULL)
        {
            referral = (CCDfsReferral *)cmListIteratorNext(&iterator);
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " in list: %s, %p, isIOPerformed %d", cmWDump(referral->item.name), referral, referral->isIOPerformed);

            if (referral == referralContext)
            {
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "continue, same");
                continue;
            }

            if (!referral->isIOPerformed)
            {
                pCredentials = pShare->user->credentials;
                res.share = ccShareConnect(referral->item.name, pMount, &pCredentials, FALSE);
                if (pCredentials != pShare->user->credentials)
                    cmMemoryFree(pCredentials);
                if (res.share != NULL)
                {
                    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "connected to candidate");
                    context->referral = &referral->item;
                    break;
                }
            }
        }
        cmListIteratorTerminate(&iterator);
        createResultPath(file, 0, referral ? &referral->item : NULL, &res);
        goto Exit;
    }
    else if (!(pShare->user->server->capabilities & CC_CAP_DFS))
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Server: %s does not support DFS", cmWDump(pShare->user->server->item.name));
        goto Exit;
    }

    /* construct remote path to file */
    path = ccUtilsComposeRemotePathToFile(pShare->user->server->item.name, pShare->item.name, file);
    if (NULL == path)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "remote path: %s", cmWDump((const NQ_WCHAR *)path));

    /* find in cache */
    pCache = ccDfsCacheFindPath(path);
    if (NULL != pCache)   /* found in cache */
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "found in cache %s match", pCache->isExactMatch ? "exact" : "partial");
        printReferrals(pCache->refList);

        if (pCache->isExactMatch)
        {
            /* iterate through all referrals, return 1st successfully connected */
            CMItem * item = NULL;
            CMIterator iterator;

            cmListIteratorStart(pCache->refList, &iterator);
            while (cmListIteratorHasNext(&iterator) && res.share == NULL)
            {
                item = cmListIteratorNext(&iterator);
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " %s", cmWDump(item->name));

                pCredentials = pShare->user->credentials;
                res.share = ccShareConnect(item->name, pMount, &pCredentials, FALSE);
                if (pCredentials !=  pShare->user->credentials)
                    cmMemoryFree(pCredentials);
            }
            cmListIteratorTerminate(&iterator);

            if (NULL != context)
                context->referral = item;
            createResultPath(path, pCache->numPathConsumed, item, &res);
            goto Exit;
        }
        else
        {   /* not exact match */
            if (pCache->isRoot)
            {
                /* ask root for referrals */
                /* get new share and path */
                CCShare * pRootShare = NULL;

                /* connect to root */
                {
                    /* iterate through all referrals, return 1st successfully connected */
                    CMItem * item = NULL;
                    CMIterator iterator;

                    cmListIteratorStart(pCache->refList, &iterator);
                    while (cmListIteratorHasNext(&iterator) && pRootShare == NULL)
                    {
                        item = cmListIteratorNext(&iterator);
                        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " %s", cmWDump(item->name));

                        pCredentials = pShare->user->credentials;
                        pRootShare = ccShareConnect(item->name, pMount, &pCredentials, FALSE);
                        if (NULL != pRootShare)
                        	ccMountAddShareLink(pMount, pRootShare);

                        if (pCredentials !=  pShare->user->credentials)
                            cmMemoryFree(pCredentials);
                    }
                    cmListIteratorTerminate(&iterator);
                }

                /* ask root for referrals */
                if (pRootShare && getReferrals(pMount ,pRootShare, path, parseReferralCallback))
                {
                    /* return 1st found referral */
                    pCache = ccDfsCacheFindPath(path);
                    if (NULL != pCache)   /* found in cache */
                    {
                        /* iterate through all referrals, return 1st successfully connected */
                        CMItem * item = NULL;
                        CMIterator iterator;

                        cmListIteratorStart(pCache->refList, &iterator);

                        while (cmListIteratorHasNext(&iterator) && res.share == NULL)
                        {
                            item = cmListIteratorNext(&iterator);
                            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " %s", cmWDump(item->name));

                            pCredentials = pShare->user->credentials;
                            res.share = ccShareConnect(item->name, pMount, &pCredentials, FALSE);
                            if (pCredentials !=  pShare->user->credentials)
                                cmMemoryFree(pCredentials);
                        }
                        cmListIteratorTerminate(&iterator);

                        if (NULL != context && NULL != res.share)
                            context->referral = item;
                        createResultPath(path, pCache->numPathConsumed, item, &res);
                        goto Exit;
                    }
                }
            }
            else
            {
                /* iterate through all referrals, return 1st successfully connected */
                CCDfsReferral *referral = NULL;
                CMIterator iterator;

                cmListIteratorStart(pCache->refList, &iterator);
                while (cmListIteratorHasNext(&iterator) && res.share == NULL)
                {
                    referral = (CCDfsReferral *)cmListIteratorNext(&iterator);
                    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " %s", cmWDump(referral->item.name));

                    if (referral->isIOPerformed && referral->lastIOStatus != NQ_SUCCESS)
                        continue;
                    pCredentials = pShare->user->credentials;
                    res.share = ccShareConnect(referral->item.name, pMount, &pCredentials, FALSE);
                    if (pCredentials !=  pShare->user->credentials)
                        cmMemoryFree(pCredentials);
                }
                cmListIteratorTerminate(&iterator);

                if (NULL != context && NULL != res.share)
                    context->referral = &referral->item;
                createResultPath(path, pCache->numPathConsumed, &referral->item, &res);
                goto Exit;
            }
        }
    }
    else   /* not found in cache */
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "not found in cache");

        /* get referrals and add to cache */
        if (getReferrals(pMount ,pShare, path, parseReferralCallback))
        {
            /* return 1st found referral */
            pCache = ccDfsCacheFindPath(path);
            if (NULL != pCache)   /* found in cache */
            {
                /* iterate through all referrals, return 1st successfully connected */
                CMItem * item = NULL;
                CMIterator iterator;

                cmListIteratorStart(pCache->refList, &iterator);
                while (cmListIteratorHasNext(&iterator) && res.share == NULL)
                {
                    item = cmListIteratorNext(&iterator);
                    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " %s", cmWDump(item->name));

                    pCredentials = pShare->user->credentials;
                    res.share = ccShareConnect(item->name, pMount, &pCredentials, FALSE);
                    if (pCredentials != pShare->user->credentials)
                        cmMemoryFree(pCredentials);
                }
                cmListIteratorTerminate(&iterator);

                if (NULL != context && NULL != res.share)
                    context->referral = item;
                createResultPath(path, pCache->numPathConsumed, item, &res);
                goto Exit;
            }
        }
        else
        {
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Failed to get referrals");
        }
    }
#endif /* UD_CC_INCLUDEDFS */

Exit:
#ifdef UD_CC_INCLUDEDFS
	if (NULL != res.share)
		ccMountAddShareLink(pMount, res.share);

    cmMemoryFree(path);
    logPrintResult(res);
#endif /* UD_CC_INCLUDEDFS */
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", res);
    return res;
}

void ccDfsResolveDispose(CCDfsResult * pRes)
{
    if (pRes && pRes->path)
        cmMemoryFree(pRes->path);
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
