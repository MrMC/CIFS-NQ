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

/* -- Static data and defintions */

#define DFS_ROOT_TARGET 0x0001
#define DFS_LINK_TARGET 0x0000


/* 
 * Internal referral structure 
 */
typedef struct 
{
    CMItem item;                /* list item */
    NQ_UINT16 numPathConsumed;  /* number of request path characters consumed */
    NQ_UINT16 serverType;       /* server type */
    NQ_UINT16 flags;            /* referral flags */
    NQ_UINT32 ttl;              /* time to live */
    NQ_WCHAR * dfsPath;         /* original path */
    NQ_WCHAR * netPath;         /* resolved path */
} Referral;


/* -- Static functions -- */

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

#ifdef UD_CC_INCLUDEDFS
static NQ_BOOL dfsIsOn = TRUE; /* turn DFS on/off */

static void printReferrals(CMList *pList)
{
#ifdef UD_NQ_INCLUDETRACE
    CMIterator iterator;

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Referrals:");
    cmListIteratorStart(pList, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * item = cmListIteratorNext(&iterator);  
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " %s", cmWDump(item->name));
    }
    cmListIteratorTerminate(&iterator);
#endif /* UD_NQ_INCLUDETRACE */
}

/*
 * Explicitely close and dispose referral (see above):
 *  - disconnects from the share
 *  - disposes private data  
 */
static NQ_BOOL disposeReferralCallback(CMItem * pItem)
{
    Referral * pRef;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pRef = (Referral *)pItem;
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
    Referral * ref;             /* referral entry */    
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

        ref = (Referral *)cmListItemCreate(sizeof(Referral), NULL, FALSE);
        ref->numPathConsumed = (NQ_UINT16)(pathConsumed / 2 + 1);
        ref->serverType = (serverType == DFS_ROOT_TARGET);
        ref->flags = flags;
        ref->ttl = ttl;
        ref->dfsPath = (dfsPath == NULL) ? NULL : cmMemoryCloneWString(dfsPath);
        ref->netPath = cmMemoryCloneWString(netPath);
        cmListItemAdd(pList, (CMItem *)ref, disposeReferralCallback);
    }
}

static NQ_WCHAR * getDomainReferral(const NQ_WCHAR *dcName, const NQ_WCHAR *path)
{
    CCShare *pShare;
    NQ_WCHAR *ipcPath;
    NQ_WCHAR *resultReferral = NULL;
    const AMCredentialsW *pCredentials = NULL;
    static const NQ_WCHAR ipcName[] = {cmWChar('I'), cmWChar('P'), cmWChar('C'), cmWChar('$'), cmWChar(0)};

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "dc name: %s", cmWDump((const NQ_WCHAR *)dcName)); 
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "path: %s", cmWDump(path));    

    /* connect to IPC$ share */
    ipcPath = ccUtilsComposeRemotePathToShare(dcName, ipcName);
    if (NULL == ipcPath)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }

    pShare = ccShareConnect(ipcPath, &pCredentials, FALSE);
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
                Referral * pDomainRef;
                CCShare * pShareReferral;
                
                pDomainRef = (Referral *)cmListIteratorNext(&domainIter);
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "got domain dfs referral: %s, rootOrLink: %s", cmWDump(pDomainRef->netPath), pDomainRef->serverType == DFS_ROOT_TARGET ? "root" : "link");

                pCredentials = pShare->user->credentials;
                pShareReferral = ccShareConnect(pDomainRef->netPath, &pCredentials, FALSE);
                if (pCredentials !=  pShare->user->credentials)
                    cmMemoryFree(pCredentials); 
                if (pShareReferral != NULL)
                {
                    ccDfsCacheAddPath(path + 1, pDomainRef->netPath, pDomainRef->ttl, pDomainRef->serverType == DFS_ROOT_TARGET, pDomainRef->numPathConsumed); 
                    resultReferral = cmMemoryCloneWString(pDomainRef->netPath);
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
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return resultReferral;
}


static NQ_BOOL getReferrals(CCShare * pShare, const NQ_WCHAR * path, CCCifsParseReferral parser)
{   
    CCShare *ipc;
    CMList  refs; 
    NQ_STATUS  result = NQ_FAIL;
    NQ_BOOL isPathAdded = FALSE;
    const AMCredentialsW *pCredentials = pShare->user->credentials;
    NQ_STATUS        prevStatus = 0;        /* status to handle failed connect tries*/ 

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "path: %s", cmWDump((const NQ_WCHAR *)path));

    /* connect to IPC$ share */
    ipc = ccShareConnectIpc(pShare->user->server, &pCredentials);
    if (pCredentials !=  pShare->user->credentials)
    {
        /* new credentaisl were allocated */
        cmMemoryFree(pCredentials);
    }

    /* send get referrals */
    if (NULL != ipc)
    {
        CMIterator iterator;
        
        cmListStart(&refs);
        result = pShare->user->server->smb->doQueryDfsReferrals(ipc, path + 1, parseReferralCallback, &refs);
        
        /* try to connect and store into cache only successfully connected */
        if (NQ_SUCCESS == result)
        {
            CCShare *pShareReferral;
            
            cmListIteratorStart(&refs, &iterator);
            while (cmListIteratorHasNext(&iterator))
            {
                Referral * pRef;            /* next referral */
                CCDfsCacheEntry * pEntry;   /* DFS cache entry */
                NQ_WCHAR * pDomain;
                NQ_WCHAR * netPath = NULL;

                pRef = (Referral *)cmListIteratorNext(&iterator);
                
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "got referral: %s, rootOrLink: %s, pathConsumed: %d", cmWDump(pRef->netPath), pRef->serverType == DFS_ROOT_TARGET ? "root" : "link", pRef->numPathConsumed);

                /* look in domain cache by first path component */  
                pDomain = ccUtilsHostFromRemotePath(pRef->netPath);
                if (NULL == pDomain)
                {
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
                    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                    return FALSE;
                }
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "pDomain: %s", cmWDump(pDomain));
                pEntry = ccDfsCacheFindDomain(pDomain);  
                cmMemoryFree(pDomain);
                if (NULL != pEntry && NULL != pEntry->refList && NULL != pEntry->refList->first)
                {
                    NQ_WCHAR *domainReferral = NULL, *serverHostComponent = NULL, *pathComponent = NULL;
                    
                    /* printReferrals(pEntry->refList); */
                    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Found in domain cache DC: %s", cmWDump(pEntry->refList->first->name));

                    /* ask domain's dc for referral */
                    serverHostComponent = ccUtilsHostShareFromRemotePath(pRef->netPath);                    
                    pathComponent = ccUtilsFilePathFromRemotePath(pRef->netPath, FALSE);
                    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "serverHostComponent: %s", cmWDump(serverHostComponent));
                    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "pathComponent: %s", cmWDump(pathComponent));
                   
                    if (NULL == serverHostComponent || NULL == pathComponent)
                    {
                        cmListItemUnlock((CMItem *)ipc);
                        cmMemoryFree(serverHostComponent);
                        cmMemoryFree(pathComponent);
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
                        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        return FALSE;
                    }
                    
                    domainReferral = getDomainReferral(pEntry->refList->first->name, serverHostComponent);
                    cmMemoryFree(serverHostComponent);
                    if (NULL != domainReferral)
                    {
                        netPath = (pRef->numPathConsumed == cmWStrlen(path)) ? 
                                               cmMemoryCloneWString(domainReferral) :
                                               ccUtilsComposeRemotePathToFileByMountPath(domainReferral, pathComponent);
                        cmMemoryFree(domainReferral);
                        if (NULL == netPath)
                        {    
                            cmMemoryFree(pathComponent);                                               
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
                            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                            return FALSE;
                        }                        
                        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "New path: %s", cmWDump(netPath));
                    }
                    cmMemoryFree(pathComponent);
                }

                if (NULL == netPath)
                {
                    netPath = cmMemoryCloneWString(pRef->netPath);
                    if (NULL == netPath)
                    {
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
                        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                        return FALSE;
                    }
                }

                pCredentials = pShare->user->credentials;
                pShareReferral = ccShareConnect(netPath, &pCredentials, FALSE);
                if (pCredentials !=  pShare->user->credentials)
                    cmMemoryFree(pCredentials); 
                if (pShareReferral != NULL)
                { 
                    ccDfsCacheAddPath(path, netPath, pRef->ttl, pRef->serverType == DFS_ROOT_TARGET, pRef->numPathConsumed);
                    isPathAdded = TRUE;
                }
                cmMemoryFree(netPath);
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

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "dc name: %s", cmWDump((const NQ_WCHAR *)dcName));    

    /* connect to IPC$ share */
    ipcPath = ccUtilsComposeRemotePathToShare(dcName, ipcName);
    if (NULL == ipcPath)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return;
    }

    pShare = ccShareConnect(ipcPath, &pCredentials, FALSE);
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
                Referral * pDomainRef;
                CMList dcRefs; 
				CMIterator dcIter;
                
                pDomainRef = (Referral *)cmListIteratorNext(&domainIter);
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "got domain referral: %s, rootOrLink: %s", cmWDump(pDomainRef->netPath), pDomainRef->serverType == DFS_ROOT_TARGET ? "root" : "link");
                cmListStart(&dcRefs);
                /* send get referrals (for each domain dfs name get it's dc) */
                result = pShare->user->server->smb->doQueryDfsReferrals(pShare, pDomainRef->netPath, parseReferralCallback, &dcRefs);
                if (NQ_SUCCESS == result)
                {                                        
                    cmListIteratorStart(&dcRefs, &dcIter);
                    while (cmListIteratorHasNext(&dcIter))
                    {
                        Referral * pRootRef;

                        pRootRef = (Referral *)cmListIteratorNext(&dcIter);
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
    cmMemoryFree(pCredentials);   /*Can Handle NULL*/
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

#endif /* UD_CC_INCLUDEDFS */ 

/* -- API Functions */

NQ_BOOL ccDfsStart(void)
{
#ifdef UD_CC_INCLUDEDFS
    NQ_CHAR *dcNameA;
    NQ_WCHAR *dcName;
    NQ_STATUS status;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* get default domain dc */
    dcNameA = cmMemoryAllocate(sizeof(NQ_CHAR) * (CM_NQ_HOSTNAMESIZE + 1));
    if (NULL == dcNameA)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return TRUE;
    }
    if ((status = cmGetDCName(dcNameA, NULL)) != NQ_ERR_OK)
    {
        cmMemoryFree(dcNameA);
        sySetLastError((NQ_UINT32)status);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return TRUE;
    }

    dcName = cmMemoryCloneAString(dcNameA);
    cmMemoryFree(dcNameA);
    if (NULL == dcName)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return TRUE;
    }
    getDomainDC(dcName);
    cmMemoryFree(dcName);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
#endif    
    return TRUE;
}

void ccDfsShutdown(void)
{
  
}

const NQ_WCHAR * ccDfsResolveHost(const NQ_WCHAR * host)
{
#ifdef UD_CC_INCLUDEDFS 
    CCDfsCacheEntry * pEntry;   /* DFS cache entry */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "host: %s", cmWDump(host));
    
    if (!dfsIsOn)
    {
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return host;
    }
    
    /* assume required host is a domain name */
    /* look in domain cache first */
    pEntry = ccDfsCacheFindDomain(host);  
    if (NULL != pEntry && NULL != pEntry->refList && NULL != pEntry->refList->first)
    {
        printReferrals(pEntry->refList);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Found in domain cache: %s", cmWDump(pEntry->refList->first->name));
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return cmMemoryCloneWString(pEntry->refList->first->name);
    }
    else
    {
        NQ_CHAR * dcNameA;      /* DC name in ASCII */
        NQ_CHAR * domainNameA;  /* (expected) domain name in ASCII */
        NQ_WCHAR * dcNameW;     /* DC name in Unicode */
        NQ_STATUS res;          /* DC resolution status */

        /* try to resolve it as domain, return DC name, add to domain name */
        dcNameA = cmMemoryAllocate(sizeof(NQ_CHAR) * (CM_NQ_HOSTNAMESIZE + 1));
        if (NULL == dcNameA)
        {
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
        domainNameA = cmMemoryCloneWStringAsAscii(host);
        if (NULL == domainNameA)
        {
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
        res = cmGetDCNameByDomain(domainNameA, dcNameA);
        cmMemoryFree(domainNameA);
        if (NQ_SUCCESS != res) 
        {
            cmMemoryFree(dcNameA);
            sySetLastError((NQ_UINT32)res);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
        dcNameW = cmMemoryCloneAString(dcNameA);
        cmMemoryFree(dcNameA);
        if (NULL == dcNameW)
        {
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }      
        
        ccDfsCacheAddDomain(host, dcNameW, 0);
        LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Resolved DC: %s", cmWDump(dcNameW));    
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return dcNameW;
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return NULL;
#else /* UD_CC_INCLUDEDFS */ 
    return cmMemoryCloneWString(host);
#endif /* UD_CC_INCLUDEDFS */ 
}

CCDfsResult ccDfsResolvePath(CCShare * pShare, const NQ_WCHAR * file)
{
    CCDfsResult res;
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    syMemset(&res, 0, sizeof(res));

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "server: %s", cmWDump((const NQ_WCHAR *)pShare->user->server->item.name));  
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "share: %s", cmWDump((const NQ_WCHAR *)pShare->item.name));
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "file: %s", file ? cmWDump((const NQ_WCHAR *)file) : "null");

#ifdef UD_CC_INCLUDEDFS 

    if (dfsIsOn && (pShare->user->server->capabilities & CC_CAP_DFS))
    {
        CCDfsCacheEntry *pCache;    /* cache entry pointer */
        NQ_WCHAR        *path;      /* network path to file */
        const AMCredentialsW *pCredentials;

        /* construct remote path to file */
        path = ccUtilsComposeRemotePathToFile(pShare->user->server->item.name, pShare->item.name, file);
        if (NULL == path)
        {
            sySetLastError(NQ_ERR_OUTOFMEMORY);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return res;
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
                    res.share = ccShareConnect(item->name, &pCredentials, FALSE);
                    if (pCredentials !=  pShare->user->credentials)
                        cmMemoryFree(pCredentials);                       
                }
                cmListIteratorTerminate(&iterator);

                /* create result path */
                if (item != NULL && res.share != NULL)
                {
                    res.path = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(item->name) + cmWStrlen(path))));
                    if (res.path)
                    {
                        cmWStrcpy(res.path, item->name);
                        cmWStrcat(res.path, path + pCache->numPathConsumed);
                    }
                    res.server = res.share->user->server;
                }
                    
                logPrintResult(res);
                cmMemoryFree(path);
                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
                return res;
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
		                    pRootShare = ccShareConnect(item->name, &pCredentials, FALSE);
		                    if (pCredentials !=  pShare->user->credentials)
		                        cmMemoryFree(pCredentials);                       
		                }
		                cmListIteratorTerminate(&iterator);
                    }
                    
                    /* ask root for referrals */
                    if (pRootShare && getReferrals(pRootShare, path, parseReferralCallback))
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
			                    res.share = ccShareConnect(item->name, &pCredentials, FALSE);
			                    if (pCredentials !=  pShare->user->credentials)
			                        cmMemoryFree(pCredentials);                       
			                }
			                cmListIteratorTerminate(&iterator);
			
			                /* create result path */
			                if (item != NULL && res.share != NULL)
			                {
			                    res.path = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(item->name) + cmWStrlen(path))));
			                    if (res.path)
			                    {
			                        cmWStrcpy(res.path, item->name);
			                        cmWStrcat(res.path, path + pCache->numPathConsumed);
			                    }
			                    res.server = res.share->user->server;
			                }
			                    
                            logPrintResult(res);
			                cmMemoryFree(path);
			                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			                return res;
                        }
                    }
                }
                else
                {
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
			                    res.share = ccShareConnect(item->name, &pCredentials, FALSE);
			                    if (pCredentials !=  pShare->user->credentials)
			                        cmMemoryFree(pCredentials);                       
			                }
			                cmListIteratorTerminate(&iterator);
			
			                /* create result path */
			                if (item != NULL && res.share != NULL)
			                {
			                    res.path = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(item->name) + cmWStrlen(path))));
			                    if (res.path)
			                    {
			                        cmWStrcpy(res.path, item->name);
			                        cmWStrcat(res.path, path + pCache->numPathConsumed);
			                    }
			                    res.server = res.share->user->server;
			                }
			                    
                            logPrintResult(res);
			                cmMemoryFree(path);
			                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
			                return res;
                    }
                }
            }           
        }
        else   /* not found in cache */
        {
            LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "not found in cache");

            /* get referrals and add to cache */
            if (getReferrals(pShare, path, parseReferralCallback))
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
	                    res.share = ccShareConnect(item->name, &pCredentials, FALSE);
	                    if (pCredentials !=  pShare->user->credentials)
	                        cmMemoryFree(pCredentials); 
	                }
	                cmListIteratorTerminate(&iterator);
	
	                /* create result path */
	                if (item != NULL && res.share != NULL)
	                {
	                    res.path = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(item->name) + cmWStrlen(path))));
	                    if (res.path)
	                    {
	                        cmWStrcpy(res.path, item->name);
	                        cmWStrcat(res.path, path + pCache->numPathConsumed);
	                    }
	                    res.server = res.share->user->server;
	                }
	                    
                    logPrintResult(res);
	                cmMemoryFree(path);
	                LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
	                return res;
                }
            }
        }
        cmMemoryFree(path);
    }
    
#endif /* UD_CC_INCLUDEDFS */ 

    logPrintResult(res);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return res;
}

void ccDfsResolveDispose(CCDfsResult * pRes)
{
    if (pRes && pRes->path)
        cmMemoryFree(pRes->path);
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */

