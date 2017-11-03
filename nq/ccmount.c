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

#include "ccmount.h"
#include "cmapi.h"
#include "ccutils.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static data -- */
static CMList mounts;

/* -- Local constants -- */

#define MOUNTNTPATH_SIZE 64
#define SHAREPATH_SIZE   CM_NQ_HOSTNAMESIZE + UD_FS_MAXSHARELEN + 3

/* -- Local functions -- */

/*
 * Print mount-specific information 
 */
#if SY_DEBUGMODE
static void dumpOne(CMItem * pItem)
{
#if defined (UD_NQ_EXTERNALTRACE) || defined (NQ_INTERNALTRACE)
    CCMount * pMount = (CCMount *)pItem;
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  Mount:: path: %s server %p share %p", cmWDump(pMount->path), pMount->server, pMount->share);
#endif /* defined (UD_NQ_EXTERNALTRACE) || defined (NQ_INTERNALTRACE) */
}
#endif /* SY_DEBUGMODE */

/*
 * Explicitly dispose mount point:
 *     - disconnects from the server
 *  - disposes private data  
 */
static void disposeMount(CCMount * pMount)
{
#ifdef UD_CC_INCLUDEDFS
	CMIterator shareLinkIter;
	CCShareLink *pShareLink;
#endif

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "mount:%p", pMount);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "About to dispose mount %s", cmWDump(pMount->item.name));

    if (NULL != pMount->credentials)
        cmMemoryFree(pMount->credentials);
    if (NULL != pMount->path)
        cmMemoryFree(pMount->path);
    if (NULL != pMount->pathPrefix)
        cmMemoryFree(pMount->pathPrefix);

#ifdef UD_CC_INCLUDEDFS
    cmListIteratorStart(&pMount->shareLinks, &shareLinkIter);

    while(cmListIteratorHasNext(&shareLinkIter))
    {
    	pShareLink = (CCShareLink *)cmListIteratorNext(&shareLinkIter);
    	cmListItemUnlock((CMItem *)pShareLink->pShare);
    }
    cmListIteratorTerminate(&shareLinkIter);
    cmListShutdown(&pMount->shareLinks);
#endif

    cmListItemRemoveAndDispose((CMItem *)pMount);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 * Callback for share unlock and disposal:
 *     - disconnects from the share
 *  - disposes private data  
 */
static NQ_BOOL unlockCallback(CMItem * pItem)
{
    disposeMount((CCMount *)pItem);
    return TRUE;
}

/*
 * Check mount point name 
 */
static NQ_BOOL isValidMountPointName(const NQ_WCHAR * name)
{
    static NQ_WCHAR illegal[] = {
        cmWChar('"'), cmWChar('['), cmWChar(']'), cmWChar(';'), cmWChar('='), cmWChar(','), 
        cmWChar('\\'), cmWChar('/'), cmWChar(':'), cmWChar('*'), cmWChar('?'), cmWChar('<'), 
        cmWChar('>'), cmWChar('|')
        };

    NQ_INT length;
    NQ_UINT i;
    NQ_BOOL result = FALSE;

    length = (NQ_INT)cmWStrlen(name);

    /* check length */
    if ((length < 2) || (length >= MOUNTNTPATH_SIZE) || (name[0] != cmWChar('\\')))
    {
        goto Exit;
    }
    /* skip the first character */
    name++;

    for (i = 0; i < sizeof(illegal)/sizeof(NQ_WCHAR); i++)
        if (cmWStrchr(name, illegal[i]) != NULL)
            goto Exit;

    result = TRUE;

Exit:
    return result;
}

/*
 * Check remote path
 */

static NQ_BOOL isValidRemotePathName(const NQ_WCHAR * name)
{
    NQ_COUNT i; 
    const NQ_WCHAR * p;   
    NQ_BOOL result = FALSE;

    if (!name || cmWStrlen(name) >= SHAREPATH_SIZE)
        goto Exit;
    
    for (i = 0, p = name; *p != cmWChar('\0'); p++)
    {
        if (*p == cmWChar('\\'))
            i++;
    }

    result = (i >= 3);

Exit:
    return result;
}


/* -- API functions -- */

NQ_BOOL ccMountStart(void)
{
    cmListStart(&mounts);
#if SY_DEBUGMODE
    mounts.name = "mounts";
#endif
    return TRUE;
}

void ccMountShutdown(void)
{
    CMIterator  iterator;
     
    cmListIteratorStart(&mounts, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * pItem;

        pItem = cmListIteratorNext(&iterator);
        cmListItemUnlock(pItem);
    }
    cmListIteratorTerminate(&iterator);
    cmListShutdown(&mounts);
}

void ccMountIterateMounts(CMIterator * iterator)
{
    cmListIteratorStart(&mounts, iterator);
}

#if SY_DEBUGMODE

void ccMountDump(void)
{
    cmListDump(&mounts);
}

#endif /* SY_DEBUGMODE */

/* -- NQ API functions */

NQ_INT nqAddMountA(const NQ_CHAR * mountPoint, const NQ_CHAR * remotePath, NQ_BOOL connect)
{
    NQ_WCHAR * wPoint = NULL;
    NQ_WCHAR * wPath = NULL;
    NQ_INT res = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    wPoint = cmMemoryCloneAString(mountPoint);
    wPath = cmMemoryCloneAString(remotePath);
    if (NULL == wPoint || NULL == wPath)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    res = nqAddMountW(wPoint, wPath, connect);

Exit:
    cmMemoryFree(wPoint);
    cmMemoryFree(wPath);
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%d", res);
    return res;
}

NQ_INT nqAddMountW(const NQ_WCHAR * mountPoint, const NQ_WCHAR * remotePath, NQ_BOOL connect)
{
    CCMount * pMount = NULL;       /* pointer to mount */
    CCShare * pShare = NULL;       /* pointer to share */
    NQ_WCHAR * mountFilePath = NULL;
    NQ_WCHAR * filePathFromRemotePath = NULL;
    NQ_INT result = NQ_FAIL;       /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "point:%s path:%s connect:%s", cmWDump(mountPoint), cmWDump(remotePath), connect ? "TRUE" : "FALSE");

    if (!isValidMountPointName(mountPoint))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal mount point name: %s", cmWDump(mountPoint));
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

    if (!isValidRemotePathName(remotePath))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal share path: %s", cmWDump(remotePath));
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    pMount = (CCMount *)cmListItemFind(&mounts, mountPoint + 1, TRUE , TRUE);
    if (NULL != pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Duplicate mount point");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Error;
    }
    pMount = (CCMount *)cmListItemCreateAndAdd(&mounts, sizeof(CCMount), mountPoint + 1, unlockCallback, CM_LISTITEM_LOCK);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }

#ifdef UD_CC_INCLUDEDFS
    cmListStart(&pMount->shareLinks);
#endif

    pMount->path = cmMemoryCloneWString(remotePath);
    if (NULL == pMount->path)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Error;
    }
    cmWStrupr(pMount->path);
    pMount->pathPrefix = NULL;
    pMount->credentials = NULL; /* will be set later */
    pShare = ccShareConnect(pMount->path, pMount, &pMount->credentials, TRUE);
    if (NULL == pShare)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to connect");
        goto Error;
    }

    if (NULL != pShare->dfsReferral)
    {
        cmListItemAddReference((CMItem *)pMount, (CMItem *)pShare->dfsReferral);
        pMount->share = pShare->dfsReferral;
        pMount->server = pShare->dfsReferral->user->server;
    }
    else
    {
        cmListItemAddReference((CMItem *)pMount, (CMItem *)pShare);
        pMount->share = pShare;
        pMount->server = pShare->user->server;
    }
    cmListItemUnlock((CMItem *)pShare);

    /* check sub folder path existence */
    {
        filePathFromRemotePath = ccUtilsFilePathFromRemotePath(remotePath, TRUE);

        if (NULL != filePathFromRemotePath)
        {
            FileInfo_t fileInfo;
            
            if (cmWStrlen(filePathFromRemotePath) == 0)
            {
                cmMemoryFree(filePathFromRemotePath);
            }
            else
            {
                mountFilePath = ccUtilsComposeLocalPathToFileByMountPoint(pMount->item.name, filePathFromRemotePath);            
                if (NULL == mountFilePath)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
                    sySetLastError(NQ_ERR_OUTOFMEMORY);
                    goto Error;
                }
                if (!ccGetFileInformationByNameW(mountFilePath, &fileInfo))
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Failed to connect to sub folder");
                    goto Error;
                }
                pMount->pathPrefix = filePathFromRemotePath;
            }
        }   
    }
#if SY_DEBUGMODE
    pMount->item.dump = dumpOne; 
#endif /* SY_DEBUGMODE */

    result = NQ_SUCCESS;
    goto Exit;

Error:
    cmMemoryFree(filePathFromRemotePath);
    cmListItemUnlock((CMItem *)pMount);

Exit:
    cmMemoryFree(mountFilePath);
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%d", result);
    return result;
}

NQ_INT nqRemoveMountA(const NQ_CHAR * mountPoint)
{
    NQ_WCHAR * pointW = NULL; /* mount point in Unicode */
    NQ_INT res = NQ_FAIL;     /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    pointW = cmMemoryCloneAString(mountPoint);
    if (NULL == pointW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    res = nqRemoveMountW(pointW);

Exit:
    cmMemoryFree(pointW);
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%d", res);
    return res;
}

NQ_INT nqRemoveMountW(const NQ_WCHAR * mountPoint)
{
    CCMount * pMount = NULL;     /* mount point pointer */
    NQ_INT result = NQ_FAIL;     /* return value */
#ifdef UD_CC_INCLUDEDFS
    CMIterator shareLinkIter;
    CCShareLink *pShareLink;
#endif

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "point:%s", cmWDump(mountPoint));

    pMount = (CCMount *)cmListItemFind(&mounts, mountPoint + 1, TRUE , FALSE); /*no need to lock*/
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Mount point not found");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }

#ifdef UD_CC_INCLUDEDFS
    cmListIteratorStart(&pMount->shareLinks, &shareLinkIter);

    while(cmListIteratorHasNext(&shareLinkIter))
    {
    	pShareLink = (CCShareLink *)cmListIteratorNext(&shareLinkIter);
    	cmListItemUnlock((CMItem *)pShareLink->pShare);
    }
    cmListIteratorTerminate(&shareLinkIter);
    cmListShutdown(&pMount->shareLinks);
#endif

    cmListItemUnlock((CMItem *)pMount);

    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%d", result);
    return result;
}

CCMount * ccMountFind(const NQ_WCHAR * path)
{
    CCMount * pMount = NULL;           /* mount point pointer */
    const NQ_WCHAR * mpName = NULL;    /* mount point name */
    CCMount * pResult = NULL;          /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "path:%s", cmWDump(path));

    mpName = ccUtilsMountPointFromLocalPath(path);
    if (NULL == mpName)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    pMount = (CCMount *)cmListItemFind(&mounts, mpName, TRUE , TRUE);
    cmMemoryFree(mpName);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Mount point not found");
        goto Exit;
    }
    if (NULL == pMount->server || NULL == pMount->share)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Mount point not connected");
        goto Exit;
    }
    pResult = pMount;

Exit:
    if (NULL != pMount)
        cmListItemUnlock((CMItem *)pMount);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
    return pResult;
}

NQ_BOOL ccResetCredentailsA(const NQ_CHAR * mountPoint)
{
    NQ_WCHAR * pointW = NULL;    /* mount pint in Unicode */
    NQ_BOOL res = FALSE;         /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    pointW = cmMemoryCloneAString(mountPoint);
    if (NULL == pointW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        goto Exit;
    }
    res = ccResetCredentailsW(pointW);

Exit:
    cmMemoryFree(pointW);
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", res ? "TRUE" : "FALSE");
    return res;
}

NQ_BOOL ccResetCredentailsW(const NQ_WCHAR * mountPoint)
{
    CCMount * pMount = NULL;       /* mount point pointer */
    CCUser * pUser = NULL;         /* user structure pointer */
    CMIterator iServer;            /* servers iterator */
    NQ_BOOL result = FALSE;        /* return value */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "point:%s", cmWDump(mountPoint));

    pMount = (CCMount *)cmListItemFind(&mounts, mountPoint + 1, TRUE , TRUE);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Mount point not found");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    if (NULL == pMount->share)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Mount point not connected to share");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    pUser = pMount->share->user;
    if (NULL == pUser)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Associated share is not connected");
        sySetLastError(NQ_ERR_BADPARAM);
        goto Exit;
    }
    pMount->credentials = NULL;
    ccServerIterateServers(&iServer);
    while (cmListIteratorHasNext(&iServer))
    {
        CMIterator iUser;     /* users on server iterator */
        
        ccServerIterateUsers((CCServer *)cmListIteratorNext(&iServer), &iUser);
        while (cmListIteratorHasNext(&iUser))
        {
            CCUser * pNextUser;     /* next user pointer */

            pNextUser = (CCUser *)cmListIteratorNext(&iUser);
            if (0 == cmU64Cmp(&pUser->uid, &pNextUser->uid))
            {
                if (NULL != pNextUser->credentials)
                {
                    cmMemoryFree(pNextUser->credentials);
                    pNextUser->credentials = NULL;
                }
            }
        }
        cmListIteratorTerminate(&iUser);
    }
    cmListIteratorTerminate(&iServer);
    result = TRUE;

Exit:
    if (NULL != pMount)
        cmListItemUnlock((CMItem *)pMount);
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

/* Description
 * Per each mount, shares that are mounted as part of DFS
 * are kept in a list so they can be unlocked on remove mount.
 * Each share should appear once only, so if an existing share is
 * again listed, one item unlock should be performed. *
 */
void ccMountAddShareLink(CCMount *pMount, CCShare *pShare)
{
#ifdef UD_CC_INCLUDEDFS
	CMIterator shareLinkIter;
	CCShareLink *pShareLink;
	NQ_BOOL shareExists = FALSE;
#endif

	LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL, "Share: %s, pMount: %p", cmWDump((const NQ_WCHAR *)pShare->item.name), pMount);

#ifdef UD_CC_INCLUDEDFS
	if (NULL == pMount)
	{
		goto Exit;
	}

	/* first check if this share is already in this mounts list */
	cmListIteratorStart(&pMount->shareLinks, &shareLinkIter);

	while(cmListIteratorHasNext(&shareLinkIter))
	{
		pShareLink = (CCShareLink *)cmListIteratorNext(&shareLinkIter);
		if (pShare == pShareLink->pShare)
		{
			/* each connect the share is locked. if this share connect is related to this mount and lokced by this mount. one time is enough. */
			cmListItemUnlock((CMItem *)pShare);
			shareExists = TRUE;
			break;
		}
	}
	cmListIteratorTerminate(&shareLinkIter);

	if (FALSE == shareExists)
	{
		pShareLink = (CCShareLink *)cmListItemCreateAndAdd(&pMount->shareLinks, sizeof(CCShareLink), pShare->item.name, NULL,  CM_LISTITEM_NOLOCK);
		pShareLink->pShare = pShare;
	}

Exit:
#endif

	LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
}
#endif /* UD_NQ_INCLUDECIFSCLIENT */
