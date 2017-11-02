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
#ifdef UD_NQ_INCLUDETRACE
    CCMount * pMount = (CCMount *)pItem;
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  Mount:: path: %s server %p share %p", cmWDump(pMount->path), pMount->server, pMount->share);
#endif /* UD_NQ_INCLUDETRACE */
}
#endif /* SY_DEBUGMODE */

/*
 * Explicitely dispose mount point:
 * 	- disconnects from the server
 *  - disposes private data  
 */
static void disposeMount(CCMount * pMount)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "About to dispose mount %s", cmWDump(pMount->item.name));

    if (NULL!= pMount->credentials)
            cmMemoryFree(pMount->credentials);
    if (NULL!= pMount->path)
        cmMemoryFree(pMount->path);
    cmListItemRemoveAndDispose((CMItem *)pMount);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 * Callback for share unlock and disposal:
 * 	- disconnects from the share
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

    length = (NQ_INT)cmWStrlen(name);
    
    /* check length */
    if ((length < 2) || (length >= MOUNTNTPATH_SIZE) || (name[0] != cmWChar('\\')))
        return FALSE;

    /* skip the first character */
    name++;

    for (i = 0; i < sizeof(illegal)/sizeof(NQ_WCHAR); i++)
        if (cmWStrchr(name, illegal[i]) != NULL)
            return FALSE;

    return TRUE;
}

/*
 * Check remote path
 */

static NQ_BOOL isValidRemotePathName(const NQ_WCHAR * name)
{
    NQ_COUNT i; 
    const NQ_WCHAR * p;   

    if (!name || cmWStrlen(name) >= SHAREPATH_SIZE)
        return FALSE;
    
    for (i = 0, p = name; *p != cmWChar('\0'); p++)
    {
        if (*p == cmWChar('\\'))
            i++;
    }
    return (i == 3);      
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
    NQ_WCHAR * wPoint;
    NQ_WCHAR * wPath;
    NQ_INT res;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    wPoint = cmMemoryCloneAString(mountPoint);
    wPath = cmMemoryCloneAString(remotePath);
    if (NULL == wPoint || NULL == wPath)
    {
        cmMemoryFree(wPoint);   /* handles NULL */
        cmMemoryFree(wPath);    /* handles NULL */
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return NQ_FAIL;
    }
    res = nqAddMountW(wPoint, wPath, connect);
    cmMemoryFree(wPoint);
    cmMemoryFree(wPath);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return res;
}

NQ_INT nqAddMountW(const NQ_WCHAR * mountPoint, const NQ_WCHAR * remotePath, NQ_BOOL connect)
{
    CCMount * pMount;       /* pointer to mount */
    CCShare * pShare;       /* pointer to share */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    if (!isValidMountPointName(mountPoint))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal mount point name: %s", cmWDump(mountPoint));
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return NQ_FAIL;
    }

    if (!isValidRemotePathName(remotePath))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Illegal share path: %s", cmWDump(remotePath));
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return NQ_FAIL;
    }
    pMount = (CCMount *)cmListItemFind(&mounts, mountPoint + 1, TRUE , TRUE);
    if (NULL != pMount)
    {
        cmListItemUnlock((CMItem *)pMount);
        LOGERR(CM_TRC_LEVEL_ERROR, "Duplicate mount point");
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return NQ_FAIL;
    }
    pMount = (CCMount *)cmListItemCreateAndAdd(&mounts, sizeof(CCMount), mountPoint + 1, unlockCallback, TRUE);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return NQ_FAIL;
    }
    pMount->path = cmMemoryCloneWString(remotePath);
    if (NULL == pMount->path)
    {
        cmListItemUnlock((CMItem *)pMount);
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return NQ_FAIL;
    }
    cmWStrupr(pMount->path);
    pMount->credentials = NULL; /* will be set later */
    pShare = ccShareConnect(pMount->path, &pMount->credentials, TRUE);
    if (NULL == pShare)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to connect");
        cmListItemUnlock((CMItem *)pMount);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return NQ_FAIL;
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
    
#if SY_DEBUGMODE
    pMount->item.dump = dumpOne; 
#endif /* SY_DEBUGMODE */        
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return NQ_SUCCESS;
}

NQ_INT nqRemoveMountA(const NQ_CHAR * mountPoint)
{
    NQ_WCHAR * pointW;	/* mount pint in Unicode */
    NQ_INT res;			/* Unicode operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    pointW = cmMemoryCloneAString(mountPoint);
    if (NULL == pointW)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return NQ_FAIL;
    }
    res = nqRemoveMountW(pointW);
    cmMemoryFree(pointW);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return res;
}

NQ_INT nqRemoveMountW(const NQ_WCHAR * mountPoint)
{
    CCMount * pMount;       /* mount point pointer */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    pMount = (CCMount *)cmListItemFind(&mounts, mountPoint + 1, TRUE , FALSE); /*no need to lock*/
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Mount point not found");
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return NQ_FAIL;
    }
    cmListItemUnlock((CMItem *)pMount);               
    
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return NQ_SUCCESS;
}

CCMount * ccMountFind(const NQ_WCHAR * path)
{
    CCMount * pMount;           /* mount point pointer */
    const NQ_WCHAR * mpName;    /* mount point name */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    mpName = ccUtilsMountPointFromLocalPath(path);
    if (NULL == mpName)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    pMount = (CCMount *)cmListItemFind(&mounts, mpName, TRUE , TRUE);
    cmMemoryFree(mpName);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Mount point not found");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    if (NULL == pMount->server || NULL == pMount->share)
    {
        cmListItemUnlock((CMItem *)pMount);
        LOGERR(CM_TRC_LEVEL_ERROR, "Mount point not connected");
        LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
        return NULL;
    }
    cmListItemUnlock((CMItem *)pMount);
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pMount;
}

NQ_BOOL ccResetCredentailsA(const NQ_CHAR * mountPoint)
{
    NQ_WCHAR * pointW;	/* mount pint in Unicode */
    NQ_BOOL res;		/* Unicode operation result */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    pointW = cmMemoryCloneAString(mountPoint);
    if (NULL == pointW)
    {
        sySetLastError(NQ_ERR_OUTOFMEMORY);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return NQ_FAIL;
    }
    res = ccResetCredentailsW(pointW);
    cmMemoryFree(pointW);

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return res;
}

NQ_BOOL ccResetCredentailsW(const NQ_WCHAR * mountPoint)
{
    CCMount * pMount;       /* mount point pointer */
    CCUser * pUser;         /* user structure pointer */
    CMIterator iServer;     /* servers iterator */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    pMount = (CCMount *)cmListItemFind(&mounts, mountPoint + 1, TRUE , TRUE);
    if (NULL == pMount)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Mount point not found");
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return FALSE;
    }
    if (NULL == pMount->share)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Mount point not connected to share");
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return FALSE;
    }
    pUser = pMount->share->user;
    if (NULL == pUser)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Associated share is not connected");
        sySetLastError(NQ_ERR_BADPARAM);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return FALSE;
    }
    pMount->credentials = NULL;
    cmListItemUnlock((CMItem *)pMount);
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

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return TRUE;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
