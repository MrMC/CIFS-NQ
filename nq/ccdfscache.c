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

#include "ccdfscache.h"

#ifdef UD_NQ_INCLUDECIFSCLIENT

/* -- Static data -- */

#define CCDFSCACHE_CLEANUPTIMER 1800    /* in seconds, each such period of time cache is checked and cleaned
                                           30 minutes is Windows default referral TTL */

static CMList pathCache;                /* DFS cache */
static CMList domainCache;              /* DFS cache */
static NQ_BOOL isCacheOn;               /* indicates whether cache is maintained */
static NQ_UINT32 cacheTTL;              /* timer for cache cleanup, zeroed every CCDFSCACHE_CLEANUPTIMER of seconds */

/* -- Local functions -- */

#if SY_DEBUGMODE

static void dumpOne(CMItem * pItem)
{
    CMIterator iterator;
    CCDfsCacheEntry * pEntry = (CCDfsCacheEntry *)pItem;
    NQ_COUNT i = 0;

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  DFS entry:: name: %s", cmWDump(pEntry->item.name));
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "              rootOrLink: %s", pEntry->isRoot ? "root" : "link");
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "              ttl: %u, numConsumed: %d", pEntry->ttl, pEntry->numPathConsumed);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "              Referrals list::");
    /*cmListDump(pEntry->refList);*/

    cmListIteratorStart(pEntry->refList, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CCDfsReferral *ref = (CCDfsReferral *)cmListIteratorNext(&iterator);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  referral #%d:: name: %s", ++i, cmWDump(ref->item.name));
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "              isIOPerformed: %d", ref->isIOPerformed);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "              lastIOStatus: %d (0x%x)", ref->lastIOStatus, ref->lastIOStatus);
    }
    cmListIteratorTerminate(&iterator);
}

static void dumpCache(CMList *pList)
{
    CMIterator  iterator;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "list:%p", pList);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "DFS cache [%s] dump start:", pList->name);

    cmListIteratorStart(pList, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        dumpOne(cmListIteratorNext(&iterator));
    }
    cmListIteratorTerminate(&iterator);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "DFS cache dump end");
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}


#endif /* SY_DEBUGMODE */

/*
* Callback for DFS entry unlock and disposal:
*  - disposes private data
*/
static NQ_BOOL unlockCallback(CMItem * pItem)
{
    CCDfsCacheEntry * pEntry = (CCDfsCacheEntry *)pItem;

    cmListShutdown(pEntry->refList);
    cmMemoryFree(pEntry->refList);

    return FALSE;
}

static void removeReferral(CMList * list, const NQ_WCHAR * path)
{
    CMItem * pItem;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "list:%p path:%s", list, cmWDump(path));

    pItem = cmListItemFind(list, path, TRUE, FALSE);
    if (NULL != pItem)
    {
        cmListItemDispose(pItem); /* disposal callback will be called */
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static CCDfsCacheEntry * addReferral(CMList * list, const NQ_WCHAR * path, const CCDfsReferral * referral)
{
    CCDfsCacheEntry * pEntry = NULL;
    CCDfsCacheEntry * pResult = NULL;
    CMItem * pItem = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "list:%p path:%s referral:%p", list, cmWDump(path), referral);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "referral: %s", cmWDump(referral->netPath));

    /* find existing referral in cache (same path) */
    pItem = cmListItemFind(list, path, TRUE, FALSE);
    if (NULL == pItem)
    {
        CCDfsReferral * pRef = NULL;
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "not found, create new");
        pEntry = (CCDfsCacheEntry *)cmListItemCreate(sizeof(CCDfsCacheEntry), path, CM_LISTITEM_NOLOCK);
        if (NULL == pEntry)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Item was not created");
            goto Exit;
        }
        pEntry->isRoot = referral->serverType == DFS_ROOT_TARGET;
        pEntry->ttl = (NQ_UINT32)syGetTimeInSec() + referral->ttl;
        pEntry->numPathConsumed = referral->numPathConsumed;
        pEntry->lastIOStatus = NQ_ERR_ERROR;
#if SY_DEBUGMODE
        pEntry->item.dump = dumpOne;
#endif /* SY_DEBUGMODE */
        if (!cmListItemAdd(list, (CMItem *)pEntry, unlockCallback))
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Item was not added");
            goto Error1;
        }

        pEntry->refList = (CMList *)cmMemoryAllocate(sizeof(CMList));
        if (NULL == pEntry->refList)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            goto Error1;
        }

        cmListStart(pEntry->refList);
        pItem = cmListItemCreate(sizeof(CCDfsReferral), referral->netPath, CM_LISTITEM_NOLOCK);
        if (NULL == pItem)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Item was not created");
            goto Error2;
        }
        if (!cmListItemAdd(pEntry->refList, pItem, NULL))
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Item was not added");
            goto Error3;
        }
        pRef = (CCDfsReferral *)pItem;
        pRef->isConnected = FALSE;
        pRef->isIOPerformed = FALSE;
        pRef->lastIOStatus = NQ_SUCCESS;
        pRef->serverType = 0;
        pRef->flags = 0;
        pRef->ttl = (NQ_UINT32)syGetTimeInSec() + referral->ttl;
        pRef->isConnected = 0;
        pRef->netPath = referral->netPath;
        pRef->dfsPath = (NQ_WCHAR *)path;
    }
    else
    {
        CCDfsReferral * pRef = NULL;

        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "found");

        /* add additional referral into referrals list */
        pEntry = (CCDfsCacheEntry *)pItem;

        /* do not add additional referral if it points to itself */
        if (cmWStricmp(pEntry->item.name, referral->netPath) != 0)
        {
            /* do not add double referrals */
            if (NULL == cmListItemFind(pEntry->refList, referral->netPath, TRUE, FALSE))
            {
                pItem = cmListItemCreate(sizeof(CCDfsReferral), referral->netPath, CM_LISTITEM_NOLOCK);
                if (NULL == pItem)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Item was not created");
                    goto Exit;
                }
                if (!cmListItemAdd(pEntry->refList, pItem, NULL))
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "Item was not added");
                    goto Error4;
                }
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "added into referrals list");

                /* update entry's ttl to a new one */
                pEntry->ttl = (NQ_UINT32)syGetTimeInSec() + referral->ttl;

                pRef = (CCDfsReferral *)pItem;
                pRef->isConnected = FALSE;
                pRef->isIOPerformed = FALSE;
                pRef->lastIOStatus = NQ_SUCCESS;
                pRef->serverType = 0;
                pRef->flags = 0;
                pRef->ttl = (NQ_UINT32)syGetTimeInSec() + referral->ttl;
                pRef->isConnected = 0;
                pRef->netPath = referral->netPath;
                pRef->dfsPath = (NQ_WCHAR *)path;
            }
        }
    }
    pResult = pEntry;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pResult);
    return pResult;

Error4:
    cmMemoryFree(pItem);
    goto Exit;

Error3:
    cmMemoryFree(pItem);

Error2:
    unlockCallback((CMItem *)pEntry);

Error1:
    cmMemoryFree(pEntry);
    goto Exit;
}

static void cleanCache(CMList *pCache)
{
    NQ_UINT32 timeNow = (NQ_UINT32)syGetTimeInSec();
    CMIterator iterator;
    CCDfsCacheEntry *pEntry;
    NQ_COUNT removed = 0;
        
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "pCache:%p cacheTTL:%u timeNow:%u", pCache, cacheTTL, timeNow);

    if (cacheTTL < timeNow)
    {
        cmListIteratorStart(pCache, &iterator);
        while (cmListIteratorHasNext(&iterator))
        {
            pEntry = (CCDfsCacheEntry *)cmListIteratorNext(&iterator);
            if (pEntry->ttl > timeNow)
            {
                removed++;
                cmListItemCheck((CMItem *)pEntry);
                cmListItemRemoveAndDispose((CMItem *)pEntry);
            }
            else
            {
                /* in ref list still can be entries with old TTL */
                CMIterator iter;

                cmListIteratorStart(pEntry->refList, &iter);
                while (cmListIteratorHasNext(&iter))
                {
                    CCDfsReferral *ref = (CCDfsReferral *)cmListIteratorNext(&iter);

                    if (ref->ttl > timeNow)
                    {
                        removed++;
                        cmListItemRemoveAndDispose((CMItem *)ref);
                    }
                }
                cmListIteratorTerminate(&iter);
            }
        }
        cmListIteratorTerminate(&iterator);

        cacheTTL = (NQ_UINT32)syGetTimeInSec() + CCDFSCACHE_CLEANUPTIMER;
    }

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "removed %d entries", removed);
}

/* -- API Functions */

NQ_BOOL ccDfsCacheStart(void)
{
    cmListStart(&pathCache);
    cmListStart(&domainCache);
#if SY_DEBUGMODE
    pathCache.name = "pathCache";
    domainCache.name = "domainCache";
#endif
    cacheTTL = (NQ_UINT32)syGetTimeInSec() + CCDFSCACHE_CLEANUPTIMER;
    isCacheOn = TRUE;
    return TRUE;
}

void ccDfsCacheShutdown(void)
{
    CMIterator  itr;

    cmListIteratorStart(&pathCache, &itr);
    while (cmListIteratorHasNext(&itr))
    {
        CMItem * pItem;

        pItem = cmListIteratorNext(&itr);
        cmListItemCheck(pItem);
    }
    cmListIteratorTerminate(&itr);

    cmListIteratorStart(&domainCache, &itr);
    while (cmListIteratorHasNext(&itr))
    {
        CMItem * pItem;

        pItem = cmListIteratorNext(&itr);
        cmListItemCheck(pItem);
    }
    cmListIteratorTerminate(&itr);

    cmListShutdown(&pathCache);
    cmListShutdown(&domainCache);
    isCacheOn = FALSE;
}

NQ_BOOL ccDfsIsCacheOn(void)
{
    return isCacheOn;
}

CCDfsCacheEntry * ccDfsCacheFindPath(const NQ_WCHAR * path)
{
    CCDfsCacheEntry     *pEntryTemp;            /* for iterating entries */
    CMIterator          iterator;               /* list iterator */
    CCDfsCacheEntry     *pEntry = NULL;         /* entry candidate */
    NQ_COUNT            maxEntryLength = 0;     /* max entry length  */
    NQ_UINT32           timeNow = (NQ_UINT32)syGetTimeInSec();

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "path:%s", cmWDump(path));
#if SY_DEBUGMODE
    dumpCache(&pathCache);
#endif
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "FIND : %s", cmWDump((const NQ_WCHAR *)path));*/

    cmListIteratorStart(&pathCache, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        pEntryTemp = (CCDfsCacheEntry *)cmListIteratorNext(&iterator);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " entry: %s", cmWDump((const NQ_WCHAR *)pEntryTemp->item.name));

        /* looking for exact match or longest partial match using whole path components */
        if (0 == cmWStrncmp(pEntryTemp->item.name, path, cmWStrlen(pEntryTemp->item.name)))
        {
            if ((timeNow < pEntryTemp->ttl) && (cmWStrlen(pEntryTemp->item.name) > maxEntryLength))
            {
                maxEntryLength = cmWStrlen(pEntryTemp->item.name);
                pEntry = pEntryTemp;
            }
        }
    }
    cmListIteratorTerminate(&iterator);

    if (pEntry)
    {
        pEntry->isExactMatch = (cmWStrlen(path) == cmWStrlen(pEntry->item.name));
    }
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "%s match: %s", pEntry && pEntry->isExactMatch ? "exact" : "best", pEntry ? cmWDump((const NQ_WCHAR *)pEntry->item.name) : "null");
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pEntry);
    return pEntry;
}

void ccDfsCacheRemovePath(const NQ_WCHAR * path)
{
    removeReferral(&pathCache, path);
}

CCDfsCacheEntry * ccDfsCacheAddPath(const NQ_WCHAR * path, const CCDfsReferral * referral)
{
    CCDfsCacheEntry * pEntry; /* resulted entries */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "path:%s referral:%p", cmWDump(path), referral);

    cleanCache(&pathCache);
    pEntry = addReferral(&pathCache, path, referral);
#if SY_DEBUGMODE
    dumpCache(&pathCache);
#endif
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pEntry);
    return pEntry;
}

CCDfsCacheEntry * ccDfsCacheFindDomain(const NQ_WCHAR * domain)
{
    CCDfsCacheEntry * pEntry; /* resulted entries */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s", cmWDump(domain));
#if SY_DEBUGMODE
    dumpCache(&domainCache);
#endif
    pEntry = (CCDfsCacheEntry *)cmListItemFind(&domainCache, domain, TRUE, FALSE);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pEntry);
    return pEntry;
}

void ccDfsCacheRemoveDomain(const NQ_WCHAR * domain)
{
    removeReferral(&domainCache, domain);
}

CCDfsCacheEntry * ccDfsCacheAddDomain(const NQ_WCHAR * domain, const NQ_WCHAR * host, NQ_UINT32 ttl)
{
    CCDfsReferral ref;
    CCDfsCacheEntry * pEntry = NULL; /* resulted entries */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "domain:%s host:%s ttl:%u", cmWDump(domain), cmWDump(host), ttl);

    ref.ttl = ttl;
    ref.netPath = cmMemoryCloneWString(host);
    ref.serverType = DFS_ROOT_TARGET;
    ref.numPathConsumed = 0;
    if (NULL == ref.netPath)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
        goto Exit;
    }

    pEntry = addReferral(&domainCache, domain, &ref);
    cmMemoryFree(ref.netPath);

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pEntry);
    return pEntry;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */
