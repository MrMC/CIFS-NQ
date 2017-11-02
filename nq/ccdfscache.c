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

static CMList pathCache;        /* DFS cache */
static CMList domainCache;      /* DFS cache */
static NQ_BOOL isCacheOn;       /* indicates whethe cache is maintained */

/* -- Local functions -- */

#if SY_DEBUGMODE

static void dumpOne(CMItem * pItem)
{
    CCDfsCacheEntry * pEntry = (CCDfsCacheEntry *)pItem;
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  DFS entry:: name: %s", cmWDump(pEntry->item.name));
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "              rootOrLink: %s", pEntry->isRoot ? "root" : "link");
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "              ttl: %d, numConsumed: %d", pEntry->ttl, pEntry->numPathConsumed);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "              referrals list:");
    cmListDump(pEntry->refList);
}

static void dumpCache(CMList *pList)
{
    CMIterator  iterator;
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    cmListIteratorStart(pList, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        dumpOne(cmListIteratorNext(&iterator));
    }
    cmListIteratorTerminate(&iterator);
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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pItem = cmListItemFind(list, path, TRUE , FALSE);
    if (NULL != pItem)
    {
        cmListItemDispose(pItem); /* disposal callback will be called */
    }

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

static CCDfsCacheEntry * addReferral(CMList * list, const NQ_WCHAR * path, const NQ_WCHAR * referral, NQ_UINT32 ttl, NQ_BOOL isRoot, NQ_UINT16 numPathConsumed)
{
    CCDfsCacheEntry * pEntry;
    CMItem * pItem;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

	/* find existing referral in cache (same path) */
    pItem = cmListItemFind(list, path, TRUE, FALSE);
    if (NULL == pItem)
    {
        TRC("not found, create new");
        pEntry = (CCDfsCacheEntry *)cmListItemCreate(sizeof(CCDfsCacheEntry), path , FALSE);
        if (NULL == pEntry)
        {
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
        pEntry->isRoot = isRoot;
        pEntry->ttl = ttl;
        pEntry->numPathConsumed = numPathConsumed;
#if SY_DEBUGMODE
        pEntry->item.dump = dumpOne;
#endif /* SY_DEBUGMODE */
        if (!cmListItemAdd(list, (CMItem *)pEntry, unlockCallback))
        {
            cmMemoryFree(pEntry);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
  
        pEntry->refList = cmMemoryAllocate(sizeof(CMList));
        if (NULL == pEntry->refList)
        {
            cmMemoryFree(pEntry->refList);
            cmMemoryFree(pEntry);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }      

        cmListStart(pEntry->refList);
        pItem = cmListItemCreate(sizeof(CMItem), referral, FALSE);
        if (NULL == pEntry)
        {
            unlockCallback((CMItem *)pEntry);
            cmMemoryFree(pEntry);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }      
        if (!cmListItemAdd(pEntry->refList, pItem, NULL))
        {
            cmMemoryFree(pItem);
            unlockCallback((CMItem *)pEntry);
            cmMemoryFree(pEntry);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
    }
    else
    {
        TRC("found, add into referrals");

        /* add additional referral into referrals list */
        pEntry = (CCDfsCacheEntry *)pItem;

        pItem = cmListItemCreate(sizeof(CMItem), referral, FALSE);
        if (NULL == pItem)
        {
            unlockCallback((CMItem *)pEntry);
            cmMemoryFree(pEntry);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }      
        if (!cmListItemAdd(pEntry->refList, pItem, NULL))
        {
            unlockCallback((CMItem *)pEntry);
            cmMemoryFree(pEntry);
            LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
            return NULL;
        }
    }
  
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pEntry;
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
    isCacheOn = TRUE;
    return TRUE;
}

void ccDfsCacheShutdown(void)
{
    CMIterator  itr;

    cmListIteratorStart(&pathCache, &itr);
    while (cmListIteratorHasNext(&itr))
    {
        CMItem *    pItem;

        pItem = cmListIteratorNext(&itr);
        cmListItemCheck(pItem);
    }
    cmListIteratorTerminate(&itr);

    cmListIteratorStart(&domainCache, &itr);
    while (cmListIteratorHasNext(&itr))
    {
        CMItem *    pItem;

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

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "FIND : %s", cmWDump((const NQ_WCHAR *)path));

    cmListIteratorStart(&pathCache, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        pEntryTemp = (CCDfsCacheEntry *)cmListIteratorNext(&iterator);
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, " entry: %s", cmWDump((const NQ_WCHAR *)pEntryTemp->item.name));

        /* looking for exact match or longest partial match using whole path components */
        if (0 == cmWStrncmp(pEntryTemp->item.name, path, cmWStrlen(pEntryTemp->item.name))) 
        {
            if (cmWStrlen(pEntryTemp->item.name) > maxEntryLength)
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
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pEntry;
}

void ccDfsCacheRemovePath(const NQ_WCHAR * path)
{
  removeReferral(&pathCache, path);
}

CCDfsCacheEntry * ccDfsCacheAddPath(const NQ_WCHAR * path, const NQ_WCHAR * referral, NQ_UINT32 ttl, NQ_BOOL isRoot, NQ_UINT16 numPathConsumed)
{
    CCDfsCacheEntry * pEntry; /* resulted entries */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pEntry = addReferral(&pathCache, path, referral, ttl, isRoot, numPathConsumed);
#if SY_DEBUGMODE
    dumpCache(&pathCache);
#endif 
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pEntry;
}

CCDfsCacheEntry * ccDfsCacheFindDomain(const NQ_WCHAR * domain)
{
    CCDfsCacheEntry * pEntry; /* resulted entries */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pEntry = (CCDfsCacheEntry *)cmListItemFind(&domainCache, domain, TRUE , FALSE);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pEntry;
}

void ccDfsCacheRemoveDomain(const NQ_WCHAR * domain)
{
  removeReferral(&domainCache, domain);
}

CCDfsCacheEntry * ccDfsCacheAddDomain(const NQ_WCHAR * domain, const NQ_WCHAR * host, NQ_UINT32 ttl)
{
    CCDfsCacheEntry * pEntry; /* resulted entries */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    pEntry = addReferral(&domainCache, domain, host, ttl, FALSE, 0);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
    return pEntry;
}

#endif /* UD_NQ_INCLUDECIFSCLIENT */

