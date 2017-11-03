/*************************************************************************
 * Copyright 2011-2014 by Visuality Systems, Ltd.
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


#include "cmrepository.h"
#include "cmmemory.h"

NQ_BOOL cmRepositoryInit(
		CMRepository * pRepo,
		NQ_UINT16 flags,
		CMRepositoryItemInit doInit,
		CMRepositoryItemDispose doDispose
		)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "repo:%p flags:%d init:%p dispose:%p", pRepo, flags, doInit, doDispose);

    pRepo->isUsed = TRUE;
	pRepo->guard = NULL;
	pRepo->numOfAllocedItems = 0;
	pRepo->flags = flags;
	pRepo->doInit = doInit;
	pRepo->doDispose = doDispose;
	cmListStart(&pRepo->list);
	cmListStart(&pRepo->itemPool);
	if (TRUE)  /* should be flags & some flag for mutex */
	{
		pRepo->guard = (SYMutex *)cmMemoryAllocate(sizeof(SYMutex));
		syMutexCreate(pRepo->guard);
	}
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", TRUE ? "TRUE" : "FALSE");
	return TRUE;
}

NQ_BOOL cmRepositoryItemPoolAlloc(CMRepository * pRepo , NQ_UINT preallocateNum , NQ_UINT size)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "repo:%p num:%u size:%u", pRepo, preallocateNum, size);

	if (NULL != pRepo->guard)
		syMutexTake(pRepo->guard);
	pRepo->numOfItemsToAlloc = preallocateNum;
	pRepo->itemSize = size;
	while (pRepo->numOfAllocedItems < preallocateNum)
	{
		CMItem * pItem;

		pItem = cmListItemCreateAndAdd(&pRepo->itemPool, size + (NQ_UINT)sizeof(CMItem), NULL, NULL, CM_LISTITEM_NOLOCK);
		if (pRepo->doInit != NULL)
		{
			pRepo->doInit(pItem + 1);
		}
		pRepo->numOfAllocedItems++;
	}
	if (NULL != pRepo->guard)
		syMutexGive(pRepo->guard);

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", TRUE ? "TRUE" : "FALSE");
	return TRUE;
}

void cmRepositoryShutdown(CMRepository * pRepo)
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "repo:%p", pRepo);

    if (pRepo->isUsed)
	{
    	cmListShutdown(&pRepo->list);

		if (pRepo->doDispose != NULL)
		{
			CMIterator itr;

			cmListIteratorStart(&pRepo->itemPool, &itr);
			while (cmListIteratorHasNext(&itr))
			{
				CMItem *pItem = cmListIteratorNext(&itr);
				pRepo->doDispose(pItem + 1);
			}			
			cmListIteratorTerminate(&itr);
		}
		cmListShutdown(&pRepo->itemPool);

		if (pRepo->guard != NULL)
		{
			syMutexDelete(pRepo->guard);
			cmMemoryFree(pRepo->guard);
			pRepo->guard = NULL;
		}
	}

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}


NQ_BOOL cmRepositoryAddItem(CMRepository * pRepo , CMItem * pItem , NQ_BYTE * key , NQ_BOOL (*callback)(CMItem * pItem) )
{
	NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "repo:%p item:%p key:%p callback:%p",  pRepo, pItem, key, callback);
    if (!pRepo->isUsed)
	{
		goto Exit;
	}

	cmListItemAdd(&pRepo->list , pItem , callback);
	result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s", result ? "TRUE" : "FALSE");
	return result;
}

CMItem * cmRepositoryGetNewItem(CMRepository * pRepo)
{
    CMItem * pItem = NULL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "repo:%p", pRepo);

    if (!pRepo->isUsed)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Repository not in use");
		goto Exit;
	}

    if (NULL != pRepo->guard)	syMutexTake(pRepo->guard);

    if (pRepo->itemPool.last == NULL)
	{
		LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "Repository : adding new");
		/* TODO: fix this so that callback will not depend on first item in list*/
		pItem = cmListItemCreate(pRepo->itemSize + (NQ_UINT)sizeof(CMItem) ,NULL , CM_LISTITEM_NOLOCK);
		cmListItemAdd(&pRepo->list , pItem , NULL);
		if (pRepo->doInit != NULL)
			pRepo->doInit(pItem + 1);
	}
	else
	{
		pItem = pRepo->itemPool.last;
		cmListItemRemove(pItem);
		cmListItemAdd(&pRepo->list , pItem , pItem->callback);
		pRepo->numOfAllocedItems--;
	}
    if (NULL != pRepo->guard)	syMutexGive(pRepo->guard);

    if (NULL != pItem)
    	pItem++;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%p", pItem);
    return pItem;
}

NQ_BOOL cmRepositoryReleaseItem(CMRepository * pRepo, CMItem * pItem )
{
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "repo:%p item:%p", pRepo, pItem);

    if (!pRepo->isUsed)
	{
		LOGERR(CM_TRC_LEVEL_ERROR, "Repository not in use");
		goto Exit;
	}

	if (NULL != pRepo->guard)	syMutexTake(pRepo->guard);

	if ((pItem -1)->master != &pRepo->list)
	{
		if (NULL != pRepo->guard)	syMutexGive(pRepo->guard);
		LOGERR(CM_TRC_LEVEL_ERROR, "Not repository item");
		goto Exit;
	}

	if (pRepo->flags & CM_REPOSITORY_RELEASE_IMMEDIATELY)
	{
		cmListItemRemoveAndDispose(pItem - 1);
	}
	else
	{
		cmListItemRemove(pItem - 1);
		cmListItemAdd(&pRepo->itemPool, pItem - 1, NULL);
		pRepo->numOfAllocedItems++;
	}
	
	if (NULL != pRepo->guard)	syMutexGive(pRepo->guard);

    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%s:", result ? "TRUE" : "FALSE");
	return result;
}

void cmRepositoryIteratorStart(CMRepository * pRepo, CMIterator * iterator)
{
	CMList * pList = &pRepo->list;

	if (NULL != pRepo->guard)	syMutexTake(pRepo->guard);
	cmListIteratorStart(pList, iterator);
}

void cmRepositoryIteratorTerminate(CMRepository * pRepo, CMIterator * iterator)
{
	cmListIteratorTerminate(iterator);
	if (NULL != pRepo->guard)	syMutexGive(pRepo->guard);
}

CMItem * cmRepositoryIteratorNext(CMIterator * iterator)
{
	CMItem * pItem = cmListIteratorNext(iterator);
    return pItem + 1;
}
