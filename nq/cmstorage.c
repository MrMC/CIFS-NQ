/*************************************************************************
* Copyright 2011-2016 by Visuality Systems, Ltd.
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

#include "cmstorage.h"

static NQ_BOOL storageListEnlarge(CMStorageData * pData)
{
    CMStorageList *	pList = NULL;
    NQ_BYTE	* pTemp = NULL;
    NQ_UINT32 i = 0;
    NQ_UINT32 newNumOfLists = 0;
    NQ_BOOL result = FALSE;

    pTemp = (NQ_BYTE *)cmMemoryAllocate((NQ_UINT)(pData->numOfLists * sizeof(CMStorageList)));
    if (NULL == pTemp)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memoroy");
        goto Exit;
    }

    syMemcpy(pTemp, pData->list, pData->numOfLists * sizeof(CMStorageList));
    cmMemoryFree(pData->list);

    newNumOfLists = 2 * pData->numOfLists;
    pData->list = (CMStorageList *)cmMemoryAllocate((NQ_UINT)(newNumOfLists * sizeof(CMStorageList)));
    if (NULL == pData->list)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memoroy");
        goto Exit;
    }

    syMemcpy(pData->list, pTemp, pData->numOfLists * sizeof(CMStorageList));

    for (i = pData->numOfLists; i < newNumOfLists; i++)
    {
        NQ_UINT32	j = 0;
        CMStorageItem	*	pItem;

        pList = &pData->list[i];
        pList->items = cmMemoryAllocate((NQ_UINT)(pData->numOfListItems * pData->itemSize));
        if (NULL == pList->items)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
            goto Exit;
        }

        pItem = (CMStorageItem *)pList->items;
        pList->freeItems = pItem;
        syMutexCreate(&pList->guard);
        for (j = 0; j < pData->numOfListItems; j++)
        {
            pItem->itemIndex.high = i;
            pItem->itemIndex.low = j + 1;
            pItem->isUsed = FALSE;
            pItem->isFindable = FALSE;
            if (j < pData->numOfListItems - 1)
                pItem->next = (CMStorageItem *)((NQ_BYTE *)pItem + pData->itemSize);
            else
            {
                pItem->next = NULL;
                pList->lastFreeItems = pItem;
            }

            pItem = (CMStorageItem *)((NQ_BYTE *)pItem + pData->itemSize);
        }
        pList->index = i;
    }
    pData->numOfLists = newNumOfLists;
    result = TRUE;

Exit:
    cmMemoryFree(pTemp);
    return result;
}


NQ_BOOL cmStorageListInit(CMStorageData * pData, NQ_UINT itemSize, NQ_UINT numOfLists, NQ_UINT numOfListItems)
{
    NQ_UINT32 i = 0;
    CMStorageList *	pList = NULL;
    NQ_BOOL result = FALSE;

    syMutexCreate(&pData->guard);
    pData->itemSize = itemSize;
    pData->numOfUsedItems = 0;
    pData->list = (CMStorageList *)cmMemoryAllocate((NQ_UINT)(numOfLists * sizeof(CMStorageList)));
    if (pData->list == NULL)
        goto Exit;

    pData->numOfLists = numOfLists;
    for (i = 0; i < numOfLists; i++)
    {
        CMStorageItem	*	pItem;
        NQ_UINT32	j = 0;

        pList = &pData->list[i];
        pList->items = cmMemoryAllocate(numOfListItems * pData->itemSize);
        if (pList->items == NULL)
            goto Exit;

        pItem = (CMStorageItem *)pList->items;
        pList->freeItems = pItem;
        pList->usedItems = 0;
        syMutexCreate(&pList->guard);
        pData->numOfListItems = numOfListItems;
        for (j = 0; j < numOfListItems; j++)
        {
            pItem->itemIndex.high = i;
            pItem->itemIndex.low = j + 1;
            pItem->isUsed = FALSE;
            pItem->isFindable = FALSE;
            if (j < numOfListItems - 1)
                pItem->next = (CMStorageItem *)((NQ_BYTE *)pItem + pData->itemSize);
            else
            {
                pItem->next = NULL;
                pList->lastFreeItems = pItem;
            }

            pItem = (CMStorageItem *)((NQ_BYTE *)pItem + pData->itemSize);
        }
        pList->index = i;
    }

    result = TRUE;

Exit:
    return result;
}

CMStorageItem * cmStorageItemGetNew(CMStorageData * pData, NQ_INT condition)
{
    CMStorageItem * pItem = NULL;
    CMStorageItem * pResult = NULL;
    CMStorageList *	pList = NULL;
    NQ_BOOL			limit = condition & STORAGE_IS_TREE;
    NQ_UINT			i;

    syMutexTake(&pData->guard);
    if (limit ? condition - STORAGE_IS_TREE == STORAGE_IS_LIMITED : condition == STORAGE_IS_LIMITED)
    {
        pList = &pData->list[0];

        if (pList->freeItems == NULL || pList->usedItems == 0xFFFD)
        {
            goto Error;
        }

        goto Exit;
    }

    for (i = 1; i < pData->numOfLists; i++)
    {
        pList = &pData->list[i];
        if (pList->freeItems != NULL)
        {
            if (limit && i >= 0xFFFD)
            {
                goto Error;
            }
            goto Exit;
        }
    }

    if (limit && pData->numOfLists >= 0xFFFD)
    {
        goto Error;
    }

    i = pData->numOfLists;
    if (storageListEnlarge(pData))
    {
        pList = &pData->list[i];
        if (pList->freeItems != NULL)
        {
            goto Exit;
        }
    }
    goto Error;

Exit:
    pItem = (CMStorageItem *)pList->freeItems;
    syMutexTake(&pList->guard);
    if (pList->freeItems != NULL)
    {
        pList->freeItems = pItem->next;
        if (NULL == pList->freeItems)
        	pList->lastFreeItems = NULL;
    }
    pList->usedItems++;
    if (NULL != pItem)
    {
        pItem->isUsed = TRUE;
        pItem->isFindable = TRUE;
    }
    syMutexGive(&pList->guard);
    pData->numOfUsedItems++;
    pResult = pItem;

Error:
    syMutexGive(&pData->guard);
    return pResult;
}

CMStorageItem * cmStorageItemFind(CMStorageData * pData, NQ_UINT row, NQ_UINT cell, NQ_BOOL isFindAll)
{
    CMStorageList * pList = NULL;
    CMStorageItem *	pItem = NULL;

    cell--;
    syMutexTake(&pData->guard);

    if (row < pData->numOfLists && cell < pData->numOfListItems)
    {
        pList = &pData->list[row];
        pItem = (CMStorageItem *)((NQ_BYTE *)pList->items + (pData->itemSize * cell));
        pItem = ((pItem->isUsed && (isFindAll || pItem->isFindable)) ? pItem : NULL);
    }

    syMutexGive(&pData->guard);
    return pItem;

}

void cmStorageItemRemove(CMStorageData * pData, NQ_UINT row, NQ_UINT cell)
{
    CMStorageList *	pList = NULL;
    CMStorageItem * pItem = NULL;

    cell--;
    if (row < pData->numOfLists && cell < pData->numOfListItems)
    {
        syMutexTake(&pData->guard);
        pList = &pData->list[row];
        pItem = (CMStorageItem *)((NQ_BYTE *)pList->items + (pData->itemSize * cell));
        if (pItem->isUsed)
        {
        	CMStorageItem * pTmpItem;

            pItem->isUsed = FALSE;
            pItem->isFindable = FALSE;
            pTmpItem = (CMStorageItem *)pList->lastFreeItems;
            syMutexTake(&pList->guard);
            if (NULL == pTmpItem)
            {
            	pList->freeItems = pList->lastFreeItems = pItem;
            }
            else
            	pList->lastFreeItems = pTmpItem->next = pItem;
            pItem->next = NULL;

            if (pList->usedItems != 0)
                pList->usedItems--;
            syMutexGive(&pList->guard);
            pData->numOfUsedItems--;
        }
        syMutexGive(&pData->guard);
    }
}

void cmStorageListShutdown(CMStorageData * pData)
{
    NQ_UINT	i = 0;

    for (i = 0; i < pData->numOfLists; i++)
    {
        syMutexDelete(&pData->list[i].guard);
        cmMemoryFree(pData->list[i].items);
        pData->list[i].items = NULL;
    }
    cmMemoryFree(pData->list);
    syMutexDelete(&pData->guard);
    pData->list = NULL;

    return;
}

void cmStorageIteratorStart(CMStorageData * pData, CMStorageIterator * Itr)
{
    syMutexTake(&Itr->itrGuard);
    syMutexTake(&pData->guard);
    Itr->pData = pData;
    Itr->listNumber = 0;
    Itr->itemNumber = 0;
}

CMStorageItem * cmStorageIteratorNext(CMStorageIterator * Itr)
{
    CMStorageItem * pItem = NULL;

    if (Itr->pData != NULL)
    {
        if (Itr->listNumber < Itr->pData->numOfLists)
        {
            if (Itr->itemNumber < Itr->pData->numOfListItems)
            {
                pItem = (CMStorageItem *)((NQ_BYTE *)Itr->pData->list[Itr->listNumber].items + Itr->pData->itemSize * Itr->itemNumber);
                Itr->itemNumber++;
                if (Itr->itemNumber == Itr->pData->numOfListItems)
                {
                    Itr->listNumber++;
                    Itr->itemNumber = 0;
                }
                goto Exit;
            }
        }
    }

Exit:
    return pItem;
}

NQ_BOOL cmStorageIteratorHasNext(CMStorageIterator * Itr)
{
    NQ_BOOL result = FALSE;

    if (Itr->pData != NULL && Itr->pData->numOfUsedItems > 0)
    {
        if (Itr->listNumber < Itr->pData->numOfLists && Itr->itemNumber <= Itr->pData->numOfListItems)
        {
            CMStorageList	*	pList;

            pList = &Itr->pData->list[Itr->listNumber];
            if (pList->usedItems != 0)
            {
                while (Itr->itemNumber < Itr->pData->numOfListItems)
                {
                    CMStorageItem * pItem = NULL;

                    pItem = (CMStorageItem *)((NQ_BYTE *)Itr->pData->list[Itr->listNumber].items + Itr->pData->itemSize * Itr->itemNumber);
                    if (pItem->isUsed && pItem->isFindable)
                    {
                        result = TRUE;
                        goto Exit;
                    }
                    Itr->itemNumber++;
                }
                Itr->itemNumber = 0;
                Itr->listNumber++;
                pList = &Itr->pData->list[Itr->listNumber];
            }

            while (Itr->listNumber < Itr->pData->numOfLists && pList->usedItems == 0)
            {
                Itr->itemNumber = 0;
                Itr->listNumber++;
                pList = &Itr->pData->list[Itr->listNumber];
            }

            if (Itr->listNumber < Itr->pData->numOfLists && pList->usedItems != 0)
            {
                while (Itr->itemNumber < Itr->pData->numOfListItems)
                {
                    CMStorageItem * pItem = NULL;

                    pItem = (CMStorageItem *)((NQ_BYTE *)Itr->pData->list[Itr->listNumber].items + Itr->pData->itemSize * Itr->itemNumber);
                    if (pItem->isUsed && pItem->isFindable)
                    {
                        result = TRUE;
                        goto Exit;
                    }
                    Itr->itemNumber++;
                }
            }
        }
    }

Exit:
    return result;
}

void cmStorageIteratorTerminate(CMStorageIterator * Itr)
{
    if (Itr->pData != NULL)
    {
        syMutexGive(&Itr->pData->guard);
        Itr->pData = NULL;
        Itr->listNumber = 0;
        Itr->itemNumber = 0;
        syMutexGive(&Itr->itrGuard);
    }
}

NQ_BOOL cmStorageHashListStart(CMStorageHashList * pHList, CMStorageHashFunction doHash)
{
    NQ_UINT32	i;

    for (i = 0; i < HASH_N; i++)
        cmListStart(&pHList->list[i]);

    pHList->doHash = doHash;
    pHList->isUsed = TRUE;

    return TRUE;
}

CMList * cmStorageHashFindList(CMStorageHashList * pHList, const void * value)
{
    NQ_UINT32 hashedV = 0;
    CMList * pResult = NULL;

    if (pHList->isUsed)
    {
        hashedV = pHList->doHash(value);
        pResult = &pHList->list[hashedV];
    }

    return pResult;
}

void cmStorageHashListShutdown(CMStorageHashList * pHList)
{
    NQ_UINT32	i;
    CMIterator iterator;

    if (pHList->isUsed)
    {
        for (i = 0; i < HASH_N; i++)
        {
            cmListIteratorStart(&pHList->list[i], &iterator);
            while (cmListIteratorHasNext(&iterator))
            {
                CMItem	*	pSItem = NULL;

                pSItem = cmListIteratorNext(&iterator);
                cmMemoryFree(pSItem->name);
                pSItem->name = NULL;
                cmListItemRemove(pSItem);
            }
            cmListIteratorTerminate(&iterator);
            syMutexDelete(&pHList->list[i].guard);
        }
        pHList->doHash = NULL;
        pHList->isUsed = FALSE;
    }
}

void cmStorageHashListDispose(CMStorageHashList * pHList)
{
    NQ_UINT32	i;
    CMIterator iterator;

    if (pHList->isUsed)
    {
        for (i = 0; i < HASH_N; i++)
        {
            cmListIteratorStart(&pHList->list[i], &iterator);
            while (cmListIteratorHasNext(&iterator))
            {
                CMItem	*pSItem = cmListIteratorNext(&iterator);
                cmListItemRemoveAndDispose(pSItem);
            }
            cmListIteratorTerminate(&iterator);
            syMutexDelete(&pHList->list[i].guard);
        }
        pHList->doHash = NULL;
        pHList->isUsed = FALSE;
    }
}


NQ_UINT32 cmStorageNameHash(const void * name)
{
    const NQ_WCHAR	*	pName = (const NQ_WCHAR *)name;
    const NQ_UINT32 prime = 0x01000193; /*   16777619*/
    const NQ_UINT32 seed = 0x811C9DC5; /* 2166136261*/
    NQ_UINT32 hash = seed;
    NQ_UINT32 numBytes;

#ifdef NQ_DEBUG
    syAssert(pName);
#endif /* NQ_DEBUG */
    numBytes = cmWStrlen(pName);

    while (numBytes--)
        hash = pName[numBytes] ^ hash * prime;

    return hash % HASH_N;
    /*return (NQ_UINT32)((pName[0] + pName[cmWStrlen(pName)] + pName[cmWStrlen(pName)/2 -1]) % HASH_N); - old hash*/
}
