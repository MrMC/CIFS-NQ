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

#include "cmlist.h"
#include "cmmemory.h"

/* -- API functions -- */

void cmListStart(CMList * pList)
{
#if SY_DEBUGMODE
    pList->name = "";
#endif
    pList->first = pList->last = NULL;
    syMutexCreate(&pList->guard);
    pList->isUsed = TRUE;
}

void cmListShutdown(CMList * pList)
{
    cmListRemoveAndDisposeAll(pList);
    syMutexDelete(&pList->guard);
    pList->isUsed = FALSE;
}


void cmListRemoveAndDisposeAll(CMList * pList)
{
    while (NULL != pList->first)
    {
        if (!cmListItemRemoveAndDispose(pList->first))
            break;
    }
}

NQ_BOOL cmListItemAdd(CMList * pList, CMItem * pItem, NQ_BOOL (*callback)(CMItem * pItem))
{
    /* item can be NULL */
    if (NULL == pItem || !pList->isUsed)
        return FALSE;

    /* we protect the list but we do not protect the item since it cannot 
    * be found until it is inside the list
    */
    syMutexTake(&pList->guard);

    /* adding to the end of list */
    if (NULL == pList->last)
    {
        pList->first = pList->last = pItem;
        pItem->prev = NULL;
    }
    else
    {
        pList->last->next = pItem;
        pItem->prev = pList->last;
        pList->last = pItem;
    }
    pItem->master = pList;
    pItem->callback = callback;
    pItem->next = NULL;
    pItem->beingDisposed = FALSE;
    pItem->findable = TRUE;
    syMutexGive(&pList->guard);
    return TRUE;
}

CMItem * cmListItemCreate(NQ_UINT size, const NQ_WCHAR * name , NQ_BOOL lock)
{
    CMItem * pItem;

    LOGFB(CM_TRC_LEVEL_CMLIST);
    LOGMSG(CM_TRC_LEVEL_CMLIST, "Create item: %s, lock: %s", name ? cmWDump(name) : "", lock ? "yes" : "no");
    
    pItem = (CMItem *)cmMemoryAllocate(size);
    if (NULL != pItem)
    {
        if (NULL != name)
        {
            pItem->name = cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(name) + 1)));
            if (NULL != pItem->name)
            {
                cmWStrcpy(pItem->name, name);
            }
        }
        else
        {
            pItem->name = NULL;
        }
        
        syMutexCreate(&pItem->guard);
        pItem->locks = 0;
        if (lock)
        {
            cmListItemLock(pItem);
        }
        pItem->isStatic = FALSE;
        cmListStart(&pItem->references);
    }
    LOGFE(CM_TRC_LEVEL_CMLIST);
    return pItem;
}
   
CMItem * cmListItemCreateAndAdd(CMList * pList, NQ_UINT size, const NQ_WCHAR * name, NQ_BOOL (*callback)(CMItem * pItem) , NQ_BOOL lock)
{
    CMItem * pItem;

    pItem = cmListItemCreate(size, name , lock);
    if (NULL != pItem)
    {
        if (!cmListItemAdd(pList, pItem, callback))
        {
            cmListItemDispose(pItem);
            pItem = NULL;
        }
    }
    return pItem;
}

NQ_BOOL cmListItemRemove(CMItem * pItem)
{
    CMList * pList;
    
    LOGFB(CM_TRC_LEVEL_CMLIST);
    LOGMSG(CM_TRC_LEVEL_CMLIST, "Remove item: %s", pItem->name ? cmWDump(pItem->name) : "");

    if (0 != pItem->locks)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to remove locked item: %p, lock=%d, name:%s", pItem, pItem->locks, pItem->name ? cmWDump(pItem->name) : "");
        LOGFE(CM_TRC_LEVEL_CMLIST);
        return FALSE;
    }
    pList = pItem->master;
    
    if (NULL == pList || !pList->isUsed)
    {
        LOGFE(CM_TRC_LEVEL_CMLIST);
        return FALSE; /* may be normal for nested removal */
    }
    
    /* we protect the list but we do not protect the item since we do 
    * not modify its contents 
    */
    syMutexTake(&pList->guard);
    if (NULL == pItem->prev)  /* first in the list */
    {
#if SY_DEBUGMODE
        if (pItem != pList->first)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Corrupted list or item: first: %p, expected: %p", pList->first, pItem);
            syMutexGive(&pList->guard);
            LOGFE(CM_TRC_LEVEL_CMLIST);
            return FALSE;
        }
#endif /* SY_DEBUGMODE */
        pList->first = pItem->next;
    }
    else
    {
        pItem->prev->next = pItem->next;
    }
    if (NULL == pItem->next)  /* last in the list */
    {
        pList->last = pItem->prev;
    }
    else
    {
        pItem->next->prev = pItem->prev;
    }
    pItem->master = NULL;
    syMutexGive(&pList->guard);
    LOGFE(CM_TRC_LEVEL_CMLIST);
    return TRUE;
}

void cmListItemDispose(CMItem * pItem)
{
    CMIterator iterator;

    LOGFB(CM_TRC_LEVEL_CMLIST);
    LOGMSG(CM_TRC_LEVEL_CMLIST, "Dispose item: %s", pItem->name ? cmWDump(pItem->name) : "");
    
    if (pItem->beingDisposed || pItem->isStatic)
    {
        LOGFE(CM_TRC_LEVEL_CMLIST);
        return;
    }

    pItem->beingDisposed = TRUE;
    pItem->findable = FALSE;
    cmListIteratorStart(&pItem->references, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMReference * ref = (CMReference *)cmListIteratorNext(&iterator);
        CMItem * pRefItem = ref->ref;
        cmListItemRemoveAndDispose((CMItem *)ref);
        cmListItemUnlock(pRefItem);
    }
    cmListIteratorTerminate(&iterator);
    cmListShutdown(&pItem->references);
    cmListItemCheck(pItem);
    if (NULL != pItem->name)
    {
        cmMemoryFree(pItem->name);
    }
    syMutexDelete(&pItem->guard);
    cmMemoryFree(pItem);
    LOGFE(CM_TRC_LEVEL_CMLIST);
}

NQ_BOOL cmListItemRemoveAndDispose(CMItem * pItem)
{
    LOGFB(CM_TRC_LEVEL_CMLIST);
    LOGMSG(CM_TRC_LEVEL_CMLIST, "Remove & dispose item: %s", pItem->name ? cmWDump(pItem->name) : "");

    if (cmListItemRemove(pItem))
    {
        cmListItemDispose(pItem);
        LOGFE(CM_TRC_LEVEL_CMLIST);
        return TRUE;
    }
    LOGFE(CM_TRC_LEVEL_CMLIST);
    return FALSE;
}

void cmListItemAddReference(CMItem * referencing, CMItem * referenced)
{
    /* we do not protect the item since its ref list is protected anyway */
    CMReference * ref = (CMReference *)cmListItemCreateAndAdd(&referencing->references, sizeof(CMReference), NULL, NULL , FALSE);
    if (NULL != ref)
    {
        ref->ref = referenced;
        cmListItemLock(referenced);
    }
}

void cmListItemRemoveReference(CMItem * referencing, CMItem * referenced)
{
    CMIterator iterator;        /* in the list of references */

    cmListIteratorStart(&referencing->references, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMReference * ref = (CMReference *)cmListIteratorNext(&iterator);
        if (ref->ref == referenced)
        {
            cmListIteratorTerminate(&iterator);
            cmListItemRemoveAndDispose((CMItem *)ref);
            cmListItemUnlock(referenced);
            return;
        }
    }
    cmListIteratorTerminate(&iterator);
}

void cmListIteratorStart(CMList * pList, CMIterator * iterator)
{
    if (pList->isUsed)
    {
        syMutexTake(&pList->guard);
        iterator->list = pList;
        iterator->next = pList->first;
    }
    else
    {
        iterator->list = pList;
        iterator->next = NULL;
    }
}

void cmListIteratorTerminate(CMIterator * iterator)
{
    if (iterator->list->isUsed)
        syMutexGive(&iterator->list->guard);
}

CMItem * cmListIteratorNext(CMIterator * iterator)
{
    CMItem * pItem = iterator->next;
    if (NULL == pItem)
    {
        syMutexGive(&iterator->list->guard);
    }
    else
    {
        iterator->next = pItem->next;
    }
    return pItem;
}

void cmListItemLock(CMItem * pItem)
{
    LOGFB(CM_TRC_LEVEL_CMLIST);
    
    syMutexTake(&pItem->guard);
    pItem->locks++;
    LOGMSG(CM_TRC_LEVEL_CMLIST, "Lock item: %s, now: %d", pItem->name ? cmWDump(pItem->name) : "", pItem->locks);
    syMutexGive(&pItem->guard);
    
    LOGFE(CM_TRC_LEVEL_CMLIST);
}

void cmListItemUnlock(CMItem * pItem)
{
    LOGFB(CM_TRC_LEVEL_CMLIST);

    syMutexTake(&pItem->guard);
    LOGMSG(CM_TRC_LEVEL_CMLIST, "Unlock item: %s, was: %d", pItem->name ? cmWDump(pItem->name) : "", pItem->locks);
    if (0 == pItem->locks || 0 == --pItem->locks)
    {
        if (NULL != pItem->callback)
        {
            NQ_BOOL res = TRUE;
        	pItem->findable = FALSE;
        	res = (*pItem->callback)(pItem);
            if (!res)
                syMutexGive(&pItem->guard);            
            LOGFE(CM_TRC_LEVEL_CMLIST);
            return;         /* We assume that the item was disposed and the mutex with it*/
        }
    }
    syMutexGive(&pItem->guard);
    LOGFE(CM_TRC_LEVEL_CMLIST);
}

void cmListItemCheck(CMItem * pItem)
{
    syMutexTake(&pItem->guard);
    if (0 == pItem->locks)
    {
        if (NULL != pItem->callback && !pItem->beingDisposed)
        {
        	NQ_BOOL res = TRUE;
        	pItem->findable = FALSE;
        	res = (*pItem->callback)(pItem);
            if (!res)
                syMutexGive(&pItem->guard);            
            return;         /* We assume that the item was disposed and the mutex with it*/
        }
    }
    syMutexGive(&pItem->guard);
}

CMItem * cmListItemFind(CMList * pList, const NQ_WCHAR * name, NQ_BOOL ignoringCase , NQ_BOOL lock)
{
    CMIterator iterator;

    if (name == NULL)
        return NULL;
    
    cmListIteratorStart(pList, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * pItem = (CMItem *)cmListIteratorNext(&iterator);
        if (NULL != pItem->name && (ignoringCase ? (0 == cmWStricmp(name, pItem->name)) : (0 == cmWStrcmp(name, pItem->name))))
        {
            cmListIteratorTerminate(&iterator);
            
            if (pItem->findable)
            {
                if (lock)
                {
                    cmListItemLock(pItem);
                }
                return pItem;
            }
            else
            {
                return NULL;
            }
        }
    }
    cmListIteratorTerminate(&iterator);
    return NULL;
}

void cmListItemTake(CMItem * pItem)
{
    syMutexTake(&pItem->guard);
}

void cmListItemGive(CMItem * pItem) 
{
    syMutexGive(&pItem->guard);
}

#if SY_DEBUGMODE

void cmListDump(CMList * pList)
{
#ifdef UD_NQ_INCLUDETRACE
    CMIterator iterator;
    NQ_INT i = 0;

    LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "List [%s] %p (first: %p, last: %p):", pList->name, pList, pList->first, pList->last);
    cmListIteratorStart(pList, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMItem * pItem = cmListIteratorNext(&iterator);
        if (pItem->master != pList)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "  !! item %p corrupted (list: %p item: %p item->master : %p)",pItem, pList, pItem, pItem->master);
        }
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "  [%04d] item %p next: %p, prev: %p, locks: %d, name: %s", i++, pItem, pItem->next, pItem->prev, pItem->locks, pItem->name != NULL? cmWDump(pItem->name) : "<none>");
        if (NULL != pItem->dump)
            pItem->dump(pItem);
        if (pItem->references.first != NULL)
        {
            CMIterator refIterator;
            LOGMSG( CM_TRC_LEVEL_MESS_NORMAL, "  references:"); 
            cmListIteratorStart(&pItem->references, &refIterator);
            while (cmListIteratorHasNext(&refIterator))
            {
                CMReference * ref = (CMReference *)cmListIteratorNext(&refIterator);
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "    item %p master %p (%s): %p, prev: %p, locks: %d, flags: %x, name: %s", ref->ref, ref->ref->master, ref->ref->master->name);
            }
            cmListIteratorTerminate(&refIterator);
        }
    }
    cmListIteratorTerminate(&iterator);
#endif /* UD_NQ_INCLUDETRACE */
}

#endif /* SY_DEBUGMODE */
