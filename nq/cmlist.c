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
void cmListItemInit(CMItem * item)
{
	item->locks 	= 0;
    item->callback  = NULL;
	item->guard 	= NULL;
	item->name 		= NULL;
	item->next 		= NULL;
	item->prev 		= NULL;
	item->master	= NULL;
	item->findable 	= FALSE;
	item->isStatic	= FALSE;
	item->beingDisposed = FALSE;
#if SY_DEBUGMODE
	item->dump      = NULL;
#endif
}

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
	syMutexTake(&pList->guard);
    cmListRemoveAndDisposeAll(pList);
	pList->isUsed = FALSE;
    syMutexGive(&pList->guard);
    syMutexDelete(&pList->guard);
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
    NQ_BOOL result = FALSE;

    /* item can be NULL */
    if (NULL == pItem || !pList->isUsed)
        goto Exit;

    /* we protect the list but we do not protect the item since it cannot 
    * be found until it is inside the list
    */
    syMutexTake(&pList->guard);
    cmListItemTake(pItem);
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
    cmListItemGive(pItem);
    syMutexGive(&pList->guard);
    result = TRUE;

Exit:
    return result;
}

CMItem * cmListItemCreate(NQ_UINT size, const NQ_WCHAR * name , NQ_UINT32 lock)
{
    CMItem * pItem;

    LOGFB(CM_TRC_LEVEL_CMLIST, "size:%u name:%s lock:%u", size,cmWDump(name), lock );
    LOGMSG(CM_TRC_LEVEL_CMLIST, "Create item: %s, lock: %s", name ? cmWDump(name) : "", lock ? "yes" : "no");

    pItem = (CMItem *)cmMemoryAllocate(size);
    if (NULL != pItem)
    {
    	cmListItemInit(pItem);
        if (NULL != name)
        {
            pItem->name = (NQ_WCHAR *)cmMemoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (cmWStrlen(name) + 1)));
            if (NULL != pItem->name)
            {
                cmWStrcpy(pItem->name, name);
            }
		    else
		    {
		        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
				goto Error;
		    }
        }

		/* do not create mutex if exclusive access required */
		if (!(lock & CM_LISTITEM_EXCLUSIVE))
		{
			pItem->guard = (SYMutex *)cmMemoryAllocate(sizeof(*pItem->guard));
			if (NULL == pItem->guard)
			{
				cmMemoryFree(pItem->name);
				pItem->name = NULL;
				goto Error;
			}
			syMutexCreate(pItem->guard);
		}

		if (lock & CM_LISTITEM_LOCK)
			cmListItemLock(pItem);
 
        pItem->isStatic = FALSE;
        cmListStart(&pItem->references);
    }
    else
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Out of memory");
    }

	goto Exit;

Error:
	pItem->locks = 0;
	pItem->guard = NULL;
	cmMemoryFree(pItem);
	pItem = NULL;

Exit:
    LOGFE(CM_TRC_LEVEL_CMLIST, "result:%p", pItem);
    return pItem;
}
   
CMItem * cmListItemCreateAndAdd(CMList * pList, NQ_UINT size, const NQ_WCHAR * name, NQ_BOOL (*callback)(CMItem * pItem) , NQ_UINT32 lock)
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
    CMList * pList = NULL;
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_CMLIST, "item:%p", pItem);
	LOGMSG(CM_TRC_LEVEL_CMLIST, "Remove item: %s, %p", pItem->name ? cmWDump(pItem->name) : "", pItem);

    if (0 != pItem->locks)
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Unable to remove locked item: %s, lock=%d, %p", pItem->name ? cmWDump(pItem->name) : "", pItem->locks, pItem);
        goto Exit;
    }
    pList = pItem->master;
    
    if (NULL == pList || !pList->isUsed)
    {
        /* may be normal for nested removal */
        goto Exit;
    }

    /* we protect the list but we do not protect the item since we do 
    * not modify its contents 
    */
    syMutexTake(&pList->guard);
    cmListItemTake(pItem);
    if (NULL == pItem->prev)  /* first in the list */
    {
#if SY_DEBUGMODE
        if (pItem != pList->first)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Corrupted list or item: first: %p, expected: %p", pList->first, pItem);
            syMutexGive(&pList->guard);
            goto Exit;
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
    pItem->master 	= NULL;
    pItem->next		= NULL;
	pItem->prev		= NULL;
    cmListItemGive(pItem);
    syMutexGive(&pList->guard);
    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_CMLIST, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

void cmListItemDispose(CMItem * pItem)
{
    CMIterator iterator;

    LOGFB(CM_TRC_LEVEL_CMLIST, "item:%p", pItem);

	cmListItemTake(pItem);
	LOGMSG(CM_TRC_LEVEL_CMLIST, "Dispose item: %s, locks: %d, %p", pItem->name ? cmWDump(pItem->name) : "", pItem->locks, pItem);

    if (pItem->beingDisposed || pItem->isStatic)
    {
    	cmListItemGive(pItem);
        goto Exit;
    }

    pItem->findable = FALSE;
    pItem->beingDisposed = TRUE;
    if (NULL != pItem->guard)	syMutexGive(pItem->guard);

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
        pItem->name = NULL;
    }
    if (NULL != pItem->guard)
	{
		syMutexDelete(pItem->guard);
		cmMemoryFree(pItem->guard);
		pItem->guard = NULL;
	}
    cmMemoryFree(pItem);
    pItem = NULL;

Exit:
    LOGFE(CM_TRC_LEVEL_CMLIST);
}

NQ_BOOL cmListItemRemoveAndDispose(CMItem * pItem)
{
    NQ_BOOL result = FALSE;

    LOGFB(CM_TRC_LEVEL_CMLIST, "item:%p", pItem);
	LOGMSG(CM_TRC_LEVEL_CMLIST, "Remove & dispose item: %s, %p", pItem->name ? cmWDump(pItem->name) : "", pItem);

    if (cmListItemRemove(pItem))
    {
        cmListItemDispose(pItem);
        result = TRUE;
        goto Exit;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_CMLIST, "result:%s", result ? "TRUE" : "FALSE");
    return result;
}

void cmListItemAddReference(CMItem * referencing, CMItem * referenced)
{
    /* we do not protect the item since its references list is protected anyway */
	CMReference * ref;

	LOGFB(CM_TRC_LEVEL_CMLIST, "referencing:%p referenced:%p", referencing, referenced);
	LOGMSG(CM_TRC_LEVEL_CMLIST, "Add reference - referencing item: %s, %p", referencing->name ? cmWDump(referencing->name) : "", referencing);
	LOGMSG(CM_TRC_LEVEL_CMLIST, "Add reference - referenced item: %s, %p (lock)", referenced->name ? cmWDump(referenced->name) : "", referenced);

	ref = (CMReference *)cmListItemCreateAndAdd(&referencing->references, sizeof(CMReference), NULL, NULL, CM_LISTITEM_NOLOCK);
    if (NULL != ref)
    {
        ref->ref = referenced;
        cmListItemLock(referenced);
    }
	LOGFE(CM_TRC_LEVEL_CMLIST);
}

void cmListItemRemoveReference(CMItem * referencing, CMItem * referenced)
{
    CMIterator iterator;        /* in the list of references */

	LOGFB(CM_TRC_LEVEL_CMLIST, "referencing:%p referenced:%p", referencing, referenced);
	LOGMSG(CM_TRC_LEVEL_CMLIST, "Remove reference - referencing item: %s, %p", referencing->name ? cmWDump(referencing->name) : "", referencing);
	LOGMSG(CM_TRC_LEVEL_CMLIST, "Remove reference - referenced item: %s, %p (unlock)", referenced->name ? cmWDump(referenced->name) : "", referenced);

    cmListIteratorStart(&referencing->references, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        CMReference * ref = (CMReference *)cmListIteratorNext(&iterator);
        if (ref->ref == referenced)
        {
            cmListIteratorTerminate(&iterator);
            cmListItemRemoveAndDispose((CMItem *)ref);
            cmListItemUnlock(referenced);
			LOGFE(CM_TRC_LEVEL_CMLIST);
            return;
        }
    }
    cmListIteratorTerminate(&iterator);
	LOGFE(CM_TRC_LEVEL_CMLIST);
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
    LOGFB(CM_TRC_LEVEL_CMLIST, "item:%p", pItem);
    
    cmListItemTake(pItem);
    pItem->locks++;
    LOGMSG(CM_TRC_LEVEL_CMLIST, "Lock item: %s, %p, now: %d", pItem->name ? cmWDump(pItem->name) : "", pItem, pItem->locks);
    cmListItemGive(pItem);
    
    LOGFE(CM_TRC_LEVEL_CMLIST);
}

void cmListItemUnlock(CMItem * pItem)
{
    LOGFB(CM_TRC_LEVEL_CMLIST, "item:%p", pItem);

    cmListItemTake(pItem);
    LOGMSG(CM_TRC_LEVEL_CMLIST, "Unlock item: %s, %p, was: %d", pItem->name ? cmWDump(pItem->name) : "", pItem, pItem->locks);
    if (0 == pItem->locks || 0 == --pItem->locks)
    {
		if (NULL != pItem->callback)
		{
			if (pItem->findable == FALSE)
			{
				cmListItemGive(pItem);
				goto Exit;
			}
			pItem->findable = FALSE;
		}
		cmListItemGive(pItem);
        if (NULL != pItem->callback)
        {
            (*pItem->callback)(pItem);
        }
        goto Exit;
    }
    cmListItemGive(pItem);

Exit:
    LOGFE(CM_TRC_LEVEL_CMLIST);
}

void cmListItemCheck(CMItem * pItem)
{
	LOGFB(CM_TRC_LEVEL_CMLIST, "item:%p", pItem);

	cmListItemTake(pItem);
	LOGMSG(CM_TRC_LEVEL_CMLIST, "Check item: %s, %p, locks: %d", pItem->name ? cmWDump(pItem->name) : "", pItem, pItem->locks);

    if (0 == pItem->locks)
    {
    	cmListItemGive(pItem);
        if (NULL != pItem->callback && !pItem->beingDisposed)
        {
        	pItem->findable = FALSE;
        	(*pItem->callback)(pItem);
        }
        goto Exit;
    }
    cmListItemGive(pItem);
Exit:
	LOGFE(CM_TRC_LEVEL_CMLIST);
	return;
}

CMItem * cmListItemFind(CMList * pList, const NQ_WCHAR * name, NQ_BOOL ignoringCase , NQ_BOOL lock)
{
    CMIterator iterator;
    CMItem * pItem = NULL;

	LOGFB(CM_TRC_LEVEL_CMLIST, "list:%p name:%s ignoringCase:%s lock:%s", pList, cmWDump(name), ignoringCase ? "TRUE" : "FALSE", lock ? "TRUE" : "FALSE");

    if (name == NULL)
        goto Exit;

	LOGMSG(CM_TRC_LEVEL_CMLIST, "Find item: %s and lock: %s", cmWDump(name), lock ? "yes" : "no");
    
    cmListIteratorStart(pList, &iterator);
    while (cmListIteratorHasNext(&iterator))
    {
        pItem = (CMItem *)cmListIteratorNext(&iterator);
        if (NULL != pItem->name && (ignoringCase ? (0 == cmWStricmp(name, pItem->name)) : (0 == cmWStrcmp(name, pItem->name))))
        {
            if (pItem->findable)
            {
            	cmListItemTake(pItem);
            	if (lock)
                {
            		cmListItemGive(pItem);
            		cmListItemLock(pItem);
                    goto Exit;
                }
        		cmListItemGive(pItem);
                goto Exit;
            }
            else
            {
                goto Error;
            }
        }
        else
        	pItem = NULL;
    }

Error:
	pItem = NULL;

Exit:
	if (name != NULL)
		cmListIteratorTerminate(&iterator);
    LOGFE(CM_TRC_LEVEL_CMLIST, "result:%p", pItem);
    return pItem;
}

void cmListItemTake(CMItem * pItem)
{
	if (pItem->beingDisposed)	return;
	if (NULL != pItem->guard)	syMutexTake(pItem->guard);
}

void cmListItemGive(CMItem * pItem) 
{
	if (pItem->beingDisposed)	return;
	if (NULL != pItem->guard)	syMutexGive(pItem->guard);
}

#if SY_DEBUGMODE

void cmListDump(CMList * pList)
{
#ifdef NQ_INTERNALTRACE
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
				LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "    item %p master: %p, locks: %d", ref->ref, ref->ref->master, ref->ref->locks);
            }
            cmListIteratorTerminate(&refIterator);
        }
    }
    cmListIteratorTerminate(&iterator);
#endif /* NQ_INTERNALTRACE */
}

#endif /* SY_DEBUGMODE */
