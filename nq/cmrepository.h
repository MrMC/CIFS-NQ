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
#ifndef _CMREPOSITORY_H_
#define _CMREPOSITORY_H_

#include "cmlist.h"

/* repository flags */

#define CM_REPOSITORY_RELEASE_IMMEDIATELY  1  /* used for very large buffers, to be released instead of being returned to repository */

/*
 * if key size is 0 then object is not initialized.
 *
 * */

typedef void (* CMRepositoryItemInit)(CMItem * pItem);
typedef void (* CMRepositoryItemDispose)(CMItem * pItem);

typedef struct {
	NQ_UINT 	numOfItemsToAlloc;
	NQ_UINT		numOfAllocedItems;
	NQ_UINT		itemSize;
	CMRepositoryItemInit doInit;
	CMRepositoryItemDispose doDispose;
	SYMutex *	guard;
	CMList 		list; /* one list */
	CMList 		itemPool;
	NQ_BOOL		isUsed;
	NQ_UINT16   flags;
} CMRepository;


NQ_BOOL cmRepositoryInit(
		CMRepository * pRepo,
		NQ_UINT16 flags,
		CMRepositoryItemInit doInit,
		CMRepositoryItemDispose doDispose
		);

NQ_BOOL cmRepositoryItemPoolAlloc(CMRepository * pRepo , NQ_UINT preallocateNum , NQ_UINT size);

/*Key size is 0 , dynamicly allocated table is freed with all of its items */
void cmRepositoryShutdown(CMRepository * pRepo);

CMItem * cmRepositoryGetNewItem(CMRepository * pRepo );

NQ_BOOL cmRepositoryAddItem(CMRepository * pRepo , CMItem * pItem , NQ_BYTE * key , NQ_BOOL (*callback)(CMItem * pItem) );

NQ_BOOL cmRepositoryReleaseItem(CMRepository * pRepo , CMItem * pItem );

void cmRepositoryIteratorStart(CMRepository * pRepo , CMIterator * iterator);

void cmRepositoryIteratorTerminate(CMRepository * pRepo , CMIterator * iterator);

CMItem * cmRepositoryIteratorNext(CMIterator * iterator);

#define cmRepositoryIteratorHasNext(_iterator_) ((_iterator_)->next != NULL)

#endif /*_CMREPOSITORY_H_*/



