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

#ifndef _CMSTORAGE_H_
#define _CMSTORAGE_H_

#include "cmapi.h"

#define STORAGE_IS_TREE     0x0010
#define STORAGE_IS_LIMITED  0x0100 /* used for SMB1 only */

typedef struct _cmstorageitem{
    NQ_UINT64               itemIndex;
    NQ_BOOL                 isUsed;
    NQ_BOOL                 isFindable;
    struct _cmstorageitem * next;
}CMStorageItem;

typedef struct{
    NQ_UINT32       index;
    void *          items;
    void *          freeItems;
    void *          lastFreeItems;
    SYMutex         guard;
    NQ_UINT16       usedItems;
}CMStorageList;

typedef struct{
    NQ_UINT         itemSize;
    CMStorageList * list;
    NQ_UINT         numOfLists;
    NQ_UINT         numOfListItems;
    NQ_UINT32       numOfUsedItems;
    SYMutex         guard;
}CMStorageData;

typedef struct{
    CMStorageData * pData;
    NQ_UINT         listNumber;
    NQ_UINT         itemNumber;
    SYMutex         itrGuard;
}CMStorageIterator;

NQ_BOOL cmStorageListInit(CMStorageData * pData, NQ_UINT itemSize, NQ_UINT numOfLists, NQ_UINT numOfListItems);
void cmStorageListShutdown(CMStorageData * pData);
CMStorageItem * cmStorageItemGetNew(CMStorageData * pData, NQ_INT condition);
CMStorageItem * cmStorageItemFind(CMStorageData * pData, NQ_UINT row, NQ_UINT cell, NQ_BOOL isFindAll);
void cmStorageItemRemove(CMStorageData * pData, NQ_UINT row, NQ_UINT cell);

void cmStorageIteratorStart(CMStorageData * pData, CMStorageIterator * Itr);
NQ_BOOL cmStorageIteratorHasNext(CMStorageIterator * Itr);
CMStorageItem * cmStorageIteratorNext(CMStorageIterator * Itr);
void cmStorageIteratorTerminate(CMStorageIterator * Itr);

typedef struct{
    CMItem  item;
    void *  storeItem;
}CMHashItem;

#define HASH_N	17

typedef NQ_UINT32(*CMStorageHashFunction)(const void * value);

typedef struct{
    CMList                  list[HASH_N];
    CMStorageHashFunction   doHash;
    NQ_BOOL                 isUsed;
}CMStorageHashList;

NQ_BOOL cmStorageHashListStart(CMStorageHashList * pHList, CMStorageHashFunction doHash);
void cmStorageHashListShutdown(CMStorageHashList * pHList);
void cmStorageHashListDispose(CMStorageHashList * pHList);
CMList * cmStorageHashFindList(CMStorageHashList * pHList, const void * value);

NQ_UINT32 cmStorageNameHash(const void * name);

#endif /* _CMSTORAGE_H_ */
