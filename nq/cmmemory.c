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

#include "cmmemory.h"
#include "cmapi.h"

/* -- Constants and typedefs -- */

/*#define PRINTOUT*/  /* define this to have debug printouts on the screen */
/*#define MEMORY_SHUTDOWN_PRINTOUT*/ /* define this to get a report if there is any unreleased memory */

/* each allocated memory block is prefixed by a 32-bit signature value and a 32-bit size */
#define SIGNATURE ((NQ_UINT32)0xFED12345)	 

typedef struct
{
#if SY_DEBUGMODE
	CMItem item;			/* element in linked list */
	NQ_UINT line;			/* line number */
#endif /* SY_DEBUGMODE */
	NQ_UINT32 size;			/* block size */
	NQ_UINT32 signature;	/* NQ signature */
    NQ_UINT seq;            /* sequence number */
} Extra;

typedef struct 
{
	NQ_UINT32 maxBytes;
	NQ_UINT32 bytesInUse;
#if SY_DEBUGMODE
	NQ_UINT32 bytesAllocated;
	NQ_UINT32 bytesDeallocated;
	NQ_UINT32 blocksAllocated;
	NQ_UINT32 blocksDeallocated;
	NQ_UINT32 blocksInUse;
#endif /* SY_DEBUGMODE */
} Statistics;


/* -- Static data -- */

static Statistics statistics;   /* memory usage statistics */
static NQ_INT nextSeq;  		/* next sequence number */
#if SY_DEBUGMODE 
static CMList blocks;           /* list of allocated memory blocks */
#endif /* SY_DEBUGMODE */


/* -- Static functions --*/

static void * memoryAllocate(NQ_UINT size, const NQ_CHAR *text, const NQ_UINT line);
static void memoryFree(const void * block, const NQ_CHAR *function, const NQ_UINT line);
static NQ_WCHAR * memoryCloneWString(const NQ_WCHAR * str, const NQ_CHAR *function, const NQ_UINT line);
static NQ_WCHAR * memoryCloneAString(const NQ_CHAR * str, const NQ_CHAR *function, const NQ_UINT line);
static NQ_CHAR * memoryCloneWStringAsAscii(const NQ_WCHAR * str, const NQ_CHAR *function, const NQ_UINT line);
static CMBlob memoryCloneBlob(const CMBlob * origin, const NQ_CHAR *function, const NQ_UINT line);
static void memoryFreeBlob(CMBlob * blob, const NQ_CHAR *function, const NQ_UINT line);

#if SY_DEBUGMODE
static void dumpBlock(CMItem *pItem)
{
#ifdef NQ_INTERNALTRACE
	Extra *extra = (Extra*)((NQ_BYTE *)pItem - sizeof(NQ_UINT32) * 2 - sizeof(NQ_UINT));       
    LOGMSG(CM_TRC_LEVEL_MEMORY, "		Memory block # %d %p of %d bytes not released yet", extra->seq, extra + 1 ,extra->size);
#endif /* NQ_INTERNALTRACE */
}
#endif /* SY_DEBUGMODE */


/* -- API functions -- */

NQ_BOOL cmMemoryStart(NQ_COUNT maxBytes)
{
	syMemset(&statistics, 0, sizeof(statistics));
	statistics.maxBytes = maxBytes; 
    nextSeq = 0;
#if SY_DEBUGMODE
	cmListStart(&blocks);
	blocks.name = "memory";
#endif /* SY_DEBUGMODE */
	return TRUE;
}

void cmMemoryShutdown(void)
{	
#if SY_DEBUGMODE

	CMIterator	memItr;

	cmListIteratorStart(&blocks,&memItr);
#ifdef MEMORY_SHUTDOWN_PRINTOUT
	syPrintf(" =========Unreleased Memory List:============= \n");
#endif
	if (cmListIteratorHasNext(&memItr))
	{
#ifdef MEMORY_SHUTDOWN_PRINTOUT
		Extra *extra;
		syPrintf("||Memory usage:\n");
		syPrintf("||  bytes in use %d\n", statistics.bytesInUse);
		syPrintf("||  blocks in use %d\n", statistics.blocksInUse);
#endif
		while (cmListIteratorHasNext(&memItr))
		{
			CMItem	*pItem;


			pItem = cmListIteratorNext(&memItr);

			cmListItemRemove(pItem);

#ifdef MEMORY_SHUTDOWN_PRINTOUT
			extra = (Extra*)pItem;
			syPrintf(" Memory Item Address: %p Name: %s \n" , pItem , cmWDump(pItem->name));
			syPrintf("	->Memory block # %d %p of %d bytes not released yet \n", extra->seq, extra + 1 ,extra->size);
#endif
			if (NULL != pItem->name)
			{
				syFree(pItem->name);
			}
			if (NULL != pItem->guard)
			{
				syMutexGive(pItem->guard);
				syMutexDelete(pItem->guard);
				syFree(pItem->guard);
			}

			syFree(pItem);
			pItem = NULL;
		}
	}
#ifdef MEMORY_SHUTDOWN_PRINTOUT
	else
	{
		syPrintf("\tNo unreleased blocks were found \n");
	}
    syPrintf(" ============================================= \n");
#endif
	cmListIteratorTerminate(&memItr);
#endif /* SY_DEBUGMODE */
}


void * cmMemoryAllocNonDebug(NQ_UINT size)
{
    return memoryAllocate(size, NULL, 0);
}


#if SY_DEBUGMODE
void * cmMemoryAllocDebug(NQ_UINT size, const NQ_CHAR *function, const NQ_UINT line)
{
    return memoryAllocate(size, function, line);
}
#endif


static void * memoryAllocate(NQ_UINT size, const NQ_CHAR *function, const NQ_UINT line)
{
	Extra * extra;
    void * pResult = NULL;

	if (size == 0)
	{
#ifdef PRINTOUT
		syPrintf("ALLOC: Trying to allocate 0 bytes");
#endif
        LOGERR(CM_TRC_LEVEL_MEMORY, "Trying to allocate 0 bytes");
        goto Exit;
	}
	if (statistics.maxBytes > 0 && statistics.bytesInUse + size > statistics.maxBytes)
	{
#ifdef PRINTOUT
		syPrintf("ALLOC: NQ run out of allowed memory %d", statistics.maxBytes);
#endif
		LOGERR(CM_TRC_LEVEL_ERROR, "NQ run out of allowed memory; statistics.maxBytes:%u, statistics.bytesInUse:%u", statistics.maxBytes, statistics.bytesInUse);
        goto Exit;
	}
	size += (NQ_UINT)sizeof(Extra);	/* signature + size */
	extra = (Extra *)syMalloc((NQ_UINT)size);
	if (NULL != extra)
	{
#if SY_DEBUGMODE
        NQ_BOOL isAdded;

		statistics.bytesAllocated += (NQ_COUNT)(size - sizeof(Extra));
		statistics.blocksAllocated += 1;
		statistics.blocksInUse += 1;
#endif /* SY_DEBUGMODE */
		statistics.bytesInUse += (NQ_COUNT)(size - sizeof(Extra));
		extra->signature = SIGNATURE;
		extra->size = (NQ_UINT32)(size - sizeof(Extra));
        extra->seq = (NQ_UINT)++nextSeq;
#if SY_DEBUGMODE
        cmListItemInit(&extra->item);
        extra->item.guard = (SYMutex *)syMalloc(sizeof(*extra->item.guard));
    	if(NULL == extra->item.guard)
    	{
    		LOGERR(CM_TRC_LEVEL_ERROR, "syMalloc: Out of memory");
    		goto Exit;
    	}
        syMutexCreate(extra->item.guard);
        cmListStart(&extra->item.references);
		if (function)
		{
	        extra->item.name = (NQ_WCHAR *)syMalloc((syStrlen(function) + 1)* sizeof(NQ_WCHAR));
			if (extra->item.name)
				cmAnsiToUnicode(extra->item.name, function);
		}
    	isAdded = cmListItemAdd(&blocks, &extra->item, NULL);
		extra->line = line;
    	extra->item.dump = dumpBlock;
		LOGMSG(CM_TRC_LEVEL_MEMORY, "ALLOC: bloc #%d, %d bytes, %p (called by %s() line %d) %s", extra->seq, extra->size, extra + 1, function ? function : "[]", line,  
			isAdded ? "" : "(not added to the list!)");
#endif /* SY_DEBUGMODE */
#ifdef PRINTOUT
        syPrintf("ALLOC: bloc #%4d, %5d bytes by %s (line %d), %p\n", extra->seq, extra->size, function ? function : "[]", line, extra + 1);
#endif /* PRINTOUT */

	    pResult = extra + 1;
	    goto Exit;
	}
#if SY_DEBUGMODE	
	LOGERR(CM_TRC_LEVEL_ERROR, "ALLOC: failed %s (line %d), %d bytes", function, line, size);
	cmMemoryDump();
#endif /* SY_DEBUGMODE */
#ifdef PRINTOUT
    syPrintf("ALLOC: failed %d bytes by %s (line %d)\n", size, function ? function : "[]", line);
#endif /* PRINTOUT */

Exit:
    return pResult;
}

void cmMemoryFreeNonDebug(const void * block)
{
    memoryFree(block, NULL, 0);
}

#if SY_DEBUGMODE
void cmMemoryFreeDebug(const void * block, const NQ_CHAR *function, const NQ_UINT line)
{
    memoryFree(block, function, line);
}
#endif


static void memoryFree(const void * block, const NQ_CHAR *function, const NQ_UINT line)
{
	Extra * extra;

    if (NULL == block)
	{	
#if SY_DEBUGMODE
		LOGERR(CM_TRC_LEVEL_MEMORY, "An attempt to free null block (called by %s() line %d)", function ? function : "[]", line);
#endif /* SY_DEBUGMODE */
#ifdef PRINTOUT
		syPrintf("FREE: An attempt to free null block\n");
#endif /* PRINTOUT */
		return;
	}

    extra = (Extra *)block - 1;
	if (extra->signature == SIGNATURE)
	{
		NQ_UINT32 size = extra->size;
#if SY_DEBUGMODE		
		NQ_BOOL isRemoved;
#endif

#ifdef PRINTOUT
       syPrintf("FREE:  bloc #%4d, %5d bytes by %s (line %d), %p\n", extra->seq, extra->size, function ? function : "[]", line, block);
#endif /* PRINTOUT */
		
#if SY_DEBUGMODE
        /* item name is not unique anyway 
		{
			CMItem *pItem;

			pItem = cmListItemFind(&blocks, extra->item.name, TRUE , FALSE);
			if (!pItem)
			{
				LOGERR(CM_TRC_LEVEL_MEMORY, "FREE: item %p %s not found in list!", block, extra->item.name ? cmWDump(extra->item.name) : "<none>");
			}
		}*/
	    isRemoved = cmListItemRemove(&extra->item);
		LOGMSG(CM_TRC_LEVEL_MEMORY, "FREE: bloc #%d, %d bytes, %p (called by %s() line %d, allocated by %s() line %d) %s", extra->seq, extra->size, block, function ? function : "[]", line, 
			extra->item.name ? cmWDump(extra->item.name) : "<none>", extra->line, isRemoved ? "" : "Failed to remove block from the list");
        
        if (extra->item.name)
        {
            syFree(extra->item.name);
            extra->item.name = NULL;
        }
        if (extra->item.guard)
        {
            syMutexDelete(extra->item.guard);
            syFree(extra->item.guard);
            extra->item.guard = NULL;
        }        
        cmListShutdown(&extra->item.references);
#endif /* SY_DEBUGMODE */
        syFree((void *)extra);
		statistics.bytesInUse -= (NQ_COUNT)size;
#if SY_DEBUGMODE
		statistics.bytesDeallocated += size;
		statistics.blocksDeallocated += 1;
		statistics.blocksInUse -= 1;
#endif /* SY_DEBUGMODE */
	}
	else
	{		
#if SY_DEBUGMODE
		LOGERR(CM_TRC_LEVEL_MEMORY, "An attempt to release bad memory block %p by %s (line %d)", block, function, line);
#endif /* SY_DEBUGMODE */
#ifdef PRINTOUT
       syPrintf("FREE: An attempt to release bad memory block %p by %s (line %d)\n", block, function ? function : "[]", line);
#endif /* PRINTOUT */
       syFree((void *)block);
	}
}

#if SY_DEBUGMODE
NQ_WCHAR * cmMemoryCloneWStringDebug(const NQ_WCHAR * str, const NQ_CHAR *function, const NQ_UINT line)
{
	return memoryCloneWString(str, function, line);
}
#endif

NQ_WCHAR * cmMemoryCloneWStringNonDebug(const NQ_WCHAR * str)
{
	return memoryCloneWString(str, NULL, 0);
}

static NQ_WCHAR * memoryCloneWString(const NQ_WCHAR * str, const NQ_CHAR *function, const NQ_UINT line)
{
	NQ_WCHAR * res = (NQ_WCHAR *)memoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (1 + cmWStrlen(str))), function, line);
	if (NULL != res)
		cmWStrcpy(res, str);
	return res;
}

#if SY_DEBUGMODE
NQ_WCHAR * cmMemoryCloneAStringDebug(const NQ_CHAR * str, const NQ_CHAR *function, const NQ_UINT line)
{
	return memoryCloneAString(str, function, line);
}
#endif
NQ_WCHAR * cmMemoryCloneAStringNonDebug(const NQ_CHAR * str)
{
	return memoryCloneAString(str, NULL, 0);
}

static NQ_WCHAR * memoryCloneAString(const NQ_CHAR * str, const NQ_CHAR *function, const NQ_UINT line)
{
	NQ_WCHAR * res = (NQ_WCHAR *)memoryAllocate((NQ_UINT)(sizeof(NQ_WCHAR) * (1 + syStrlen(str))), function, line);
	if (NULL != res)
		cmAnsiToUnicode(res, str);
	return res;
}

#if SY_DEBUGMODE
NQ_CHAR * cmMemoryCloneWStringAsAsciiDebug(const NQ_WCHAR * str, const NQ_CHAR *function, const NQ_UINT line)
{
	return memoryCloneWStringAsAscii(str, function, line);
}
#endif
NQ_CHAR * cmMemoryCloneWStringAsAsciiNonDebug(const NQ_WCHAR * str)
{
	return memoryCloneWStringAsAscii(str, NULL, 0);
}

#if SY_DEBUGMODE
#define cmMemoryCloneWStringAsAscii(_str) cmMemoryCloneWStringAsAsciiDebug(_str, SY_LOG_FUNCTION, SY_LOG_LINE) 
#else
#define cmMemoryCloneWStringAsAscii(_str) cmMemoryCloneWStringAsAsciiNonDebug(_str)
#endif


static NQ_CHAR * memoryCloneWStringAsAscii(const NQ_WCHAR * str, const NQ_CHAR *function, const NQ_UINT line)
{
    /* we allocate 4 x string length because of multibyte character strings (Chinese) */
	NQ_CHAR * res = (NQ_CHAR *)memoryAllocate((NQ_UINT)(4 * sizeof(NQ_CHAR) * (1 + syWStrlen(str))), function, line);
	if (NULL != res)
		cmUnicodeToAnsi(res, str);
	return res;
}


#if SY_DEBUGMODE
CMBlob cmMemoryCloneBlobDebug(const CMBlob * origin, const NQ_CHAR *function, const NQ_UINT line)
{
	return memoryCloneBlob(origin, function, line);
}
#endif
CMBlob cmMemoryCloneBlobNonDebug(const CMBlob * origin)
{
	return memoryCloneBlob(origin, NULL, 0);
}

#if SY_DEBUGMODE
#define cmMemoryCloneBlob(_origin) cmMemoryCloneBlobDebug(_origin, SY_LOG_FUNCTION, SY_LOG_LINE) 
#else
#define cmMemoryCloneBlob(_origin) cmMemoryCloneBlobNonDebug(_origin)
#endif

static CMBlob memoryCloneBlob(const CMBlob * origin, const NQ_CHAR *function, const NQ_UINT line)
{
	CMBlob newBlob;
	
	newBlob.data = NULL;
	newBlob.len = origin->len;
	if (NULL != origin->data)
	{
		newBlob.data = (NQ_BYTE *)memoryAllocate(origin->len, function, line);
		if (NULL != newBlob.data)
			syMemcpy(newBlob.data, origin->data, newBlob.len);
	}
	return newBlob;
}


#if SY_DEBUGMODE
void cmMemoryFreeBlobDebug(CMBlob * blob, const NQ_CHAR *function, const NQ_UINT line)
{
	memoryFreeBlob(blob, function, line);
}
#endif
void cmMemoryFreeBlobNonDebug(CMBlob * blob)
{
	memoryFreeBlob(blob, NULL, 0);
}

#if SY_DEBUGMODE
#define cmMemoryFreeBlob(_blob) cmMemoryFreeBlobDebug(_blob, SY_LOG_FUNCTION, SY_LOG_LINE) 
#else
#define cmMemoryFreeBlob(_blob) cmMemoryFreeBlobNonDebug(_blob)
#endif

static void memoryFreeBlob(CMBlob * blob, const NQ_CHAR *function, const NQ_UINT line)
{
	if (NULL != blob->data)
		memoryFree(blob->data, function, line);
	blob->data = NULL;
	blob->len = 0;
}

#if SY_DEBUGMODE

void cmMemoryStatistics(NQ_UINT32 * memAlloc, NQ_UINT32 * memDealloc, NQ_UINT32 * blockAlloc, NQ_UINT32 * blockDealloc)
{
	*memAlloc = statistics.bytesAllocated;
	*memDealloc = statistics.bytesDeallocated;
	*blockAlloc = statistics.blocksAllocated;
	*blockDealloc = statistics.blocksDeallocated;
}

void cmMemoryDump(void)
{
	LOGFB(CM_TRC_LEVEL_MEMORY);
	LOGMSG(CM_TRC_LEVEL_MEMORY, "Memory usage:");
	LOGMSG(CM_TRC_LEVEL_MEMORY, "  bytes allocated %u", statistics.bytesAllocated);
	LOGMSG(CM_TRC_LEVEL_MESS_ALWAYS, "  bytes allocated %u", statistics.bytesAllocated);
	LOGMSG(CM_TRC_LEVEL_MEMORY, "  bytes deallocated %u", statistics.bytesDeallocated);
	LOGMSG(CM_TRC_LEVEL_MEMORY, "  blocks allocated %u", statistics.blocksAllocated);
	LOGMSG(CM_TRC_LEVEL_MEMORY, "  blocks deallocated %u", statistics.blocksDeallocated);
	LOGMSG(CM_TRC_LEVEL_MEMORY, "  bytes in use %u", statistics.bytesInUse);
	LOGMSG(CM_TRC_LEVEL_MEMORY, "  blocks in use %u", statistics.blocksInUse);
	LOGMSG(CM_TRC_LEVEL_MEMORY, "  block dump:");
	cmListDump(&blocks);
	LOGFE(CM_TRC_LEVEL_MEMORY);
}

#endif /* SY_DEBUGMODE */


