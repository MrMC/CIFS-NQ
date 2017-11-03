/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Socket pool management
 *--------------------------------------------------------------------
 * MODULE        :
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 22-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "nssocket.h"
#include "cmrepository.h"

/*
 NS module keeps trek of sockets created by means of nsSocket. For this
 reason we use a pool of socket descriptors.

 This pool is organized an an array of descriptors. It is controlled by another
 array of "free descriptor" pointers. This second array is a cyclical array of
 pointers to free descriptors. Two indexes (of the 1-st and of the last cell) "roll around"
 in this array.

 Access to the pool is protected by a mutex.
 Slot index is reserved for a future use. SInce it is refrerenced only in initSocketPool()
 this does not affect the performance.
*/

/*
    Static data
    -----------
 */


#define FIRST_PORT  6000                            /* bottom of the port pool for sockets */

typedef struct
{
	CMRepository socketSlots;
	NQ_BOOL isUp;
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

static void initSlot(CMItem * pItem)
{
	SocketSlot * pSlot = (SocketSlot *)pItem;

	pSlot->socket = syInvalidSocket();    /* no socket yet */
}

static  void disposeSlot(CMItem * pItem)
{
	SocketSlot * pSlot = (SocketSlot *)pItem;

	if (syIsValidSocket(pSlot->socket))
		syCloseSocket(pSlot->socket);
}

/*
 *====================================================================
 * PURPOSE: Initialize the pool
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *====================================================================
 */

NQ_STATUS
nsInitSocketPool(
    void
    )
{
    NQ_STATUS result = NQ_SUCCESS;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate socket pool");
        result = NQ_FAIL;
        sySetLastError(NQ_ERR_NOMEM);
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

    cmRepositoryInit(&staticData->socketSlots, 0, initSlot, disposeSlot);
    cmRepositoryItemPoolAlloc(&staticData->socketSlots, UD_NS_NUMSOCKETS, sizeof(SocketSlot));
    staticData->isUp = TRUE;
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Release the pool
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *====================================================================
 */

void
nsExitSocketPool(
    void
    )
{
	if (staticData->isUp)
	{
		staticData->isUp = FALSE;
		cmRepositoryShutdown(&staticData->socketSlots);
	}
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        cmMemoryFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}

/*
 *====================================================================
 * PURPOSE: Get underlying socket's handle
 *--------------------------------------------------------------------
 * PARAMS:  NS level socket handle
 *
 * RETURNS: SY level socket handle
 *
 * NOTES:
 *====================================================================
 */

SYSocketHandle nsGetSySocket(NSSocketHandle socket)
{
    SocketSlot* slot = (SocketSlot*)socket;

    return slot->socket;
}

/*
 *====================================================================
 * PURPOSE: Get a socket descriptor from the pool
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: buffer pointer or NULL on failure
 *
 * NOTES:   Takes a slot from the 1st free pointer.
 *          On pool overflow the operation fails
 *====================================================================
 */

SocketSlot * getSocketSlot(
    void
    )
{
    SocketSlot * res = NULL;  /* pointer to return on exit */

    res = (SocketSlot *)cmRepositoryGetNewItem(&staticData->socketSlots);
    return res;
}

/*
 *====================================================================
 * PURPOSE: Return a buffer to the pool
 *--------------------------------------------------------------------
 * PARAMS:  Pointer to the buffer to return
 *
 * RETURNS: none
 *
 * NOTES:   fills the next free slot ptr with a reference to the releases slot
 *====================================================================
 */

void putSocketSlot(SocketSlot * slot)
{
    if (syIsValidSocket(slot->socket))
    {
        if (syIsSocketAlive(slot->socket) && syShutdownSocket(slot->socket) != NQ_SUCCESS)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to shutdown a connection");
        }

        if (syCloseSocket(slot->socket) != NQ_SUCCESS)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Unable to close a socket");
        }

        slot->socket = syInvalidSocket();
        cmRepositoryReleaseItem(&staticData->socketSlots, (CMItem *)slot);
    }
}
