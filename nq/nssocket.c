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
    SocketSlot   sockSlots[UD_NS_NUMSOCKETS];    /* socket pool */
    SocketSlot*  freeSocks[UD_NS_NUMSOCKETS];    /* array of free socket pointers */
    NQ_INT       firstFree;                      /* index of the 1st free socket pointer */
    NQ_INT       lastFree;                       /* index of the last free socket pointer */
    SYMutex      sockGuard;                      /* mutex for exclusive access */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

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
    NQ_INDEX i;

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate socket pool");
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->firstFree = 0;
    staticData->lastFree = UD_NS_NUMSOCKETS -1;

    syMutexCreate(&staticData->sockGuard);

    for (i=0; i<UD_NS_NUMSOCKETS; i++)
    {
        staticData->freeSocks[i] = &staticData->sockSlots[i];               /* all slots are free */
        staticData->sockSlots[i].idx = i;                       /* reserved for a future use */
        staticData->sockSlots[i].socket = syInvalidSocket();    /* no socket yet */
    }
    return NQ_SUCCESS;
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
    syMutexDelete(&staticData->sockGuard);
    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
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

SYSocketHandle
nsGetSySocket(
    NSSocketHandle socket
    )
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

SocketSlot*
getSocketSlot(
    void
    )
{
    SocketSlot* res;  /* pointer to return on exit */

    syMutexTake(&staticData->sockGuard);

    if (staticData->firstFree == staticData->lastFree)
    {
        TRCERR("NS no more socket slots");

        syMutexGive(&staticData->sockGuard);
        return NULL;
    }

    res = staticData->freeSocks[staticData->firstFree];
    staticData->firstFree++;
    staticData->firstFree %= UD_NS_NUMSOCKETS;              /* wrap around */

    syMutexGive(&staticData->sockGuard);

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

void
putSocketSlot(
    SocketSlot* slot
    )
{
    if (syIsValidSocket(slot->socket))
    {
        if (syIsSocketAlive(slot->socket) && syShutdownSocket(slot->socket) != NQ_SUCCESS)
        {
            TRCERR("Unable to shutdown a connection");
        }

        if (syCloseSocket(slot->socket) != NQ_SUCCESS)
        {
            TRCERR("Unable to close a socket");
        }

        slot->socket = syInvalidSocket();
        syMutexTake(&staticData->sockGuard);

        staticData->lastFree++;                         /* if was -1 will start from index 0 */
        staticData->lastFree %= UD_NS_NUMSOCKETS;       /* wrap around */
        staticData->freeSocks[staticData->lastFree] = slot;         /* free it */

        syMutexGive(&staticData->sockGuard);
    }
}
