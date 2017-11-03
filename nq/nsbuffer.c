/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Buffer pool
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 14-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "nsbuffer.h"

/*
 NS module is reenterant. However, because of a limited stack size we cannot
 allocate large buffers on the task stack. Instead we are allocating them
 statically. Even locally used, those bufer are allocated on a per-task basis.
 For this reason we use buffer pool.

 Buffer pool is organized an an array of buffers. It is controlled by another
 array of "free buffer" pointers. This second array is a cyclical array of
 pointers to free buffers. Two indexes (of the 1-st and of the last cell) "roll around"
 in this array.

 Access to the buffer pool is protected by a mutex. The overflow condition is controlled
 by a binary semaphore, so that on overflow a task will wait until another tasks releases
 a buffer.
 */

/*
    Static data
    -----------
 */

/* number of buffers to allocate */

#ifdef UD_NS_NUMBUFFERS
#define NUM_BUFFERS UD_NS_NUMBUFFERS
#else
#define NUM_BUFFERS CM_NB_NUMBUFFERS
#endif

typedef NQ_BYTE MessageBuffer[NUM_BUFFERS];     /* message buffer */

typedef struct
{
    NQ_INT       firstFree;             /* Index of the 1st free buf pointer */
    NQ_INT       lastFree;              /* Index of the last free buf pointer */
    SYMutex      sendDatagramGuard;     /* Mutex for exclusive access to the datagram buffer */
    SYMutex      recvDatagramGuard;     /* Mutex for exclusive access to the datagram buffer */
#ifndef CM_NQ_STORAGE
    SYMutex      bufGuard;              /* Mutex for exclusive access to data */
    MessageBuffer* freeBufs[NUM_BUFFERS];    /* Array of free buffer pointers */
    SYSemaphore  overflowGuard;         /* Binary semaphore for resolving pool
                                           overflow. If pool is empty, a task waits
                                           for this semaphore until another task
                                           releases a buffer. */
#endif
    NQ_BYTE sendDatagramBuffer[CM_NB_DATAGRAMBUFFERSIZE];   /* send buffer */
    NQ_BYTE recvDatagramBuffer[CM_NB_DATAGRAMBUFFERSIZE];   /* receive buffer */
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
nsInitMessageBufferPool(
    void
    )
{
#ifndef CM_NQ_STORAGE
    NQ_INT i;
#endif
    NQ_STATUS result = NQ_FAIL;

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate buffers");
        sySetLastError(NQ_ERR_NOMEM); 
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->firstFree = 0;
    staticData->lastFree = -1;

    syMutexCreate(&staticData->sendDatagramGuard);
    syMutexCreate(&staticData->recvDatagramGuard);
#ifndef CM_NQ_STORAGE
    syMutexCreate(&staticData->bufGuard);
    sySemaphoreCreate(&staticData->overflowGuard, NUM_BUFFERS);

    for (i=0; i<NUM_BUFFERS; i++)
    {
        staticData->freeBufs[i] = (MessageBuffer*) udAllocateBuffer(i, NUM_BUFFERS, UD_NS_BUFFERSIZE);
                                        /* set free buffer pointers to the respective buffers
                                           all buffers are still free */
    }
#endif
    result = NQ_SUCCESS;

Exit:
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
nsReleaseMessageBufferPool(
    void
    )
{
#ifndef CM_NQ_STORAGE
    NQ_INT i;

    for (i=0; i<NUM_BUFFERS; i++)
    {
        udReleaseBuffer(i, NUM_BUFFERS, (NQ_BYTE*)staticData->freeBufs[i], UD_NS_BUFFERSIZE);
    }
    syMutexDelete(&staticData->bufGuard);
    sySemaphoreDelete(staticData->overflowGuard);
#endif
    syMutexDelete(&staticData->sendDatagramGuard);
    syMutexDelete(&staticData->recvDatagramGuard);

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        cmMemoryFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */
}


/*
 *====================================================================
 * PURPOSE: Get send datagram buffer
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: buffer address
 *====================================================================
 */

NQ_BYTE*
nsGetSendDatagramBuffer(
    void
    )
{
    syMutexTake(&staticData->sendDatagramGuard);
    return staticData->sendDatagramBuffer;
}

/*
 *====================================================================
 * PURPOSE: Get receive datagram buffer
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: buffer address
 *====================================================================
 */

NQ_BYTE*
nsGetRecvDatagramBuffer(
    void
    )
{
    syMutexTake(&staticData->recvDatagramGuard);
    return staticData->recvDatagramBuffer;
}

/*
 *====================================================================
 * PURPOSE: Release receive datagram buffer
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: buffer address
 *====================================================================
 */

void
nsPutSendDatagramBuffer(
    void
    )
{
    syMutexGive(&staticData->sendDatagramGuard);
}

/*
 *====================================================================
 * PURPOSE: Release send datagram buffer
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *====================================================================
 */

void
nsPutRecvDatagramBuffer(
    void
    )
{
    syMutexGive(&staticData->recvDatagramGuard);
}

#ifndef CM_NQ_STORAGE

/*
 *====================================================================
 * PURPOSE: Reset buffer pool to its initial state
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *====================================================================
 */

void
nsResetBufferPool(
    void
    )
{
    syMutexTake(&staticData->bufGuard);

    staticData->firstFree = 0;
    staticData->lastFree = -1;
    sySemaphoreDelete(staticData->overflowGuard);
    sySemaphoreCreate(&staticData->overflowGuard, NUM_BUFFERS);

    syMutexGive(&staticData->bufGuard);
} 

/*
 *====================================================================
 * PURPOSE: Get a buffer from the pool
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: buffer pointer or NULL on failure
 *
 * NOTES:   because of the binary semaphore the 1st free index will never come
 *          over the last free index
 *====================================================================
 */

NQ_BYTE*
nsGetBuffer(
    )
{
    MessageBuffer* buffer;  /* pointer to return */

    sySemaphoreTake(staticData->overflowGuard);
    syMutexTake(&staticData->bufGuard);

    buffer = staticData->freeBufs[staticData->firstFree];   /* take this buffer */
    staticData->firstFree++;                    /* mark this one as being used */
    staticData->firstFree %= NUM_BUFFERS;       /* wrap around if at the end of the array */

    syMutexGive(&staticData->bufGuard);

    return (NQ_BYTE*)buffer;
}

/*
 *====================================================================
 * PURPOSE: Return a buffer to the pool
 *--------------------------------------------------------------------
 * PARAMS:  Pointer to the buffer to return
 *
 * RETURNS: none
 *====================================================================
 */

void
nsPutBuffer(
    NQ_BYTE* buffer
    )
{
    syMutexTake(&staticData->bufGuard);

    staticData->lastFree++;                     /* find space to point to the buffer (if initially it
                                       was -1 - will start from index 0) */
    staticData->lastFree %= NUM_BUFFERS;        /* wrap around */
    staticData->freeBufs[staticData->lastFree] = (MessageBuffer*)buffer;    /* return the buffer */

    syMutexGive(&staticData->bufGuard);

    sySemaphoreGive(staticData->overflowGuard);
}
#endif


