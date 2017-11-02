/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Pool of sockets for internal communications with
 *                 Name Daemon and Datagram Daemon
 *--------------------------------------------------------------------
 * MODULE        : NS - NetBIOS Sockets
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 27-May-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "nsinsock.h"

/*
 NS module communicates with localhost Name and Datagram Daemons over a socket.
 Since NS is reenterant, using the same socket may significantly decrease performance.
 To avoid this problem we use a pool of pre-connected sockets.

 The pool uses preallocated socket slots. It is controlled by an array of "free socket"
 pointers. This array is a cyclical array of pointers to free socket slots. Two indexes
 (of the 1-st and of the last cell) "roll around" in this array.

 Access to the buffer pool is protected by a mutex. The overflow condition is controlled
 by a binary semaphore.
 */

/*
    Static data & functions
    -----------------------
 */

/* Initialize an internal socket */

static NQ_STATUS                    /* NQ_SUCCESS or NQ_FAIL */
initInternalSocketHandle(
    SYSocketHandle *socket          /* pointer to socket handle */
    );

typedef struct
{
    InternalSocket   slotsND[UD_NS_NUMNDCHANNELS];   /* NS socket pool */
    InternalSocket*  freeND[UD_NS_NUMNDCHANNELS];    /* free slot pointers */
    NQ_INT firstFreeND;             /* Index of the pointer to the 1st free ND socket */
    NQ_INT lastFreeND;              /* Index of the pointer to the last free ND socket */
    SYMutex      poolGuardND;       /* Mutex for exclusive access to data */
    SYSemaphore  overflowGuardND;   /* Binary semaphore for resolving pool
                                       overflow. If pool is empty, a task waits
                                       for this semaphore until another task
                                       releases a buffer. */
    InternalSocket   slotsDD[UD_NS_NUMDDCHANNELS];   /* DD socket pool */
    InternalSocket*  freeDD[UD_NS_NUMDDCHANNELS];    /* Array of pointers to free DD sockets */
    NQ_INT firstFreeDD;             /* Index of the pointer to the 1st free DD socket */
    NQ_INT lastFreeDD;              /* Index of the pointer to the last free DD socket */
    SYMutex      poolGuardDD;       /* Mutex for exclusive access to data */
    SYSemaphore  overflowGuardDD;   /* Binary semaphore for resolving pool
                                       overflow. If pool is empty, a task waits
                                       for this semaphore until another task
                                       releases a buffer. */
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
 *
 * NOTES:   1) create sockets
 *          2) bind each of them to a dynamic port and any available IP
 *====================================================================
 */

NQ_STATUS
nsInitInternalSockets(
    void
    )
{
    NQ_INDEX     i;       /* just a counter */

    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate internal sockets");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->firstFreeND = 0;
    staticData->lastFreeND  = -1;
    staticData->firstFreeDD = 0;
    staticData->lastFreeDD  = -1;

    /* Name Daemon sockets */

    syMutexCreate(&staticData->poolGuardND);
    sySemaphoreCreate(&staticData->overflowGuardND, UD_NS_NUMNDCHANNELS);

    syMutexTake(&staticData->poolGuardND);
    for (i=0; i<UD_NS_NUMNDCHANNELS; i++)
    {
#ifdef SY_INTERNALSOCKETPOOL
        staticData->slotsND[i].socket = syInvalidSocket();
        if (initInternalSocketHandle(&staticData->slotsND[i].socket) == NQ_FAIL)
        {
            syMutexGive(&staticData->poolGuardND);               
            TRCE();
            return NQ_FAIL;
        }
#endif
        staticData->freeND[i] = &staticData->slotsND[i];
        staticData->slotsND[i].idx = i;
    }
    syMutexGive(&staticData->poolGuardND);

    /* Datagram Daemon sockets */

    syMutexCreate(&staticData->poolGuardDD);
    sySemaphoreCreate(&staticData->overflowGuardDD, UD_NS_NUMDDCHANNELS);

    syMutexTake(&staticData->poolGuardDD);
    for (i=0; i<UD_NS_NUMDDCHANNELS; i++)
    {
#ifdef SY_INTERNALSOCKETPOOL
        staticData->slotsDD[i].socket = syInvalidSocket();
        if (initInternalSocketHandle(&staticData->slotsDD[i].socket) == NQ_FAIL)
        {
            syMutexGive(&staticData->poolGuardDD);
            TRCE();
            return NQ_FAIL;
        }
#endif
        staticData->freeDD[i] = &staticData->slotsDD[i];
        staticData->slotsDD[i].idx = i;
    }
    syMutexGive(&staticData->poolGuardDD);

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Clean up the pool
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:   1) close sockets
 *          2) delete semaphores
 *====================================================================
 */

NQ_STATUS
nsExitInternalSockets(
    void
    )
{
    NQ_INT     i;       /* just a counter */

    TRCB();

    syMutexTake(&staticData->poolGuardND);
    syMutexTake(&staticData->poolGuardDD);

    /* Name Daemon sockets */

    for (i=0; i<UD_NS_NUMNDCHANNELS; i++)
    {
#ifdef SY_INTERNALSOCKETPOOL
        if (syIsValidSocket(staticData->slotsND[i].socket))
        {
            syCloseSocket(staticData->slotsND[i].socket);
        }
#endif
    }

    /* Datagram Daemon sockets */

    for (i=0; i<UD_NS_NUMDDCHANNELS; i++)
    {
#ifdef SY_INTERNALSOCKETPOOL
        if (syIsValidSocket(staticData->slotsDD[i].socket))
        {
            syCloseSocket(staticData->slotsDD[i].socket);
        }
#endif
    }

    syMutexGive(&staticData->poolGuardND);
    syMutexGive(&staticData->poolGuardDD);
    syMutexDelete(&staticData->poolGuardND);
    syMutexDelete(&staticData->poolGuardDD);
    sySemaphoreDelete(staticData->overflowGuardND);
    sySemaphoreDelete(staticData->overflowGuardDD);

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

    TRCE();

    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Get an ND socket from the pool
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: socket pointer or NULL on failure
 *====================================================================
 */

InternalSocket*
getInternalSocketND(
    void
    )
{
    InternalSocket* socket;  /* pointer to return */

    sySemaphoreTake(staticData->overflowGuardND);
    syMutexTake(&staticData->poolGuardND);

    socket = staticData->freeND[staticData->firstFreeND];       /* get the 1st */
    staticData->firstFreeND++;                      /* shift to next */
    staticData->firstFreeND %= UD_NS_NUMNDCHANNELS; /* wrap around */

    syMutexGive(&staticData->poolGuardND);

#ifndef SY_INTERNALSOCKETPOOL
    if (initInternalSocketHandle(&(socket->socket))==NQ_FAIL)
    {
        return NULL;
    }
#endif
    return socket;
}

/*
 *====================================================================
 * PURPOSE: Return an internal ND socket
 *--------------------------------------------------------------------
 * PARAMS:  Pointer to the socket to return
 *
 * RETURNS: none
 *====================================================================
 */

void
putInternalSocketND(
    InternalSocket* socket
    )
{
#ifndef SY_INTERNALSOCKETPOOL
    syCloseSocket(socket->socket);
#endif

    syMutexTake(&staticData->poolGuardND);

    staticData->lastFreeND++;                       /* if was -1 will start from index 0 */
    staticData->lastFreeND %= UD_NS_NUMNDCHANNELS;  /* wrap around */
    staticData->freeND[staticData->lastFreeND] = socket;        /* write a free slot pointer */

    syMutexGive(&staticData->poolGuardND);

    sySemaphoreGive(staticData->overflowGuardND);
}


/*
 *====================================================================
 * PURPOSE: Get an DD socket from the pool
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: socket pointer or NULL on failure
 *====================================================================
 */

InternalSocket*
getInternalSocketDD(
    void
    )
{
    InternalSocket* socket;  /* pointer to return */

    sySemaphoreTake(staticData->overflowGuardDD);
    syMutexTake(&staticData->poolGuardDD);

    socket = staticData->freeDD[staticData->firstFreeDD];               /* get 1st free */
    staticData->firstFreeDD++;                              /* shift to the next */
    staticData->firstFreeDD %= UD_NS_NUMDDCHANNELS;         /* wrap around */

    syMutexGive(&staticData->poolGuardDD);

#ifndef SY_INTERNALSOCKETPOOL
    if (initInternalSocketHandle(&(socket->socket))==NQ_FAIL)
    {
        return NULL;
    }
#endif

    return socket;
}

/*
 *====================================================================
 * PURPOSE: Return an internal DD socket
 *--------------------------------------------------------------------
 * PARAMS:  Pointer to the socket to return
 *
 * RETURNS: none
 *====================================================================
 */

void
putInternalSocketDD(
    InternalSocket* socket
    )
{
#ifndef SY_INTERNALSOCKETPOOL
    syCloseSocket(socket->socket);
#endif

    syMutexTake(&staticData->poolGuardDD);

    staticData->lastFreeDD++;                       /* if was -1 will start from index 0 */
    staticData->lastFreeDD %= UD_NS_NUMDDCHANNELS;  /* wrap around */
    staticData->freeDD[staticData->lastFreeDD] = socket;        /* write a free slot pointer */

    syMutexGive(&staticData->poolGuardDD);

    sySemaphoreGive(staticData->overflowGuardDD);
}

/*
 *====================================================================
 * PURPOSE: Init an internal socket
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT Pointer to the socket handle
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *====================================================================
 */

static NQ_STATUS
initInternalSocketHandle(
    SYSocketHandle *socket
    )
{
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
    NQ_PORT port;      /* dynamic port number */
    NQ_IPADDRESS ip;   /* assigned IP */

    TRCB();

    *socket = syCreateSocket(FALSE, CM_IPADDR_IPV4);    /* datagram socket */
    if(!syIsValidSocket(*socket))       /* error */
    {
        TRCERR("Unable to create internal communication socket");
        TRCE();
        return NQ_FAIL;
    }
    if (syBindSocket(*socket, &localhost, 0) == NQ_FAIL)
    {
        syCloseSocket(*socket);
        TRCERR("Unable to bind internal communication socket");
        TRCE();
        return NQ_FAIL;
    }
    syGetSocketPortAndIP(*socket, &ip, &port);
    if (port == 0)
    {
        syCloseSocket(*socket);
        TRCERR("Unable to get internal communication socket's port");
        TRCE();
        return NQ_FAIL;
    }

    TRCE();
    return NQ_SUCCESS;
}


