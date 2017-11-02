/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Adapter Information Management
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBIOS Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 27-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ndadaptr.h"
#include "nsapi.h"

#ifdef UD_ND_INCLUDENBDAEMON

/* This code provides access to the list of adapters with the following assumtions:
    all operations are synchronous and thread safe because there is no concarrent calls. */

/*
    Static data & functions
    -----------------------
 */

typedef struct
{
    NQ_BOOL adaptersStarted;                    /* for one-time initialization of adapters when NQ is restarted */
    NDAdapterInfo adapters[UD_NS_MAXADAPTERS];  /* list of adapters */
    NQ_UINT numAdapters;                        /* number of adapters */
    NQ_INDEX nextIdx;                           /* index of the next adapter for enumeration */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* clean up resources associated with adapter */

static NQ_STATUS
cleanUpAdapter(
    NDAdapterInfo* adapter  /* pointer to adapter structure */
    );

/*
 *====================================================================
 * PURPOSE: Initialize the list of adapters
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:   set all to NONE
 *====================================================================
 */

NQ_STATUS
ndAdapterListInit(
    void
    )
{
    NQ_INDEX idx;              /* index in the list of adapters */

    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate adapter table");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    staticData->adaptersStarted = FALSE;
    staticData->numAdapters = 0;
    staticData->nextIdx = 0;

    /* mark all slots as emtry */

    for (idx = 0; idx < sizeof(staticData->adapters)/sizeof(staticData->adapters[0]); idx++)
    {
        staticData->adapters[idx].status = ND_ADAPTER_NONE;
    }

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Release the list of adapters
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
ndAdapterListStop(
    void
    )
{
    NQ_INDEX idx;              /* index in the list of adapters */

    TRCB();

    /* release all adapters */

    for (idx = 0; idx < sizeof(staticData->adapters)/sizeof(staticData->adapters[0]); idx++)
    {
        if (staticData->adapters[idx].status != ND_ADAPTER_NONE)
            cleanUpAdapter(&staticData->adapters[idx]);
    }

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

    TRCE();
}

/*
 *====================================================================
 * PURPOSE: Load/reload the list of adapters
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   Asks User layer for the list of adapters and loads them into
 *          an internal storage.
 *          Mark adapters as new or removed
 *====================================================================
 */

NQ_STATUS
ndAdapterListLoad(
    void
    )
{
    NQ_COUNT oldAdapters;      /* old number of adapters */
    NQ_INDEX idx;              /* index in the list of adapters */
    NQ_IPADDRESS4 ip;          /* next IP address */
    const CMSelfIp * nextIp;   /* next host IP */ 

    TRCB();

    /* mark all existing adapters as temporary
       later we will deside whether an adapter is reloaded, removed or added */

    oldAdapters = sizeof(staticData->adapters)/sizeof(staticData->adapters[0]);
    for (idx = 0; idx < oldAdapters; idx++)
    {
        if (staticData->adapters[idx].status != ND_ADAPTER_NONE)
            staticData->adapters[idx].status = ND_ADAPTER_TEMP;
    }

    /* get new adapters and determine its status */

    staticData->numAdapters = 0;
    for (cmSelfipIterate(); NULL != (nextIp = cmSelfipNext()) && staticData->numAdapters < UD_NS_MAXADAPTERS; )
    {
        NQ_UINT32 bcast;           /* next broadcast address */
        NQ_BOOL isOld;             /* adapter already exists */
        NQ_INT emptyIdx;         /* index of an empty slot */

        if (CM_IPADDR_IPV4 != CM_IPADDR_VERSION(nextIp->ip))
            continue;

        ip = CM_IPADDR_GET4(nextIp->ip);
        bcast = nextIp->bcast;
        TRC(">> Adapter attached: ip:%08lx, broadcast:%08lx", ip, bcast);

        /* compare this adapter with existing adapters and define it is NEW or OLD */

        isOld = FALSE;
        emptyIdx = -1;
        for (idx = 0; idx < oldAdapters; idx++)
        {
            if (staticData->adapters[idx].status == ND_ADAPTER_NONE && emptyIdx == -1)
            {
                emptyIdx = (NQ_INT)idx;
            }
            else if (   staticData->adapters[idx].ip == ip
                     && staticData->adapters[idx].bcast == bcast
                     && staticData->adapters[idx].wins == udGetWins()
                    )
            {
                staticData->adapters[idx].status = ND_ADAPTER_OLD;
                isOld = TRUE;
                break;
            }
        }

        /* if the adapter is new - find an empty slot and fill in adapter information */

        if (!isOld)
        {
            TRC1P("new adapter at idx: %d", emptyIdx);

            if (emptyIdx == -1)
            {
                emptyIdx = (NQ_INT)oldAdapters;
                if (emptyIdx >= UD_NS_MAXADAPTERS)
                {
                    cmSelfipTerminate();
                    TRCERR("Adapter list overflow");
                    TRC2P("Max adapters: %d, required: %d", UD_NS_MAXADAPTERS, emptyIdx);

                    TRCE();
                    return NQ_FAIL;
                }
            }
            idx = (NQ_INDEX)emptyIdx;
            staticData->adapters[idx].ip = ip;
            staticData->adapters[idx].bcast = bcast;
            staticData->adapters[idx].wins = udGetWins();
            staticData->adapters[idx].typeB = (staticData->adapters[emptyIdx].wins == 0L);
            staticData->adapters[idx].status = ND_ADAPTER_NEW;
            staticData->adapters[idx].subnet = nextIp->subnet;
            syGetMacAddress(ip, staticData->adapters[idx].mac);

            cleanUpAdapter(&staticData->adapters[idx]);
        }

        staticData->adapters[idx].idx = staticData->numAdapters;    /* internal index */
        staticData->numAdapters++;
    }

    staticData->adaptersStarted = TRUE;

    /* the rest of adapters (those that remained TEMP) should be removed  */

    for (idx = 0; idx < oldAdapters; idx++)
    {
        if (staticData->adapters[idx].status == ND_ADAPTER_TEMP)
        {
            staticData->adapters[idx].status = ND_ADAPTER_NONE;
            if (cleanUpAdapter(&staticData->adapters[idx]) == NQ_FAIL)
            {
                cmSelfipTerminate();
                return NQ_FAIL;
            }
        }
    }
    cmSelfipTerminate();
    TRC1P("Number of adapters: %d", staticData->numAdapters);

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: Enumerate adapters
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: Next adapter descriptor or NULL if no more adapters exist
 *
 * NOTES:   cyclically scans the list of adapters skipping empty slots
 *====================================================================
 */

NDAdapterInfo*
ndAdapterGetNext(
    void
    )
{
    while (   staticData->nextIdx < sizeof(staticData->adapters)/sizeof(staticData->adapters[0])
           && staticData->adapters[staticData->nextIdx].status == ND_ADAPTER_NONE
          )
    {
        staticData->nextIdx++;
    }

    if (staticData->nextIdx >= sizeof(staticData->adapters)/sizeof(staticData->adapters[0]))
    {
        staticData->nextIdx = 0;
        return NULL;
    }

    return &staticData->adapters[staticData->nextIdx++];
}

NDAdapterInfo*
ndFindAdapter(
    NQ_IPADDRESS4 ip,
    NDAdapterInfo *internalAdapter
    )
{
    NQ_UINT i;

    TRCB();

    for (i = 0; i < staticData->numAdapters; i++)
    {
        NDAdapterInfo *a = &staticData->adapters[i];
        NQ_IPADDRESS4 bcast = (ip & a->subnet) | (0xFFFFFFFF & ~a->subnet);

        if (bcast == a->bcast)
        {
            TRC("ndFindAdapter: found exact match");
            TRCE();
            return a;
        }
    }

    TRC("ndFindAdapter: no matching adapter, returning internal");
    TRCE();
    return internalAdapter;
}

/*
 *====================================================================
 * PURPOSE: Clean up resources associated with adapter
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT pointer to the adapter structure
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
cleanUpAdapter(
    NDAdapterInfo* adapter
    )
{
    TRCB();

    adapter->nsSocket = syInvalidSocket();
    adapter->dsSocket = syInvalidSocket();
#ifdef UD_NB_RETARGETSESSIONS
    adapter->ssSocket = syInvalidSocket();
#endif /* UD_NB_RETARGETSESSIONS */

    TRCE();
    return NQ_SUCCESS;
}

#endif /* UD_ND_INCLUDENBDAEMON */

