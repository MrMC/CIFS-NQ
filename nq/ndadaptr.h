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
 * CREATION DATE : 29-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#ifndef _NDADAPTR_H_
#define _NDADAPTR_H_

#include "cmapi.h"

/* Adapter information structure */

typedef struct
{
    NQ_UINT idx;                /* adapter index */
    NQ_IPADDRESS4 ip;            /* this adapter address (in NBO) */
    NQ_IPADDRESS4 bcast;         /* broadcast address already in NBO */
    NQ_IPADDRESS4 wins;          /* WINS address already in NBO */
    NQ_INT status;              /* see values below */
    NQ_BOOL typeB;              /* broadcast registration (otherwise - use WINS) */
    SYSocketHandle nsSocket;    /* Name Service listening socket */
    SYSocketHandle dsSocket;    /* Datagram Service listening socket */
#ifdef UD_NB_RETARGETSESSIONS
    SYSocketHandle ssSocket;    /* Session Service listening socket */
#endif
    SYSocketHandle newSocket;   /* Accepted dynamic socket (used in SS only) */
    NQ_UINT16 inPort;           /* sender port from the incoming message (in NBO) */
    NQ_IPADDRESS4 inIp;          /* sender address from the incoming message (in NBO) */
    NQ_UINT16 inTranId;         /* sender Tran ID (not persdistent) */
    const NQ_BYTE* inMsg;       /* incoming message pointer */
    NQ_UINT inLen;              /* incoming message length */
    NQ_BYTE* outMsg;            /* outgoing message buffer */
    NQ_BOOL bcastDest;          /* the destination of the incoming msg was broadcast */
    NQ_IPADDRESS4 subnet;       /* subnet mask */
    NQ_BYTE mac[6];             /* MAC address (may be zeroed) */
}
NDAdapterInfo;

#define ND_ADAPTER_TEMP -1      /* temporary value - for reloading adapters */
#define ND_ADAPTER_NONE 0       /* this is an empty place */
#define ND_ADAPTER_NEW  1       /* recently inserted (names not registered yet over it) */
#define ND_ADAPTER_OLD  2       /* names already registered (or are being registered)
                                   over this adapter */

/* Init the list of adapters */

NQ_STATUS                          /* NQ_SUCCESS or NQ_FAIL */
ndAdapterListInit(
    void
    );

/* Release the list of adapters */

void
ndAdapterListStop(
    void
    );

/* load/reload the list of adapters */

NQ_STATUS                          /* NQ_SUCCESS or NQ_FAIL */
ndAdapterListLoad(
    void
    );

/* enumerate adapters */

NDAdapterInfo*                  /* pointer to adapter descriptor or NULL on the end of the
                                   list */
ndAdapterGetNext(
    void
    );

/* find adapter with the local address closest to the supplied source IP address */

NDAdapterInfo*
ndFindAdapter(
    NQ_IPADDRESS4 ip,
    NDAdapterInfo *internalAdapter
    );

#endif  /* _NDADAPTR_H_ */
