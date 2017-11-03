/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Name Service functions for external names
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBios Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 26-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "ndinname.h"
#include "ndframes.h"
#include "nsapi.h"
#include "udapi.h"

#ifdef UD_ND_INCLUDENBDAEMON

typedef struct                              /* name query request */
{
    NQ_UINT16 port;                         /* Requester port (internal) */
    NQ_UINT16 tranId;                       /* Requester tranId */
    NDAdapterInfo* adapter;                 /* Requester adapter (dummy) */
} Request;

typedef struct                              /* name entry structure */
{
    CMNetBiosNameInfo nameInfo;                 /* NB name + group flag */
    CMNetBiosAddrEntry addrEntry;               /* name destination IP and flags */
    NQ_INT status;                              /* name operation status */
    NQ_BOOL step;                               /* name resolution step (for H nodes only) */
    NQ_BOOL hasHybrids;                         /* whether this host ahs H interfaces */
    Request requests[UD_ND_MAXQUERYREQUESTS];   /* number of concurrent query requests
                                                   to the same name */
    NQ_UINT numRequests;                        /* number of active concurrent requests */
    NQ_UINT count;                              /* repeat count for timeout */
    NQ_UINT ttl;                                /* timeout value for queried name
                                                   or TTL for known name */
    NQ_UINT timeout;                            /* count down number of daemon ticks */
    NQ_UINT16 tranId;                           /* query tran ID */
}
NameEntry;

/* values for the Status field */

#define NAME_EMPTY             -1   /* an empty slot */
#define NAME_NEW                0   /* nothing done yet */
#define NAME_INQUERY            1   /* name is being queried */
#define NAME_KNOWN              2   /* name was discovered and TTL didn't expire yet */
#define NAME_NOT_KNOWN          3   /* name was not discovered (doesn't exist) and TTL didn't expire yet */

typedef struct
{
    NameEntry names[UD_ND_MAXEXTERNALNAMES];     /* list of names */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* find name in the list */

static NQ_INT         /* name index or NO_NAME */
findName(
    const CMNetBiosName name    /* the query name */
    );

/* find an empty entry in the list */

static NQ_INT         /* name index or NO_NAME */
findNoName(
    void
    );

/* Send different packets:
    Functions whose name starts with "send" are sending packets outside
    Functions whose name starts with "return" are sending packets back to an internal
    Application */

static NQ_STATUS
sendQueryRequest(                   /* NQ_SUCCESS or NQ_FAIL */
    NameEntry* name,                /* name to query for */
    const NDAdapterInfo* adapter    /* adapter to send over */
    );

static NQ_STATUS                       /* NQ_SUCCESS or NQ_FAIL */
returnPositiveQueryResponse(
    const NameEntry* name,              /* discovered name */
    const NDAdapterInfo* adapter,       /* "dummy" adapter to response through */
    const CMNetBiosAddrEntry* addrEntry /* address information */
    );

static NQ_STATUS                       /* NQ_SUCCESS or NQ_FAIL */
returnNegativeQueryResponse(
    const NameEntry* name,              /* discovered name */
    const NDAdapterInfo* adapter,       /* "dummy" adapter to response through */
    NQ_UINT error                          /* error code */
    );

/* query operation timeout measured in daemon cycles */

#define QUERY_TIMEOUT \
        (CM_NB_UNICASTREQRETRYTIMEOUT + UD_ND_DAEMONTIMEOUT - 1) / UD_ND_DAEMONTIMEOUT

#define NAME_ENTRY_MAX_TTL      5       /* max TTL for entry */


/*
 *====================================================================
 * PURPOSE: Initialize this code
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   Mark all names as empty slots.
 *====================================================================
 */

NQ_STATUS
ndExternalNameInit(
    void
    )
{
    NQ_UINT idx;       /* index in the names */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate External Names data");
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        staticData->names[idx].status = NAME_EMPTY;
        staticData->names[idx].numRequests = 0;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: release internal data
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NONE
 *
 * NOTES:
 *====================================================================
 */

void
ndExternalNameStop(
    void
    )
{
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        cmMemoryFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

    LOGFE(CM_TRC_LEVEL_FUNC_COMMON);
}

/*
 *====================================================================
 * PURPOSE: Start registering a name over a specific adapter
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT: adapter to response to "dummy"
 *          IN: name to query for
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   A name may either exist or not. If not exist - we create it.
 *====================================================================
 */

NQ_STATUS
ndExternalNameQuery(
    NDAdapterInfo* response,
    const CMNetBiosName name
    )
{
    NQ_INT idx;                         /* index in names */
    NQ_STATUS opStatus;                 /* operation status */
    NQ_STATUS retValue = NQ_SUCCESS;    /* value to return */
    NQ_CHAR * oneB;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "response:%p name:%s",  response, name ? name : "");

    /* find name in the list */
    /*LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "name: %s", name);*/

    idx = findName(name);

    if (idx == NAME_EMPTY)
    {

        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "New name");

        /* create name */

        idx = findNoName();

        if (idx == NAME_EMPTY)
        {
            retValue = NQ_FAIL;
            goto Exit;
        }
        syMemcpy(staticData->names[idx].nameInfo.name, name, sizeof(CMNetBiosName));
    }
    
    oneB = (NQ_CHAR *)syStrchr(name, 0x1b);

    /* validate operation status */

    opStatus = staticData->names[idx].status;

    switch (opStatus)
    {
    case NAME_KNOWN:
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NAME_KNOWN");
        response->inTranId = cmGetSUint16(((CMNetBiosHeader*)response->inMsg)->tranID);
        returnPositiveQueryResponse(&staticData->names[idx], response, &staticData->names[idx].addrEntry);
        break;
    case NAME_NOT_KNOWN:
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NAME_NOT_KNOWN");
        response->inTranId = cmGetSUint16(((CMNetBiosHeader*)response->inMsg)->tranID);
        returnNegativeQueryResponse(&staticData->names[idx], response, CM_NB_RCODE_NAMERR);
        break;
    case NAME_NEW:
    case NAME_EMPTY:
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "NAME_NEW or NAME_EMPTY");
        sendQueryRequest(&staticData->names[idx], response);

        /* calculate timeout */

        staticData->names[idx].count = oneB ? 0 : CM_NB_UNICASTREQRETRYCOUNT;
        staticData->names[idx].ttl = (udGetWins() == 0) ? CM_NB_BROADCASTTIMEOUT : QUERY_TIMEOUT;
        staticData->names[idx].timeout = staticData->names[idx].ttl;
        staticData->names[idx].status = NAME_INQUERY;

        /* continue to the next case */

    case NAME_INQUERY:
        {
            Request* res;       /* request cell in the name entry */
            NQ_UINT i;          /* index in requests */

            /* check if we already have request from the same source and use the same request */

            for (i = 0; i<staticData->names[idx].numRequests; i++)
            {
                if (staticData->names[idx].requests[i].port == response->inPort)
                    break;
            }

            if (i == staticData->names[idx].numRequests && i < UD_ND_MAXQUERYREQUESTS)
            {
                if (staticData->names[idx].numRequests < UD_ND_MAXQUERYREQUESTS)
                    staticData->names[idx].numRequests++;
                res = &staticData->names[idx].requests[staticData->names[idx].numRequests - 1];
                res->adapter = (NDAdapterInfo*)response;
                res->tranId = syNtoh16(cmGetSUint16(((CMNetBiosHeader*)response->inMsg)->tranID));
                res->port = response->inPort;
            }
        }
        break;
    default:
        break;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", retValue);
    return retValue;
}

/*
 *====================================================================
 * PURPOSE: Process Positive Name Query Response
 *--------------------------------------------------------------------
 * PARAMS:  IN: source adapter
 *          IN: the discovered name
 *          IN: the rest of the packet after the name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   A name may either exist or not
 *          We use only the 1st ADDR_ENTRY of the response
 *====================================================================
 */

NQ_STATUS
ndExternalNamePositiveQuery(
    const NDAdapterInfo* adapter,
    const CMNetBiosName name,
    const NQ_BYTE* addData
    )
{
    NQ_INT idx;                         /* index in names */
    NQ_STATUS opStatus;                 /* operation status */
    NQ_STATUS retValue = NQ_SUCCESS;    /* value to return */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "adapter:%p name:%s addData:%p", adapter, name ? name : "", addData);

    /* find name in the list */

    idx = findName(name);

    if (idx == NAME_EMPTY)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Positive Name Query Response for unknown name");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "name: %s", name);
        goto Exit;
    }

    /* validate operation status */

    opStatus = staticData->names[idx].status;

    switch (opStatus)
    {
    case NAME_INQUERY:
        {
            NQ_UINT32 ttl;                          /* TTL as in the packet */
            CMNetBiosResourceRecord* resRecord;     /* pointer to the resource record */
            CMNetBiosAddrEntry* addrEntry;          /* addr entry of the interest */
            NQ_UINT length;                         /* length of the addr entry array */
            NQ_UINT i;             /* index in responses */
            Request* res;       /* reguest cell in the name entry */

            /* compare TranID with the expected TranID */

            if (!(staticData->names[idx].tranId == cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID)))
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Positive Query Response with unexpected Tran ID");
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, 
                    "Expected - %d, accepted - %d",
                    syNtoh16(staticData->names[idx].tranId),
                    syNtoh16(cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID))
                    );
                goto Exit;
            }

            /* validate the rest of the packet */

            resRecord = (CMNetBiosResourceRecord*) addData;
            if (CM_NB_RTYPE_NB != syNtoh16(cmGetSUint16(resRecord->rrType)))
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Positive Query Response with unexpected Addr Rec type");
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "Addr Rec type = %d", syNtoh16(cmGetSUint16(resRecord->rrType)));
                goto Exit;
            }

            length = syNtoh16(cmGetSUint16(resRecord->rdLength));

            if ( length < (NQ_INT)sizeof(CMNetBiosAddrEntry))
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Illegal resource record");
                retValue = NQ_FAIL;
                goto Exit;
            }

            /* find the proper ADDR ENTRY:
                - if there is only one ADDR ENTRY - use it
                - if there is ADD ENTRY with IP on the same network - use the 1st one
                - otherwise try to connect to name session service of all those IPs untill success */

            addrEntry = (CMNetBiosAddrEntry*)(resRecord + 1);

            if (length != sizeof(CMNetBiosAddrEntry))
            {
                NQ_COUNT i;         /* address entry index */
                NQ_UINT num;        /* number of address entry records */
                NQ_IPADDRESS4 ip;   /* server IP in NBO */
                NQ_BOOL found = FALSE;  /* whether a match was found */

                num = length / sizeof(CMNetBiosAddrEntry);

                for (i = 0; i < num; i++)
                {
                    ip = cmGetSUint32((addrEntry + i)->ip);
                    if ((adapter->subnet & ip) == (adapter->subnet & adapter->ip))
                    {
                        addrEntry += i;
                        found = TRUE;
                        break;                      /* the same subnet */
                    }
                }

                if (!found)
                {
                    SYSocketHandle sock;    /* socket to try connection */

                    sock = syCreateSocket(TRUE, CM_IPADDR_IPV4);        /* TCP socket */

                    if (!syIsValidSocket(sock))
                    {
                        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to create socket");
                        goto Exit;
                    }

                    for (i = 0; i < num; i++)
                    {
                        NQ_IPADDRESS ip;
                        CM_IPADDR_ASSIGN4(ip, cmGetSUint32((addrEntry + i)->ip));

                        if (syConnectSocket(sock, &ip, syHton16(CM_NB_SESSIONSERVICEPORT)) == NQ_SUCCESS)
                        {
                            addrEntry += i;
                            found = TRUE;
                            break;
                        }
                    }

                    syCloseSocket(sock);
                }

                if (!found)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "No IP selected");
                    goto Exit;
                }
            }

            syMemcpy(
                &staticData->names[idx].addrEntry,
                (NQ_BYTE*)(addrEntry),
                sizeof(staticData->names[idx].addrEntry)
                );

            /* set up TTL */

            ttl = syNtoh32(cmGetSUint32(resRecord->ttl));
            ttl = ttl > NAME_ENTRY_MAX_TTL ? NAME_ENTRY_MAX_TTL : ttl;
            staticData->names[idx].ttl = (NQ_UINT)((ttl + UD_ND_DAEMONTIMEOUT - 1) / UD_ND_DAEMONTIMEOUT);
            staticData->names[idx].timeout = staticData->names[idx].ttl;

            /* send responses over the internal connection */

            for (i = 0; i< staticData->names[idx].numRequests; i++)
            {
                res = &staticData->names[idx].requests[i];
                res->adapter->inPort = res->port;
                res->adapter->inTranId = res->tranId;
                returnPositiveQueryResponse(&staticData->names[idx], res->adapter, &staticData->names[idx].addrEntry);
            }
            staticData->names[idx].numRequests = 0;
        }
        staticData->names[idx].status = NAME_KNOWN;
        break;
    default:
        break;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", retValue);
    return retValue;
}

/*
 *====================================================================
 * PURPOSE: Process Negative Name Query Response
 *--------------------------------------------------------------------
 * PARAMS:  IN: source adapter
 *          IN: the discovered name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   A name may either exist or not
 *====================================================================
 */

NQ_STATUS
ndExternalNameNegativeQuery(
    const NDAdapterInfo* adapter,
    const CMNetBiosName name
    )
{
    NQ_INT idx;                      /* index in names */
    NQ_STATUS opStatus;              /* operation status */
    NQ_STATUS retValue = NQ_SUCCESS;    /* value to return */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "adapter:%p name:%s", adapter, name ? name : "");

    /* find name in the list */

    idx = findName(name);

    if (idx == NAME_EMPTY)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Negative Name Query Response for unknown name");
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "name: %s", name);
        goto Exit;
    }

    /* validate operation status */

    opStatus = staticData->names[idx].status;

    switch (opStatus)
    {
    case NAME_INQUERY:
        {
            NQ_UINT i;          /* index in responses */
            Request* res;       /* request cell in the name entry */

            /* compare TranID with the expected TranID */

            if (!(staticData->names[idx].tranId == cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID)))
            {
                LOGERR(CM_TRC_LEVEL_ERROR, "Negative Query Response with unexpected Tran ID");
                LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, 
                    "Expected - %d, accepted - %d",
                    syNtoh16(staticData->names[idx].tranId),
                    syNtoh16(cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID))
                    );
                goto Exit;
            }
            {
                /* send responses */

                for (i = 0; i< staticData->names[idx].numRequests; i++)
                {
                    res = &staticData->names[idx].requests[i];
                    res->adapter->inPort = res->port;
                    res->adapter->inTranId = res->tranId;
                    returnNegativeQueryResponse(&staticData->names[idx], res->adapter, CM_NB_RCODE_NAMERR);
                }
                staticData->names[idx].numRequests = 0;
                staticData->names[idx].status = NAME_EMPTY;
            }
        }

        break;
    default:
        break;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", retValue);
    return retValue;
}

/*
 *====================================================================
 * PURPOSE: Process WACK Response
 *--------------------------------------------------------------------
 * PARAMS:  IN: source adapter
 *          IN: the queried name
 *          IN: the rest of the packet after the name
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   A name may either exist or not
 *          We use only the 1st ADDR_ENTRY of the response
 *====================================================================
 */

NQ_STATUS
ndExternalNameWack(
    const NDAdapterInfo* response,
    const CMNetBiosName name,
    const NQ_BYTE* addData
    )
{
    NQ_INT idx;                      /* index in names */
    NQ_STATUS opStatus;              /* operation status */
    NQ_STATUS retValue = NQ_SUCCESS;    /* value to return */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "response:%p name:%s addData:%p", response, name ? name : "", addData);

    /* find name in the list */

    idx = findName(name);

    if (idx == NAME_EMPTY)
    {
        LOGMSG(CM_TRC_LEVEL_MESS_NORMAL, "WACK for unknown name: %s", name);
        goto Exit;
    }

    /* validate operation status */

    opStatus = staticData->names[idx].status;

    switch (opStatus)
    {
    case NAME_INQUERY:
        {
            CMNetBiosResourceRecord* resRecord;     /* pointer to the resource record */
            NQ_UINT32 ttl;                             /* TTL as in the package */

            resRecord = (CMNetBiosResourceRecord*) addData;

            ttl = syNtoh32(cmGetSUint32(resRecord->ttl));

            if ( ttl != 0)
            {
                staticData->names[idx].timeout = (NQ_UINT)((ttl - 1) / UD_ND_DAEMONTIMEOUT);
            }

        }
        break;
    default:
        break;
    }

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", retValue);
    return retValue;
}

/*
 *====================================================================
 * PURPOSE: Process Daemon timeout
 *--------------------------------------------------------------------
 * PARAMS:  IN elapsed time in seconds
 *
 * RETURNS: timeout
 *
 * NOTES:   A name may either exist or not
 *          We use only the 1st ADDR_ENTRY of the response
 *====================================================================
 */

NQ_COUNT
ndExternalNameTimeout(
    NQ_INT delta
    )
{
    NQ_UINT idx;                /* index in names */
    NQ_COUNT retValue = CM_NB_VERYBIGNBTIMEOUT;   /* the result */
    
    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "delta:%d", delta);

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        switch(staticData->names[idx].status)
        {
        case NAME_INQUERY:
               retValue = UD_ND_DAEMONTIMEOUT;
               if (   staticData->names[idx].ttl !=0
                && staticData->names[idx].timeout-- <= 0
               )
            {
                if (staticData->names[idx].count-- > 0)
                {
                    sendQueryRequest(&staticData->names[idx], staticData->names[idx].requests[0].adapter);
                    staticData->names[idx].timeout = staticData->names[idx].ttl;
                }
                else
                {
                    NQ_UINT i;          /* index in responses */

                    for (i = 0; i < staticData->names[idx].numRequests; i++)
                    {
                        staticData->names[idx].requests[i].adapter->inPort = staticData->names[idx].requests[i].port;
                        staticData->names[idx].requests[i].adapter->inTranId = staticData->names[idx].requests[i].tranId;
                        returnNegativeQueryResponse(&staticData->names[idx], staticData->names[idx].requests[i].adapter, CM_NB_RCODE_NAMERR);
                    }
                    staticData->names[idx].numRequests = 0;
                    /*staticData->names[idx].status = NAME_EMPTY;*/
                    staticData->names[idx].status = NAME_NOT_KNOWN;
                    staticData->names[idx].ttl = UD_ND_DAEMONTIMEOUT * 2; /* name gets status of NAME_NOT_KNOWN for 2 seconds */
                    staticData->names[idx].timeout = staticData->names[idx].ttl;
                }
            }
            break;
        case NAME_NOT_KNOWN:
            if (staticData->names[idx].timeout-- <= 0)
            {
                staticData->names[idx].status = NAME_EMPTY;
            }
            break;
        case NAME_KNOWN:
            if (   staticData->names[idx].ttl !=0
                && staticData->names[idx].timeout-- <= 0
               )
            {
                staticData->names[idx].status = NAME_EMPTY;
            }
            break;
        }
    }
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", retValue);
    return retValue;
}

/*
 *====================================================================
 * PURPOSE: Send Name Query Request externally
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT: name entry to query for
 *          IN: adapter to send over
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   we multiplex the request over all adapters
 *====================================================================
 */

static NQ_STATUS
sendQueryRequest(
    NameEntry* name,
    const NDAdapterInfo* dummy
    )
{
    NQ_INT msgLen;                  /* length of the outgoing message */
    NQ_INT resLen;                  /* length of the sent data */
    CMNetBiosHeader* msgHdr;        /* casted pointer to the outgoing message */
    const NDAdapterInfo* adapter;   /* next adapter to send over */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p dummy:%p", name, dummy);

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)dummy->outMsg;
    msgLen = ndGenerateNameQueryRequest(msgHdr, name->nameInfo.name);

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    /* determine tran ID, called address type and flags */

    name->tranId = syHton16(cmNetBiosGetNextTranId());
    cmPutSUint16(msgHdr->tranID, name->tranId);
    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_OPCODE_QUERY));  /* unicast */

    /* send the message over all adapters */

    name->hasHybrids = FALSE;

    while ((adapter = ndAdapterGetNext()) != NULL)
    {
        NQ_IPADDRESS ip;      /* IP address to use */

        CM_IPADDR_ASSIGN4(ip, adapter->bcast);
        cmPutSUint16(msgHdr->packCodes, cmGetSUint16(msgHdr->packCodes) | syHton16(CM_NB_NAMEFLAGS_B));
        resLen = sySendToSocket(
            adapter->nsSocket,
            (NQ_BYTE*)msgHdr,
            (NQ_UINT)msgLen,
            &ip,
            syHton16(CM_NB_NAMESERVICEPORT)
            );
        if (resLen <= 0)
        {
            LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send the Name Query Request");
        }
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send Positive Name Query Response internally
 *--------------------------------------------------------------------
 * PARAMS:  IN: name entry to report on
 *          IN: dummy adapter to report through
 *          IN: address information to return
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
returnPositiveQueryResponse(
    const NameEntry* name,
    const NDAdapterInfo* dummy,
    const CMNetBiosAddrEntry* addrEntry
    )
{
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
    NQ_INT msgLen;              /* length of the outgoing message */
    NQ_INT resLen;              /* length of the sent data */
    CMNetBiosHeader* msgHdr;    /* casted pointer to the outgoing message */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p dummy:%p addrEntry:%p, in port: %d", name, dummy, addrEntry, dummy->inPort);

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)dummy->outMsg;
    msgLen = ndGenerateNameWhateverResponse(
        msgHdr,
        name->nameInfo.name,
        CM_NB_RTYPE_NB,
        (NQ_BYTE*)addrEntry,
        sizeof(*addrEntry)
        );

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    /* determine tran ID, called address type and flags */

    cmPutSUint16(msgHdr->tranID, dummy->inTranId);
    cmPutSUint16(msgHdr->packCodes, syHton16(CM_NB_OPCODE_QUERY | CM_NB_RESPONSE));

    /* send the message */

    resLen = sySendToSocket(
        dummy->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &localhost,
        dummy->inPort
        );
    if (resLen <= 0)
    {
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Send Negative Name Query Response internally
 *--------------------------------------------------------------------
 * PARAMS:  IN: name entry to report on
 *          IN: dummy adapter to report through
 *          IN: error code
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

static NQ_STATUS
returnNegativeQueryResponse(
    const NameEntry* name,
    const NDAdapterInfo* dummy,
    NQ_UINT error
    )
{
    NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;
    NQ_INT msgLen;              /* length of the outgoing message */
    NQ_INT resLen;              /* length of the sent data */
    CMNetBiosHeader* msgHdr;    /* casted pointer to the outgoing message */
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%p dummy:%p error:0x%x", name, dummy, error);

    udNetBiosError(CM_NBERR_NEGATIVERESPONSE, name->nameInfo.name);

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)dummy->outMsg;
    msgLen = ndGenerateNameWhateverResponse(
        msgHdr,
        name->nameInfo.name,
        CM_NB_RTYPE_NB,
        NULL,
        0
        );

    if (msgLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "msgLen:%d", msgLen);
        goto Exit;
    }

    /* determine tran ID, called address type and flags */

    cmPutSUint16(msgHdr->tranID, dummy->inTranId);
    cmPutSUint16(msgHdr->packCodes, syHton16((NQ_UINT16)(CM_NB_OPCODE_QUERY | CM_NB_RESPONSE | error)));

    /* send the message */

    resLen = sySendToSocket(
        dummy->nsSocket,
        (NQ_BYTE*)msgHdr,
        (NQ_UINT)msgLen,
        &localhost,
        dummy->inPort
        );
    if (resLen <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Failed to send Negative Query Response internally");
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

/*
 *====================================================================
 * PURPOSE: Find name in the list
 *--------------------------------------------------------------------
 * PARAMS:  IN: Name to query
 *
 * RETURNS: Name index or NO_NAME
 *
 * NOTES:
 *====================================================================
 */

static NQ_INT
findName(
    const CMNetBiosName name
    )
{
    NQ_COUNT idx;       /* index in names */
    NQ_INT result = NAME_EMPTY;

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        if (staticData->names[idx].status != NAME_EMPTY)
        {
            if (cmNetBiosSameNames(name, staticData->names[idx].nameInfo.name))
            {
                result = (NQ_INT)idx;
                goto Exit;
            }
        }
    }

Exit:
    return result;
}

/*
 *====================================================================
 * PURPOSE: Find an empty entry in the list
 *--------------------------------------------------------------------
 * PARAMS:  IN: Name to query
 *
 * RETURNS: Name index or NO_NAME
 *
 * NOTES:
 *====================================================================
 */

static NQ_INT
findNoName(
    void
    )
{
	NQ_COUNT idx, oldestNameIndex = 0;       /* index in names */
	NQ_UINT oldestValue = 0;
	NQ_INT result = NAME_EMPTY;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        if (staticData->names[idx].status == NAME_EMPTY)
        {
            result = (NQ_INT)idx;
            goto Exit;
        }
    }

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
   	{
    	if ((staticData->names[idx].ttl - staticData->names[idx].timeout) > oldestValue)
    	{
    		oldestValue = staticData->names[idx].ttl - staticData->names[idx].timeout;
   			oldestNameIndex = idx;
   		}
   	}

    staticData->names[oldestNameIndex].status = NAME_EMPTY;
    staticData->names[oldestNameIndex].numRequests = 0;
	
    result = (NQ_INT)oldestNameIndex;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:%d", result);
    return result;
}

#endif /* UD_ND_INCLUDENBDAEMON */

