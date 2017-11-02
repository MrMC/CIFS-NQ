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
    NQ_UINT16 port;                         /* requestor port (internal) */
    NQ_UINT16 tranId;                       /* requestor tranId */
    NDAdapterInfo* adapter;                 /* requestor adapter (dummy) */
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
    NQ_UINT timeout;                            /* countdown number of daemon ticks */
    NQ_UINT16 tranId;                           /* query tran ID */
}
NameEntry;

/* values for the Status field */

#define NAME_EMPTY             -1   /* an empty slot */
#define NAME_NEW                0   /* nothing done yet */
#define NAME_INQUERY            1   /* name is being quered */
#define NAME_KNOWN              2   /* name was discovered and TTL didn't expired yet */
#define NAME_NOT_KNOWN          3   /* name was not discovered (doesn't exist) and TTL didn't expired yet */

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
    apprlication */

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

/* query operation timeout mesured in daemon cycles */

#define QUERY_TIMEOUT \
        (CM_NB_UNICASTREQRETRYTIMEOUT + UD_ND_DAEMONTIMEOUT - 1) / UD_ND_DAEMONTIMEOUT

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

    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate External Names data");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        staticData->names[idx].status = NAME_EMPTY;
        staticData->names[idx].numRequests = 0;
    }

    TRCE();
    return NQ_SUCCESS;
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
    TRCB();

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
    NQ_INT idx;                      /* index in names */
    NQ_STATUS opStatus;              /* operation status */
    NQ_STATUS retValue = NQ_SUCCESS;    /* value to return */
    NQ_CHAR * oneB;

    TRCB();

    /* find name in the list */
    TRC("name: %s", name);

    idx = findName(name);

    if (idx == NAME_EMPTY)
    {

        TRC("New name");

        /* create name */

        idx = findNoName();

        if (idx == NAME_EMPTY)
        {
            TRCE();

            return NQ_FAIL;
        }

        syMemcpy(staticData->names[idx].nameInfo.name, name, sizeof(CMNetBiosName));

    }
    
    oneB = syStrchr(name, 0x1b);

    /* validate operation status */

    opStatus = staticData->names[idx].status;

    switch (opStatus)
    {
    case NAME_KNOWN:
        TRC("NAME_KNOWN");
        response->inTranId = cmGetSUint16(((CMNetBiosHeader*)response->inMsg)->tranID);
        returnPositiveQueryResponse(&staticData->names[idx], response, &staticData->names[idx].addrEntry);
        break;
    case NAME_NOT_KNOWN:
        TRC("NAME_NOT_KNOWN");
        response->inTranId = cmGetSUint16(((CMNetBiosHeader*)response->inMsg)->tranID);
        returnNegativeQueryResponse(&staticData->names[idx], response, CM_NB_RCODE_NAMERR);
        break;
    case NAME_NEW:
    case NAME_EMPTY:
        TRC("NAME_NEW or NAME_EMPTY");
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

    TRCE();
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
    NQ_INT idx;                      /* index in names */
    NQ_STATUS opStatus;              /* operation status */
    NQ_STATUS retValue = NQ_SUCCESS;    /* value to return */

    TRCB();

    /* find name in the list */

    idx = findName(name);

    if (idx == NAME_EMPTY)
    {
        TRCERR("Positive Name Query Response for unknown name");
        TRC1P("name: %s", name);

        TRCE();
        return NQ_SUCCESS;
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
                TRCERR("Positive Query Response with unexpected Tran ID");
                TRC2P(
                    "Expected - %d, accepted - %d",
                    syNtoh16(staticData->names[idx].tranId),
                    syNtoh16(cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID))
                    );

                TRCE();
                return NQ_SUCCESS;
            }

            /* validate the rest of the packet */

            resRecord = (CMNetBiosResourceRecord*) addData;
            if (CM_NB_RTYPE_NB != syNtoh16(cmGetSUint16(resRecord->rrType)))
            {
                TRCERR("Positive Query Response with unexpected Addr Rec type");
                TRC1P("Addr Rec type = %d", syNtoh16(cmGetSUint16(resRecord->rrType)));
                TRCE();
                return NQ_SUCCESS;
            }

            length = syNtoh16(cmGetSUint16(resRecord->rdLength));

            if ( length < (NQ_INT)sizeof(CMNetBiosAddrEntry))
            {
                TRCERR("Illegal resource record");

                TRCE();
                return NQ_FAIL;
            }

            /* find the proper ADDR ENTRY:
                - if there is only one ADDR ENTRY - use it
                - if there is ADD ENTRY with IP on the same network - use the 1st one
                - otherwise try to connect to name session service of all those IPs untill success */

            addrEntry = (CMNetBiosAddrEntry*)(resRecord + 1);

            if (length != sizeof(CMNetBiosAddrEntry))
            {
                NQ_COUNT i;         /* addr entry index */
                NQ_UINT num;        /* num of addr entry records */
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
                        TRCERR("Unable to create socket");

                        TRCE();
                        return NQ_FAIL;
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
                    TRCERR("No IP selected");

                    TRCE();
                    return NQ_SUCCESS;         /* no IP selected */
                }
            }

            syMemcpy(
                &staticData->names[idx].addrEntry,
                (NQ_BYTE*)(addrEntry),
                sizeof(staticData->names[idx].addrEntry)
                );

            /* set up TTL */

            ttl = syNtoh32(cmGetSUint32(resRecord->ttl));
            staticData->names[idx].ttl = (ttl + UD_ND_DAEMONTIMEOUT - 1) / UD_ND_DAEMONTIMEOUT;
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

    TRCE();
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

    TRCB();

    /* find name in the list */

    idx = findName(name);

    if (idx == NAME_EMPTY)
    {
        TRCERR("Negative Name Query Response for unknown name");
        TRC1P("name: %s", name);

        TRCE();
        return NQ_SUCCESS;
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
                TRCERR("Negative Query Response with unexpected Tran ID");
                TRC2P(
                    "Expected - %d, accepted - %d",
                    syNtoh16(staticData->names[idx].tranId),
                    syNtoh16(cmGetSUint16(((CMNetBiosHeader*)adapter->inMsg)->tranID))
                    );

                TRCE();
                return NQ_SUCCESS;
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

    TRCE();
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

    TRCB();

    /* find name in the list */

    idx = findName(name);

    if (idx == NAME_EMPTY)
    {
        TRC1P("WACK for unknown name: %s", name);

        TRCE();
        return NQ_SUCCESS;
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
                staticData->names[idx].timeout = (ttl - 1) / UD_ND_DAEMONTIMEOUT;
            }

        }
        break;
    default:
        break;
    }

    TRCE();
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
    
    TRCB();

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
    TRCE();
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

    TRCB();

    /* compose the message */

    msgHdr = (CMNetBiosHeader*)dummy->outMsg;
    msgLen = ndGenerateNameQueryRequest(msgHdr, name->nameInfo.name);

    if (msgLen <= 0)
    {
        TRCE();
        return NQ_FAIL;
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
            TRCERR("Failed to send the Name Query Request");
        }
    }

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();

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
        TRCE();
        return NQ_FAIL;
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
        TRCERR("Failed to send Positive Query Response internally");
        TRCE();
        return NQ_FAIL;
    }

    TRCE();
    return NQ_SUCCESS;
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

    TRCB();

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
        TRCE();
        return NQ_FAIL;
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
        TRCERR("Failed to send Negative Query Response internally");
        TRCE();
        return NQ_FAIL;
    }

    TRCE();
    return NQ_SUCCESS;
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
    NQ_INT idx;       /* index in names */

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        if (staticData->names[idx].status != NAME_EMPTY)
        {
            if (cmNetBiosSameNames(name, staticData->names[idx].nameInfo.name))
            {
                return idx;
            }
        }
    }

    return NAME_EMPTY;
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
    NQ_INT idx;       /* index in names */

    for (idx = 0; idx < sizeof(staticData->names)/sizeof(staticData->names[0]); idx++)
    {
        if (staticData->names[idx].status == NAME_EMPTY)
        {
            return idx;
        }
    }

    TRCERR("Overflow in the name table");

    return NAME_EMPTY;
}

#endif /* UD_ND_INCLUDENBDAEMON */

