/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Processing incoming messages and timeouts for
 *                 Datagram Service
 *--------------------------------------------------------------------
 * MODULE        : ND - NetBios Daemon
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 26-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "nddatpro.h"
#include "ndinname.h"
#include "nsapi.h"

#ifdef UD_ND_INCLUDENBDAEMON

/* These sources implement the Datagram Service of the NB Daemon for both internal and
   external sources.
 */

/*
    Static data & functions
    -----------------------
 */

typedef struct
{
    NQ_CHAR scopeId[255];       /* buffer for parsed scope ID */
    NQ_CHAR tempName[255];      /* buffer for skipped name */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

/* process internal LISTEN REQUEST */

static NQ_STATUS                                  /* NQ_SUCCESS or NQ_FAIL */
processListenRequest(
    const CMNetBiosName name,           /* source name */
    const CMNetBiosVIPCListen* pIpc,    /* pointer to an internal (VIPC) structure in the
                                           incoming package */
    const NDAdapterInfo* adapter        /* source adapter (dummy) */
    );

/* process internal CANCEL LISTEN REQUEST */

static NQ_STATUS                                  /* NQ_SUCCESS or NQ_FAIL */
processCancelRequest(
    const CMNetBiosName name,           /* source name */
    const CMNetBiosVIPCCancel* pIpc,    /* pointer to an internal (VIPC) structure in the
                                           incoming package */
    const NDAdapterInfo* adapter        /* source adapter (dummy) */
    );

/*
 *====================================================================
 * PURPOSE: initalize internal data
 *--------------------------------------------------------------------
 * PARAMS:  NONE
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
ndDatagramInit(
    void
    )
{
    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syCalloc(1, sizeof(*staticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate Datagram Service data");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

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
ndDatagramStop(
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
 * PURPOSE: Internal message processing
 *--------------------------------------------------------------------
 * PARAMS:  IN: source adapter (dummy)
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This functions processes a datagram from internal communication sockets
 *          Possible causes are:
 *          1) An internal protocol command to a) start listening or b) cancel
 *             listening
 *          2) A broadcast/multicast datagram. Application cannot broadcast directly
 *====================================================================
 */

NQ_STATUS
ndDatagramProcessInternalMessage(
    NDAdapterInfo* adapter
    )
{
    CMNetBiosDatagramMessage* pHdr;     /* casted pointer to the incoming message */
    CMNetBiosName name;                 /* source name after parsing */
    NQ_BYTE* pTemp;                     /* pointer to diffrent places in the packet */
    const CMNetBiosVIPCHeader* pIpc;    /* casted pointer to the internal (VIPC) data */

    TRCB();

    pHdr = (CMNetBiosDatagramMessage*) adapter->inMsg;

    /* decode source name */

    pTemp = cmNetBiosParseName(
        adapter->inMsg,
        pHdr + 1,
        name,
        staticData->scopeId,
        sizeof(staticData->scopeId)
        );

    if (pTemp == NULL)
    {
        TRCERR("Error in parsing the source name");

        TRCE();
        return NQ_FAIL;
    }

    /* skip destination name (we do not use it) */

    pTemp = cmNetBiosParseName(
        adapter->inMsg,
        pTemp,
        staticData->tempName,
        staticData->scopeId,
        sizeof(staticData->scopeId)
        );

    if (pTemp == NULL)
    {
        TRCERR("Error in parsing the destination name");

        TRCE();
        return NQ_FAIL;
    }


    /* dispatch by the datagram type */

    switch (pHdr->type)
    {
    case CM_NB_DATAGRAM_DIRECTUNIQUE:

        /* this is an IPC (internal protocol) request */

        pIpc = (CMNetBiosVIPCHeader*)pTemp;
        if (cmGetSUint16(pIpc->protocolVersion) != CM_NB_VIPCVERSION)
        {
            TRCERR("Illegal version of VIPC");
            TRC2P(
                " expected: %d, received: %d",
                CM_NB_VIPCVERSION,
                cmGetSUint16(pIpc->protocolVersion)
                );
            TRCE();
            return NQ_FAIL;
        }

        /* dispatch by VIPC code */

        switch (cmGetSUint16(pIpc->code))
        {
        case CM_NB_LISTENREQUEST:
            processListenRequest(name, (CMNetBiosVIPCListen*)pIpc, adapter);
            break;
        case CM_NB_CANCELLISTEN:
            processCancelRequest(name, (CMNetBiosVIPCCancel*)pIpc, adapter);
            break;
        default:
            TRCERR("Unrecognized VIPC code");
            TRC1P(" code: %02x", cmGetSUint16(pIpc->code));
            TRCE();
            return NQ_FAIL;
        }
        break;

    case CM_NB_DATAGRAM_DIRECTGROUP:
    case CM_NB_DATAGRAM_BROADCAST:

        /* loop over all adapters:
           broacast over B adapters and send to WINS on H adapters */

        {
            const NDAdapterInfo* nextAdapter;   /* next adapter */
            NQ_INT retValue;                    /* send operation result */
            NQ_BOOL error = FALSE;              /* send operation error  */

            while ((nextAdapter = ndAdapterGetNext()) != NULL)
            {
                NQ_IPADDRESS ip;      /* destination IP */

                /* Broadcast regardless of the node type */

                CM_IPADDR_ASSIGN4(ip, nextAdapter->bcast);

                cmPutSUint32(pHdr->sourceIP, nextAdapter->ip);
                cmPutSUint16(pHdr->sourcePort, syHton16(CM_IN_DATAGRAMSERVICEPORT));

                /* send the response */

                retValue = sySendToSocket(
                    nextAdapter->dsSocket,
                    (NQ_BYTE*)adapter->inMsg,
                    adapter->inLen,
                    &ip,
                    syHton16(CM_NB_DATAGRAMSERVICEPORT)
                    );
                if (retValue < 0)
                {
                    TRCERR("Unable to forward internal request");
                    error = TRUE;
                }
            }

            if(error == TRUE) 
            {
                TRCE();
                return NQ_FAIL;
            }    
 
        }
        break;

    default:

        TRCERR("Internal datagram of unexpected type");
        TRC1P(" type: %02x", pHdr->type);
        return NQ_FAIL;
    }

    TRCE();
    return TRUE;
}

/*
 *====================================================================
 * PURPOSE: External message processing
 *--------------------------------------------------------------------
 * PARAMS:  IN: source adapter
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This functions processes an external datagram. The only allowed datagram is
 *          DIRECT UNIQUE
 *====================================================================
 */

NQ_STATUS
ndDatagramProcessExternalMessage(
    NDAdapterInfo* adapter
    )
{
    CMNetBiosDatagramMessage* pHdr;         /* casted pointer to the incoming message */
    NQ_STATUS status = NQ_SUCCESS;             /* return status */
    CMNetBiosName name;                     /* source name after parsing */
    NQ_BYTE* pTemp;                         /* pointer to diffrent places in the packet */

    TRCB();

    pHdr = (CMNetBiosDatagramMessage*) adapter->inMsg;

    /* skip source name (we do not use it) */

    pTemp = cmNetBiosParseName(
        adapter->inMsg,
        pHdr + 1,
        staticData->tempName,
        staticData->scopeId,
        sizeof(staticData->scopeId)
        );

    if (pTemp == NULL)
    {
        TRCERR("Error in parsing the source name");

        TRCE();
        return NQ_FAIL;
    }

    /* decode destination name */

    pTemp = cmNetBiosParseName(
        adapter->inMsg,
        pTemp,
        name,
        staticData->scopeId,
        sizeof(staticData->scopeId)
        );

    if (pTemp == NULL)
    {
        TRCERR("Error in parsing the destination name");

        TRCE();
        return NQ_FAIL;
    }

    /* dispatch by the datagram type */

    switch (pHdr->type)
    {
    case CM_NB_DATAGRAM_DIRECTUNIQUE:
    case CM_NB_DATAGRAM_DIRECTGROUP:
        {
            NQ_INT16 port = ndInternalNameGetPort(name);  /* port to forward the datagram */
            NQ_IPADDRESS inIp;

            /* check the destination port */
            if (port == 0 || port == ND_NOINTERNALNAME)
            {
                /* compose and send the error response in only case the message type is DIRECTUNIQUE*/

                if (pHdr->type != CM_NB_DATAGRAM_DIRECTGROUP)
                {
                    CMNetBiosDatagramError* errMsg; /* error message pointer */

                    pHdr->type = CM_NB_DATAGRAM_ERROR;
                    errMsg = (CMNetBiosDatagramError*)pHdr;
                    errMsg->errorCode = CM_NB_DATAGRAM_ERROR_NODESTIONATION;   /* error code */

                    CM_IPADDR_ASSIGN4(inIp, adapter->inIp);
                    if (sySendToSocket(
                            adapter->dsSocket,
                            (NQ_BYTE*)adapter->inMsg,
                            sizeof(*errMsg),
                            &inIp,
                            adapter->inPort
                            ) < 0
                       )
                    {
                        TRCERR("Unable to return error response");
                        TRCE();
                        return NQ_FAIL;
                    }
                 }
            }
            else
            {
                NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;

                /* forward the datagram */
                if (sySendToSocket(
                        adapter->dsSocket,
                        (NQ_BYTE*)adapter->inMsg,
                        adapter->inLen,
                        &localhost,
                        (NQ_PORT)port
                        ) < 0
                   )
                {
                    TRCERR("Unable to forward the datagram");
                    TRCE();
                    return NQ_FAIL;
                }
            }
        }

        break;
    default:
        TRCERR("External datagram of unexpected type");
        TRC1P(" type: %02x", pHdr->type);
        return NQ_FAIL;
    }

    TRCE();
    return status;
}

/*
 *====================================================================
 * PURPOSE: process internal LISTEN REQUEST
 *--------------------------------------------------------------------
 * PARAMS:  IN: source name (application name)
 *          IN: pointer to the internal (VIPC) structure in the packet
 *          IN: source adapter (dummy)
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This is an internal message between an application and the daemon
 *          on the same computer. It conforms to the proprietary (VIPC) protocol
 *====================================================================
 */

static NQ_STATUS
processListenRequest(
    const CMNetBiosName name,
    const CMNetBiosVIPCListen* pIpc,
    const NDAdapterInfo* adapter
    )
{
    CMNetBiosDatagramMessage* pHdr;     /* pointer to the outgoing datagram header */
    CMNetBiosVIPCResponse* pResponse;   /* casted pointer to the response VIPC record */
    NQ_UINT length;                     /* data length */
    NQ_COUNT retValue;                  /* various temporary values */
    NQ_UINT16 status;                   /* response status */
    NQ_IPADDRESS inIp;
    NQ_INT res;

    TRCB();

    /* set the retarget port */

    if (ndInternalNameSetPort(name, cmGetSUint16(pIpc->port)) == NQ_SUCCESS)
    {
        status = CM_NB_VIPCOK;
    }
    else
    {
        TRCERR("Internal name not registered yet");
        TRC1P(" name: %s", name);
        status = CM_NB_VIPCUNSPECIFIED;
    }

    /* compose the LISTEN RESPONSE, we use the incoming buffer, assuming that the
       header is already composed, except for the 1) length, 2) src and dst names that
       should be switched. tempName already contains the source name after parsinf the
       request.
       We do not care about flags */

    pHdr = (CMNetBiosDatagramMessage*)adapter->inMsg;

    if ((retValue = cmNetBiosEncodeName(staticData->tempName, (NQ_BYTE*)(pHdr + 1))) <= 0)
    {
        TRCERR("Unable to compose the source name");

        TRCE();
        return FALSE;
    }
    length = retValue;

    if ((retValue = cmNetBiosEncodeName(name, (NQ_BYTE*)(pHdr + 1) + retValue)) <= 0)
    {
        TRCERR("Unable to compose the destination name");

        TRCE();
        return NQ_FAIL;
    }
    length += retValue;

    /* compose VIPC response */

    pResponse = (CMNetBiosVIPCResponse*)((NQ_BYTE*)(pHdr + 1) + length);

    cmPutSUint16(pResponse->header.protocolVersion, CM_NB_VIPCVERSION);
    cmPutSUint16(pResponse->status, status);
    length += (NQ_UINT)(sizeof(*pResponse) + sizeof(*pHdr));

    /* send the response */

    CM_IPADDR_ASSIGN4(inIp, adapter->inIp);
    res = sySendToSocket(
        adapter->dsSocket,
        (NQ_BYTE*)adapter->inMsg,
        length,
        &inIp,
        adapter->inPort
        );
    if (res < 0)
    {
        TRCERR("Unable to send internal response");
        TRCE();
        return NQ_FAIL;
    }

    TRCE();
    return NQ_SUCCESS;
}

/*
 *====================================================================
 * PURPOSE: process internal CANCEL LISTEN REQUEST
 *--------------------------------------------------------------------
 * PARAMS:  IN: source name (application name)
 *          IN: pointer to the internal (VIPC) structure in the packet
 *          IN: source adapter (dummy)
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:   This is an internal message between an application and the daemon
 *          on the same computer. It conforms to the proprietary (VIPC) protocol
 *====================================================================
 */

static NQ_STATUS                                  /* NQ_SUCCESS or NQ_FAIL */
processCancelRequest(
    const CMNetBiosName name,           /* source name */
    const CMNetBiosVIPCCancel* pIpc,    /* pointer to an internal (VIPC) structure in the
                                           incoming package */
    const NDAdapterInfo* adapter        /* source adapter (dummy) */
    )
{
    TRCB();

    /* set no port */

    if (ndInternalNameSetPort(name, 0) != NQ_SUCCESS)
    {
        TRCERR("Internal name not registered yet");
        TRC1P(" name: %s", name);

        TRCE();
        return NQ_FAIL;
    }

    TRCE();
    return NQ_SUCCESS;
}

#endif /* UD_ND_INCLUDENBDAEMON */

