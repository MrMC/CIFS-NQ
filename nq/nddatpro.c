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
	NQ_STATUS result = NQ_SUCCESS;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON);
    
    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)cmMemoryAllocate(sizeof(*staticData));
    if (NULL == staticData)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to allocate Datagram Service data");
        result = NQ_FAIL;
        goto Exit;
    }
#endif /* SY_FORCEALLOCATION */

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:0x%x", result);
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
ndDatagramStop(
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
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "adapter:%p", adapter);

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
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in parsing the source name");
        goto Exit;
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in parsing the destination name");
        goto Exit;
    }


    /* dispatch by the datagram type */

    switch (pHdr->type)
    {
    case CM_NB_DATAGRAM_DIRECTUNIQUE:

        /* this is an IPC (internal protocol) request */

        pIpc = (CMNetBiosVIPCHeader*)pTemp;
        if (cmGetSUint16(pIpc->protocolVersion) != CM_NB_VIPCVERSION)
        {
			LOGERR(CM_TRC_LEVEL_ERROR, "Illegal version of VIPC expected: %d, received : %d",
				   CM_NB_VIPCVERSION, cmGetSUint16(pIpc->protocolVersion));
            goto Exit;
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
			LOGERR(CM_TRC_LEVEL_ERROR, "Unrecognized VIPC code: %02x", cmGetSUint16(pIpc->code));
            goto Exit;
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
                    LOGERR(CM_TRC_LEVEL_ERROR, "Unable to forward internal request");
                    error = TRUE;
                }
            }

            if (error == TRUE) 
            {
                goto Exit;
            }

        }
        break;
    default:
		LOGERR(CM_TRC_LEVEL_ERROR, "Internal datagram of unexpected type: %02x", pHdr->type);
        goto Exit;
    }
    result = TRUE;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:0x%x", result);
    return result;
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
    NQ_STATUS status = NQ_FAIL;             /* return status */
    CMNetBiosName name;                     /* source name after parsing */
    NQ_BYTE* pTemp;                         /* pointer to diffrent places in the packet */

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "result:%p",adapter);

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
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in parsing the source name");
        goto Exit;
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Error in parsing the destination name");
        goto Exit;
    }

    /* dispatch by the datagram type */

    switch (pHdr->type)
    {
    case CM_NB_DATAGRAM_DIRECTUNIQUE:
    case CM_NB_DATAGRAM_DIRECTGROUP:
        {
			CMList *pPorts = ndInternalNameGetPort(name);
            NQ_IPADDRESS inIp;

            /* check the destination port */
			if (pPorts == NULL /*port == 0 || port == ND_NOINTERNALNAME*/)
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
                        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to return error response");
                        goto Exit;
                    }
                 }
            }
            else
            {
				CMIterator itr;
                NQ_IPADDRESS localhost = CM_IPADDR_LOCAL;

				cmListIteratorStart(pPorts, &itr);
				while (cmListIteratorHasNext(&itr))
				{
					CMItem *pItem = cmListIteratorNext(&itr);

					/* forward the datagram to all ports in the list */
					if (sySendToSocket(
							adapter->dsSocket,
							(NQ_BYTE*)adapter->inMsg,
							adapter->inLen,
							&localhost,
							((BindPort *)pItem)->port
							) < 0
					   )
					{
						LOGERR(CM_TRC_LEVEL_ERROR, "Unable to forward the datagram to port:0x%x", ((BindPort *)pItem)->port);
					}
				}
				cmListIteratorTerminate(&itr); 
            }
        }
        break;
    default:
		LOGERR(CM_TRC_LEVEL_ERROR, "External datagram of unexpected type: %02x", pHdr->type);
        goto Exit;
    }
    status = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:0x%x", status);
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
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s pIpc:%p adapter:%p", name ? name : "", pIpc, adapter);

    /* set the retarget port */

    if (ndInternalNameSetPort(name, cmGetSUint16(pIpc->port)) == NQ_SUCCESS)
    {
        status = CM_NB_VIPCOK;
    }
    else
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Internal name not registered yet: %s", name);
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to compose the source name");
        goto Exit;
    }
    length = retValue;

    if ((retValue = cmNetBiosEncodeName(name, (NQ_BYTE*)(pHdr + 1) + retValue)) <= 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to compose the destination name");
        goto Exit;
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
        LOGERR(CM_TRC_LEVEL_ERROR, "Unable to send internal response");
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:0x%x", result);
    return result;
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
    NQ_STATUS result = NQ_FAIL;

    LOGFB(CM_TRC_LEVEL_FUNC_COMMON, "name:%s pIpc:%p adapter:%p", name ? name : "", pIpc, adapter);

    /* set no port */

    if (ndInternalNameSetPort(name, 0) != NQ_SUCCESS)
    {
		LOGERR(CM_TRC_LEVEL_ERROR, "Internal name not registered yet: %s", name);
        goto Exit;
    }
    result = NQ_SUCCESS;

Exit:
    LOGFE(CM_TRC_LEVEL_FUNC_COMMON, "result:0x%x", result);
    return result;
}

#endif /* UD_ND_INCLUDENBDAEMON */

