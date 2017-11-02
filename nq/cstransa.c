
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of the TRANSACTION command
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 13-July-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cstransa.h"
#include "csdataba.h"
#include "csparams.h"
#include "csdispat.h"
#include "csbrowse.h"
#include "csrapfnc.h"
#include "csutils.h"
#include "cspipes.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This code implents the TRANSACTION command. The implementation is a dispatcher of the
   TRANSACTION subprotocols and it calls an appropriate client. */

/*
    Static functions and data
    -------------------------
 */

/* transaction client descriptor */

typedef struct
{
    const NQ_CHAR *name;                                   /* client name */
    NQ_UINT32 (*function)(CSTransactionDescriptor*);    /* function, performing the command */
} ClientDescriptor;

/* the table of transaction clients */

static const ClientDescriptor clientTable[] =
{
     { "\\PIPE\\LANMAN", csRapApiEntry }

#ifdef UD_NQ_USETRANSPORTNETBIOS
    ,{ "\\MAILSLOT\\BROWSE", csMailslotBrowse }
#endif /* UD_NQ_USETRANSPORTNETBIOS */

#ifdef UD_CS_INCLUDERPC
    ,{ "\\PIPE\\", csNamedPipeEntry }
#endif
};

/*====================================================================
 * PURPOSE: Perform TRANSACTION command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the first parameter.
 *          It partly composes a response and asks the subcommand processor to do
 *          the actual work.
 *====================================================================
 */

NQ_UINT32
csComTransaction(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    CMCifsTransactionRequest* transactRequest;              /* casted request */
    CMCifsTransactionResponse* transactResponse;            /* casted response */
    NQ_UINT32 returnValue;                                  /* error code in NT format or 0 for no error */
    NQ_STATIC NQ_CHAR requiredClient[UD_FS_FILENAMELEN + 1];/* client name for the request */
    NQ_BOOL unicodeRequired;                                /* client requires UNICODE */

    TRCB();

    /* read unicode flag */

    unicodeRequired = cmLtoh16(cmGetSUint16(pHeaderOut->flags2)) & SMB_FLAGS2_UNICODE;

    /* cast pointers */

    transactRequest = (CMCifsTransactionRequest*) pRequest;
    transactResponse = (CMCifsTransactionResponse*) *pResponse;

    /* withdraw client (transaction) name from the request */
    {
        NQ_CHAR* pName;        /* name in the request */

        pName = (NQ_CHAR*)(transactRequest + 1) + 2 * (transactRequest->setupCount + 1);
        if (unicodeRequired)
        {
            pName = (NQ_CHAR*)cmAllignTwo(pName);
            syUnicodeToAnsi(requiredClient, (NQ_WCHAR*)pName);
        }
        else
            syStrcpy(requiredClient, (NQ_CHAR*)pName);
    }

    /* look for a client in registered clients */

    {
        NQ_UINT i;     /* just an index */

        for (i = 0; i < sizeof(clientTable)/sizeof(clientTable[0]); i++)
        {
            if (syStrncmp(
                    requiredClient,
                    clientTable[i].name,
                    syStrlen(clientTable[i].name)
                    ) == 0
               )
            {
                CSTransactionDescriptor descriptor;     /* data descriptor */

                descriptor.hdrOut = pHeaderOut;
                descriptor.dataIn = pRequest - sizeof(CMCifsHeader) + cmLtoh16(cmGetSUint16(transactRequest->dataOffset));
                descriptor.dataCount = cmLtoh16(cmGetSUint16(transactRequest->dataCount));
                descriptor.maxData = cmLtoh16(cmGetSUint16(transactRequest->maxDataCount));
                descriptor.paramIn = pRequest - sizeof(CMCifsHeader) + cmLtoh16(cmGetSUint16(transactRequest->parameterOffset));
                descriptor.paramCount = cmLtoh16(cmGetSUint16(transactRequest->parameterCount));
                descriptor.maxParam = cmLtoh16(cmGetSUint16(transactRequest->maxParameterCount));
                descriptor.setupIn = (NQ_UINT16*)(transactRequest + 1);
                descriptor.setupCount = cmLtoh16(transactRequest->setupCount);
                descriptor.maxSetup = cmLtoh16(transactRequest->maxSetupCount);
                descriptor.pBuf = (NQ_BYTE*)(transactResponse + 1);

                returnValue = clientTable[i].function(&descriptor);

                /* set up the response header */
                transactResponse->wordCount = (NQ_BYTE)(SMB_TRANSACTION_RESPONSE_WORDCOUNT + descriptor.setupCount);
                cmPutSUint16(transactResponse->totalParameterCount, cmHtol16(descriptor.paramCount));
                cmPutSUint16(transactResponse->totalDataCount, cmHtol16(descriptor.dataCount));
                cmPutSUint16(transactResponse->dataCount, cmHtol16(descriptor.dataCount));
                cmPutSUint16(transactResponse->dataOffset, cmHtol16((NQ_UINT16)(descriptor.dataOut
                                                        - (NQ_BYTE*)pHeaderOut
                                                       )));
                cmPutSUint16(transactResponse->dataDisplacement, 0);
                cmPutSUint16(transactResponse->parameterCount, cmHtol16(descriptor.paramCount));
                cmPutSUint16(transactResponse->parameterOffset, cmHtol16((NQ_UINT16)(descriptor.paramOut
                                                             - (NQ_BYTE*)pHeaderOut
                                                       )));
                cmPutSUint16(transactResponse->parameterDisplacement, 0);
                transactResponse->setupCount = (NQ_BYTE)descriptor.setupCount;
                cmPutSUint16(transactResponse->reserved, 0);
                transactResponse->reserved2 = 0;

                /* advance the pointer */

                *pResponse = descriptor.dataOut + descriptor.dataCount;

                TRCE();
                return returnValue;
            }
        }
    }

    TRCE();
    return csErrorReturn(SMB_STATUS_NOT_SUPPORTED, (NQ_UINT32)SRV_ERRnosupport);
}

/*====================================================================
 * PURPOSE: calculate subcommand data pointer and size
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the saved context
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   skips Transact header
 *====================================================================
 */

NQ_STATUS
csTransactionPrepareLateResponse(
    CSLateResponseContext* context
    )
{
    csDispatchPrepareLateResponse(context);
    context->commandData += sizeof(CMCifsTransactionResponse);
    context->commandDataSize -= (NQ_COUNT)sizeof(CMCifsTransactionResponse);

    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: send a response using saved context
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the saved context
 *          IN status to return
 *          IN number of bytes to return in the data section
 *
 * RETURNS: TRUE on success
 *
 * NOTES:   composes header and delegates send. Restrictions:
 *          - data section is provided and already placed into the buffer
 *          - parameter section is empty
 *          - setup is empty
 *====================================================================
 */


NQ_BOOL
csTransactionSendLateResponse(
    CSLateResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT dataLength
    )
{
    CMCifsTransactionResponse* transactResponse;            /* casted response */

    context->commandData -= sizeof(CMCifsTransactionResponse);
    transactResponse = (CMCifsTransactionResponse*)context->commandData;
    transactResponse->wordCount = SMB_TRANSACTION_RESPONSE_WORDCOUNT;
    cmPutSUint16(transactResponse->totalParameterCount, 0);
    cmPutSUint16(transactResponse->totalDataCount, (NQ_UINT16)(cmHtol16(dataLength) - sizeof(CMCifsPipeResponse)));
    cmPutSUint16(transactResponse->dataCount, (NQ_UINT16)(cmHtol16(dataLength) - sizeof(CMCifsPipeResponse)));
    cmPutSUint16(transactResponse->dataOffset, cmHtol16(sizeof(CMCifsTransactionResponse) + sizeof(CMCifsPipeResponse) + sizeof(CMCifsHeader)));
    cmPutSUint16(transactResponse->dataDisplacement, 0);
    cmPutSUint16(transactResponse->parameterCount, 0);
    cmPutSUint16(transactResponse->parameterOffset, cmGetSUint16(transactResponse->dataOffset));
    cmPutSUint16(transactResponse->parameterDisplacement, 0);
    transactResponse->setupCount = 0;
    cmPutSUint16(transactResponse->reserved, 0);
    transactResponse->reserved2 = 0;

    return csDispatchSendLateResponse(context, status, (NQ_COUNT)(dataLength + sizeof(*transactResponse)));
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

