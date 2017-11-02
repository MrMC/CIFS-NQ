
/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of the Named Pipes subprotocol
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 28-November-2004
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cspipes.h"
#include "csdataba.h"
#include "csparams.h"
#include "cstransa.h"
#include "csdcerpc.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

#ifdef UD_CS_INCLUDERPC

/*====================================================================
 * PURPOSE: Continue processing TRANSACTION command for a PIPE request
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT pointer to the TRANSACTION descriptor
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csNamedPipeEntry(
    CSTransactionDescriptor* descriptor /* transaction descriptor */
    )
{
    CMCifsStatus error;                 /* for composing DOS-style error */
    CSFid fid;                          /* pipe fid */
    NQ_UINT32 returnValue;              /* function result */
    CMCifsPipeResponse* pipeResponse;   /* casted request */
    NQ_BYTE* pData;                     /* pointer to the data start in response */
    CSFile* pFile;                      /* pointer to pipe file descriptor */
    CSName* pName;                      /* pointer to pipe file name descriptor */
    NQ_BOOL unicodeRequired;            /* client requires UNICODE */

    TRCB();

    /* read unicode flag */

    unicodeRequired = cmLtoh16(cmGetSUint16(descriptor->hdrOut->flags2)) & SMB_FLAGS2_UNICODE;

    /* cast pointers */
    pipeResponse = (CMCifsPipeResponse*) descriptor->pBuf;

    /* find pipe */

    fid = cmGetUint16(&descriptor->setupIn[1]);
    fid = cmLtoh16(fid);

    pFile = csGetFileByFid(
        fid,
        cmLtoh16(cmGetSUint16(descriptor->hdrOut->tid)),
        cmLtoh16(cmGetSUint16(descriptor->hdrOut->uid))
        );

    if (   pFile == NULL
        || !pFile->isPipe
        || (pName = csGetNameByNid(pFile->nid)) == NULL
       )
    {
        TRCERR("Unknown pipe");
        error = csErrorReturn(SMB_STATUS_INVALID_PIPE_STATE, DOS_ERRbadpipe);

        TRCE();
        return error;
    }

    /* find place to put response data */
    pData = (NQ_BYTE*) (pipeResponse + 1);
    pData = cmAllignTwo(pData);
    descriptor->paramOut = pData;
    descriptor->dataOut = pData;

    /* switch by pipe function */
    switch (cmLtoh16(cmGetUint16(&descriptor->setupIn[0])))
    {
    case SMB_PIPE_TRANSACT:
        returnValue = csDcerpcTransact(
            pFile,
            descriptor,
            (NQ_UINT)(CS_MAXBUFFERSIZE - (NQ_UINT)(pData - (NQ_BYTE*)descriptor->hdrOut))
            );
        descriptor->paramCount = 0;
        break;
    case SMB_PIPE_QUERYHANDSTATE:
        pData = cmAllignTwo(pData);
        cmPutUint16(pData, cmHtol16(
                                  SMB_PIPE_HANDSTATE_RETURNIMMEDIATELY
                                | SMB_PIPE_HANDSTATE_CLIENTENDPOINT
                                | SMB_PIPE_HANDSTATE_MESSAGEPIPE
                                | SMB_PIPE_HANDSTATE_READMESSAGES
                                | 1
                                )
            );
        descriptor->dataCount = 0;                    /* no data */
        descriptor->paramCount = 4;
        descriptor->dataOut += descriptor->paramCount;
        returnValue = 0;
        break;
    case SMB_PIPE_SETHANDSTATE:
        descriptor->paramCount = 0;
        descriptor->dataCount = 0;
        returnValue = 0;
        break;
    case SMB_PIPE_QUERYINFO:
        {
            CMCifsPipeInfo* pInfo = (CMCifsPipeInfo*)pData;
                                                /* pointer to the resulting structure */
            cmPutSUint16(
                pInfo->outputBufferSize,
                cmHtol16((NQ_UINT16)(CS_MAXBUFFERSIZE - (NQ_UINT16)(pData - (NQ_BYTE*)descriptor->hdrOut)))
                );
            cmPutSUint16(
                pInfo->inputBufferSize,
                cmHtol16(  CIFS_MAX_DATA_SIZE16
                         - sizeof(CMCifsHeader)
                         - sizeof(CMCifsTransactionRequest)
                         - 2 * 2
                        )
                );
            pInfo->maximumInstances = 1;
            pInfo->currentInstances = 1;
            pInfo->pipeNameLength = (NQ_BYTE)(cmTStrlen(pName->name) + 1) / sizeof(NQ_TCHAR);
            if (unicodeRequired)
            {
                pInfo->pipeNameLength = (NQ_BYTE)(pInfo->pipeNameLength * sizeof(NQ_WCHAR));
                cmTcharToUnicode((NQ_WCHAR*)(pData + sizeof(*pInfo)), pName->name);
            }
            else
            {
                cmTcharToAnsi((NQ_CHAR*)(pData + sizeof(*pInfo)), pName->name);
            }
            if (descriptor->maxData < sizeof(*pInfo))
                descriptor->dataCount = descriptor->maxData;
            else
                descriptor->dataCount = (NQ_UINT16)(sizeof(*pInfo) + pInfo->pipeNameLength);
            descriptor->paramCount = 0;
            returnValue = 0;
            break;
        }
    case SMB_PIPE_CALL:
    case SMB_PIPE_WAIT:
    case SMB_PIPE_PEEK:
    case SMB_PIPE_RAWREAD:
    case SMB_PIPE_RAWWRITE:
    default:
        {
            TRCERR("Pipe function is not supported");
            TRC1P(" code %d: ", cmLtoh16(descriptor->setupIn[0]));
            error = csErrorReturn(SMB_STATUS_INVALID_PIPE_STATE, DOS_ERRbadpipe);

            TRCE();
            return error;
        }
    }

    descriptor->setupCount = 0;
    cmPutSUint16(pipeResponse->byteCount,
                 cmHtol16((NQ_UINT16)(1 + descriptor->dataCount + descriptor->paramCount)
                ));
    pipeResponse->pad = 0;

    TRCE();
    return returnValue;

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
csNamedPipePrepareLateResponse(
    CSLateResponseContext* context
    )
{
    csTransactionPrepareLateResponse(context);
    context->commandData += sizeof(CMCifsPipeResponse);
    context->commandDataSize -= (NQ_COUNT)sizeof(CMCifsPipeResponse);

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
csNamedPipeSendLateResponse(
    CSLateResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT dataLength
    )
{
    CMCifsPipeResponse* pipeResponse;            /* casted response */

    context->commandData -= sizeof(CMCifsPipeResponse);
    pipeResponse = (CMCifsPipeResponse*)context->commandData;
    cmPutSUint16(pipeResponse->byteCount, (NQ_UINT16)(dataLength + 1));
    return csTransactionSendLateResponse(context, status, (NQ_COUNT)(dataLength + sizeof(*pipeResponse)));
}

#endif /* UD_CS_INCLUDERPC */

#endif /* UD_NQ_INCLUDECIFSSERVER */

