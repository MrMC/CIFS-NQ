/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of the NT_TRANSACTION command
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 21-August-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csnttran.h"
#include "csdataba.h"
#include "csparams.h"
#include "csdispat.h"
#include "csnotify.h"
#include "csutils.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This code implements the NT_TRANSACTION command. Implementation is a dispatcher of
   subcommands. Subcommands are implemented in other source files - according to their
   categories. */

/*
    Static functions and data
    -------------------------
 */

/* Table of subprotocol commands, where function pointer is indexed by the
   subcommand code. Unimplemented commands are specified by NULLs */

static const NtTransactionFunction commands[] =
{
    NULL                                    /* placeholder */
    ,csNtTransactionCreate                  /* 0x01 Create or Open a file */
    ,NULL                                   /* 0x02 Resume search for files */
    ,csNtTransactionSetSecurityDescriptor   /* 0x03 Set security descriptor */
    ,csNtTransactionNotifyChange            /* 0x04 Notify Change */
    ,NULL                                   /* 0x05 reserved for Rename */
    ,csNtTransactionQuerySecurityDescriptor /* 0x06 Retrieve security descriptor info */
};

/* Empty security descriptor (DACL)
 * It is not really empty:
 *      Full access for Everyone (S-1-1-0), no inheritance
 * */

static const NQ_BYTE emptySdDACL[] =
    { 0x01, 0x00, 
      0x94, 0x84, 
      0,0,0,0,
      0,0,0,0,
      0,0,0,0,
      0x14,0,0,0,
      0x02, 0x00, 0x1c, 0x00, 
      0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x14, 0x00, 0xff, 0x01, 
      0x1f, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
      0x00, 0x00, 0x00, 0x00      
     };

/* Empty security descriptor (Owner)
 * It is not really empty:
 *      Owner for Everyone (S-1-1-0)
 * */

static const NQ_BYTE emptySdOwner[] =
    { 0x01, 0x00, /* revision */
      0x00, 0x80, /* type */
      0x14,0,0,0, /* offset to owner SID */
      0,0,0,0,    /* offset to group SID */
      0,0,0,0,    /* offset to SACL */
      0,0,0,0,    /* offset to DACL */
      0x01,                               /* revision */
      0x01,                               /* num of authorities */ 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x01, /* authority */
      0x00, 0x00, 0x00, 0x00              /* sub-authorities*/ 
     };

#define SECURITY_INFO_OWNER 0x00000001
#define SECURITY_INFO_GROUP 0x00000002
#define SECURITY_INFO_DACL  0x00000004
#define SECURITY_INFO_SACL  0x00000008

const NQ_BYTE* csGetEmptySd(NQ_UINT32 filter, NQ_UINT32 *sdLength)
{
    switch (filter)
    {
        case SECURITY_INFO_OWNER:
            *sdLength = sizeof(emptySdOwner);
            return emptySdOwner;
        case SECURITY_INFO_DACL:
        default:
            *sdLength = sizeof(emptySdDACL);
            return emptySdDACL;
    }
}


/*====================================================================
 * PURPOSE: Perform NT_TRANSACTION command
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the command in the message
 *          IN header of the outgoing message
 *          IN/OUT double pointer to the response
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   Function parses the command pointed by the first parameter, decoposes it into
 *          setup, parameters and data and calls an approriate subcommand processor. Then it
 *          uses the returned values to compose the response pointers to parameters and data.
 *====================================================================
 */

NQ_UINT32
csComNtTransaction(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    const CMCifsNtTransactionRequest* transRequest; /* casted request */
    CMCifsNtTransactionResponse* transResponse;     /* casted response */
    NQ_UINT32 returnValue;                          /* error code in NT format or 0 for no error */
    NQ_UINT16 subCommand;                           /* subcommand code in Setup[0] */
    CSNtTransactionDescriptor descriptor;           /* to pass parameter to/from a subcommand */

    TRCB();

    /* cast pointers */

    transRequest = (CMCifsNtTransactionRequest*) pRequest;
    transResponse = (CMCifsNtTransactionResponse*) *pResponse;

    /* prepare pointers and offsets for response */

    descriptor.pHeaderOut = pHeaderOut;
    descriptor.requestData = transRequest;
    descriptor.pParams = *pResponse + sizeof(*transResponse);
    descriptor.pParams = cmAllignTwo(descriptor.pParams);
    descriptor.parameterCount = 0;  /* not yet */

    /* dispatch the subcommand */

    subCommand = cmLtoh16(cmGetSUint16(transRequest->function));

    /* analyse the result and compose the response */

    if (   (subCommand >= sizeof(commands)/sizeof(commands[0]))
        || commands[subCommand] == NULL)
    {
        TRCERR("Unsupported subcommand");
        TRC1P("  subcommand: %d", subCommand);
        TRCE();
        return csErrorReturn(SMB_STATUS_NOT_SUPPORTED, (NQ_UINT32)SRV_ERRnosupport);
    }

    returnValue = (*commands[subCommand])(&descriptor);

    if (cmCifsIsError(returnValue))
    {
        TRCE();
        return returnValue;
    }

    /* compose the response */
    {
        NQ_UINT32 offset;    /* for calculating offsets */

        transResponse->wordCount = SMB_NTTRANSACTION_RESPONSE_WORDCOUNT;
        offset = (NQ_UINT32)(descriptor.pParams - (NQ_BYTE*)pHeaderOut);
        cmPutSUint32(transResponse->parameterOffset, cmHtol32(offset));
        cmPutSUint32(transResponse->parameterCount, cmHtol32(descriptor.parameterCount));
        cmPutSUint32(transResponse->totalParameterCount, cmGetSUint32(transResponse->parameterCount));
        cmPutSUint32(transResponse->dataCount, cmHtol32(descriptor.dataCount));
        cmPutSUint32(transResponse->totalDataCount, cmGetSUint32(transResponse->dataCount));
        offset = (NQ_UINT32)(descriptor.pData - (NQ_BYTE*)pHeaderOut);
        cmPutSUint32(transResponse->dataOffset, cmHtol32(offset));
        cmPutSUint32(transResponse->parameterDisplacement, 0);
        cmPutSUint32(transResponse->dataDisplacement, 0);
        transResponse->reserved[0] = 0;
        transResponse->reserved[1] = 0;
        transResponse->reserved[2] = 0;
        transResponse->setupCount = 0;
        *pResponse = descriptor.pData + descriptor.dataCount;
        offset = (NQ_UINT32)((NQ_UINT32)(*pResponse - (NQ_BYTE*)(&transResponse->byteCount)) - sizeof(transResponse->byteCount));
        cmPutSUint16(transResponse->byteCount, cmHtol16((NQ_UINT16)offset));
    }

    TRCE();
    return returnValue;
}

/*====================================================================
 * PURPOSE: Perform NT_TRANSACT_QUERY_SECURITY_DESCRIPTOR subcommand of
 *          NT_TRANSACTION protocol
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT structure with subcommand parameters:
 *              IN pointer to the CIFS header
 *              IN pointer to the parameter area
 *              OUT pointer to the data area
 *              OUT length of the parameter area
 *              OUT length of the data area
 *
 * RETURNS: SMB error or 0 on success
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csNtTransactionQuerySecurityDescriptor(
    CSNtTransactionDescriptor* descriptor
    )
{
    CMCifsNtTransactionSecurityRequest* securityRequest;    /* casted request */
    NQ_UINT32 returnValue;                                  /* various values */
    CSFile* pFile;                  /* pointer to file descriptor */
    CSFid fid;                      /* required FID */
    CSUid uid;                      /* required UID */
    CSTid tid;                      /* required TID */
               

    TRCB();

    /* cast pointers */

    securityRequest = (CMCifsNtTransactionSecurityRequest*) (
                          (NQ_BYTE*)descriptor->requestData
                        - sizeof(CMCifsHeader)
                        + cmLtoh32(cmGetSUint32(descriptor->requestData->parameterOffset))
                        );

    fid = cmLtoh16(cmGetSUint16(securityRequest->fid));
    uid = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->uid));
    tid = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->tid));

    /* check access to share */

    if ((returnValue = csCanReadShare(tid)) != NQ_SUCCESS)
    {
        TRCERR("Access denied");
        TRCE();
        return returnValue;
    }

    pFile = csGetFileByFid(fid, tid, uid);
    if (pFile == NULL)
    {
        TRCERR("Illegal FID");
        TRC1P("  value %d", fid);
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

    descriptor->parameterCount = 4;
    descriptor->pData = descriptor->pParams + descriptor->parameterCount;

    returnValue = (NQ_UINT32)syGetSecurityDescriptor(
        pFile->file,
        cmLtoh32(cmGetSUint32(securityRequest->securityInformation)),
        descriptor->pData
        );
    if ((NQ_INT)returnValue == NQ_FAIL)
    {
        csGetEmptySd(cmLtoh32(cmGetSUint32(securityRequest->securityInformation)), &returnValue);
        syMemcpy(descriptor->pData, csGetEmptySd(cmLtoh32(cmGetSUint32(securityRequest->securityInformation)), &returnValue), returnValue);
    }
/*    {
        TRCERR("Unable to get security descriptor");
        TRCE();
        return csErrorReturn(SMB_STATUS_NOT_SUPPORTED, (NQ_UINT32)SRV_ERRnosupport);
    }*/

    cmPutUint32(descriptor->pParams, cmHtol32(returnValue));
    if ((NQ_UINT32) cmLtoh32(cmGetSUint32(descriptor->requestData->maxDataCount)) < returnValue)
    {
        descriptor->dataCount = 0;
        TRCERR("Buffer overflow");
        TRCE();
        return SMB_STATUS_INTERNAL_BUFFER_TOO_SMALL;
    }

    descriptor->dataCount = (NQ_UINT16)returnValue;

    TRCE();

    return 0;
}

/*====================================================================
 * PURPOSE: Perform NT_TRANSACT_SET_SECURITY_DESCRIPTOR subcommand of
 *          NT_TRANSACTION protocol
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT structure with subcommand parameters:
 *              IN pointer to the CIFS header
 *              IN pointer to the parameter area
 *              OUT pointer to the data area
 *              OUT length of the parameter area
 *              OUT length of the data area
 *
 * RETURNS: SMB error or 0 on success
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csNtTransactionSetSecurityDescriptor(
    CSNtTransactionDescriptor* descriptor
    )
{
    CMCifsNtTransactionSecurityRequest* securityRequest;    /* casted request */
    NQ_UINT32 returnValue;                                  /* various values */
    CSFile* pFile;                  /* pointer to file descriptor */
    const NQ_WCHAR* pFileName;      /* pointer to file name */
    CSFid fid;                      /* required FID */
    NQ_BYTE* pData;                 /* pointer to the security descriptor */
    CSUid uid;                      /* required UID */
    CSTid tid;                      /* required TID */
    NQ_UINT32 sdLength;             /* security descriptor length */

    TRCB();

    /* cast pointers */

    securityRequest = (CMCifsNtTransactionSecurityRequest*) (
                          (NQ_BYTE*)descriptor->requestData
                        - sizeof(CMCifsHeader)
                        + cmLtoh32(cmGetSUint32(descriptor->requestData->parameterOffset))
                        );

    pData =   (NQ_BYTE*)descriptor->requestData
            + cmLtoh32(cmGetSUint32(descriptor->requestData->dataOffset))
            - sizeof(CMCifsHeader);

    fid = cmLtoh16(cmGetSUint16(securityRequest->fid));
    uid = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->uid));
    tid = cmLtoh16(cmGetSUint16(descriptor->pHeaderOut->tid));

    /* check access to share */

    if ((returnValue = csCanWriteShare(tid)) != NQ_SUCCESS)
    {
        TRCERR("Access denied");
        TRCE();
        return returnValue;
    }

    pFile = csGetFileByFid(fid, tid, uid);
    if (pFile == NULL)
    {
        TRCERR("Illegal FID");
        TRC1P("  value %d", fid);
        TRCE();
        return csErrorReturn(SMB_STATUS_INVALID_HANDLE, DOS_ERRbadfid);
    }

    descriptor->parameterCount = 0;
    descriptor->pData = descriptor->pParams;

    returnValue = (NQ_UINT32)sySetSecurityDescriptor(
        pFile->file,
        cmLtoh32(cmGetSUint32(securityRequest->securityInformation)),
        pData,
        cmLtoh32(cmGetSUint32(descriptor->requestData->dataCount))
        );
    csGetEmptySd(cmLtoh32(cmGetSUint32(securityRequest->securityInformation)), &sdLength);
    if (    (NQ_INT)returnValue == NQ_FAIL
        && 0 != syMemcmp(pData, csGetEmptySd(cmLtoh32(cmGetSUint32(securityRequest->securityInformation)), &sdLength), sdLength)
       )
    {
        TRCERR("Unable to set security descriptor");
        TRCE();
        return csErrorReturn(SMB_STATUS_NOT_SUPPORTED, (NQ_UINT32)SRV_ERRnosupport);
    }

    pFileName = csGetFileName(pFile->fid);
    if (pFileName == NULL)
    {
        TRCERR("File name corrupted");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }
    csNotifyImmediatelly(pFileName, SMB_NOTIFYCHANGE_MODIFIED, SMB_NOTIFYCHANGE_SECURITY);
    descriptor->dataCount = 0;

    TRCE();

    return 0;
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

