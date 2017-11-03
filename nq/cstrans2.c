/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : Implementation of the TRANSACTION2 command
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 13-July-2003
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "cstrans2.h"
#include "csdataba.h"
#include "csparams.h"
#include "csdispat.h"
#include "csbrowse.h"
#include "csutils.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

/* This code implements the TRANSACTION2 command. Implementation is a dispatcher of
   subcommands. It uses the same subcommand descriptor as */

/*
    Static functions and data
    -------------------------
 */

/* Table of subprotocol commands, where function pointer is indexed by the
   subcommand code. Unimplemented commands are specified by NULLs */

static const Transaction2Function commands[] =
{
     csTransaction2Open                 /* 0x00 Create file with extended attributes */
    ,csTransaction2FindFirst            /* 0x01 Begin search for files */
    ,csTransaction2FindNext             /* 0x02 Resume search for files */
    ,csTransaction2QueryFsInformation   /* 0x03 Get file system information */
    ,NULL                               /* 0x04 Reserved */
    ,csTransaction2QueryPathInformation /* 0x05 Get information about a named file or directory */
    ,csTransaction2SetPathInformation   /* 0x06 Set information about a named file or directory */
    ,csTransaction2QueryFileInformation /* 0x07 Get information about a handle */
    ,csTransaction2SetFileInformation   /* 0x08 Set information by handle */
    ,NULL                               /* 0x09 Not implemented by NT server */
    ,NULL                               /* 0x0A Not implemented by NT server */
    ,NULL                               /* 0x0B Not implemented by NT server */
    ,NULL                               /* 0x0C Not implemented by NT server */
    ,csTransaction2CreateDirectory      /* 0x0D Create directory with extended attributes */
    ,NULL                               /* 0x0E Session setup with extended security information */
    ,NULL                               /* 0x10 Get a Dfs referral */
    ,NULL                               /* 0x11 Report a Dfs knowledge inconsistency */
};

/*====================================================================
 * PURPOSE: Perform TRANSACTION2 command
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
csComTransaction2(
    NQ_BYTE* pRequest,
    CMCifsHeader* pHeaderOut,
    NQ_BYTE** pResponse
    )
{
    const CMCifsTransaction2Request* transRequest;  /* casted request */
    CMCifsTransaction2Response* transResponse;      /* casted response */
    NQ_UINT32 returnValue;                             /* error code in NT format or 0 for no error */
    NQ_UINT16 subCommand;                          /* subcommand code in Setup[0] */
    CSTransaction2Descriptor descriptor;        /* to pass parameter to/from a subcommand */

    TRCB();

    /* cast pointers */

    transRequest = (CMCifsTransaction2Request*) pRequest;
    transResponse = (CMCifsTransaction2Response*) *pResponse;

    /* check format */

    if (transRequest->transHeader.wordCount != SMB_TRANSACTION2_REQUEST_WORDCOUNT)
    {
        TRCERR("Illegal WordCount");
        TRCE();
        return csErrorReturn(SMB_STATUS_UNSUCCESSFUL, SRV_ERRerror);
    }

    /* prepare pointers and offsets for response */

    descriptor.pHeaderOut = pHeaderOut;
    descriptor.requestData = transRequest;
    descriptor.pParams = *pResponse + sizeof(*transResponse);
    /* descriptor.pParams = cmAllignTwo(descriptor.pParams); */
    descriptor.parameterCount = 0;  /* not yet */

    /* dispatch the subcommand */

    subCommand = cmLtoh16(cmGetSUint16(transRequest->subCommand));

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

    if (returnValue != 0)
    {
        TRCE();
        return returnValue;
    }

    /* compose the response */

    {
        NQ_UINT16 offset;   /* for calculating offsets */

        transResponse->transHeader.wordCount = SMB_TRANSACTION2_RESPONSE_WORDCOUNT;
        offset = (NQ_UINT16)(descriptor.pParams - (NQ_BYTE*)pHeaderOut);
        cmPutSUint16(transResponse->transHeader.parameterOffset, cmHtol16(offset));
        cmPutSUint16(transResponse->transHeader.parameterCount, cmHtol16(descriptor.parameterCount));
        cmPutSUint16(transResponse->transHeader.totalParameterCount, cmGetSUint16(transResponse->transHeader.parameterCount));
        transResponse->transHeader.setupCount = 0;
        cmPutSUint16(transResponse->transHeader.dataCount, cmHtol16(descriptor.dataCount));
        cmPutSUint16(transResponse->transHeader.totalDataCount, cmGetSUint16(transResponse->transHeader.dataCount));
        offset = (NQ_UINT16)(descriptor.pData - (NQ_BYTE*)pHeaderOut);
        cmPutSUint16(transResponse->transHeader.dataOffset, cmHtol16(offset));
        cmPutSUint16(transResponse->transHeader.parameterDisplacement, 0);
        cmPutSUint16(transResponse->transHeader.dataDisplacement, 0);
        cmPutSUint16(transResponse->transHeader.reserved, 0);
        transResponse->transHeader.reserved2 = 0;
        *pResponse = descriptor.pData + descriptor.dataCount;
        offset = (NQ_UINT16)((*pResponse - (NQ_BYTE*)(&transResponse->byteCount)) - (NQ_UINT16)sizeof(transResponse->byteCount));
        cmPutSUint16(transResponse->byteCount, cmHtol16(offset));
    }

    TRCE();
    return returnValue;
}

#endif /* UD_NQ_INCLUDECIFSSERVER */

