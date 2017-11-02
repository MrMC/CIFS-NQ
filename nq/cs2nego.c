/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 Negotiate command handler
 *--------------------------------------------------------------------
 * MODULE        : CS
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 02-Dec-2008
 ********************************************************************/

#include "csparams.h"
#include "cmgssapi.h"
#include "cmcrypt.h"
#include "cs2disp.h"
#include "csauth.h"
#include "amspnego.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

#define RESPONSE_DATASIZE 65

static void writeSecurityData(CMBufferWriter *writer)
{
    CMBlob blob; 

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    blob = amSpnegoServerGenerateMechList();
    if (NULL != blob.data)
    {
        cmBufferWriteBytes(writer, blob.data, blob.len);
        cmMemoryFreeBlob(&blob);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
}

static void writeResponseData(CMSmb2Header *header, CMBufferWriter *writer)
{
    CMTime time;
    CMBufferWriter sbw;
    NQ_UINT16 securityMode = 0;

    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    cmBufferWriteUint16(writer, RESPONSE_DATASIZE);    /* data length */
#ifdef UD_CS_MESSAGESIGNINGPOLICY    
    securityMode |= (NQ_UINT16)((csIsMessageSigningEnabled() ? SMB2_NEGOTIATE_SIGNINGENABLED : 0) | (csIsMessageSigningRequired() ? SMB2_NEGOTIATE_SIGNINGREQUIRED : 0));
#endif    
    cmBufferWriteUint16(writer, securityMode);         /* security mode */
    cmBufferWriteUint16(writer, SMB2_DIALECTREVISION); /* dialect revision */
    cmBufferWriteUint16(writer, 0);                    /* reserved */
    cmUuidWrite(writer, cs2GetServerUuid());           /* server GUID */
    cmBufferWriteUint32(writer, 0);                    /* capabilities (0) */
    cmBufferWriteUint32(writer, CS_MAXBUFFERSIZE);     /* max transact size */
    cmBufferWriteUint32(writer, CS_SMB2_MAX_READ_SIZE);/* max read size */
    cmBufferWriteUint32(writer, CS_SMB2_MAX_WRITE_SIZE);/* max write size */

    cmGetCurrentTime(&time);
    cmTimeWrite(writer, &time);                        /* current time */
    cmTimeWrite(writer, cs2GetServerStartTime());      /* server start time */

    /* write security buffer data with a dedicated writer (offsetting 8 bytes from the current position) */
    cmBufferWriterBranch(writer, &sbw, 8);
    cmBufferWriteUint16(writer, (NQ_UINT16)cmSmb2HeaderGetWriterOffset(header, &sbw)); /* security buffer offset */    
    writeSecurityData(&sbw);
    cmBufferWriteUint16(writer, (NQ_UINT16)cmBufferWriterGetDataCount(&sbw));          /* security data size */
    cmBufferWriteUint32(writer, 0);                                                    /* reserved */

    /* synchronize the main writer (set it after last written byte in the security buffer */
    cmBufferWriterSync(writer, &sbw);

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
}

static NQ_BOOL isClientDialectSupported(CMBufferReader *reader, NQ_UINT16 count)
{
    NQ_UINT16 dialect;

    for (; count > 0; --count)
    {
        cmBufferReadUint16(reader, &dialect);

        if (dialect == SMB2_DIALECTREVISION)
            return TRUE;
    }

    return FALSE;
}

static NQ_UINT32 negotiate(CSSession *connection)
{
    LOGFB(CM_TRC_LEVEL_FUNC_TOOL);

    if (connection != NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Second negotiate for same connection");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return SMB_STATUS_INVALID_PARAMETER;
    }

    /* allocate new connection entry */
    connection = csGetNewSession();

    if (connection == NULL)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Couldn't get new connection");
        LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
        return SMB_STATUS_REQUEST_NOT_ACCEPTED;
    }

    cmGenerateRandomEncryptionKey(connection->encryptionKey);
    connection->smb2 = TRUE;
    connection->credits = SMB2_NUMCREDITS;

#ifdef UD_CS_INCLUDEPASSTHROUGH
    if (csIsPassthroughRequired()
#ifdef UD_CS_INCLUDEDOMAINMEMBERSHIP
         && !udGetComputerSecret(NULL)
#endif /* UD_CS_INCLUDEDOMAINMEMBERSHIP */
        )
    {
        /* establish connection to PDC and exchange Negotiate */
        csPassthroughNegotiate(NULL, TRUE);
    }
#endif  /* UD_CS_INCLUDEPASSTHROUGH */  

    LOGFE(CM_TRC_LEVEL_FUNC_TOOL);
    return 0;
}

/*====================================================================
 * PURPOSE: Perform SMB2 Negotiate processing
 *--------------------------------------------------------------------
 * PARAMS:  IN in - pointer to the parsed SMB2 header descriptor
 *          OUT out - pointer to the response header structure
 *          IN reader - request reader pointing to the second command field
 *          IN connection - pointer to the session structure
 *          IN user - pointer to the user structure
 *          IN tree - pointer to the tree structure
 *          OUT writer - pointer to the response writer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB2 Create command.
 *====================================================================
 */

NQ_UINT32 csSmb2OnNegotiate(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *session, CSTree *tree, CMBufferWriter *writer)
{
    /* todo: check for packet size against read buffer size */
    NQ_UINT16 dialects, security;
    NQ_UINT32 capabilities, status = 0;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

    cmBufferReadUint16(reader, &dialects);
    cmBufferReadUint16(reader, &security);
    cmBufferReaderSkip(reader, 2);           /* reserved (2) */
    cmBufferReadUint32(reader, &capabilities);
    cmBufferReaderSkip(reader, 16 + 8);      /* client GUID (16) + client start time (8) */

    /* currently only SMB2_DIALECTREVISION is supported */
    if (!isClientDialectSupported(reader, dialects))
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Unsupported dialect");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_NOT_SUPPORTED;
    }    

    /* process negotiate request */
    if ((status = negotiate(connection)) == 0)
    {
        writeResponseData(out, writer);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return status;
}

/*====================================================================
 * PURPOSE: Perform SMB1 Negotiate processing
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT - pointer to the response 
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   This function is called on SMB1 Negotiate, when SMB2 supported
 *====================================================================
 */

NQ_UINT32 csSmb2OnSmb1Negotiate(NQ_BYTE **response)
{
    CMBufferWriter writer;
    CMSmb2Header header;
    NQ_UINT32 status;

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);
    
    if ((status = negotiate(csGetSessionBySocket())) == 0)
    {
        /* compose SMB2 response (overwrite SMB1 header) */
        cmBufferWriterInit(&writer, *response - 32, 0);
        cmSmb2HeaderInitForResponse(&header, &writer, 1);
        cmSmb2HeaderWrite(&header, &writer);
        writeResponseData(&header, &writer);

        *response = cmBufferWriterGetPosition(&writer);
    }

    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return status;
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */

