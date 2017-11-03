/*********************************************************************
 *
 *           Copyright (c) 2008 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : SMB2 IOCTL command handler
 *--------------------------------------------------------------------
 * MODULE        : CS2
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATION DATE : 04-Jan-2009
 ********************************************************************/

#include "csparams.h"
#include "csutils.h"
#include "csdcerpc.h"
#include "cs2disp.h"

#if defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2)

/** 
 * Static definition, structures, data
 * -----------------------------------
 */

#define RESPONSE_LENGTH 48      /* the length of the response IOCTL header */

/* IOCTL context used for passing parameters to/from IOCTL/FSCTL methods */
typedef struct
{
    CSFile * file;                          /* IN/OUT file pointer */
    NQ_UINT32 ctlCode;                      /* IN IOCTL code */
    NQ_UINT32 inputCount;                   /* IN input count */
    const NQ_BYTE * pInput;                 /* IN pointer to the input data */
    NQ_UINT32 maxOutputResponse;            /* IN max output response */
    NQ_UINT32 flags;                        /* IN IOCTL flags */
    CMBufferWriter writer;                  /* IN/OUT method data writer */
} IoctlContext;

/* IOCTL method flags */
#define FL_USEFID   0x1             /* FID is used by the method */
#define FL_USESID	0x2				/* Session is needed for the method */

/* IOCTL Method descriptor */
typedef struct 
{
    NQ_UINT32 code;                 /* IOCTL code this method is a handle for */
    NQ_UINT32 flags;                /* various flags (see above) */
    NQ_UINT32                       /* error code or zero */
    (* handle)(                     /* method handle or NULL if not handled */
        IoctlContext * context      /* IN/OUT the context */
        );
} IoctlMethodDescriptor;

/* Handles and method descriptors */
static NQ_UINT32 handleGetObjectId(IoctlContext *); 
#ifdef UD_CS_INCLUDERPC 
static NQ_UINT32 handleTransceive(IoctlContext *); 
#endif /* UD_CS_INCLUDERPC */   
static NQ_UINT32 handleVerifyNegot(IoctlContext *);
IoctlMethodDescriptor ioctlMethods[] = {
    { 0x00060194, 0,            NULL },                   /* FSCTL_DFS_GET_REFERRALS */
    { 0x0011400C, FL_USEFID,    NULL },                   /* FSCTL_PIPE_PEEK */
#ifdef UD_CS_INCLUDERPC 
    { 0x0011C017, FL_USEFID,    handleTransceive },       /* FSCTL_PIPE_TRANSCEIVE */
#else /* UD_CS_INCLUDERPC */
    { 0x0011C017, 0,            NULL },                   /* FSCTL_PIPE_TRANSCEIVE */
#endif /* UD_CS_INCLUDERPC */   
    { 0x001440F2, 0,            NULL },                   /* FSCTL_SRV_COPYCHUNK */
    { 0x00144064, 0,            NULL },                   /* FSCTL_SRV_ENUMERATE_SNAPSHOTS */
    { 0x00140078, 0,            NULL },                   /* FSCTL_SRV_REQUEST_RESUME_KEY */
    { 0x000900c0, FL_USEFID,    handleGetObjectId },      /* FSCTL_SRV_GET_OBJECT_ID */
    { 0x00140204, FL_USESID,	handleVerifyNegot }, 	  /* FSCTL_VALIDATE_NEGOTIATE_INFO */
    };

#ifdef UD_CS_INCLUDERPC

/* preparing late response for Write */
static void
lateResponseSave(
    CSLateResponseContext* context
    );

/* preparing late response for Write */
static NQ_BOOL
lateResponsePrepare(
    CSLateResponseContext* context
    );

/* sending late response for Write */
static NQ_BOOL
lateResponseSend(
    CSLateResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT dataLength
    );

static IoctlContext *savedContext;

#endif /* UD_CS_INCLUDERPC */

/*====================================================================
 * PURPOSE: Perform IOCTL processing
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

NQ_UINT32 csSmb2OnIoctl(CMSmb2Header *in, CMSmb2Header *out, CMBufferReader *reader, CSSession *connection, CSUser *user, CSTree *tree, CMBufferWriter *writer)
{
    IoctlContext context;                   /* this command context */
    NQ_UINT32 offset;                       /* input/output offset */
    NQ_UINT32 maxCount;                     /* available room in the response */
    NQ_COUNT  i;                            /* just a counter */
    NQ_UINT32 status;                       /* returned by methods */
    const NQ_BYTE * savedOutput;            /* pointer to the start of method output */
    const NQ_BYTE * newOutput;              /* pointer to the wnd of method output */
    CSFid fid;                              /* file ID */
    NQ_UINT32 methodFlags = 0;              /* various method flags (see above) */

    LOGFB(CM_TRC_LEVEL_FUNC_PROTOCOL);

#ifdef UD_CS_INCLUDERPC
    /* save IOCTL context for further use in saveLateResponse */
    savedContext = &context;
#endif /* UD_CS_INCLUDERPC */

    /* parse request */
    cmBufferReaderSkip(reader, 2);
    cmBufferReadUint32(reader, &context.ctlCode);
    cmBufferReadUint16(reader, &fid);
    cs2ParseFid(&fid); 
    cmBufferReaderSkip(reader, 14); /* the rest of the file ID */
    cmBufferReadUint32(reader, &offset);
    context.pInput = in->_start + offset;
    cmBufferReadUint32(reader, &context.inputCount);
    cmBufferReaderSkip(reader, 3 * 4);  /* max input response, output offset and count */
    cmBufferReadUint32(reader, &context.maxOutputResponse);    
    cmBufferReadUint32(reader, &context.flags);
   
    /* check parameters */
    maxCount = CS_MAXBUFFERSIZE
                  - RESPONSE_LENGTH
                  - SMB2_HEADERSIZE;
    if (context.maxOutputResponse > maxCount)
        context.maxOutputResponse = maxCount;
    
    /* prepare the response */
    cmBufferWriterClone(writer, &context.writer, RESPONSE_LENGTH);
    savedOutput = cmBufferWriterGetPosition(&context.writer); 
    
    /* call handle */
    status = SMB_STATUS_NOT_FOUND;  /* will hit on no method handle */ 
    for (i = 0; i < sizeof(ioctlMethods)/sizeof(ioctlMethods[0]); i++)
    {
        if (ioctlMethods[i].code == context.ctlCode && ioctlMethods[i].handle != NULL)
        {
			CSFile fakeFile;
            methodFlags = ioctlMethods[i].flags; 
           

            if (methodFlags & FL_USEFID)
            {
                context.file = csGetFileByFid(fid, tree->tid, user->uid);
                if (NULL == context.file)
                {
                    LOGERR(CM_TRC_LEVEL_ERROR, "File not found for fid 0x%x", fid);
                    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
                    return SMB_STATUS_INVALID_HANDLE;
                }
            }
            else if (methodFlags & FL_USESID)
            {
            	fakeFile.session = connection->key;
            	context.file = &fakeFile;
            }
            status = ioctlMethods[i].handle(&context);
            break;
        }
    }
    if (0 != status && status != SMB_STATUS_BUFFER_OVERFLOW)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "IOCTL failed with code 0x%x", status);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return status;
    }
    
    /* compose the response */
    cmBufferWriteUint16(writer, 49);                    /* structure length */
    cmBufferWriteUint16(writer, 0);                     /* reserved */
    cmBufferWriteUint32(writer, context.ctlCode);
    if (methodFlags & FL_USEFID)
    {
        cmBufferWriteUint16(writer, context.file->fid);     
        cmBufferWriteUint16(writer, 0);                     /* fill the rest */
        cmBufferWriteUint32(writer, 0);                     /* fill the rest */
        cmBufferWriteUint32(writer, 0);                     /* fill the rest */
        cmBufferWriteUint32(writer, 0);                     /* fill the rest */
    }
    else
    {
        cmBufferWriteUint32(writer, 0xFFFFFFFF);            /* fill the rest */
        cmBufferWriteUint32(writer, 0xFFFFFFFF);            /* fill the rest */
        cmBufferWriteUint32(writer, 0xFFFFFFFF);            /* fill the rest */
        cmBufferWriteUint32(writer, 0xFFFFFFFF);            /* fill the rest */
    }
    cmBufferWriteUint32(writer, 0);                     /* input offset */
    cmBufferWriteUint32(writer, 0);                     /* input count */
    newOutput = cmBufferWriterGetPosition(&context.writer);
    offset = (NQ_UINT32)(savedOutput == newOutput? 0 : (savedOutput - out->_start));
    cmBufferWriteUint32(writer, offset);                    /* output offset */
    cmBufferWriteUint32(writer, (NQ_UINT32)(newOutput - savedOutput));   /* output count */
    cmBufferWriteUint32(writer, 0);                         /* flags */
    cmBufferWriteUint32(writer, 0);                         /* reserved */
    cmBufferWriterSync(writer, &context.writer);
    if (status == SMB_STATUS_BUFFER_OVERFLOW)
    {
        out->status = SMB_STATUS_BUFFER_OVERFLOW;
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_CUSTOM_ERROR_RESPONSE;
    }
    
    LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
    return 0;
}

#ifdef UD_CS_INCLUDERPC 

/*====================================================================
 * PURPOSE: Perform TRANSCEIVE IOCTL method
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT context - method context
 *
 * RETURNS: 0 on success or error code in NT format
 *
 *====================================================================
 */

static NQ_UINT32 handleTransceive(IoctlContext * context)
{
    NQ_UINT32 status;       /* rpc operation return code */
    /* NQ_UINT32 remaining; */    /* size of remaining data in pipe */
    NQ_BYTE * pData;        /* pointer to the outgoing buffer */

    csDcerpcSetLateResponseCallbacks(
        lateResponseSave, 
        lateResponsePrepare, 
        lateResponseSend
    );
    status = csDcerpcWrite(
            context->file, 
            context->pInput, 
            (NQ_UINT)context->inputCount, 
            FALSE 
            );
    if (0 != status)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error writing to pipe: 0x%x", status);
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return status;
    }
    
    pData = cmBufferWriterGetPosition(&context->writer); 
    context->file->maxFragment = (NQ_UINT16)context->maxOutputResponse;
	if (0 == context->file->maxFragment) 
        context->file->maxFragment = 0xFFFF;
    status = csDcerpcRead(
            context->file, 
            pData, 
            (NQ_UINT)context->maxOutputResponse,
            NULL
            );
    if (status == 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "Error reading from pipe");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_BUFFER_OVERFLOW;
    }
    cmBufferWriterSetPosition(&context->writer, pData + status);
/*    if (remaining > 0)
    {
        LOGERR(CM_TRC_LEVEL_ERROR, "IOCTL buffer overflow");
        LOGFE(CM_TRC_LEVEL_FUNC_PROTOCOL);
        return SMB_STATUS_BUFFER_OVERFLOW;
    }*/
    return 0;
} 

/*====================================================================
 * PURPOSE: Perform GET_OBJECT_ID IOCTL method
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT context - method context
 *
 * RETURNS: 0 on success or error code in NT format
 *
 *====================================================================
 */

static NQ_UINT32 handleGetObjectId(IoctlContext * context)
{
/*    cmBufferWriteZeroes(&context->writer, 16*4);
	
    return 0;*/
	
	return SMB_STATUS_INVALID_DEVICE_REQUEST;
} 

/*====================================================================
 * PURPOSE: save IOCTL parameters in late response context
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the saved context
 *
 * RETURNS: NONE
 *
 * NOTES:   skips Transact header
 *====================================================================
 */

static void
lateResponseSave(
    CSLateResponseContext* context
    )
{
    CMSmb2Header * pHeader;
    pHeader = cs2DispatchGetCurrentHeader();
    pHeader->aid.low = csSmb2SendInterimResponse(pHeader);
    pHeader->aid.high = 0;
    pHeader->credits = 0;
    
    /* write request information into the file descriptor */
    csDispatchSaveResponseContext(context);
    context->prot.smb2.commandData.ioctl.ctlCode = savedContext->ctlCode;
    context->prot.smb2.commandData.ioctl.fid = savedContext->file->fid;

    return;
}

/*====================================================================
 * PURPOSE: calculate command data pointer and size
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the saved context
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:   skips Transact header
 *====================================================================
 */
static
NQ_STATUS
lateResponsePrepare(
    CSLateResponseContext* context
    )
{
    csDispatchPrepareLateResponse(context);
    context->commandData += RESPONSE_LENGTH;
    context->commandDataSize -= RESPONSE_LENGTH;

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
static
NQ_BOOL
lateResponseSend(
    CSLateResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT dataLength
    )
{
    CMBufferWriter writer;
    NQ_BYTE * data = context->commandData;
    
    context->commandData -= RESPONSE_LENGTH;
    cmBufferWriterInit(&writer, context->commandData, RESPONSE_LENGTH + 10);
    cmBufferWriteUint16(&writer, 49);                    /* structure length */
    cmBufferWriteUint16(&writer, 0);                     /* reserved */
    cmBufferWriteUint32(&writer, context->prot.smb2.commandData.ioctl.ctlCode);
    cmBufferWriteUint16(&writer, context->prot.smb2.commandData.ioctl.fid);     
    cmBufferWriteUint16(&writer, 0);                     /* fill the rest */
    cmBufferWriteUint32(&writer, 0);                     /* fill the rest */
    cmBufferWriteUint32(&writer, 0);                     /* fill the rest */
    cmBufferWriteUint32(&writer, 0);                     /* fill the rest */
    cmBufferWriteUint32(&writer, 0);                     /* input offset */
    cmBufferWriteUint32(&writer, 0);                     /* input count */
    cmBufferWriteUint32(&writer, (NQ_UINT32)((data - context->commandData) + SMB2_HEADERSIZE));  /* output offset */
    cmBufferWriteUint32(&writer, dataLength);   /* output count */
    cmBufferWriteUint32(&writer, 0);                         /* flags */
    cmBufferWriteUint32(&writer, 0);                         /* reserved */

    return csDispatchSendLateResponse(context, status, dataLength + RESPONSE_LENGTH);
}

#endif /* UD_CS_INCLUDERPC */

static NQ_UINT32 handleVerifyNegot(IoctlContext * context)
{
	NQ_UINT16	securityMode = 0;
	CSSession *	pSession;

#ifdef UD_CS_MESSAGESIGNINGPOLICY
    securityMode |= (NQ_UINT16)((csIsMessageSigningEnabled() ? SMB2_NEGOTIATE_SIGNINGENABLED : 0) | (csIsMessageSigningRequired() ? SMB2_NEGOTIATE_SIGNINGREQUIRED : 0));
#endif
    pSession = csGetSessionById(context->file->session);
    if (pSession == NULL)
    {
    	return SMB_STATUS_INVALID_HANDLE;
    }

	cmBufferWriteUint32(&context->writer, pSession->dialect >= CS_DIALECT_SMB30 ? SMB2_CAPABILITY_ENCRYPTION : 0x0); /* capabilities*/
	cmUuidWrite(&context->writer, cs2GetServerUuid());           /* server GUID */
	cmBufferWriteUint16(&context->writer, securityMode);         /* security mode */
	switch (pSession->dialect)
	{
	case CS_DIALECT_SMB2:
			cmBufferWriteUint16(&context->writer, SMB2_DIALECTREVISION);       /* dialect revision */
			break;
	case CS_DIALECT_SMB210:
			cmBufferWriteUint16(&context->writer, SMB2_1_DIALECTREVISION);     /* dialect revision */
			break;
	case CS_DIALECT_SMB30:
			cmBufferWriteUint16(&context->writer, SMB3_DIALECTREVISION);     /* dialect revision */
			break;
	case CS_DIALECT_SMB311:
			cmBufferWriteUint16(&context->writer, SMB3_1_1_DIALECTREVISION);   /* dialect revision */
			break;
	}

	return NQ_SUCCESS;
}

#endif /* defined(UD_NQ_INCLUDECIFSSERVER) && defined(UD_NQ_INCLUDESMB2) */

