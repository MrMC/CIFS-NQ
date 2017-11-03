/*********************************************************************
 *
 *           Copyright (c) 2003 by Visuality Systems, Ltd.
 *
 *********************************************************************
 * FILE NAME     : $Workfile:$
 * ID            : $Header:$
 * REVISION      : $Revision:$
 *--------------------------------------------------------------------
 * DESCRIPTION   : RPC main access point
 *--------------------------------------------------------------------
 * MODULE        : CS - CIFS Server
 * DEPENDENCIES  :
 *--------------------------------------------------------------------
 * CREATED BY    : Mark Rabinovich
 * LAST AUTHOR   : $Author:$
 ********************************************************************/

#include "csdcerpc.h"
#include "cmrpcdef.h"

#include "cssrvsvc.h"
#include "cswkssvc.h"
#include "csspools.h"
#include "cslsarpc.h"
#include "cssamrpc.h"
#include "cswrgrpc.h"

#ifdef UD_NQ_INCLUDECIFSSERVER

#ifdef UD_CS_INCLUDERPC


/*
    Static data and definitions
    ---------------------------
 */

typedef struct
{
    CSDcerpcLateResponseSave    saveLateResponse;   /* routine for preparing late response down RPC layer */
    CSDcerpcLateResponsePrepare prepareLateResponse;/* routine for preparing late response down RPC layer */
    CSDcerpcLateResponseSend    sendLateResponse;   /* routine for sending late response down RPC layer */
}
StaticData;

#ifdef SY_FORCEALLOCATION
static StaticData* staticData = NULL;
#else  /* SY_FORCEALLOCATION */
static StaticData staticDataSrc;
static StaticData* staticData = &staticDataSrc;
#endif /* SY_FORCEALLOCATION */

const CMRpcUuid ndrTransferSyntax =  /* global UUID for NDR transfer syntax */
CM_RPC_TRANSFERSYNTAXSIGNATURE;

#define BIND_LENGTH 180

/* pipe descriptors */

static const CSRpcPipeDescriptor* (*pipes[])() =
{
#ifdef UD_CS_INCLUDERPC_SRVSVC
    csRpcSrvsvc,
#endif
#ifdef UD_CS_INCLUDERPC_WKSSVC
    csRpcWkssvc,
#endif
#ifdef UD_CS_INCLUDERPC_SPOOLSS
    csRpcSpoolss,
#endif
#ifdef UD_CS_INCLUDERPC_LSARPC
    csRpcLsa,
    csRpcLsads,
#endif
#ifdef UD_CS_INCLUDERPC_SAMRPC
    csRpcSamr,
#endif
#ifdef UD_CS_INCLUDERPC_WINREG
    csRpcWinReg,
#endif
};

/*
    Buffers for pending DCERPC requests
    -----------------------------------
   DECRPC request may come in an either Write/WriteX or a Trans packet.
   A Trans packet is processed synchronously and DCERPC immediatelly returns
   appropriate response. With Write/X request, DCERPC has to wait for subsequent
   Read/X requst to return the reponse. Therefore, on such request DCERPC saves it in
   a buffer and does approiate RPC call on Read/X request using the saved request data.
   We have a limited number of buffers for request. Usually, Read/X goes immediatelly
   after Write/X, so a collision is very unlikely. However, on buffer pool overflow, the
   latest buffer is released and its request becomes lost.
 */

typedef struct _FragmentDescriptor  /* fragment descriptor */
{
  struct _FragmentDescriptor* next; /* link */
  NQ_UINT length;                   /* fragment data length (not including header */
  NQ_UINT offset;                   /* offset in the fragment data */
  NQ_BYTE* data;                    /* fragment data bytes */
} FragmentDescriptor;

#define BUFFERTYPE_IN    1  /* incoming packet */
#define BUFFERTYPE_OUT   2  /* outgoing packet */
#define BUFFERTYPE_SAVED 3  /* saved complete response */

typedef struct          /* buffer descriptor for pending request */
{
    NQ_INT type;                    /* buffer type */
    NQ_BOOL isLast;                 /* whether last fragment is already received */
    NQ_UINT dataLen;                /* number of bytes in the buffer */
    NQ_UINT dataOff;                /* offset in the main data */
    FragmentDescriptor* first;      /* linked list of fragment desroptors */
    FragmentDescriptor* last;       /* pointer to the (currently) last fragment */
    NQ_BYTE* data;                  /* buffer with reassembled data */
    NQ_UINT32 remaining;            /* remaining bytes in the current fragment */
    NQ_BYTE majorVers;              /* major version number of the current fragment */
    NQ_BYTE minorVers;              /* minor version number of the current fragment */
    NQ_BYTE drepFlags;              /* data representation flags for the current fragment */
    NQ_BYTE drepFloatPoint;         /* FP data representation flags for the current fragment */
    NQ_BYTE packetType;             /* packet type for the current fragment */
    NQ_BYTE packetFlags;            /* packet flags for the current fragment */
    NQ_UINT16 authLength;           /* for future use */
    NQ_UINT32 callId;               /* this fragment call id */
    NQ_BYTE cancelCount;            /* this frgament cancel count */
    NQ_UINT16 contextId;            /* The same as in the request */
    NQ_UINT16 opNum;                /* The same as in the request */
    NQ_UINT count;                  /* number of bytes parsed/composed so far */
}
BufferDescriptor;

/* deallocate memory blocks used by a buffer */

static void
freeBuffer(
    BufferDescriptor* buffer    /* buffer to free */
    );

/* process incoming RPC header */

static NQ_UINT32            /* NT error code or 0 */
dcerpcInputHeader(
    BufferDescriptor* buf,  /* descriptor of an incoming buffer */
    const NQ_BYTE* data,    /* pointer to RPC header in incoming message */
    NQ_BOOL transact        /* TRUE when called from Transact */
    );

/* compose outgoing RPC header */

static NQ_UINT32            /* NT error code or 0 */
dcerpcOutputHeader(
    CSFile* pFile,          /* pointer to file descriptor */
    BufferDescriptor* buf,  /* descriptor of an outgoing buffer */
    NQ_BYTE* out,           /* pointer in the putgoing message */
    NQ_UINT size           /* space in this message */
    );

/* perform RPC command */

static NQ_UINT32            /* NT error code or 0 */
dcerpcProceed(
    CSFile* pFile,          /* pointer to file descriptor */
    BufferDescriptor* buf   /* descriptor of an incoming/outgoing buffer */
    );

/*====================================================================
 * PURPOSE: initialize buffers
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csDcerpcInit(
    void
    )
{
    NQ_UINT i;

    TRCB();

    /* allocate memory */
#ifdef SY_FORCEALLOCATION
    staticData = (StaticData *)syMalloc(sizeof(StaticData));
    if (NULL == staticData)
    {
        TRCERR("Unable to allocate DCEPRC data");
        TRCE();
        return NQ_FAIL;
    }
#endif /* SY_FORCEALLOCATION */

    for (i = 0; i < sizeof(pipes)/sizeof(pipes[0]); i++)
    {
        const CSRpcPipeDescriptor* pipeDescr;

        pipeDescr = (*pipes[i])();
        if (NULL != pipeDescr->init)
        {
            if (NQ_FAIL == pipeDescr->init())
                return NQ_FAIL;
        }
    }

    TRCE();
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: release buffers
 *--------------------------------------------------------------------
 * PARAMS:  None
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csDcerpcStop(
    void
    )
{
    NQ_UINT i;

    TRCB();

    /* release memory */
#ifdef SY_FORCEALLOCATION
    if (NULL != staticData)
        syFree(staticData);
    staticData = NULL;
#endif /* SY_FORCEALLOCATION */

    for (i = 0; i < sizeof(pipes)/sizeof(pipes[0]); i++)
    {
        const CSRpcPipeDescriptor* pipeDescr;

        pipeDescr = (*pipes[i])();
        if (NULL != pipeDescr->stop)
        {
            pipeDescr->stop();
        }
    }

    TRCE();
}

/*====================================================================
 * PURPOSE: get pipe information
 *--------------------------------------------------------------------
 * PARAMS:  IN pipe desriptor
 *          OUT buffer for pipe information
 *
 * RETURNS: NQ_SUCCESS or NQ_FAIL
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csDcerpcGetPipeInformation(
    const CSFile* pFile,
    SYFileInformation *fileInfo
    )
{
    fileInfo->allocSizeHigh = 0;
    fileInfo->allocSizeLow =  (NQ_UINT32)(UD_NS_BUFFERSIZE
                 - sizeof(CMNetBiosSessionMessage)
                 - sizeof(CMCifsHeader)
                 - sizeof(CMCifsTransactionRequest)
                 - 2 * 2
                 - sizeof(NQ_WCHAR) * (syStrlen("\\PIPE\\") + 1));
    fileInfo->allocSizeLow &= 0xFFFFFFF8;;
    fileInfo->attributes = 0;
    fileInfo->isDeleted = TRUE;
    fileInfo->numLinks = 1;
    fileInfo->sizeHigh = 0;
    fileInfo->sizeLow = 0;
    return NQ_SUCCESS;
}

/*====================================================================
 * PURPOSE: write request into pipe
 *--------------------------------------------------------------------
 * PARAMS:  IN file descriptor
 *          IN data to write into pipe
 *          IN data length
 *          IN TRUE when used internaly by Transact
 *
 * RETURNS: 0 on success or SMB error code on error
 *
 * NOTES:   no RPC call so far, the data is just kept into buffer
 *          this function assumes that a read request follows
 *====================================================================
 */

NQ_UINT32
csDcerpcWrite(
    CSFile* pFile,
    const NQ_BYTE* data,
    NQ_UINT dataLen,
    NQ_BOOL transact        
    )
{
    NQ_UINT32 status;               /* error code */
    BufferDescriptor* buffer;       /* buffer pointer */

    TRCB();

    if (pFile->rpcBuffer == NULL)
    {
        pFile->rpcBuffer = (NQ_BYTE *)syMalloc(sizeof(BufferDescriptor));
        if (pFile->rpcBuffer == NULL)
        {
            TRCERR("Unable to allocate RPC buffer descriptor");
            TRCE();
            return csErrorReturn(SMB_STATUS_BUFFER_TOO_SMALL, DOS_ERRinsufficientbuffer);
        }
        buffer = (BufferDescriptor*)pFile->rpcBuffer;
        buffer->first = buffer->last = NULL;
        buffer->data = NULL;
        buffer->dataLen = 0;
        buffer->type = BUFFERTYPE_IN;
        buffer->remaining = 0;
    }
    else
    {
        buffer = (BufferDescriptor*)pFile->rpcBuffer;
        if (buffer->type != BUFFERTYPE_IN)
        {
            freeBuffer(buffer);
            pFile->rpcBuffer = NULL;
            TRCERR("RPC buffer was not read yet");
            TRCE();
            return csErrorReturn(SMB_STATUS_BUFFER_TOO_SMALL, DOS_ERRinsufficientbuffer);
        }
    }

    /* if we are at the fragment start - parse its header */

    if (buffer->remaining == 0)     /* new fragment expected */
    {
        FragmentDescriptor* fragBuf; /* pointer to new fragment */

        status = dcerpcInputHeader(buffer, data, transact);
        if (status != 0)
        {
            freeBuffer(buffer);
            pFile->rpcBuffer = NULL;
            TRCERR("Error while processing RPC header");
            TRCE();
            return status;
        }
        data += buffer->count;
        dataLen -= buffer->count;

        /* allocate buffer for this fragment */
        fragBuf = (FragmentDescriptor*)syMalloc(buffer->remaining + sizeof(FragmentDescriptor));
        if (fragBuf == NULL)
        {
            freeBuffer(buffer);
            pFile->rpcBuffer = NULL;
            TRCERR("Unable to allocate buffer for RPC fragment");
            TRCE();
            return csErrorReturn(SMB_STATUS_BUFFER_TOO_SMALL, DOS_ERRinsufficientbuffer);
        }

        fragBuf->next = NULL;

        if (buffer->first == NULL)
        {
            buffer->first = fragBuf;
        }
        else
        {
            buffer->last->next = fragBuf;
        }
        buffer->last = fragBuf;
        fragBuf->offset = 0;
        fragBuf->length = (NQ_UINT)buffer->remaining;
        fragBuf->data = (NQ_BYTE*)fragBuf + sizeof(*fragBuf);
        buffer->dataLen += (NQ_UINT)buffer->remaining;
    }

    /* append data to the buffer */

    syMemcpy(buffer->last->data + buffer->last->offset, data, dataLen);
    buffer->last->offset += dataLen;
    buffer->remaining -= dataLen;

    /* if we are through with the last fragment - merge fragments and call RPC function */

    if (buffer->remaining == 0 && buffer->isLast)
    {
        FragmentDescriptor* nextFrag;   /* for scanning the list of fragments */
        NQ_UINT off;                    /* offset for merging */
        NQ_UINT requiredLen;            /* required buffer length */

        requiredLen = buffer->dataLen + 64;
        if (requiredLen < UD_NS_BUFFERSIZE)
        {
            requiredLen = UD_NS_BUFFERSIZE;
        }
        buffer->data = (NQ_BYTE *)syMalloc(requiredLen);
        if (buffer->data == NULL)
        {
            freeBuffer(buffer);
            pFile->rpcBuffer = NULL;
            TRCERR("Unable to allocate buffer for merging RPC fragments");
            TRCE();
            return csErrorReturn(SMB_STATUS_BUFFER_TOO_SMALL, DOS_ERRinsufficientbuffer);
        }
        buffer->dataLen = requiredLen;
        nextFrag = buffer->first;
        off = 0;
        while (nextFrag != NULL)
        {
            FragmentDescriptor* temp;

            syMemcpy(buffer->data + off, nextFrag->data, nextFrag->length);
            off += nextFrag->length;
            temp = nextFrag;
            nextFrag = nextFrag->next;
            syFree(temp);
        }
        buffer->first = buffer->last = NULL;

        status = dcerpcProceed(pFile, buffer);
        if (status != 0)
        {
            freeBuffer((BufferDescriptor *)pFile->rpcBuffer);
            pFile->rpcBuffer = NULL;
            TRCERR("Error in calling RPC function");
            TRCE();
            return status;
        }

        buffer->remaining = 0;
        buffer->dataOff = 0;
        buffer->type = BUFFERTYPE_OUT;
    }

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: response to read from a pipe
 *--------------------------------------------------------------------
 * PARAMS:  IN file descriptor
 *          OUT read buffer
 *          IN/OUT pointer to the buffer size, will get the number of bytes read
 *          OUT the number of bytes remaining in the pipe, this pointer may be NULL
 *
 * RETURNS: number of bytes read
 *
 * NOTES:   This function assumes that there was a preceeding write request and the outgoing
 *          data is already in the buffer
 *====================================================================
 */

NQ_UINT32
csDcerpcRead(
    CSFile* pFile,
    NQ_BYTE* readBuffer,
    NQ_UINT readCount,
    NQ_UINT32 * remaining
    )
{
    NQ_UINT32 status;               /* error code */
    NQ_UINT32 count;                /* the result */
    BufferDescriptor* buffer;       /* buffer pointer */

    TRCB();

    /* find a buffer with outgoing data */

    if (pFile->rpcBuffer == NULL)
    {
        TRCERR("illegal or no buffer");
        TRCE();
        return 0;
    }
    
    buffer = (BufferDescriptor*)pFile->rpcBuffer;
    
    if (buffer->type == BUFFERTYPE_SAVED)
    {
        count = buffer->count;
        syMemcpy(readBuffer, buffer->data, count);
        freeBuffer(buffer);
        pFile->rpcBuffer = NULL;
        return count;
    }
    
    count = 0;

    if (buffer->remaining == 0)
    {
        status = dcerpcOutputHeader(pFile, buffer, readBuffer, readCount);
        if (status != 0)
        {
            freeBuffer(buffer);
            pFile->rpcBuffer = NULL;
            TRCERR("illegal or no buffer");
            TRCE();
            return 0;
        }
        readCount -= buffer->count;
        readBuffer += buffer->count;
        count += buffer->count;
    }
    if (buffer->remaining < readCount)
    {
        readCount = (NQ_UINT)buffer->remaining;
    }

    /* copy data portion */

    syMemcpy(readBuffer,
             buffer->data + buffer->dataOff,
             readCount
             );
    buffer->count += readCount;
    buffer->dataLen -= readCount;
    count += readCount;

    if (buffer->dataLen == 0)
    {
        if (NULL != remaining)
        {
            *remaining = 0;
        }
        freeBuffer(buffer);
        pFile->rpcBuffer = NULL;
    }
    else
    {
        buffer->dataOff += readCount;
        buffer->remaining -= readCount;
        if (NULL != remaining)
        {
            *remaining = buffer->remaining;
        }
    }

    TRCE();
    return count;
}

/*====================================================================
 * PURPOSE: transact processing for DCERPC
 *--------------------------------------------------------------------
 * PARAMS:  IN file descriptor
 *          IN pointer to the transaction descriptor
 *          IN space in the internal buffer
 *
 * RETURNS: 0 on success or error code in NT format
 *
 * NOTES:   If there is data written by previous csDcerpcWrite requests,
 *          it is used, otherwise - new data is used
 *====================================================================
 */

NQ_UINT32
csDcerpcTransact(
    CSFile* pFile,
    CSTransactionDescriptor* descriptor,
    NQ_UINT space
    )
{
    CMCifsStatus status;        /* NT format status */
    NQ_UINT count;              /* transact result */
    BufferDescriptor* buffer;   /* pointer to the buffer */

    TRCB();

    csDcerpcSetLateResponseCallbacks(
        csDispatchSaveResponseContext,
        csNamedPipePrepareLateResponse,
        csNamedPipeSendLateResponse
        );
    status = csDcerpcWrite(
            pFile, 
            descriptor->dataIn, 
            descriptor->dataCount, 
            TRUE
        );
    if (status != 0)
    {
        TRCE();
        return status;
    }
    
    count = descriptor->maxData;

    count = (NQ_UINT)csDcerpcRead(pFile, descriptor->dataOut, count, NULL);
    buffer = (BufferDescriptor*) pFile->rpcBuffer;

    descriptor->dataCount = (NQ_UINT16)count;

    if (   buffer != NULL
        && buffer->remaining != 0
       )
    {
        status = SMB_STATUS_BUFFER_OVERFLOW;
    }

    TRCE();
    return status;
}

/*====================================================================
 * PURPOSE: NTCreateAndX calls this point to open a pipe
 *--------------------------------------------------------------------
 * PARAMS:  IN pointer to the pipe name
 *          IN pointer to the file descritor
 *
 * RETURNS: pipe identifier or RP_ILLEGALPIPE
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
csDcerpcOpenPipe(
    const NQ_WCHAR* pipeName,
    CSFile* pFile
    )
{
    NQ_UINT i;                  /* index in the table of pipes */
    NQ_CHAR pipeNameAscii[20];  /* pipe name converted to ascii */

    TRCB();

    if (syWStrlen(pipeName) + 1 > sizeof(pipeNameAscii))
    {
        TRCERR("Pipe name too long");
        TRC1P("  name: %s", cmWDump(pipeName));
        TRCE();
        return FALSE;
    }

    syUnicodeToAnsi(pipeNameAscii, pipeName);

    for (i = 0; i < sizeof(pipes)/sizeof(pipes[0]); i++)
    {
        if (0 == syStrcmp(pipeNameAscii, (*pipes[i])()->name))
        {
            pFile->isPipe = TRUE;
            pFile->maxFragment = 0;
            pFile->rpcBuffer = NULL;
            TRCE();
            return TRUE;
        }
    }

    TRCERR("Pipe not found");
    TRC1P("  name: %s", cmWDump(pipeName));
    TRCE();
    return FALSE;
}

/*====================================================================
 * PURPOSE: core CIFS calls this point to close a pipe
 *--------------------------------------------------------------------
 * PARAMS:  IN pipe identifier
 *
 * RETURNS:  sero on success, error code otherwise
 *
 * NOTES:
 *====================================================================
 */

NQ_UINT32
csDcerpcClosePipe(
    CSFile* pFile
    )
{
    NQ_INT16 i;

    freeBuffer((BufferDescriptor*)pFile->rpcBuffer);
    pFile->rpcBuffer = NULL;

    for (i = 0; i < CM_RPC_MAXNUMBEROFCONTEXTS; i++)
    {
        const CSRpcPipeDescriptor* pPipe;    /* next pipe */

        if (pFile->pipes[i] == CS_INVALIDPIPE)
            break;
        pPipe = (*pipes[pFile->pipes[i]])();
        if (NULL != pPipe->cleanup)
            pPipe->cleanup((const NQ_BYTE*)pFile);
        pFile->pipes[i] = CS_INVALIDPIPE;
    }

    return 0;
}

/*====================================================================
 * PURPOSE: set late response callback function pointers 
 *--------------------------------------------------------------------
 * PARAMS:  IN routine for saving transport late response 
 *          IN routine for preparing transport late response 
 *          IN routine for sending transport late response 
 *
 * RETURNS: None
 *
 * NOTES:   
 *====================================================================
 */

void
csDcerpcSetLateResponseCallbacks(
    CSDcerpcLateResponseSave saveLateResponse,
    CSDcerpcLateResponsePrepare prepareLateResponse,
    CSDcerpcLateResponseSend sendLateResponse       
    )
{
    staticData->saveLateResponse = saveLateResponse;
    staticData->prepareLateResponse = prepareLateResponse;
    staticData->sendLateResponse = sendLateResponse;
}

/*====================================================================
 * PURPOSE: save information for a delayed response
 *--------------------------------------------------------------------
 * PARAMS:  IN TRUE for RPC protocol involed
 *          IN packet descriptor to use (ignored if the 1st parameter is FALSE)
 *          OUT buffer for response context
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

void
csDcerpcSaveResponseContext(
    NQ_BOOL isRpc,
    const CMRpcPacketDescriptor* descr,
    CSDcerpcResponseContext* context
    )
{
    context->cifsContext.isRpc = isRpc;
    staticData->saveLateResponse(&context->cifsContext);
    if (isRpc)
    {
        context->nbo = descr->nbo;
        context->callId = descr->callId;
    }
    context->prepareLateResponse = staticData->prepareLateResponse;
    context->sendLateResponse = staticData->sendLateResponse;
}

/*====================================================================
 * PURPOSE: save information for a delayed response
 *--------------------------------------------------------------------
 * PARAMS:  IN packet descriptor to use
 *          OUT buffer for response context
 *
 * RETURNS: NQ_SUCCESS or error code
 *
 * NOTES:
 *====================================================================
 */

NQ_STATUS
csDcerpcPrepareLateResponse(
    CSDcerpcResponseContext* context
    )
{
    NQ_COUNT rpcHeaderLength = sizeof(CMRpcDcerpcPacket) + 8;    /* extra bytes for RPC response header */

    context->prepareLateResponse(&context->cifsContext);
    if (context->cifsContext.isRpc)
    {
        context->cifsContext.commandData += rpcHeaderLength;
        context->cifsContext.commandDataSize -= rpcHeaderLength;
    }
    return 0;
}

/*====================================================================
 * PURPOSE: send a delayed response
 *--------------------------------------------------------------------
 * PARAMS:  IN response context
 *          IN status to return
 *          IN size of the stub data
 *
 * RETURNS: TRUE for success
 *
 * NOTES:
 *====================================================================
 */

NQ_BOOL
csDcerpcSendLateResponse(
    CSDcerpcResponseContext* context,
    NQ_UINT32 status,
    NQ_COUNT stubDataSize
    )
{
    CMRpcPacketDescriptor out;        /* to compose RPC header */
    NQ_COUNT rpcHeaderLength = sizeof(CMRpcDcerpcPacket) + 8;    /* extra bytes for RPC response header */

    if (context->cifsContext.isRpc)
    {
        context->cifsContext.commandData -= rpcHeaderLength;
        cmRpcSetDescriptor(
            &out,
            context->cifsContext.commandData,
            context->nbo
            );
        cmRpcPackByte(&out, CM_RP_MAJORVERSION);        /* vers */
        cmRpcPackByte(&out, CM_RP_MINORVERSION);        /* minor vers */
        cmRpcPackByte(&out, 0 == status? CM_RP_PKT_RESPONSE : CM_RP_PKT_FAULT);    /* type */
        cmRpcPackByte(&out, CM_RP_PFCFLAG_FIRST | CM_RP_PFCFLAG_LAST);  /* flags */
        cmRpcPackByte(&out, context->nbo? 0 : CM_RP_DREPLE);            /* drep */
        cmRpcPackByte(&out, 0);
        cmRpcPackByte(&out, 0);
        cmRpcPackByte(&out, 0);
        cmRpcPackUint16(&out, (NQ_UINT16)(rpcHeaderLength + stubDataSize + 4)); /* frag length */
        cmRpcPackUint16(&out, 0);                                /* auth length */
        cmRpcPackUint32(&out, context->callId);                  /* call ID */
        cmRpcPackUint32(&out, stubDataSize + 4); /* alloc hint */
        cmRpcPackUint16(&out, 0);                                /* context ID */
        cmRpcPackUint16(&out, 0);                                /* cancel count + pad */
        if (0 == status)
        {
            cmRpcPackSkip(&out, stubDataSize);
        }
        cmRpcPackUint32(&out, status);                           /* status */
        rpcHeaderLength += 4;
    }
    else
    {
        rpcHeaderLength = 0;
    }
    return context->sendLateResponse(
                &context->cifsContext,
                0,
                rpcHeaderLength + (status == 0? stubDataSize : 0)
                );
}

/*====================================================================
 * PURPOSE: save a complete response packet by late response for 
 *          subsequent read(s)
 *--------------------------------------------------------------------
 * PARAMS:  IN file pointer
 *          IN pointer to a complete RPC response
 *          IN response size
 *
 * RETURNS: TRUE for success
 *
 * NOTES:
 *====================================================================
 */

void
csDcerpcSaveCompleteResponse(
    CSFile * pFile,                     
    const NQ_BYTE *pData,               
    NQ_COUNT dataSize                   
    )
{
    BufferDescriptor * buffer;
    
    buffer = (BufferDescriptor*)syMalloc(sizeof(BufferDescriptor));
    if (NULL == buffer)
    {
        TRCERR("Unable to allocate RPC buffer descriptor");
    }
    else
    {
        buffer->first = NULL;       /* no fragments */
        buffer->type = BUFFERTYPE_SAVED;
        buffer->count = dataSize;
        buffer->data = (NQ_BYTE *)syMalloc(dataSize);
        if (NULL == buffer->data)
        {
            TRCERR("Unable to allocate data buffer");
            syFree(buffer);
            buffer = NULL;
        }
        else
        {
            syMemcpy(buffer->data, pData, dataSize);
        }
    }
    if (NULL != pFile->rpcBuffer)
    {
        freeBuffer((BufferDescriptor *)pFile->rpcBuffer);
    }
    pFile->rpcBuffer = (NQ_BYTE *)buffer;
}


/*====================================================================
 * PURPOSE: Free buffer and its dependent blocks
 *--------------------------------------------------------------------
 * PARAMS:  IN buffer descriptor
 *
 * RETURNS: None
 *
 * NOTES:
 *====================================================================
 */

static void
freeBuffer(
    BufferDescriptor* buffer
    )
{
    FragmentDescriptor* frag;    /* next fragment descriptor */
    FragmentDescriptor* temp;    /* temporary fragment descriptor */
    TRCB();

    if (buffer == NULL)
    {
        TRCE();
        return;
    }

    frag = buffer->first;
    while (frag != NULL)
    {
        temp = frag;
        frag = frag->next;
        syFree(temp);
    }
    if (buffer->data != NULL)
    {
        syFree(buffer->data);
    }
    syFree(buffer);

    TRCE();
    return;
}

/*====================================================================
 * PURPOSE: Process incoming RPC header
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT pointer to file descriptor
 *          OUT pointre to allocated RPC buffer
 *          IN pointer to RPC header in incoming message
 *          IN TRUE when called from Transact
 *
 * RETURNS: NT error code or 0
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
dcerpcInputHeader(
    BufferDescriptor* buf,
    const NQ_BYTE* data,
    NQ_BOOL transact
    )
{
    CMRpcDcerpcPacket* rpcIn;                   /* casted pointer to the incoming RPC packet */
    CMRpcPacketDescriptor in;                   /* incoming packet descriptor */
    NQ_UINT16 remaining;

    TRCB();

    /* cast pointers */
    rpcIn = (CMRpcDcerpcPacket*)data;
    cmRpcSetDescriptor(
        &in,
        (NQ_BYTE*)data,
        !(rpcIn->drep.flags & CM_RP_DREPLE)
        );

    /* parse header fields */

    cmRpcParseByte(&in, &buf->majorVers);
    cmRpcParseByte(&in, &buf->minorVers);
    
    cmRpcParseByte(&in, &buf->packetType);
    cmRpcParseByte(&in, &buf->packetFlags);
    cmRpcParseByte(&in, &buf->drepFlags);
    cmRpcParseByte(&in, &buf->drepFloatPoint);
    cmRpcParseSkip(&in, 2);   /* drep remainder */
    cmRpcParseUint16(&in, &remaining);
    buf->remaining = remaining;
    cmRpcParseUint16(&in, &buf->authLength);
    cmRpcParseUint32(&in, &buf->callId);

    if (buf->packetType == CM_RP_PKT_REQUEST)
    {
        cmRpcParseSkip(&in, 4);   /* allocation hint */
        cmRpcParseUint16(&in, &buf->contextId);
        cmRpcParseUint16(&in, &buf->opNum);
    }

    /* analyse fragment */

    buf->isLast = transact || (buf->packetFlags & CM_RP_PFCFLAG_LAST);
    buf->count = (NQ_UINT)(in.current - in.origin);
    buf->remaining -= buf->count;

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Compose outgoing RPC header
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT pointer to file descriptor
 *          OUT pointer to allocated RPC buffer
 *          OUT pointer to the outgoing message
 *          IN space in this message
 *
 * RETURNS: NT error code or 0
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
dcerpcOutputHeader(
    CSFile* pFile,
    BufferDescriptor* buf,
    NQ_BYTE* outData,
    NQ_UINT size
    )
{
    CMRpcPacketDescriptor out;  /* outgoing packet descriptor for common fields */
    NQ_UINT32 fragLength;       /* length of the current fragment */
    NQ_UINT32 headerLen;        /* length of the header */

    TRCB();

    /* cast pointers */
    cmRpcSetDescriptor(
        &out,
        outData,
        !(buf->drepFlags & CM_RP_DREPLE)
        );
    out.length = size;

    cmRpcPackByte(&out, CM_RP_MAJORVERSION);
    cmRpcPackByte(&out, CM_RP_MINORVERSION);
    cmRpcPackByte(&out, buf->packetType);

    /* set fragment flags + calculate fragment length */

    buf->packetFlags = 0;
    if (buf->dataOff == 0)
    {
        buf->packetFlags |= CM_RP_PFCFLAG_FIRST;
    }

    headerLen = sizeof(CMRpcDcerpcPacket);
    if (buf->packetType == CM_RP_PKT_RESPONSE || buf->packetType == CM_RP_PKT_FAULT)
    {
        headerLen += (NQ_UINT32)(4 + 2 + 2*sizeof(NQ_BYTE));
    }

    fragLength = buf->dataLen + headerLen;
    TRC2P("Fraglen: %ld, max: %d", fragLength, pFile->maxFragment);
    if (fragLength <= pFile->maxFragment)
    {
        buf->packetFlags |= CM_RP_PFCFLAG_LAST;
        buf->isLast = TRUE;
    }
    else
    {
        fragLength = pFile->maxFragment;
        buf->isLast = FALSE;
    }

    cmRpcPackByte(&out, buf->packetFlags);
    cmRpcPackByte(&out, buf->drepFlags);
    cmRpcPackByte(&out, buf->drepFloatPoint);
    cmRpcPackUint16(&out, 0);           /* remainder of flags */
    cmRpcPackUint16(&out, (NQ_UINT16)fragLength);
    cmRpcPackUint16(&out, buf->authLength);
    cmRpcPackUint32(&out, buf->callId);

    if (buf->packetType == CM_RP_PKT_RESPONSE || buf->packetType == CM_RP_PKT_FAULT)
    {
        cmRpcPackUint32(&out, buf->dataLen);      /* Alloc hint */
        cmRpcPackUint16(&out, buf->contextId);
        cmRpcPackByte(&out, buf->cancelCount);
        cmRpcPackByte(&out, 0);                 /* padding */
    }

    buf->count = (NQ_UINT)(out.current - outData);
    buf->remaining = fragLength - headerLen;

    TRCE();
    return 0;
}

/*====================================================================
 * PURPOSE: Perform RPC command
 *--------------------------------------------------------------------
 * PARAMS:  IN/OUT pointer to file descriptor
 *          OUT pointer to allocated RPC buffer
 *
 * RETURNS: NT error code or 0
 *
 * NOTES:
 *====================================================================
 */

static NQ_UINT32
dcerpcProceed(
    CSFile* pFile,
    BufferDescriptor* buf
    )
{
    CMRpcPacketDescriptor in;                   /* incoming packet descriptor */
    CMRpcPacketDescriptor outPdu;               /* outgoing packet descriptor for PDU */

    TRCB();

    if (buf->authLength != 0)   /* we do not support SSP */
    {
        buf->packetType = CM_RP_PKT_FAULT;
        buf->authLength = 0;
        cmRpcSetDescriptor(&outPdu, buf->data, !(buf->drepFlags & CM_RP_DREPLE));
        cmRpcPackUint32(&outPdu, CM_RP_FAULTOPRNGERROR);    /* status */
        buf->dataLen = (NQ_UINT)(outPdu.current - buf->data);
        pFile->maxFragment = 100;
        return 0;
    }


    /* cast pointers */
    cmRpcSetDescriptor(&in, buf->data, !(buf->drepFlags & CM_RP_DREPLE));
       in.callId = buf->callId;

    switch (buf->packetType)
    {
    case CM_RP_PKT_BIND:
    case CM_RP_PKT_ALTER:        {
            NQ_UINT16 maxSize;          /* max transmit/receive frament size */
            NQ_UINT32 assocGroup;       /* associated group */
            NQ_BYTE numCtx;             /* number of context items */
            NQ_BYTE numTrans;           /* number of transfer syntaxes */
            NQ_UINT c, t, p;            /* counters */
            CMRpcUuid uuid;             /* abstract syntax UUID */
            NQ_UINT16 reason = 0;       /* bind result for next context */
            NQ_BOOL accept = FALSE;     /* whether to accept this bind */
            NQ_BOOL ack = FALSE;        /* whether to ack or to fail this bind */
            NQ_STATIC NQ_BYTE outBuf[BIND_LENGTH]; /* buffer for response */
            NQ_STATIC NQ_CHAR pipeName[17];
            NQ_STATIC NQ_CHAR tempPipeName[20];
            CSName* candidate = csGetNameByNid(pFile->nid);

            syStrcpy(pipeName, "\\PIPE\\1234567890");
            cmRpcSetDescriptor(&outPdu, outBuf, !(buf->drepFlags & CM_RP_DREPLE));
            outPdu.length = sizeof(outBuf);

            /* parse PDU params */
            cmRpcParseUint16(&in, &maxSize);
            cmRpcParseUint16(&in, &pFile->maxFragment);
            cmRpcParseUint32(&in, &assocGroup);
            cmRpcParseByte(&in, &numCtx);
            cmRpcParseSkip(&in, sizeof(NQ_BYTE));      /* pad */
            cmRpcParseSkip(&in, 2);    /* pad */

            /* look for a matching context, here we suggest that it will accept
               and we will pack response so far. If no context will be accepted
               we will reset outPdu and compose a nak
             */

            /* accept bind - respond by bind_ack */
            maxSize =  (NQ_UINT16)((UD_NS_BUFFERSIZE > 0xFFFF? 0xFFFF : UD_NS_BUFFERSIZE)
                     - sizeof(CMNetBiosSessionMessage)
                     - sizeof(CMCifsHeader)
                     - sizeof(CMCifsTransactionRequest)
                     - 2 * 2
                     - sizeof(NQ_WCHAR) * (syStrlen("\\PIPE\\") + 1));
            maxSize &= 0xFFF8;
            cmRpcPackUint16(&outPdu, maxSize);
            cmRpcPackUint16(&outPdu, maxSize);
            cmRpcPackUint32(&outPdu, 1);          /* we do not support association groups and always
                                                     return the same ID */
            /* skip the back slash at the beginning of the pipe name */
            syUnicodeToAnsi(tempPipeName, candidate->name + 1);
            syStrcpy(pipeName + 6, tempPipeName);
            cmRpcPackAscii(&outPdu, pipeName, CM_RP_SIZE16 | CM_RP_NULLTERM); /* secondary address */
            cmRpcAllignZero(&outPdu, 4);
            cmRpcPackByte(&outPdu, numCtx); /* the same number */
            cmRpcPackByte(&outPdu, 0); /* pad */
            cmRpcPackByte(&outPdu, 0); /* pad */
            cmRpcPackByte(&outPdu, 0); /* pad */

            /* parse presentation contexts and pack a result for each one */
            for (c = 0; c < numCtx; c++)
            {
                NQ_UINT32 version;   /* minor/major version for this context interface */
                NQ_UINT16 contextId; /* ID of next context */
                /* parse next context */
                cmRpcParseUint16(&in, &contextId);
                cmRpcParseByte(&in, &numTrans);
                cmRpcParseSkip(&in, sizeof(NQ_BYTE)); /* pad */
                cmRpcParseUuid(&in, &uuid);
                cmRpcParseUint32(&in, &version);
                reason = CM_RP_REASONABSTRACTSYNTAXNOTSUPPORTED;

                /* find a pipe to bind or alter by its name and UUID */
                if (contextId < CM_RPC_MAXNUMBEROFCONTEXTS)
                {
                    for (p = 0; !accept && p < sizeof(pipes)/sizeof(pipes[0]); p++)
                    {
                        const CSRpcPipeDescriptor* pipe = (*pipes[p])();

                        /* skip the back slash at the beginning of the pipe name */
                        if (syStrcmp(tempPipeName, pipe->name) == 0 &&
                            syMemcmp(&uuid, &pipe->uuid, sizeof(uuid)) == 0 &&
                            (version == pipe->version))
                        {
                            pFile->pipes[contextId] = (CSRpcPipe)p;
                            accept = TRUE;
                        }
                    }
                    /* at least one transfer syntax should match NDR */
                    for (t = 0; t < numTrans; t++)
                    {
                        NQ_UINT32 version;      /* transfer syntax version */

                        if (accept)
                            reason = CM_RP_REASONTRANSFERSYNTAXNOTSUPPORTED;

                        cmRpcParseUuid(&in, &uuid);
                        cmRpcParseUint32(&in, &version);
                        accept =    accept
                                 && (0 == syMemcmp(&uuid, &ndrTransferSyntax, sizeof(uuid)))
                                 && (version == CM_RPC_NDRVERSION);
                        if (accept)
                        {
                            break;
                        }
                    }

                }
                else
                {
                     TRCERR("Local limit exceeded: no more context slots");
                     reason = CM_RP_REASONLOCALLIMITEXCEEDED;
                }

                if (!accept)
                {
                    syMemset(&uuid, 0, sizeof(uuid));
                }
                cmRpcPackUint16(&outPdu, (NQ_UINT16)(accept? CM_RP_ACCEPTANCE : reason));
                cmRpcPackUint16(&outPdu, (NQ_UINT16)(accept? 0 : reason));
                cmRpcPackUuid(&outPdu, &uuid);
                cmRpcPackUint32(&outPdu, (NQ_UINT16)(accept? CM_RPC_NDRVERSION : 0));

                ack = ack || accept;
            }

            if (buf->majorVers != CM_RP_MAJORVERSION || buf->minorVers > CM_RP_MINORVERSION)
            {
                TRCERR("Unsupported version");
                TRC2P("  major: %d, minor: %d", buf->majorVers, buf->minorVers);
                ack = FALSE;
                reason = CM_RP_REASONPROTOCOLVERSIONNOTSUPPORTED;
            }

            /* accept or reject according to analyses results */
            if (ack)
            {
                buf->packetType = buf->packetType == CM_RP_PKT_BIND? CM_RP_PKT_BINDACK : CM_RP_PKT_ALTERACK;
            }
            else
            {
                TRCERR("Bind rejected");
                TRC1P(" reason: %d", reason);
                /* reject bind - respond by bind_nak */
                buf->packetType = CM_RP_PKT_BINDNAK;

                cmRpcResetDescriptor(&outPdu);
                cmRpcPackUint16(&outPdu, reason);
                cmRpcPackByte(&outPdu, 1);        /* num versions */
                cmRpcPackByte(&outPdu, CM_RP_MAJORVERSION);
                cmRpcPackByte(&outPdu, CM_RP_MINORVERSION);
                cmRpcPackUint16(&outPdu, 0);      /* placeholder ? */
            }
            syMemcpy(buf->data, outBuf, outPdu.current - outBuf);
            buf->dataLen = (NQ_UINT)(outPdu.current - outBuf);
        }
        break;
    case CM_RP_PKT_AUTH3:
        TRCE();
        return SMB_STATUS_NORESPONSE;
    case CM_RP_PKT_REQUEST:
        {
            NQ_UINT32 status = 0;       /* operation status */
            NQ_UINT32 resSize;          /* expected response size */

            /* check parameters */
            if (buf->contextId < CM_RPC_MAXNUMBEROFCONTEXTS && pFile->pipes[buf->contextId] != CS_INVALIDPIPE)
            {
                const CSRpcPipeDescriptor* pPipe = pipes[pFile->pipes[buf->contextId]]();  /* pipe descriptor */

                /* reallocate response buffer if response is too long */
                if (NULL != pPipe->checkSize)
                {
                    resSize = pPipe->checkSize(buf->opNum);
                    if (resSize > UD_NS_BUFFERSIZE)
                    {
                        NQ_BYTE * newData;      /* bigger buffer */
                        newData = (NQ_BYTE *)syMalloc(resSize);
                        if (newData == NULL)
                        {
                            TRCERR("Unable to allocate buffer for a big response");
                            status = CM_RP_OUTOFMEMORY;
                            break;
                        }
                        syFree(buf->data);
                        buf->data = newData;
                    }
                }

                /* pack outgoing PDU */
                buf->packetType = CM_RP_PKT_FAULT;
                cmRpcSetDescriptor(&outPdu, buf->data, !(buf->drepFlags & CM_RP_DREPLE));
                outPdu.length = buf->dataLen;
                outPdu.callId = buf->callId;

                /* look for the function */
                if (pPipe->numFuncs > buf->opNum && pPipe->funcs[buf->opNum].func != NULL)
                {
                    CSUser* pUser;       /* user pointer */

                    if (NULL == (pUser = csGetUserByUid(pFile->uid)))
                    {
                        TRCERR("UID not defined in the opened pipe");
                        TRC1P(" uid: %d", pFile->uid);
                        status = CM_RP_FAULTOTHER;
                    }
                    else
                    {
                        in.user = (NQ_BYTE*)pUser;
                        outPdu.user = in.user;
                        in.token = (NQ_BYTE*)(&pUser->token);
                        outPdu.token = in.token;
                        status = (*(pPipe->funcs[buf->opNum].func))(&in, &outPdu);
                        if (status == SMB_STATUS_NORESPONSE)
                            return SMB_STATUS_NORESPONSE;    /* do not respond */
                        buf->packetType = CM_RP_PKT_RESPONSE;
                    }
                }
                else
                {
                    TRCERR("RPC function not supported");
                    TRC1P(" opnum: %d", buf->opNum);
                    status = /* CM_RP_FAULTUNSUPPORTED */ CM_RP_FAULTOPRNGERROR;
                }
            }
            else
            {
                TRCERR("Context ID exceeds maximum number of contexts");
                TRC3P(" opnum: %d, context ID: %d, max contexts: %d", buf->opNum, buf->contextId, CM_RPC_MAXNUMBEROFCONTEXTS);
                status = CM_RP_FAULTCONTEXTMISMATCH;
            }

            buf->cancelCount = status == 0? 0: 1;

            if (buf->packetType == CM_RP_PKT_FAULT)
                outPdu.current = outPdu.origin;

            cmRpcPackUint32(&outPdu, status);
            buf->dataLen = (NQ_UINT)(outPdu.current - buf->data);
        }
        break;
    default:
        TRCE();
        return csErrorReturn(SMB_STATUS_NOT_SUPPORTED, (NQ_UINT32)SRV_ERRnosupport);
    }

    TRCE();
    return 0;
}

#endif /* UD_CS_INCLUDERPC */

#endif /* UD_NQ_INCLUDECIFSSERVER */

